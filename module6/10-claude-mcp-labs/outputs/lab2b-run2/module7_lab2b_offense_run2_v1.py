"""Lab 2b: dedupe + risk score over the lab 2 curated Suricata alerts (model-authored, no template).

Follows example 7.2 of docs/python-security-automation-research.md with these deviations:
  * window is FIXED, floor(epoch / 600) * 600, not a sliding deque. A sliding window needs
    ordered per-key state (Python UDF or mapGroupsWithState); a fixed window is a native
    groupBy. Events straddling a window edge can split into two offenses where a sliding
    window would merge them.
  * one offense per (fingerprint, window); `repeats` in the burst bonus is the event count of
    that offense, since the aggregate has no "first alert vs later alert" distinction.
  * ti_hits = 0 and fp_rate = 0 (no threat-intel or analyst feedback in this data).

argv[1] curated parquet dir, argv[2] offenses output dir (JSON lines), argv[3] report output dir.
"""
import json
import sys

from pyspark.sql import SparkSession
from pyspark.sql import functions as F

WINDOW_SECONDS = 600
ASSET_CRIT = {"10.70.0.66": 4}
ASSET_CRIT_DEFAULT = 2
ESCALATE_AT = 60
AUTO_CLOSE_BELOW = 25
ROUTES = ("auto-close", "queue", "escalate")


def main():
    curated_uri, offenses_uri, report_uri = sys.argv[1], sys.argv[2], sys.argv[3]

    spark = (
        SparkSession.builder.appName("module7-lab2b-offense-run2")
        .config("spark.sql.session.timeZone", "UTC")
        .getOrCreate()
    )
    spark.conf.set("spark.sql.session.timeZone", "UTC")

    raw = spark.read.parquet(curated_uri)
    total_in = raw.count()

    # Suricata severity 1 is the highest; lab 2 reports all 340 as "critical".
    base = (
        F.when(F.col("severity") == 1, 85)
        .when(F.col("severity") == 2, 60)
        .when(F.col("severity") == 3, 30)
        .otherwise(10)
    )
    asset_crit = F.lit(ASSET_CRIT_DEFAULT)
    for ip, crit in ASSET_CRIT.items():
        asset_crit = F.when(F.col("source_ip") == ip, crit).otherwise(asset_crit)

    alerts = (
        raw.select(
            F.col("signature_id").cast("string").alias("signature_id"),
            F.col("signature").cast("string").alias("signature"),
            F.col("source_ip").cast("string").alias("source_ip"),
            F.col("destination_ip").cast("string").alias("destination_ip"),
            F.col("severity").cast("int").alias("severity"),
            F.col("event_time").cast("timestamp").alias("event_ts"),
        )
        .filter(
            F.col("signature_id").isNotNull()
            & F.col("source_ip").isNotNull()
            & F.col("destination_ip").isNotNull()
            & F.col("severity").isNotNull()
            & F.col("event_ts").isNotNull()
        )
    )
    alerts_in = alerts.count()

    keyed = alerts.select(
        "signature_id",
        "signature",
        "source_ip",
        "destination_ip",
        "severity",
        "event_ts",
        F.substring(
            F.sha2(F.concat_ws("|", "signature_id", "source_ip", "destination_ip"), 256), 1, 16
        ).alias("fingerprint"),
        (F.floor(F.col("event_ts").cast("double") / WINDOW_SECONDS) * WINDOW_SECONDS)
        .cast("long")
        .alias("window_epoch"),
    )

    grouped = keyed.groupBy(
        "fingerprint", "window_epoch", "signature_id", "source_ip", "destination_ip"
    ).agg(
        F.count(F.lit(1)).cast("int").alias("event_count"),
        F.min("signature").alias("signature"),
        F.min("severity").alias("severity"),
        F.min("event_ts").alias("first_seen_ts"),
        F.max("event_ts").alias("last_seen_ts"),
    )

    scored = (
        grouped.withColumn("base_score", base)
        .withColumn("asset_crit", asset_crit)
        .withColumn(
            "raw_score",
            (
                F.col("base_score")
                + 8 * F.col("asset_crit")
                + F.least(F.lit(10), 2 * (F.col("event_count") - 1))
            ).cast("int"),
        )
        .withColumn("magnitude", F.greatest(F.lit(0), F.least(F.lit(100), F.col("raw_score"))))
        .withColumn(
            "route",
            F.when(F.col("magnitude") < AUTO_CLOSE_BELOW, "auto-close")
            .when(F.col("magnitude") >= ESCALATE_AT, "escalate")
            .otherwise("queue"),
        )
    )

    iso = "yyyy-MM-dd'T'HH:mm:ss'Z'"
    offenses = scored.select(
        "fingerprint",
        F.date_format(F.col("window_epoch").cast("timestamp"), iso).alias("window_start"),
        F.date_format((F.col("window_epoch") + WINDOW_SECONDS).cast("timestamp"), iso).alias(
            "window_end"
        ),
        "signature_id",
        "signature",
        "source_ip",
        "destination_ip",
        "severity",
        "asset_crit",
        "event_count",
        F.date_format("first_seen_ts", "yyyy-MM-dd'T'HH:mm:ss.SSS'Z'").alias("first_seen"),
        F.date_format("last_seen_ts", "yyyy-MM-dd'T'HH:mm:ss.SSS'Z'").alias("last_seen"),
        "base_score",
        "raw_score",
        "magnitude",
        "route",
    ).orderBy("window_start", "signature_id", "destination_ip")
    offenses = offenses.cache()

    offenses.coalesce(1).write.mode("errorifexists").json(offenses_uri)

    totals = offenses.agg(
        F.count(F.lit(1)).alias("offenses_out"),
        F.sum("event_count").alias("sum_event_count"),
        F.min("raw_score").alias("raw_min"),
        F.max("raw_score").alias("raw_max"),
        F.min("magnitude").alias("mag_min"),
        F.max("magnitude").alias("mag_max"),
        F.countDistinct("magnitude").alias("mag_distinct"),
    ).first()
    by_sig = (
        offenses.groupBy("signature_id", "signature")
        .agg(
            F.count(F.lit(1)).alias("offenses"),
            F.sum("event_count").alias("events"),
            F.countDistinct("window_start").alias("windows"),
            F.countDistinct("destination_ip").alias("destinations"),
        )
        .orderBy("signature_id")
        .collect()
    )
    route_counts = {r["route"]: r["count"] for r in offenses.groupBy("route").count().collect()}

    offenses_out = int(totals["offenses_out"])
    sum_events = int(totals["sum_event_count"] or 0)
    report = {
        "report_contract_version": "lab2b-offense-report-v0",
        "contract_note": "model-authored; no contract in skill server, validate by hand against sums below",
        "policy": {
            "window_seconds": WINDOW_SECONDS,
            "window_kind": "fixed floor(epoch/600) - deviates from 7.2 sliding deque",
            "fingerprint": "sha256(signature_id|source_ip|destination_ip)[:16]",
            "score": "base(sev) + 8*asset_crit + min(10, 2*(repeats-1)); ti_hits=0; fp_rate=0; clamp 0..100",
            "base": {"1": 85, "2": 60, "3": 30, "other": 10},
            "route": "<25 auto-close, >=60 escalate, else queue",
            "asset_crit": ASSET_CRIT,
            "asset_crit_default": ASSET_CRIT_DEFAULT,
            "asset_crit_keyed_on": "source_ip",
        },
        "alerts_total_in_parquet": total_in,
        "alerts_in": alerts_in,
        "alerts_excluded_null_keys": total_in - alerts_in,
        "offenses_out": offenses_out,
        "reduction_pct": round(100.0 * (1 - offenses_out / alerts_in), 2) if alerts_in else 0.0,
        "sum_event_count": sum_events,
        "sum_event_count_equals_alerts_in": sum_events == alerts_in,
        "by_route": {r: int(route_counts.get(r, 0)) for r in ROUTES},
        "by_signature": [
            {
                "signature_id": r["signature_id"],
                "signature": r["signature"],
                "offenses": int(r["offenses"]),
                "events": int(r["events"]),
                "windows": int(r["windows"]),
                "destinations": int(r["destinations"]),
            }
            for r in by_sig
        ],
        "raw_score_min": totals["raw_min"],
        "raw_score_max": totals["raw_max"],
        "magnitude_min": totals["mag_min"],
        "magnitude_max": totals["mag_max"],
        "distinct_magnitude_values": int(totals["mag_distinct"]),
        "tp_loss_measurable": False,
        "tp_loss_note": "input has no analyst labels; reduction_pct says nothing about true positives lost",
    }

    (
        spark.createDataFrame([(json.dumps(report, sort_keys=True),)], "value string")
        .coalesce(1)
        .write.mode("errorifexists")
        .text(report_uri)
    )
    spark.stop()


if __name__ == "__main__":
    main()
