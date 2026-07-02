#!/usr/bin/env python3
"""
fetch_strait_traffic.py — Fetch daily ship-transit counts for the Strait of Hormuz
(or another chokepoint) from the IMF PortWatch open-data API.

Companion to fetch_press.py. The Iranian press does NOT publish transit counts, so
quantitative "how many ships" questions cannot be answered from the Farsi outlets —
this script fills that gap from maritime-tracking data instead.

Usage:
    python3 fetch_strait_traffic.py                          # last 14 days, Hormuz
    python3 fetch_strait_traffic.py --days 30
    python3 fetch_strait_traffic.py --chokepoint "Bab el-Mandeb"
    python3 fetch_strait_traffic.py --output-dir some-run-dir/

Like fetch_press.py, this script does NOT analyze. It fetches and packages.

Data notes (see references/strait_traffic_sources.md for the full source list):
  - PortWatch counts AIS-broadcasting transits only. Ships running dark are missed,
    so in a crisis the true flow may be HIGHER than reported.
  - Publication lags ~3-5 days. For a genuine last-24-hours number, use the live
    web trackers listed in the references file (and say which one you used).
"""

import argparse
import datetime as dt
import json
import sys
from pathlib import Path

try:
    import requests
except ImportError:
    sys.exit("Missing dependency: pip install --break-system-packages requests")

PORTWATCH_LAYER = (
    "https://services9.arcgis.com/weJ1QsnbMYJlCHdG/arcgis/rest/services/"
    "Daily_Chokepoints_Data/FeatureServer/0/query"
)
TIMEOUT = 60

FIELDS = "date,portid,portname,n_tanker,n_cargo,n_total"


def query(params):
    base = {"f": "json", "outFields": FIELDS}
    base.update(params)
    r = requests.get(PORTWATCH_LAYER, params=base, timeout=TIMEOUT)
    r.raise_for_status()
    data = r.json()
    if "error" in data:
        raise RuntimeError(f"PortWatch API error: {data['error']}")
    return [f["attributes"] for f in data.get("features", [])]


def fetch_recent(chokepoint, days):
    return query({
        "where": f"portname LIKE '%{chokepoint}%'",
        "orderByFields": "date DESC",
        "resultRecordCount": str(days),
    })


def fetch_baseline(portid, latest_date):
    """Average daily transits over a ~6-month window ending 6 months before the
    latest data point — far enough back to predate the 2026 disruption."""
    latest = dt.date.fromisoformat(latest_date)
    end = latest - dt.timedelta(days=180)
    start = end - dt.timedelta(days=180)
    rows = query({
        "where": (
            f"portid = '{portid}' AND date >= DATE '{start}' AND date <= DATE '{end}'"
        ),
        "orderByFields": "date DESC",
        "resultRecordCount": "1000",
    })
    if not rows:
        return None, (start, end)
    avg = sum(r["n_total"] for r in rows) / len(rows)
    return avg, (start, end)


def render_markdown(rows, baseline, window, chokepoint, fetched_at):
    latest = rows[0]
    lag_days = (dt.date.fromisoformat(fetched_at) - dt.date.fromisoformat(latest["date"])).days
    lines = [
        f"## Strait traffic supplement — {latest['portname']}",
        "",
        f"**Source:** IMF PortWatch (AIS-based, `Daily_Chokepoints_Data`), fetched {fetched_at}",
        f"**Latest available day:** {latest['date']} ({lag_days} day(s) behind fetch date — "
        "PortWatch publishes with a lag; for a true last-24-hours figure use a live tracker, "
        "see references/strait_traffic_sources.md)",
        "",
        "| Date | Tankers | Cargo | Total transits |",
        "|------|---------|-------|----------------|",
    ]
    for r in rows:
        lines.append(f"| {r['date']} | {r['n_tanker']} | {r['n_cargo']} | {r['n_total']} |")
    lines.append("")
    if baseline is not None:
        pct = 100.0 * latest["n_total"] / baseline if baseline else 0.0
        lines.append(
            f"**Baseline:** ~{baseline:.0f} transits/day average over {window[0]} → {window[1]} "
            f"(pre-disruption window). Latest day is **{pct:.0f}%** of that baseline."
        )
        lines.append("")
    lines.append(
        "**Caveats:** counts only AIS-broadcasting crossings — ships running dark are missed, "
        "so true flow may be higher. Different trackers use different transit definitions; "
        "cross-check against a second source before quoting a single number."
    )
    lines.append("")
    return "\n".join(lines)


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[1])
    ap.add_argument("--chokepoint", default="Hormuz",
                    help="Chokepoint name substring (default: Hormuz)")
    ap.add_argument("--days", type=int, default=14,
                    help="How many most-recent days to fetch (default 14)")
    ap.add_argument("--no-baseline", action="store_true",
                    help="Skip the pre-disruption baseline query")
    ap.add_argument("--output-dir", default=None,
                    help="Also write strait-traffic.md and strait-traffic.json here "
                         "(e.g. the fetch_press.py run directory, so the traffic section "
                         "can be appended to the handoff)")
    args = ap.parse_args()

    rows = fetch_recent(args.chokepoint, args.days)
    if not rows:
        sys.exit(f"[fail] No PortWatch rows matched chokepoint '{args.chokepoint}'")

    baseline, window = (None, None)
    if not args.no_baseline:
        try:
            baseline, window = fetch_baseline(rows[0]["portid"], rows[0]["date"])
        except Exception as e:
            print(f"    [warn] baseline query failed, continuing without: {e}", file=sys.stderr)

    fetched_at = dt.date.today().isoformat()
    md = render_markdown(rows, baseline, window, args.chokepoint, fetched_at)
    print(md)

    if args.output_dir:
        out = Path(args.output_dir)
        out.mkdir(parents=True, exist_ok=True)
        (out / "strait-traffic.md").write_text(md, encoding="utf-8")
        (out / "strait-traffic.json").write_text(
            json.dumps({"fetched_at": fetched_at, "chokepoint": args.chokepoint,
                        "baseline_avg": baseline, "rows": rows},
                       ensure_ascii=False, indent=2),
            encoding="utf-8")
        print(f"[+] Wrote {out / 'strait-traffic.md'} and strait-traffic.json",
              file=sys.stderr)


if __name__ == "__main__":
    main()
