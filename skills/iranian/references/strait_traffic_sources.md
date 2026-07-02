# Strait of Hormuz traffic data sources

The Iranian Farsi-language press does **not** publish ship-transit counts. Quantitative
questions ("how many ships went through the strait yesterday?") cannot be answered by the
press-fetch layer at all — they need maritime-tracking data. This file lists the usable
sources and their caveats. `scripts/fetch_strait_traffic.py` automates the first one.

## Scriptable (use these first)

### IMF PortWatch — `fetch_strait_traffic.py` uses this
- Open ArcGIS FeatureServer, no auth, no key:
  `https://services9.arcgis.com/weJ1QsnbMYJlCHdG/arcgis/rest/services/Daily_Chokepoints_Data/FeatureServer/0/query`
- Strait of Hormuz = `portid: chokepoint6` (the script resolves by name, don't hardcode).
- Daily rows: `n_tanker`, `n_cargo`, `n_total` plus capacity fields.
- **Lag: ~3–5 days.** Verified 2026-07-02: latest row was 2026-06-28. Fine for trend
  ("recovering since the June 17 MOU"), wrong tool for "last 24 hours."
- Counts AIS-broadcasting transits only (see caveats below).

## Web dashboards (fresher, not scriptable — use WebSearch/WebFetch)

Live trackers that sprang up around the 2026 crisis; good for a same-day number, but
say which one you used because their transit definitions differ:

- WTO Data Lab Strait of Hormuz Trade Tracker — https://datalab.wto.org/Strait-of-Hormuz-Trade-Tracker
- NBC News traffic tracker — https://www.nbcnews.com/data-graphics/strait-of-hormuz-ports-traffic-trump-us-iran-war-rcna331507
- straits.live — crisis-era live monitor
- TankerMap Hormuz analytics — https://tankermap.com/analytics/straits/hormuz
- MacroMicro (mirrors the IMF PortWatch series) — https://en.macromicro.me/charts/94482/imf-strait-of-hormuz-number-of-ships-and-transit-volume
- Statista chart (periodic snapshots) — https://www.statista.com/chart/35984/ship-traffic-in-the-strait-of-hormuz/

Official maritime-security advisories (incidents rather than counts, but authoritative
on whether transits are happening at all): UKMTO, JMIC.

## Caveats that must travel with any number you quote

1. **AIS-dark undercount.** All these sources count AIS broadcasts. During the 2026
   crisis many ships transited dark (or in escorted convoys with AIS off), so true
   flow may be materially higher than any tracker shows. Numbers are floors.
2. **Definitions differ.** One tracker's "transit" is another's "port call near the
   strait." On 2026-07-01, web trackers reported ~5 transits while PortWatch showed
   ~27–30/day for the same week. Never mix sources in one comparison; quote source + date.
3. **Baseline for context.** Pre-disruption normal is ~85–95 transits/day (PortWatch
   2025 average ≈ 85; media commonly cite ~93). Give the percentage, not just the raw count.
4. **Iranian-press silence is itself a data point.** If outlets claim the strait is
   "open under Iranian control" while tracker counts stay >80% below baseline, that gap
   is a finding for the handoff — surface it, don't resolve it.

## Workflow integration

Run the traffic script into the same output directory as the press fetch, then append
its markdown to the handoff:

```bash
python3 scripts/fetch_strait_traffic.py --output-dir <press-run-dir>
cat <press-run-dir>/strait-traffic.md >> <press-run-dir>/claude-ai-handoff.md
```

Keep the layers labeled: press excerpts show what Iran *says* about the strait;
tracker data shows what ships *do*. The juxtaposition is the product — same
philosophy as the press check itself.
