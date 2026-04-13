python3 - <<'PY'
import json, datetime
with open("certificate.json") as f:
    c = json.load(f)["standalone_certificate"]["tbs_entry"]
for k in ("not_before", "not_after"):
    ts = c[k]
    print(k, "=", datetime.datetime.fromtimestamp(ts, datetime.timezone.utc))
PY
