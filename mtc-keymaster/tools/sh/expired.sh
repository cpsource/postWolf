python3 - <<'PY'
import json, time
with open("certificate.json") as f:
    c = json.load(f)["standalone_certificate"]["tbs_entry"]
now = time.time()
print("valid_now =", c["not_before"] <= now <= c["not_after"])
PY
