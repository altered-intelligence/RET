import json, sys
p = sys.argv[1]
data = open(p, 'rb').read()[:4096]
def h(b): return b.hex()[:48]
print(json.dumps({
  "findings": [{
    "id": "ht.sample",
    "claim": f"file is {len(data)} bytes (head-bounded); first 24: {h(data[:24])}; last 24: {h(data[-24:])}",
    "severity": "info",
    "confidence": "direct",
    "evidence": [{"label": "head", "value": h(data[:24]), "location": {"start": 0, "end": 24}},
                 {"label": "tail", "value": h(data[-24:]), "location": {"start": max(0, len(data)-24)}}]
  }]
}))
