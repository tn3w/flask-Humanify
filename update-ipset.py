from urllib.request import urlopen
import json
from datetime import datetime

with urlopen(
    "https://raw.githubusercontent.com/tn3w/IPSet/refs/heads/master/ipset.json"
) as response:
    data = json.load(response)

data["_timestamp"] = datetime.now().isoformat()

with open("flask_humanify/datasets/ipset.json", "w", encoding="utf-8") as f:
    json.dump(data, f)
