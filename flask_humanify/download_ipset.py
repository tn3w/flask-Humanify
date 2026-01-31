"""Download ipset.json during package installation."""

from urllib.request import urlopen
import json
from datetime import datetime
import os


def download_ipset():
    """Download the latest ipset.json file."""
    try:
        with urlopen(
            "https://raw.githubusercontent.com/tn3w/IPSet/refs/heads/master/ipset.json",
            timeout=30,
        ) as response:
            data = json.load(response)

        data["_timestamp"] = datetime.now().isoformat()

        script_dir = os.path.dirname(os.path.abspath(__file__))
        datasets_dir = os.path.join(script_dir, "datasets")

        os.makedirs(datasets_dir, exist_ok=True)

        ipset_path = os.path.join(datasets_dir, "ipset.json")

        with open(ipset_path, "w", encoding="utf-8") as f:
            json.dump(data, f)

        print(f"Successfully downloaded ipset.json to {ipset_path}")
        return True
    except Exception as e:
        print(f"Warning: Failed to download ipset.json: {e}")
        print("The package will work with the bundled version.")
        return False


if __name__ == "__main__":
    download_ipset()
