"""
Search a binary for .json filenames and check common AppData locations.
"""

import re
import os
from config import TARGET_EXE, APPDATA_CANDIDATES


def check_config_name(path):
    print(f"Scanning {path} for .json filenames...")
    try:
        with open(path, 'rb') as f:
            content = f.read()

        # Look for sequences ending in .json
        matches = re.finditer(b"([ -~]{5,20}\.json)", content, re.IGNORECASE)

        seen = set()
        print("\n--- Found JSON filenames ---")
        for m in matches:
            s = m.group(1).decode('utf-8', 'ignore')
            if s not in seen:
                print(f"Match: '{s}'")
                seen.add(s)

        # Check AppData paths
        print("\n--- Checking default AppData paths ---")
        appdata = os.getenv('APPDATA')
        localappdata = os.getenv('LOCALAPPDATA')

        candidates = []
        for name in APPDATA_CANDIDATES:
            candidates.append(os.path.join(appdata, name))
            candidates.append(os.path.join(localappdata, name))

        for c in candidates:
            if os.path.exists(c):
                print(f"Found folder: {c}")
                print(os.listdir(c))

        if not APPDATA_CANDIDATES:
            print("(No AppData candidates configured in config.py)")

    except Exception as e:
        print(f"Error: {e}")


if __name__ == "__main__":
    check_config_name(TARGET_EXE)
