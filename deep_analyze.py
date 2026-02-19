"""
Deep analysis: detect language/framework, extract interesting strings,
search for config keys, font references, JSON files, settings, and language strings.
"""

import re
from config import TARGET_EXE


def analyze_strings(path):
    print(f"Deep analyzing {path}...")
    try:
        with open(path, 'rb') as f:
            content = f.read()

        # Check for specific framework signatures
        if b"Go build" in content:
            print("[+] Detected Go (Golang) executable")
        if b"rustc" in content or b"/src/libstd/" in content:
            print("[+] Detected Rust executable")
        if b"PyInstaller" in content or b"MEI" in content or b"python" in content[:2000]:
            print("[+] Detected Python (PyInstaller likely)")
        if b"Electron" in content or b"node.dll" in content:
            print("[+] Detected Electron/Node.js")
        if b"UPX!" in content:
            print("[+] Detected UPX Packed")

        # Extract readable strings
        strings = re.findall(b"[A-Za-z0-9/\\-:_. @]{5,}", content)

        print("\n--- Interesting Strings (First 50) ---")
        count = 0
        for s in strings:
            try:
                decoded = s.decode('utf-8')
                if "pdb" in decoded.lower() or "install" in decoded.lower() or "setup" in decoded.lower():
                    print(f"Match: {decoded}")

                if count < 20:
                    print(f"String: {decoded}")
                count += 1
            except:
                pass

        print(f"\nTotal strings found: {len(strings)}")

        print("\n--- Searching for Config Keys ---")
        config_pattern = re.compile(b"[A-Za-z0-9_]{3,}")

        # Scan for "Font" and print context
        font_indices = [m.start() for m in re.finditer(b"Font", content, re.IGNORECASE)]

        for idx in font_indices:
            start = max(0, idx - 100)
            end = min(len(content), idx + 100)
            chunk = content[start:end]
            found = re.findall(b"[A-Za-z0-9_.]+", chunk)
            print(f"Context around 'Font' at {idx}: {[f.decode('utf-8', 'ignore') for f in found]}")

        print("\n--- Searching for 'json' ---")
        json_indices = [m.start() for m in re.finditer(b"json", content, re.IGNORECASE)]
        for idx in json_indices:
            start = max(0, idx - 100)
            end = min(len(content), idx + 100)
            chunk = content[start:end]
            found = re.findall(b"[A-Za-z0-9_.]+", chunk)
            print(f"Context around 'json' at {idx}: {[f.decode('utf-8', 'ignore') for f in found]}")

        print("\n--- Searching for Settings Keys ---")
        setting_pattern = re.compile(b"Setting_[A-Za-z0-9_]+")
        setting_matches = list(set(re.findall(setting_pattern, content)))

        for m in setting_matches:
            print(f"Setting Key: {m.decode('utf-8', 'ignore')}")

        print("\n--- Searching for 'Language' or 'Locale' ---")
        lang_matches = re.findall(b"[A-Za-z0-9_]*Language[A-Za-z0-9_]*", content, re.IGNORECASE)
        for m in list(set(lang_matches))[:20]:
            print(f"Lang Match: {m.decode('utf-8', 'ignore')}")

    except Exception as e:
        print(f"Analysis failed: {e}")


if __name__ == "__main__":
    analyze_strings(TARGET_EXE)
