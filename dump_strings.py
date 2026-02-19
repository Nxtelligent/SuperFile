"""
Dump all ASCII and Unicode strings from a binary to an output file.
"""

import re
import os
from config import TARGET_EXE, OUTPUT_DIR


def dump_strings(path, out_path):
    print(f"Dumping strings from {path}...")
    try:
        with open(path, 'rb') as f:
            content = f.read()

        # Extract ASCII and Unicode strings
        ascii_strings = re.findall(b"[ -~]{4,}", content)
        unicode_strings = re.findall(b"(?:[\x20-\x7E][\x00]){4,}", content)

        with open(out_path, 'w', encoding='utf-8') as f:
            f.write(f"--- ASCII Strings ({len(ascii_strings)}) ---\n")
            for s in ascii_strings:
                try:
                    f.write(s.decode('utf-8') + "\n")
                except:
                    pass

            f.write(f"\n--- Unicode Strings ({len(unicode_strings)}) ---\n")
            for s in unicode_strings:
                try:
                    f.write(s.decode('utf-16le') + "\n")
                except:
                    pass

        print(f"Strings saved to {out_path}")

    except Exception as e:
        print(f"String dump failed: {e}")


if __name__ == "__main__":
    out_path = os.path.join(OUTPUT_DIR, "strings_dump.txt")
    dump_strings(TARGET_EXE, out_path)
