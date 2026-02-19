"""
Extract and display the RT_MANIFEST resource from a PE executable.
"""

import pefile
from config import TARGET_EXE


def dump_manifest(path):
    print(f"Reading manifest from {path}...")
    try:
        pe = pefile.PE(path)

        for entry in pe.DIRECTORY_ENTRY_RESOURCE.entries:
            if entry.id == 24:  # RT_MANIFEST
                for child in entry.directory.entries:
                    if child.id == 1:
                        for lang in child.directory.entries:
                            print(f"Found Manifest Resource. Language ID: {lang.id}")
                            data_rva = lang.data.struct.OffsetToData
                            size = lang.data.struct.Size
                            data = pe.get_data(data_rva, size)
                            print("\n--- Manifest Content ---")
                            print(data.decode('utf-8', 'ignore'))
                            return
        print("No manifest found.")
    except Exception as e:
        print(f"Error reading manifest: {e}")


if __name__ == "__main__":
    dump_manifest(TARGET_EXE)
