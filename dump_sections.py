"""
Dump RCDATA resources and overlay data from a PE executable.
"""

import pefile
import os
from config import TARGET_EXE, OUTPUT_DIR


def dump_sections(path):
    try:
        pe = pefile.PE(path)

        # Dump RCDATA
        if hasattr(pe, 'DIRECTORY_ENTRY_RESOURCE'):
            for resource_type in pe.DIRECTORY_ENTRY_RESOURCE.entries:
                if resource_type.id == 10:  # RT_RCDATA is 10
                    for resource_id in resource_type.directory.entries:
                        for resource_lang in resource_id.directory.entries:
                            data = pe.get_data(resource_lang.data.struct.OffsetToData, resource_lang.data.struct.Size)
                            out_name = os.path.join(OUTPUT_DIR, f"rcdata_{resource_id.id}.bin")
                            with open(out_name, 'wb') as f:
                                f.write(data)
                            print(f"Dumped RCDATA {resource_id.id} to {out_name} ({len(data)} bytes)")

        # Dump Overlay
        overlay_offset = pe.get_overlay_data_start_offset()
        if overlay_offset:
            with open(path, 'rb') as f:
                f.seek(overlay_offset)
                overlay_data = f.read()
            out_name = os.path.join(OUTPUT_DIR, "overlay.bin")
            with open(out_name, 'wb') as f:
                f.write(overlay_data)
            print(f"Dumped Overlay to {out_name} ({len(overlay_data)} bytes)")

    except Exception as e:
        print(f"Dump failed: {e}")


if __name__ == "__main__":
    dump_sections(TARGET_EXE)
