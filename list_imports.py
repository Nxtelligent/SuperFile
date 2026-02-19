"""
List all DLL imports from a PE executable.
"""

import pefile
from config import TARGET_EXE


def list_imports(path):
    try:
        pe = pefile.PE(path)
        print(f"Imports for {path}:")
        if hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                print(f"\n[{entry.dll.decode('utf-8')}]")
                for imp in entry.imports:
                    if imp.name:
                        print(f"  - {imp.name.decode('utf-8')}")
        else:
            print("No imports found.")
    except Exception as e:
        print(f"Error: {e}")


if __name__ == "__main__":
    list_imports(TARGET_EXE)
