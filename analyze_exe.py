"""
Analyze an executable: PE header info, .NET detection, installer signature detection.
"""

import os
import pefile
from config import TARGET_EXE


def analyze_exe(path):
    if not os.path.exists(path):
        print(f"File not found: {path}")
        return

    print(f"Analyzing {path}...")
    try:
        pe = pefile.PE(path)
        print(f"Machine: {hex(pe.FILE_HEADER.Machine)}")
        print(f"TimeDateStamp: {pe.FILE_HEADER.TimeDateStamp}")

        is_dotnet = False
        try:
            if pe.OPTIONAL_HEADER.DATA_DIRECTORY[14].Size > 0:
                print("Detected .NET Assembly")
                is_dotnet = True
        except Exception as e:
            print(f"Error checking .NET: {e}")

        # Basic string search for installer signatures
        with open(path, 'rb') as f:
            content = f.read()

            if b"Inno Setup" in content:
                print("Detected: Inno Setup")
            elif b"NullsoftInst" in content:
                print("Detected: NSIS Installer")
            elif b"InstallShield" in content:
                print("Detected: InstallShield")
            elif b"7z" in content and b"\x37\x7A\xBC\xAF\x27\x1C" in content:
                print("Detected: 7-Zip Self Extracting Archive")
            elif b"PyInstaller" in content or b"_MEI" in content:
                print("Detected: PyInstaller")
            else:
                print("No obvious installer signature found in simple scan.")

    except Exception as e:
        print(f"PE Analysis failed: {e}")


if __name__ == "__main__":
    analyze_exe(TARGET_EXE)
