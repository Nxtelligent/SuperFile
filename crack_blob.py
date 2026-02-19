"""
Attempt to decompress or XOR-decrypt a binary blob,
looking for PE (MZ) or ZIP headers.
"""

import zlib
import lzma
import bz2
import os
from config import OUTPUT_DIR


def try_decompress(data, algo_name, func, base_path):
    try:
        decompressed = func(data)
        print(f"[+] Success with {algo_name}! Size: {len(decompressed)}")
        out_path = base_path + f".{algo_name}.bin"
        with open(out_path, "wb") as f:
            f.write(decompressed)
        print(f"    Header: {decompressed[:16].hex()}")
        if decompressed.startswith(b'MZ'):
            print("    -> IT IS A PE FILE!")
    except:
        pass


def xor_decrypt(data, key):
    return bytes([b ^ key for b in data])


def analyze_blob(path):
    with open(path, 'rb') as f:
        data = f.read()

    print(f"Analyzing blob: {len(data)} bytes")

    # Try standard decompressions
    try_decompress(data, "zlib", zlib.decompress, path)
    try_decompress(data, "zlib_raw", lambda d: zlib.decompress(d, -15), path)
    try_decompress(data, "lzma", lzma.decompress, path)
    try_decompress(data, "bz2", bz2.decompress, path)

    # Try XOR with common keys (0-255)
    print("Trying XOR single byte keys (looking for MZ header)...")
    for key in range(256):
        decrypted = xor_decrypt(data[:100], key)
        if decrypted.startswith(b'MZ'):
            print(f"[+] Found MZ header with XOR key: {hex(key)}")
            full_decrypt = xor_decrypt(data, key)
            with open(path + f".xor_{hex(key)}.bin", "wb") as f:
                f.write(full_decrypt)
            print("    -> Saved decrypted file.")
            break
        elif decrypted.startswith(b'PK\x03\x04'):
            print(f"[+] Found ZIP header with XOR key: {hex(key)}")
            full_decrypt = xor_decrypt(data, key)
            with open(path + f".xor_{hex(key)}.bin", "wb") as f:
                f.write(full_decrypt)
            break


if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1:
        analyze_blob(sys.argv[1])
    else:
        print("Usage: python crack_blob.py <path_to_blob>")
        print(f"  Tip: dumped blobs are in {OUTPUT_DIR}")
