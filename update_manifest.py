"""
Inject a UTF-8 manifest into a PE executable using the Win32 UpdateResource API.
"""

import ctypes
from ctypes import wintypes
import os
from config import TARGET_EXE

# Define constants
RT_MANIFEST = 24
ID_MANIFEST = 1

# Define kernel32 functions
kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)

BeginUpdateResourceW = kernel32.BeginUpdateResourceW
BeginUpdateResourceW.argtypes = [wintypes.LPCWSTR, wintypes.BOOL]
BeginUpdateResourceW.restype = wintypes.HANDLE

UpdateResourceW = kernel32.UpdateResourceW
UpdateResourceW.argtypes = [
    wintypes.HANDLE,
    wintypes.LPCWSTR,
    wintypes.LPCWSTR,
    wintypes.WORD,
    wintypes.LPVOID,
    wintypes.DWORD
]
UpdateResourceW.restype = wintypes.BOOL

EndUpdateResourceW = kernel32.EndUpdateResourceW
EndUpdateResourceW.argtypes = [wintypes.HANDLE, wintypes.BOOL]
EndUpdateResourceW.restype = wintypes.BOOL

# New Manifest Content with UTF-8 support
new_manifest = """
<assembly xmlns="urn:schemas-microsoft-com:asm.v1" manifestVersion="1.0">
  <trustInfo xmlns="urn:schemas-microsoft-com:asm.v3">
    <security>
      <requestedPrivileges>
        <requestedExecutionLevel level="asInvoker" uiAccess="false"></requestedExecutionLevel>
      </requestedPrivileges>
    </security>
  </trustInfo>
  <application xmlns="urn:schemas-microsoft-com:asm.v3">
    <windowsSettings>
      <longPathAware xmlns="http://schemas.microsoft.com/SMI/2016/WindowsSettings">true</longPathAware>
      <activeCodePage xmlns="http://schemas.microsoft.com/SMI/2019/WindowsSettings">UTF-8</activeCodePage>
    </windowsSettings>
  </application>
  <dependency>
    <dependentAssembly>
      <assemblyIdentity type="win32" name="Microsoft.Windows.Common-Controls" version="6.0.0.0" processorArchitecture="amd64" publicKeyToken="6595b64144ccf1df" language="*"></assemblyIdentity>
    </dependentAssembly>
  </dependency>
</assembly>
""".strip()


def update_manifest(target_file=None):
    if target_file is None:
        target_file = TARGET_EXE

    if not os.path.exists(target_file):
        print(f"Error: File not found: {target_file}")
        return

    print(f"Updating manifest in {target_file}...")

    manifest_data = new_manifest.encode('utf-8')

    # 1. Begin Update
    hUpdate = BeginUpdateResourceW(target_file, False)
    if not hUpdate:
        print(f"BeginUpdateResource failed: {ctypes.get_last_error()}")
        return

    # 2. Update Resource
    rt_manifest = ctypes.cast(24, ctypes.c_wchar_p)
    id_manifest = ctypes.cast(1, ctypes.c_wchar_p)

    print(f"Calling UpdateResourceW with language ID 1033...")
    result = UpdateResourceW(
        hUpdate,
        rt_manifest,
        id_manifest,
        1033,  # Language: English (US)
        manifest_data,
        len(manifest_data)
    )

    if not result:
        print(f"UpdateResource failed: {ctypes.get_last_error()}")
        print("discarding changes...")
        EndUpdateResourceW(hUpdate, True)  # Discard
        return

    # 3. End Update (Write changes)
    if EndUpdateResourceW(hUpdate, False):
        print("Manifest updated successfully!")
    else:
        print(f"EndUpdateResource failed: {ctypes.get_last_error()}")


if __name__ == "__main__":
    update_manifest()
