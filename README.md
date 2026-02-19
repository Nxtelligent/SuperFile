# SuperFile

Reverse engineering and analysis toolkit for Windows executables.

## Quick Start

1. Edit `config.py` — set `TARGET_EXE` to the path of your target executable
2. Run any script: `python analyze_exe.py`

## Scripts

| Script | Purpose |
|---|---|
| `analyze_exe.py` | PE header analysis, installer signature detection |
| `deep_analyze.py` | String extraction, config key search, framework detection |
| `dump_manifest.py` | Extract RT_MANIFEST from PE resources |
| `dump_sections.py` | Dump RCDATA and overlay sections |
| `dump_strings.py` | Dump all ASCII/Unicode strings to file |
| `find_config_name.py` | Search for `.json` filenames and AppData paths |
| `list_imports.py` | List DLL imports |
| `update_manifest.py` | Inject UTF-8 manifest via Win32 API |
| `crack_blob.py` | Decompress/XOR decrypt binary blobs |

## Configuration

All scripts use `config.py` for paths:

```python
TARGET_EXE = r"C:\path\to\your\target.exe"
```

Output files (dumps, extracted resources) go to the `output/` directory.

## Requirements

```
pip install pefile
```
