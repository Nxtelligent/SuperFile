"""
SuperFile — Utility Functions
"""

import os
import math


def format_file_size(size_bytes):
    """Format a file size in bytes to a human-readable string."""
    if size_bytes <= 0:
        return "0 B"
    units = ("B", "KB", "MB", "GB", "TB")
    i = int(math.floor(math.log(size_bytes, 1024)))
    i = min(i, len(units) - 1)
    value = size_bytes / (1024 ** i)
    if i == 0:
        return f"{int(value)} B"
    return f"{value:.1f} {units[i]}"


def get_file_type(filepath):
    """Return a human-readable file type description."""
    if os.path.isdir(filepath):
        return "Folder"
    ext = os.path.splitext(filepath)[1].lower()
    type_map = {
        ".txt": "Text File",
        ".py": "Python Script",
        ".js": "JavaScript File",
        ".html": "HTML File",
        ".css": "CSS File",
        ".json": "JSON File",
        ".xml": "XML File",
        ".md": "Markdown File",
        ".csv": "CSV File",
        ".log": "Log File",
        ".ini": "Config File",
        ".cfg": "Config File",
        ".yaml": "YAML File",
        ".yml": "YAML File",
        ".toml": "TOML File",
        ".png": "PNG Image",
        ".jpg": "JPEG Image",
        ".jpeg": "JPEG Image",
        ".gif": "GIF Image",
        ".bmp": "Bitmap Image",
        ".svg": "SVG Image",
        ".ico": "Icon File",
        ".webp": "WebP Image",
        ".mp3": "MP3 Audio",
        ".wav": "WAV Audio",
        ".mp4": "MP4 Video",
        ".avi": "AVI Video",
        ".mkv": "MKV Video",
        ".zip": "ZIP Archive",
        ".rar": "RAR Archive",
        ".7z": "7-Zip Archive",
        ".tar": "TAR Archive",
        ".gz": "GZip Archive",
        ".exe": "Executable",
        ".msi": "Installer",
        ".dll": "DLL Library",
        ".bat": "Batch Script",
        ".ps1": "PowerShell Script",
        ".sh": "Shell Script",
        ".pdf": "PDF Document",
        ".doc": "Word Document",
        ".docx": "Word Document",
        ".xls": "Excel Spreadsheet",
        ".xlsx": "Excel Spreadsheet",
        ".ppt": "PowerPoint",
        ".pptx": "PowerPoint",
    }
    return type_map.get(ext, f"{ext.upper()[1:]} File" if ext else "File")


IMAGE_EXTENSIONS = {".png", ".jpg", ".jpeg", ".gif", ".bmp", ".svg", ".ico", ".webp"}
TEXT_EXTENSIONS = {
    ".txt", ".py", ".js", ".ts", ".html", ".css", ".json", ".xml", ".md",
    ".csv", ".log", ".ini", ".cfg", ".yaml", ".yml", ".toml", ".bat",
    ".ps1", ".sh", ".c", ".cpp", ".h", ".hpp", ".java", ".rs", ".go",
    ".rb", ".php", ".sql", ".gitignore", ".env",
}


def is_text_file(filepath):
    """Check if a file is likely a text file based on extension."""
    ext = os.path.splitext(filepath)[1].lower()
    if ext in TEXT_EXTENSIONS:
        return True
    # Try reading first bytes for unknown extensions
    if not ext or ext not in IMAGE_EXTENSIONS:
        try:
            with open(filepath, 'rb') as f:
                chunk = f.read(512)
            # If most bytes are printable, it's probably text
            text_chars = sum(1 for b in chunk if b in range(32, 127) or b in (9, 10, 13))
            return len(chunk) > 0 and (text_chars / len(chunk)) > 0.85
        except (OSError, ZeroDivisionError):
            return False
    return False


def is_image_file(filepath):
    """Check if a file is an image based on extension."""
    ext = os.path.splitext(filepath)[1].lower()
    return ext in IMAGE_EXTENSIONS


def get_drive_list():
    """Get list of available drive letters on Windows."""
    import string
    drives = []
    for letter in string.ascii_uppercase:
        drive = f"{letter}:\\"
        if os.path.exists(drive):
            drives.append(drive)
    return drives
