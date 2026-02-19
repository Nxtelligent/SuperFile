"""
SuperFile — Central Configuration
==================================
Edit the paths below to point at your target executable.
All analysis scripts import from this file.
"""

import os

# --- TARGET CONFIGURATION ---
# Path to the executable you want to analyze
TARGET_EXE = r"C:\path\to\your\target.exe"

# Directory for output files (dumps, extracted resources, etc.)
OUTPUT_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "output")

# Ensure output directory exists
os.makedirs(OUTPUT_DIR, exist_ok=True)

# --- OPTIONAL: AppData candidate names ---
# Add folder names to search for in %APPDATA% and %LOCALAPPDATA%
APPDATA_CANDIDATES = [
    # "YourApp",
    # "CompanyName",
    # "App Name",
]
