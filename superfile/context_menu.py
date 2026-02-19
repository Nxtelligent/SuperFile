"""
SuperFile — Context Menu
Right-click menu for file operations.
"""

import os
import subprocess
from PySide6.QtWidgets import QMenu
from PySide6.QtGui import QAction

from .file_model import FileOperations


class FileContextMenu(QMenu):
    """Context menu for file/folder operations."""

    def __init__(self, filepath, panel, parent=None):
        super().__init__(parent)
        self.filepath = filepath
        self.panel = panel
        self._build_menu()

    def _build_menu(self):
        """Build the context menu items."""
        is_dir = os.path.isdir(self.filepath) if self.filepath else False
        name = os.path.basename(self.filepath) if self.filepath else ""

        if self.filepath:
            # Open
            if is_dir:
                action_open = self.addAction("📂  Open")
                action_open.triggered.connect(lambda: self.panel.navigate_to(self.filepath))

                action_open_tab = self.addAction("📑  Open in New Tab")
                action_open_tab.triggered.connect(lambda: self.panel.open_in_new_tab(self.filepath))
            else:
                action_open = self.addAction("📄  Open")
                action_open.triggered.connect(lambda: os.startfile(self.filepath))

            self.addSeparator()

            # Edit operations
            action_copy = self.addAction("📋  Copy")
            action_copy.setShortcut("Ctrl+C")
            action_copy.triggered.connect(lambda: self.panel.copy_selected())

            action_cut = self.addAction("✂  Cut")
            action_cut.setShortcut("Ctrl+X")
            action_cut.triggered.connect(lambda: self.panel.cut_selected())

            action_paste = self.addAction("📌  Paste")
            action_paste.setShortcut("Ctrl+V")
            action_paste.triggered.connect(lambda: self.panel.paste())
            action_paste.setEnabled(self.panel.has_clipboard())

            self.addSeparator()

            # Rename & Delete
            action_rename = self.addAction("✏  Rename")
            action_rename.setShortcut("F2")
            action_rename.triggered.connect(lambda: self.panel.rename_selected())

            action_delete = self.addAction("🗑  Delete")
            action_delete.setShortcut("Del")
            action_delete.triggered.connect(lambda: self.panel.delete_selected())

            self.addSeparator()

        # New items (always available)
        action_new_folder = self.addAction("📁  New Folder")
        action_new_folder.triggered.connect(lambda: self.panel.create_new_folder())

        if self.filepath:
            self.addSeparator()

            # System actions
            action_explorer = self.addAction("🔍  Show in Explorer")
            action_explorer.triggered.connect(self._show_in_explorer)

            action_terminal = self.addAction("💻  Open Terminal Here")
            action_terminal.triggered.connect(self._open_terminal)

            self.addSeparator()

            # Properties
            action_props = self.addAction("ℹ  Properties")
            action_props.triggered.connect(self._show_properties)

    def _show_in_explorer(self):
        """Open the file location in Windows Explorer."""
        if os.path.isdir(self.filepath):
            subprocess.Popen(f'explorer "{self.filepath}"')
        else:
            subprocess.Popen(f'explorer /select,"{self.filepath}"')

    def _open_terminal(self):
        """Open a terminal in the file's directory."""
        directory = self.filepath if os.path.isdir(self.filepath) else os.path.dirname(self.filepath)
        subprocess.Popen(f'wt -d "{directory}"', shell=True)

    def _show_properties(self):
        """Show Windows file properties dialog."""
        try:
            import ctypes
            ctypes.windll.shell32.ShellExecuteW(
                None, "properties", self.filepath, None, None, 0
            )
        except Exception:
            pass
