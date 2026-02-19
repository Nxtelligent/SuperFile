"""
SuperFile — File Inspector Panel
Preview text files, images, and folder info.
"""

import os
from PySide6.QtCore import Qt, QSize
from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QLabel, QPlainTextEdit, QScrollArea, QFrame
)
from PySide6.QtGui import QPixmap

from .utils import is_text_file, is_image_file, format_file_size, get_file_type


class Inspector(QWidget):
    """Side panel for previewing file contents."""

    MAX_TEXT_SIZE = 512 * 1024  # 512 KB max for text preview

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setMinimumWidth(250)
        self.setMaximumWidth(500)
        self._setup_ui()

    def _setup_ui(self):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(8, 8, 8, 8)
        layout.setSpacing(8)

        # Header
        self.header = QLabel("Inspector")
        self.header.setStyleSheet("""
            font-size: 14px;
            font-weight: bold;
            color: #8888aa;
            padding-bottom: 4px;
            border-bottom: 1px solid #2a2a4a;
        """)
        layout.addWidget(self.header)

        # File info section
        self.info_label = QLabel("Select a file to preview")
        self.info_label.setWordWrap(True)
        self.info_label.setStyleSheet("color: #8888aa; font-size: 11px;")
        layout.addWidget(self.info_label)

        # Separator
        sep = QFrame()
        sep.setFrameShape(QFrame.Shape.HLine)
        layout.addWidget(sep)

        # Image preview
        self.image_label = QLabel()
        self.image_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.image_label.setVisible(False)
        layout.addWidget(self.image_label)

        # Text preview
        self.text_preview = QPlainTextEdit()
        self.text_preview.setReadOnly(True)
        self.text_preview.setVisible(False)
        self.text_preview.setLineWrapMode(QPlainTextEdit.LineWrapMode.WidgetWidth)
        layout.addWidget(self.text_preview)

        # Folder info
        self.folder_label = QLabel()
        self.folder_label.setWordWrap(True)
        self.folder_label.setVisible(False)
        layout.addWidget(self.folder_label)

        layout.addStretch()

    def preview(self, filepath):
        """Preview a file or folder."""
        self._clear_preview()

        if not filepath or not os.path.exists(filepath):
            self.info_label.setText("Path not found")
            return

        name = os.path.basename(filepath)
        file_type = get_file_type(filepath)

        if os.path.isdir(filepath):
            self._preview_folder(filepath, name)
        elif is_image_file(filepath):
            self._preview_image(filepath, name, file_type)
        elif is_text_file(filepath):
            self._preview_text(filepath, name, file_type)
        else:
            self._preview_generic(filepath, name, file_type)

    def _clear_preview(self):
        """Reset all preview widgets."""
        self.image_label.setVisible(False)
        self.text_preview.setVisible(False)
        self.folder_label.setVisible(False)
        self.text_preview.clear()
        self.image_label.clear()

    def _preview_folder(self, path, name):
        """Preview a folder's info."""
        try:
            items = os.listdir(path)
            files = sum(1 for i in items if os.path.isfile(os.path.join(path, i)))
            dirs = sum(1 for i in items if os.path.isdir(os.path.join(path, i)))
        except PermissionError:
            items = []
            files = dirs = 0

        self.info_label.setText(
            f"📁  {name}\n"
            f"Type: Folder\n"
            f"Items: {len(items)} ({dirs} folders, {files} files)"
        )

        if items:
            preview_items = items[:20]
            text = "\n".join(f"  {'📁' if os.path.isdir(os.path.join(path, i)) else '📄'}  {i}" for i in preview_items)
            if len(items) > 20:
                text += f"\n  ... and {len(items) - 20} more"
            self.folder_label.setText(text)
            self.folder_label.setStyleSheet("color: #8888aa; font-size: 11px; font-family: 'Cascadia Code', 'Consolas', monospace;")
            self.folder_label.setVisible(True)

    def _preview_image(self, path, name, file_type):
        """Preview an image file."""
        try:
            size = os.path.getsize(path)
            self.info_label.setText(
                f"🖼  {name}\n"
                f"Type: {file_type}\n"
                f"Size: {format_file_size(size)}"
            )
            pixmap = QPixmap(path)
            if not pixmap.isNull():
                scaled = pixmap.scaled(
                    QSize(400, 400),
                    Qt.AspectRatioMode.KeepAspectRatio,
                    Qt.TransformationMode.SmoothTransformation
                )
                self.image_label.setPixmap(scaled)
                self.info_label.setText(
                    self.info_label.text() +
                    f"\nDimensions: {pixmap.width()} × {pixmap.height()}"
                )
            self.image_label.setVisible(True)
        except Exception:
            self.info_label.setText(f"🖼  {name}\nCould not load image")

    def _preview_text(self, path, name, file_type):
        """Preview a text file."""
        try:
            size = os.path.getsize(path)
            self.info_label.setText(
                f"📄  {name}\n"
                f"Type: {file_type}\n"
                f"Size: {format_file_size(size)}"
            )

            read_size = min(size, self.MAX_TEXT_SIZE)
            with open(path, 'r', encoding='utf-8', errors='replace') as f:
                content = f.read(read_size)

            if size > self.MAX_TEXT_SIZE:
                content += f"\n\n... [Truncated, showing first {format_file_size(self.MAX_TEXT_SIZE)} of {format_file_size(size)}]"

            lines = content.count('\n') + 1
            self.info_label.setText(self.info_label.text() + f"\nLines: ~{lines:,}")

            self.text_preview.setPlainText(content)
            self.text_preview.setVisible(True)
        except Exception as e:
            self.info_label.setText(f"📄  {name}\nCould not read file: {e}")

    def _preview_generic(self, path, name, file_type):
        """Show basic file info for unsupported types."""
        try:
            size = os.path.getsize(path)
            self.info_label.setText(
                f"📄  {name}\n"
                f"Type: {file_type}\n"
                f"Size: {format_file_size(size)}"
            )
        except Exception:
            self.info_label.setText(f"📄  {name}")

    def clear(self):
        """Clear the inspector."""
        self._clear_preview()
        self.info_label.setText("Select a file to preview")
