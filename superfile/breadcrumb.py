"""
SuperFile — Breadcrumb Path Bar
Clickable path segments like: This PC > Local Disk (C:) > Users > jayeyemachine
"""

import os
import string
import ctypes
from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import (
    QWidget, QHBoxLayout, QLabel, QPushButton, QScrollArea, QLineEdit,
    QSizePolicy
)


class BreadcrumbSegment(QPushButton):
    """A single clickable segment in the breadcrumb path."""

    def __init__(self, label, path, parent=None):
        super().__init__(label, parent)
        self.path = path
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        self.setSizePolicy(QSizePolicy.Policy.Fixed, QSizePolicy.Policy.Fixed)
        self.setStyleSheet("""
            QPushButton {
                background-color: transparent;
                border: none;
                color: #8888aa;
                font-size: 12px;
                padding: 4px 2px;
            }
            QPushButton:hover {
                color: #e0e0e0;
                text-decoration: underline;
            }
        """)


class BreadcrumbSeparator(QLabel):
    """Separator arrow between breadcrumb segments."""

    def __init__(self, parent=None):
        super().__init__("›", parent)
        self.setStyleSheet("""
            QLabel {
                color: #4a4a6a;
                font-size: 14px;
                padding: 0 2px;
                background-color: transparent;
            }
        """)


class BreadcrumbBar(QWidget):
    """Breadcrumb-style navigation bar showing clickable path segments."""

    path_changed = Signal(str)

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setFixedHeight(32)
        self._current_path = ""
        self._editing = False

        self._setup_ui()

    def _setup_ui(self):
        main_layout = QHBoxLayout(self)
        main_layout.setContentsMargins(0, 0, 0, 0)
        main_layout.setSpacing(0)

        # Nav buttons
        self.btn_back = QPushButton("←")
        self.btn_back.setFixedSize(28, 28)
        self.btn_back.setToolTip("Back")
        self.btn_back.setStyleSheet(self._nav_btn_style())
        main_layout.addWidget(self.btn_back)

        self.btn_forward = QPushButton("→")
        self.btn_forward.setFixedSize(28, 28)
        self.btn_forward.setToolTip("Forward")
        self.btn_forward.setStyleSheet(self._nav_btn_style())
        main_layout.addWidget(self.btn_forward)

        self.btn_up = QPushButton("↑")
        self.btn_up.setFixedSize(28, 28)
        self.btn_up.setToolTip("Up one level")
        self.btn_up.setStyleSheet(self._nav_btn_style())
        main_layout.addWidget(self.btn_up)

        self.btn_down = QPushButton("↓")
        self.btn_down.setFixedSize(28, 28)
        self.btn_down.setToolTip("Recent directories")
        self.btn_down.setStyleSheet(self._nav_btn_style())
        main_layout.addWidget(self.btn_down)

        # Home / bookmark buttons
        self.btn_home = QPushButton("⌂")
        self.btn_home.setFixedSize(28, 28)
        self.btn_home.setToolTip("Home")
        self.btn_home.setStyleSheet(self._nav_btn_style())
        main_layout.addWidget(self.btn_home)

        self.btn_bookmark = QPushButton("★")
        self.btn_bookmark.setFixedSize(28, 28)
        self.btn_bookmark.setToolTip("Bookmark this folder")
        self.btn_bookmark.setStyleSheet(self._nav_btn_style())
        main_layout.addWidget(self.btn_bookmark)

        # Breadcrumb container
        self.breadcrumb_container = QWidget()
        self.breadcrumb_container.setStyleSheet("""
            background-color: #1a1a2a;
            border: 1px solid #2a2a3e;
            border-radius: 4px;
        """)
        self.breadcrumb_layout = QHBoxLayout(self.breadcrumb_container)
        self.breadcrumb_layout.setContentsMargins(8, 0, 8, 0)
        self.breadcrumb_layout.setSpacing(0)
        main_layout.addWidget(self.breadcrumb_container, 1)

        # Editable line edit (hidden by default, shown on click)
        self.path_edit = QLineEdit()
        self.path_edit.setStyleSheet("""
            QLineEdit {
                background-color: #1a1a2a;
                border: 1px solid #5a5a8a;
                border-radius: 4px;
                padding: 4px 8px;
                color: #e0e0e0;
                font-size: 12px;
            }
        """)
        self.path_edit.setVisible(False)
        self.path_edit.returnPressed.connect(self._on_edit_confirmed)
        self.path_edit.editingFinished.connect(self._on_edit_finished)
        main_layout.addWidget(self.path_edit, 1)

        # History
        self._history = []
        self._history_index = -1

        # Signals
        self.btn_back.clicked.connect(self.go_back)
        self.btn_forward.clicked.connect(self.go_forward)
        self.btn_up.clicked.connect(self.go_up)
        self.btn_home.clicked.connect(self._go_home)

        self._update_nav_buttons()

    def _nav_btn_style(self):
        return """
            QPushButton {
                background-color: transparent;
                border: none;
                color: #6a6a8a;
                font-size: 14px;
                border-radius: 4px;
            }
            QPushButton:hover {
                background-color: #2a2a3e;
                color: #c0c0d0;
            }
            QPushButton:disabled {
                color: #3a3a4e;
            }
        """

    def set_path(self, path, add_to_history=True):
        """Set the current path and rebuild breadcrumbs."""
        path = os.path.normpath(path)
        self._current_path = path
        self.path_edit.setText(path)

        if add_to_history:
            self._history = self._history[:self._history_index + 1]
            self._history.append(path)
            self._history_index = len(self._history) - 1

        self._rebuild_breadcrumbs(path)
        self._update_nav_buttons()

    def get_path(self):
        return self._current_path

    def _rebuild_breadcrumbs(self, path):
        """Rebuild breadcrumb segments from path."""
        # Clear existing
        while self.breadcrumb_layout.count():
            item = self.breadcrumb_layout.takeAt(0)
            if item.widget():
                item.widget().deleteLater()

        # Split path into segments
        parts = []
        current = path
        while True:
            head, tail = os.path.split(current)
            if tail:
                parts.append((tail, current))
                current = head
            else:
                if head:
                    # Drive root like C:\
                    drive_label = self._get_drive_label(head)
                    parts.append((drive_label, head))
                break

        # Add "This PC" as root
        parts.append(("This PC", ""))
        parts.reverse()

        for i, (label, seg_path) in enumerate(parts):
            if i > 0:
                sep = BreadcrumbSeparator()
                self.breadcrumb_layout.addWidget(sep)

            btn = BreadcrumbSegment(label, seg_path)
            if seg_path:
                btn.clicked.connect(lambda checked, p=seg_path: self._on_segment_clicked(p))
            self.breadcrumb_layout.addWidget(btn)

        self.breadcrumb_layout.addStretch()

    def _get_drive_label(self, drive_root):
        """Get a label like 'Local Disk (C:)' for a drive."""
        letter = drive_root[0].upper()
        try:
            buf = ctypes.create_unicode_buffer(256)
            ctypes.windll.kernel32.GetVolumeInformationW(
                drive_root, buf, 256, None, None, None, None, 0
            )
            if buf.value:
                return f"{buf.value} ({letter}:)"
        except Exception:
            pass
        return f"Local Disk ({letter}:)"

    def _on_segment_clicked(self, path):
        """Navigate to a breadcrumb segment."""
        if os.path.isdir(path):
            self.set_path(path)
            self.path_changed.emit(path)

    def enable_editing(self):
        """Switch to text edit mode (when user clicks address bar area or Ctrl+L)."""
        self._editing = True
        self.breadcrumb_container.setVisible(False)
        self.path_edit.setVisible(True)
        self.path_edit.setText(self._current_path)
        self.path_edit.setFocus()
        self.path_edit.selectAll()

    def _on_edit_confirmed(self):
        """Handle Enter in the path edit."""
        path = self.path_edit.text().strip()
        if os.path.isdir(path):
            self.set_path(path)
            self.path_changed.emit(path)
        self._exit_edit_mode()

    def _on_edit_finished(self):
        """Handle loss of focus on path edit."""
        self._exit_edit_mode()

    def _exit_edit_mode(self):
        self._editing = False
        self.path_edit.setVisible(False)
        self.breadcrumb_container.setVisible(True)

    def go_back(self):
        if self._history_index > 0:
            self._history_index -= 1
            path = self._history[self._history_index]
            self._current_path = path
            self._rebuild_breadcrumbs(path)
            self.path_edit.setText(path)
            self.path_changed.emit(path)
            self._update_nav_buttons()

    def go_forward(self):
        if self._history_index < len(self._history) - 1:
            self._history_index += 1
            path = self._history[self._history_index]
            self._current_path = path
            self._rebuild_breadcrumbs(path)
            self.path_edit.setText(path)
            self.path_changed.emit(path)
            self._update_nav_buttons()

    def go_up(self):
        current = self._current_path
        parent = os.path.dirname(current)
        if parent and parent != current:
            self.set_path(parent)
            self.path_changed.emit(parent)

    def _go_home(self):
        home = os.path.expanduser("~")
        self.set_path(home)
        self.path_changed.emit(home)

    def _update_nav_buttons(self):
        self.btn_back.setEnabled(self._history_index > 0)
        self.btn_forward.setEnabled(self._history_index < len(self._history) - 1)
        current = self._current_path
        self.btn_up.setEnabled(bool(current) and os.path.dirname(current) != current)
