"""
SuperFile — Address Bar with Path Autocompletion
"""

import os
from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import (
    QLineEdit, QCompleter, QHBoxLayout, QWidget, QPushButton,
    QFileSystemModel
)


class AddressBar(QWidget):
    """Address bar with path autocompletion and navigation buttons."""

    path_changed = Signal(str)

    def __init__(self, parent=None):
        super().__init__(parent)
        self._setup_ui()

    def _setup_ui(self):
        layout = QHBoxLayout(self)
        layout.setContentsMargins(4, 4, 4, 4)
        layout.setSpacing(4)

        # Back button
        self.btn_back = QPushButton("◀")
        self.btn_back.setFixedSize(28, 28)
        self.btn_back.setToolTip("Back")
        layout.addWidget(self.btn_back)

        # Forward button
        self.btn_forward = QPushButton("▶")
        self.btn_forward.setFixedSize(28, 28)
        self.btn_forward.setToolTip("Forward")
        layout.addWidget(self.btn_forward)

        # Up button
        self.btn_up = QPushButton("▲")
        self.btn_up.setFixedSize(28, 28)
        self.btn_up.setToolTip("Up one level")
        layout.addWidget(self.btn_up)

        # Path input
        self.path_edit = QLineEdit()
        self.path_edit.setPlaceholderText("Enter path...")
        layout.addWidget(self.path_edit)

        # Setup completer for path autocompletion
        self._fs_model = QFileSystemModel()
        self._fs_model.setRootPath("")
        self._completer = QCompleter(self._fs_model, self)
        self._completer.setCompletionMode(QCompleter.CompletionMode.PopupCompletion)
        self._completer.setCaseSensitivity(Qt.CaseSensitivity.CaseInsensitive)
        self.path_edit.setCompleter(self._completer)

        # Signals
        self.path_edit.returnPressed.connect(self._on_return_pressed)

        # Navigation history
        self._history = []
        self._history_index = -1

        self.btn_back.clicked.connect(self.go_back)
        self.btn_forward.clicked.connect(self.go_forward)
        self.btn_up.clicked.connect(self.go_up)

        self._update_nav_buttons()

    def set_path(self, path, add_to_history=True):
        """Set the current path displayed."""
        path = os.path.normpath(path)
        self.path_edit.setText(path)
        if add_to_history:
            # Trim forward history
            self._history = self._history[:self._history_index + 1]
            self._history.append(path)
            self._history_index = len(self._history) - 1
        self._update_nav_buttons()

    def get_path(self):
        """Get the current path."""
        return self.path_edit.text()

    def go_back(self):
        """Navigate to previous path in history."""
        if self._history_index > 0:
            self._history_index -= 1
            path = self._history[self._history_index]
            self.path_edit.setText(path)
            self.path_changed.emit(path)
            self._update_nav_buttons()

    def go_forward(self):
        """Navigate to next path in history."""
        if self._history_index < len(self._history) - 1:
            self._history_index += 1
            path = self._history[self._history_index]
            self.path_edit.setText(path)
            self.path_changed.emit(path)
            self._update_nav_buttons()

    def go_up(self):
        """Navigate to parent directory."""
        current = self.get_path()
        parent = os.path.dirname(current)
        if parent and parent != current:
            self.set_path(parent)
            self.path_changed.emit(parent)

    def _on_return_pressed(self):
        """Handle Enter key in path input."""
        path = self.path_edit.text().strip()
        if os.path.isdir(path):
            self.set_path(path)
            self.path_changed.emit(path)

    def _update_nav_buttons(self):
        """Enable/disable nav buttons based on history state."""
        self.btn_back.setEnabled(self._history_index > 0)
        self.btn_forward.setEnabled(self._history_index < len(self._history) - 1)
        current = self.get_path()
        self.btn_up.setEnabled(bool(current) and os.path.dirname(current) != current)
