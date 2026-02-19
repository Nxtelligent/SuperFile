"""
SuperFile — Keyboard Shortcuts
"""

from PySide6.QtGui import QShortcut, QKeySequence
from PySide6.QtWidgets import QWidget


def setup_shortcuts(window):
    """Set up global keyboard shortcuts on the main window."""

    shortcuts = {
        "Ctrl+T": window.new_tab,
        "Ctrl+W": window.close_tab,
        "Ctrl+Tab": window.next_tab,
        "Ctrl+Shift+Tab": window.prev_tab,
        "Ctrl+L": window.focus_address_bar,
        "Ctrl+I": window.toggle_inspector,
        "F5": window.refresh,
        "Ctrl+N": window.create_new_folder,
        "Alt+Left": window.go_back,
        "Alt+Right": window.go_forward,
        "Alt+Up": window.go_up,
        "Ctrl+Shift+E": window.toggle_dual_pane,
    }

    for key_seq, callback in shortcuts.items():
        shortcut = QShortcut(QKeySequence(key_seq), window)
        shortcut.activated.connect(callback)

    return shortcuts
