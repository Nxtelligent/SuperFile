"""
SuperFile — Main Application Window
Dual-pane file manager with navigation sidebar, inspector, tabs, and dark theme.
"""

import os
import shutil
from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QMainWindow, QSplitter, QStatusBar, QLabel, QWidget, QHBoxLayout
)
from PySide6.QtGui import QAction

from .file_panel import FilePanel
from .sidebar import NavigationSidebar
from .inspector import Inspector
from .shortcuts import setup_shortcuts
from .utils import format_file_size


class MainWindow(QMainWindow):
    """SuperFile main window — dual-pane file manager with sidebar."""

    def __init__(self):
        super().__init__()
        self.setWindowTitle("SuperFile")
        self.setMinimumSize(1000, 600)
        self.resize(1400, 800)

        self._inspector_visible = True
        self._dual_pane = True

        self._setup_menu_bar()
        self._setup_central()
        self._setup_status_bar()
        setup_shortcuts(self)

        # Start in home directory
        home = os.path.expanduser("~")
        self.left_panel.navigate_to(home)
        self.right_panel.navigate_to(home)

    def _setup_menu_bar(self):
        menubar = self.menuBar()

        # File
        file_menu = menubar.addMenu("&File")
        self._add_action(file_menu, "New Tab", "Ctrl+T", self.new_tab)
        self._add_action(file_menu, "Close Tab", "Ctrl+W", self.close_tab)
        file_menu.addSeparator()
        self._add_action(file_menu, "New Folder", "Ctrl+N", self.create_new_folder)
        file_menu.addSeparator()
        self._add_action(file_menu, "Exit", "Alt+F4", self.close)

        # Edit
        edit_menu = menubar.addMenu("&Edit")
        self._add_action(edit_menu, "Copy", "Ctrl+C", lambda: self._active_panel().copy_selected())
        self._add_action(edit_menu, "Cut", "Ctrl+X", lambda: self._active_panel().cut_selected())
        self._add_action(edit_menu, "Paste", "Ctrl+V", lambda: self._active_panel().paste())
        edit_menu.addSeparator()
        self._add_action(edit_menu, "Rename", "F2", lambda: self._active_panel().rename_selected())
        self._add_action(edit_menu, "Delete", "Delete", lambda: self._active_panel().delete_selected())

        # View
        view_menu = menubar.addMenu("&View")
        self._add_action(view_menu, "Toggle Sidebar", "Ctrl+B", self.toggle_sidebar)
        self._add_action(view_menu, "Toggle Inspector", "Ctrl+I", self.toggle_inspector)
        self._add_action(view_menu, "Toggle Dual Pane", "Ctrl+Shift+E", self.toggle_dual_pane)
        view_menu.addSeparator()
        self._add_action(view_menu, "Refresh", "F5", self.refresh)

        # Go
        go_menu = menubar.addMenu("&Go")
        self._add_action(go_menu, "Back", "Alt+Left", self.go_back)
        self._add_action(go_menu, "Forward", "Alt+Right", self.go_forward)
        self._add_action(go_menu, "Up", "Alt+Up", self.go_up)
        go_menu.addSeparator()
        self._add_action(go_menu, "Home", None, lambda: self._active_panel().navigate_to(os.path.expanduser("~")))
        self._add_action(go_menu, "Desktop", None, lambda: self._active_panel().navigate_to(os.path.join(os.path.expanduser("~"), "Desktop")))
        self._add_action(go_menu, "Documents", None, lambda: self._active_panel().navigate_to(os.path.join(os.path.expanduser("~"), "Documents")))
        self._add_action(go_menu, "Downloads", None, lambda: self._active_panel().navigate_to(os.path.join(os.path.expanduser("~"), "Downloads")))

    def _add_action(self, menu, name, shortcut, callback):
        action = QAction(name, self)
        if shortcut:
            action.setShortcut(shortcut)
        action.triggered.connect(callback)
        menu.addAction(action)

    def _setup_central(self):
        """Set up: Sidebar | Panes | Inspector"""
        # Root horizontal layout
        self.root_splitter = QSplitter(Qt.Orientation.Horizontal)

        # Navigation Sidebar
        self.sidebar = NavigationSidebar()
        self.sidebar.navigate_to.connect(self._on_sidebar_navigate)
        self.root_splitter.addWidget(self.sidebar)

        # File panels splitter
        self.pane_splitter = QSplitter(Qt.Orientation.Horizontal)

        # Left panel
        self.left_panel = FilePanel()
        self.left_panel.file_selected.connect(self._on_file_selected)
        self.left_panel.status_message.connect(self._set_status)
        self.left_panel.directory_changed.connect(self._on_directory_changed)

        # Right panel
        self.right_panel = FilePanel()
        self.right_panel.file_selected.connect(self._on_file_selected)
        self.right_panel.status_message.connect(self._set_status)

        self.pane_splitter.addWidget(self.left_panel)
        self.pane_splitter.addWidget(self.right_panel)
        self.pane_splitter.setSizes([550, 550])

        self.root_splitter.addWidget(self.pane_splitter)

        # Inspector
        self.inspector = Inspector()
        self.root_splitter.addWidget(self.inspector)

        # Splitter proportions: sidebar ~220, panes ~850, inspector ~300
        self.root_splitter.setSizes([220, 850, 300])

        # Don't allow sidebar to collapse below ~150px
        self.root_splitter.setStretchFactor(0, 0)
        self.root_splitter.setStretchFactor(1, 1)
        self.root_splitter.setStretchFactor(2, 0)

        self.setCentralWidget(self.root_splitter)

        # Track active panel
        self._active = self.left_panel
        self.left_panel.tree.clicked.connect(lambda: self._set_active(self.left_panel))
        self.right_panel.tree.clicked.connect(lambda: self._set_active(self.right_panel))

    def _setup_status_bar(self):
        self.status = QStatusBar()
        self.setStatusBar(self.status)

        # Filter info (left side)
        self.filter_label = QLabel("🔍 Filter 22 files...")
        self.filter_label.setStyleSheet("color: #4a4a6a; font-size: 11px;")
        self.status.addWidget(self.filter_label)

        self.status_label = QLabel("Ready")
        self.status_label.setStyleSheet("color: #6a6a8a; font-size: 11px;")
        self.status.addWidget(self.status_label, 1)

        # Item counts
        self.count_label = QLabel()
        self.count_label.setStyleSheet("color: #6a6a8a; font-size: 11px;")
        self.status.addPermanentWidget(self.count_label)

        # Disk space
        self.disk_label = QLabel()
        self.disk_label.setStyleSheet("color: #6a6a8a; font-size: 11px;")
        self.status.addPermanentWidget(self.disk_label)

        self._update_disk_info()

    def _update_disk_info(self):
        try:
            path = self._active_panel().current_path()
            total, used, free = shutil.disk_usage(path)
            self.disk_label.setText(f"Free: {format_file_size(free)} / {format_file_size(total)}")
        except Exception:
            self.disk_label.setText("")

    # ─── Active Panel ─────────────────────────────

    def _active_panel(self) -> FilePanel:
        return self._active

    def _set_active(self, panel):
        self._active = panel
        self._update_disk_info()

    # ─── Actions ──────────────────────────────────

    def new_tab(self):
        self._active_panel().new_tab()

    def close_tab(self):
        self._active_panel().close_current_tab()

    def next_tab(self):
        self._active_panel().next_tab()

    def prev_tab(self):
        self._active_panel().prev_tab()

    def focus_address_bar(self):
        self._active_panel().breadcrumb.enable_editing()

    def toggle_sidebar(self):
        self.sidebar.setVisible(not self.sidebar.isVisible())

    def toggle_inspector(self):
        self._inspector_visible = not self._inspector_visible
        self.inspector.setVisible(self._inspector_visible)

    def toggle_dual_pane(self):
        self._dual_pane = not self._dual_pane
        self.right_panel.setVisible(self._dual_pane)

    def refresh(self):
        self._active_panel().refresh()

    def create_new_folder(self):
        self._active_panel().create_new_folder()

    def go_back(self):
        self._active_panel().breadcrumb.go_back()

    def go_forward(self):
        self._active_panel().breadcrumb.go_forward()

    def go_up(self):
        self._active_panel().breadcrumb.go_up()

    # ─── Signals ──────────────────────────────────

    def _on_file_selected(self, path):
        self.inspector.preview(path)
        self._update_disk_info()

    def _on_directory_changed(self, path):
        """Track directory changes for sidebar recents."""
        self.sidebar.add_recent(path)
        self._update_item_counts(path)

    def _on_sidebar_navigate(self, path):
        """Handle navigation from sidebar click."""
        self._active_panel().navigate_to(path)

    def _set_status(self, msg):
        self.status_label.setText(msg)

    def _update_item_counts(self, path):
        """Update the status bar item counts."""
        try:
            items = os.listdir(path)
            total = len(items)
            folders = sum(1 for i in items if os.path.isdir(os.path.join(path, i)))
            self.count_label.setText(f"{total} items  •  {folders} folders")
            self.filter_label.setText(f"🔍 Filter {total} files...")
        except Exception:
            pass
