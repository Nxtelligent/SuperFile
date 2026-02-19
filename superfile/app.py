"""
SuperFile — Main Application Window
Dual-pane file manager with inspector, tabs, and dark theme.
"""

import os
import shutil
from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QMainWindow, QSplitter, QStatusBar, QMenuBar, QToolBar,
    QLabel, QWidget, QHBoxLayout
)
from PySide6.QtGui import QAction

from .file_panel import FilePanel
from .inspector import Inspector
from .shortcuts import setup_shortcuts
from .utils import format_file_size


class MainWindow(QMainWindow):
    """SuperFile main window — dual-pane file manager."""

    def __init__(self):
        super().__init__()
        self.setWindowTitle("SuperFile")
        self.setMinimumSize(1000, 600)
        self.resize(1400, 800)

        self._inspector_visible = True
        self._dual_pane = True

        self._setup_menu_bar()
        self._setup_toolbar()
        self._setup_central()
        self._setup_status_bar()
        setup_shortcuts(self)

        # Start in home directory
        home = os.path.expanduser("~")
        self.left_panel.navigate_to(home)
        self.right_panel.navigate_to(home)

    def _setup_menu_bar(self):
        """Create the menu bar."""
        menubar = self.menuBar()

        # File menu
        file_menu = menubar.addMenu("&File")

        new_tab_action = QAction("New Tab", self)
        new_tab_action.setShortcut("Ctrl+T")
        new_tab_action.triggered.connect(self.new_tab)
        file_menu.addAction(new_tab_action)

        close_tab_action = QAction("Close Tab", self)
        close_tab_action.setShortcut("Ctrl+W")
        close_tab_action.triggered.connect(self.close_tab)
        file_menu.addAction(close_tab_action)

        file_menu.addSeparator()

        new_folder_action = QAction("New Folder", self)
        new_folder_action.setShortcut("Ctrl+N")
        new_folder_action.triggered.connect(self.create_new_folder)
        file_menu.addAction(new_folder_action)

        file_menu.addSeparator()

        exit_action = QAction("Exit", self)
        exit_action.setShortcut("Alt+F4")
        exit_action.triggered.connect(self.close)
        file_menu.addAction(exit_action)

        # Edit menu
        edit_menu = menubar.addMenu("&Edit")

        copy_action = QAction("Copy", self)
        copy_action.setShortcut("Ctrl+C")
        copy_action.triggered.connect(lambda: self._active_panel().copy_selected())
        edit_menu.addAction(copy_action)

        cut_action = QAction("Cut", self)
        cut_action.setShortcut("Ctrl+X")
        cut_action.triggered.connect(lambda: self._active_panel().cut_selected())
        edit_menu.addAction(cut_action)

        paste_action = QAction("Paste", self)
        paste_action.setShortcut("Ctrl+V")
        paste_action.triggered.connect(lambda: self._active_panel().paste())
        edit_menu.addAction(paste_action)

        edit_menu.addSeparator()

        rename_action = QAction("Rename", self)
        rename_action.setShortcut("F2")
        rename_action.triggered.connect(lambda: self._active_panel().rename_selected())
        edit_menu.addAction(rename_action)

        delete_action = QAction("Delete", self)
        delete_action.setShortcut("Delete")
        delete_action.triggered.connect(lambda: self._active_panel().delete_selected())
        edit_menu.addAction(delete_action)

        # View menu
        view_menu = menubar.addMenu("&View")

        toggle_inspector = QAction("Toggle Inspector", self)
        toggle_inspector.setShortcut("Ctrl+I")
        toggle_inspector.triggered.connect(self.toggle_inspector)
        view_menu.addAction(toggle_inspector)

        toggle_dual = QAction("Toggle Dual Pane", self)
        toggle_dual.setShortcut("Ctrl+Shift+E")
        toggle_dual.triggered.connect(self.toggle_dual_pane)
        view_menu.addAction(toggle_dual)

        view_menu.addSeparator()

        refresh_action = QAction("Refresh", self)
        refresh_action.setShortcut("F5")
        refresh_action.triggered.connect(self.refresh)
        view_menu.addAction(refresh_action)

        # Go menu
        go_menu = menubar.addMenu("&Go")

        back_action = QAction("Back", self)
        back_action.setShortcut("Alt+Left")
        back_action.triggered.connect(self.go_back)
        go_menu.addAction(back_action)

        forward_action = QAction("Forward", self)
        forward_action.setShortcut("Alt+Right")
        forward_action.triggered.connect(self.go_forward)
        go_menu.addAction(forward_action)

        up_action = QAction("Up", self)
        up_action.setShortcut("Alt+Up")
        up_action.triggered.connect(self.go_up)
        go_menu.addAction(up_action)

        go_menu.addSeparator()

        home_action = QAction("Home", self)
        home_action.triggered.connect(lambda: self._active_panel().navigate_to(os.path.expanduser("~")))
        go_menu.addAction(home_action)

        desktop_action = QAction("Desktop", self)
        desktop_action.triggered.connect(
            lambda: self._active_panel().navigate_to(os.path.join(os.path.expanduser("~"), "Desktop"))
        )
        go_menu.addAction(desktop_action)

        docs_action = QAction("Documents", self)
        docs_action.triggered.connect(
            lambda: self._active_panel().navigate_to(os.path.join(os.path.expanduser("~"), "Documents"))
        )
        go_menu.addAction(docs_action)

        downloads_action = QAction("Downloads", self)
        downloads_action.triggered.connect(
            lambda: self._active_panel().navigate_to(os.path.join(os.path.expanduser("~"), "Downloads"))
        )
        go_menu.addAction(downloads_action)

    def _setup_toolbar(self):
        """Create the toolbar."""
        toolbar = QToolBar("Navigation")
        toolbar.setMovable(False)
        self.addToolBar(toolbar)

        toolbar.addAction("◀ Back", self.go_back)
        toolbar.addAction("▶ Fwd", self.go_forward)
        toolbar.addAction("▲ Up", self.go_up)
        toolbar.addSeparator()
        toolbar.addAction("📂 New Tab", self.new_tab)
        toolbar.addAction("🔄 Refresh", self.refresh)
        toolbar.addSeparator()
        toolbar.addAction("👁 Inspector", self.toggle_inspector)
        toolbar.addAction("⧉ Dual Pane", self.toggle_dual_pane)

    def _setup_central(self):
        """Set up the central widget with dual panes and inspector."""
        # Main horizontal splitter
        self.main_splitter = QSplitter(Qt.Orientation.Horizontal)

        # Left panel
        self.left_panel = FilePanel()
        self.left_panel.file_selected.connect(self._on_file_selected)
        self.left_panel.status_message.connect(self._set_status)

        # Right panel
        self.right_panel = FilePanel()
        self.right_panel.file_selected.connect(self._on_file_selected)
        self.right_panel.status_message.connect(self._set_status)

        # Inspector
        self.inspector = Inspector()

        # Pane splitter (left + right panels)
        self.pane_splitter = QSplitter(Qt.Orientation.Horizontal)
        self.pane_splitter.addWidget(self.left_panel)
        self.pane_splitter.addWidget(self.right_panel)
        self.pane_splitter.setSizes([600, 600])

        # Main splitter (panes + inspector)
        self.main_splitter.addWidget(self.pane_splitter)
        self.main_splitter.addWidget(self.inspector)
        self.main_splitter.setSizes([900, 300])

        self.setCentralWidget(self.main_splitter)

        # Track active panel (which one was clicked last)
        self._active = self.left_panel
        self.left_panel.tree.clicked.connect(lambda: self._set_active(self.left_panel))
        self.right_panel.tree.clicked.connect(lambda: self._set_active(self.right_panel))
        self.left_panel.address_bar.path_edit.focusInEvent = lambda e: (
            self._set_active(self.left_panel),
            type(self.left_panel.address_bar.path_edit).focusInEvent(self.left_panel.address_bar.path_edit, e)
        )

    def _setup_status_bar(self):
        """Create the status bar."""
        self.status = QStatusBar()
        self.setStatusBar(self.status)

        self.status_label = QLabel("Ready")
        self.status.addWidget(self.status_label, 1)

        # Disk space info
        self.disk_label = QLabel()
        self.status.addPermanentWidget(self.disk_label)
        self._update_disk_info()

    def _update_disk_info(self):
        """Show free disk space in status bar."""
        try:
            path = self._active_panel().current_path()
            total, used, free = shutil.disk_usage(path)
            self.disk_label.setText(
                f"Free: {format_file_size(free)} / {format_file_size(total)}"
            )
        except Exception:
            self.disk_label.setText("")

    # ─── Active Panel ─────────────────────────────

    def _active_panel(self) -> FilePanel:
        """Get the currently active file panel."""
        return self._active

    def _set_active(self, panel):
        """Set the active panel."""
        self._active = panel
        self._update_disk_info()

    # ─── Actions (called by shortcuts & menus) ────

    def new_tab(self):
        self._active_panel().new_tab()

    def close_tab(self):
        self._active_panel().close_current_tab()

    def next_tab(self):
        self._active_panel().next_tab()

    def prev_tab(self):
        self._active_panel().prev_tab()

    def focus_address_bar(self):
        self._active_panel().address_bar.path_edit.setFocus()
        self._active_panel().address_bar.path_edit.selectAll()

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
        self._active_panel().address_bar.go_back()

    def go_forward(self):
        self._active_panel().address_bar.go_forward()

    def go_up(self):
        self._active_panel().address_bar.go_up()

    # ─── Signals ──────────────────────────────────

    def _on_file_selected(self, path):
        """Update inspector when a file is selected."""
        self.inspector.preview(path)
        self._update_disk_info()

    def _set_status(self, msg):
        """Update status bar message."""
        self.status_label.setText(msg)
