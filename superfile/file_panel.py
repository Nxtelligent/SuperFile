"""
SuperFile — File Panel
A tabbed file browser panel with tree view, breadcrumb bar, and file operations.
"""

import os
from PySide6.QtCore import Qt, Signal, QModelIndex, QDir
from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QTabBar, QTreeView, QHeaderView,
    QAbstractItemView, QMessageBox, QInputDialog
)
from PySide6.QtGui import QKeySequence, QShortcut

from .file_model import FileModel, FileOperations
from .breadcrumb import BreadcrumbBar
from .context_menu import FileContextMenu


class FilePanel(QWidget):
    """
    A file browser panel with tabs. Each tab holds a directory path.
    The panel displays files in a tree view with columns.
    """

    file_selected = Signal(str)       # Emitted when a file is clicked
    directory_changed = Signal(str)   # Emitted when directory changes
    status_message = Signal(str)      # Status bar messages

    def __init__(self, start_path=None, parent=None):
        super().__init__(parent)
        if start_path is None:
            start_path = os.path.expanduser("~")

        self._clipboard = []
        self._clipboard_cut = False

        self._setup_ui(start_path)
        self._setup_shortcuts()

    def _setup_ui(self, start_path):
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        # Tab bar
        self.tab_bar = QTabBar()
        self.tab_bar.setTabsClosable(True)
        self.tab_bar.setMovable(True)
        self.tab_bar.setExpanding(False)
        self.tab_bar.tabCloseRequested.connect(self._close_tab)
        self.tab_bar.currentChanged.connect(self._on_tab_changed)
        layout.addWidget(self.tab_bar)

        # Breadcrumb bar
        self.breadcrumb = BreadcrumbBar()
        self.breadcrumb.path_changed.connect(self.navigate_to)
        layout.addWidget(self.breadcrumb)

        # File model
        self.model = FileModel()

        # Tree view
        self.tree = QTreeView()
        self.tree.setModel(self.model)
        self.tree.setRootIndex(self.model.index(start_path))
        self.tree.setAnimated(False)
        self.tree.setIndentation(16)
        self.tree.setSortingEnabled(True)
        self.tree.sortByColumn(0, Qt.SortOrder.AscendingOrder)
        self.tree.setSelectionMode(QAbstractItemView.SelectionMode.ExtendedSelection)
        self.tree.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.tree.setAlternatingRowColors(True)
        self.tree.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)

        # Column widths — all user-resizable
        header = self.tree.header()
        header.setStretchLastSection(False)
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        header.setSectionResizeMode(1, QHeaderView.ResizeMode.Interactive)
        header.setSectionResizeMode(2, QHeaderView.ResizeMode.Interactive)
        header.setSectionResizeMode(3, QHeaderView.ResizeMode.Interactive)
        # Default widths for non-stretch columns
        header.resizeSection(1, 100)
        header.resizeSection(2, 100)
        header.resizeSection(3, 140)

        layout.addWidget(self.tree)

        # Signals
        self.tree.doubleClicked.connect(self._on_double_click)
        self.tree.clicked.connect(self._on_click)
        self.tree.customContextMenuRequested.connect(self._on_context_menu)

        # Add first tab
        self._tabs = []  # list of paths per tab
        self._add_tab(start_path)

    def _setup_shortcuts(self):
        """Panel-local shortcuts."""
        shortcuts = [
            ("Ctrl+C", self.copy_selected),
            ("Ctrl+X", self.cut_selected),
            ("Ctrl+V", self.paste),
            ("F2", self.rename_selected),
            ("Delete", self.delete_selected),
            ("Return", self._open_selected),
            ("Backspace", self.breadcrumb.go_up),
        ]
        for key, func in shortcuts:
            s = QShortcut(QKeySequence(key), self)
            s.activated.connect(func)

    # ─── Tab Management ──────────────────────────────────

    def _add_tab(self, path):
        path = os.path.normpath(path)
        name = os.path.basename(path) or path
        idx = self.tab_bar.addTab(name)
        self._tabs.append(path)
        self.tab_bar.setCurrentIndex(idx)
        self._navigate(path)

    def _close_tab(self, index):
        if self.tab_bar.count() <= 1:
            # Last tab — navigate to home instead of preventing close
            home = os.path.expanduser("~")
            self._tabs[0] = home
            self.tab_bar.setTabText(0, os.path.basename(home))
            self._navigate(home)
            return
        self._tabs.pop(index)
        self.tab_bar.removeTab(index)

    def _on_tab_changed(self, index):
        if 0 <= index < len(self._tabs):
            self._navigate(self._tabs[index])

    def new_tab(self, path=None):
        if path is None:
            path = self.current_path()
        self._add_tab(path)

    def close_current_tab(self):
        self._close_tab(self.tab_bar.currentIndex())

    def next_tab(self):
        idx = self.tab_bar.currentIndex()
        self.tab_bar.setCurrentIndex((idx + 1) % self.tab_bar.count())

    def prev_tab(self):
        idx = self.tab_bar.currentIndex()
        self.tab_bar.setCurrentIndex((idx - 1) % self.tab_bar.count())

    # ─── Navigation ──────────────────────────────────────

    def navigate_to(self, path):
        path = os.path.normpath(path)
        if os.path.isdir(path):
            self._navigate(path)
            idx = self.tab_bar.currentIndex()
            if 0 <= idx < len(self._tabs):
                self._tabs[idx] = path
                self.tab_bar.setTabText(idx, os.path.basename(path) or path)

    def _navigate(self, path):
        path = os.path.normpath(path)
        idx = self.model.index(path)
        if idx.isValid():
            self.tree.setRootIndex(idx)
            self.breadcrumb.set_path(path)
            self.directory_changed.emit(path)
            self._update_status()

    def current_path(self):
        idx = self.tab_bar.currentIndex()
        if 0 <= idx < len(self._tabs):
            return self._tabs[idx]
        return os.path.expanduser("~")

    def refresh(self):
        path = self.current_path()
        self.model.setRootPath("")
        self.model.setRootPath(path)
        self._navigate(path)

    # ─── File Operations ─────────────────────────────────

    def _get_selected_paths(self):
        indexes = self.tree.selectionModel().selectedRows(0)
        return [self.model.filePath(idx) for idx in indexes]

    def _get_selected_path(self):
        paths = self._get_selected_paths()
        return paths[0] if paths else None

    def copy_selected(self):
        self._clipboard = self._get_selected_paths()
        self._clipboard_cut = False
        if self._clipboard:
            self.status_message.emit(f"Copied {len(self._clipboard)} item(s)")

    def cut_selected(self):
        self._clipboard = self._get_selected_paths()
        self._clipboard_cut = True
        if self._clipboard:
            self.status_message.emit(f"Cut {len(self._clipboard)} item(s)")

    def paste(self):
        if not self._clipboard:
            return
        dst = self.current_path()
        try:
            for src in self._clipboard:
                if self._clipboard_cut:
                    FileOperations.move_file(src, dst)
                else:
                    FileOperations.copy_file(src, dst)
            count = len(self._clipboard)
            action = "Moved" if self._clipboard_cut else "Copied"
            self.status_message.emit(f"{action} {count} item(s)")
            if self._clipboard_cut:
                self._clipboard = []
        except Exception as e:
            QMessageBox.warning(self, "Error", f"Paste failed: {e}")

    def has_clipboard(self):
        return bool(self._clipboard)

    def delete_selected(self):
        paths = self._get_selected_paths()
        if not paths:
            return
        names = [os.path.basename(p) for p in paths]
        msg = f"Delete {len(paths)} item(s)?\n\n" + "\n".join(names[:10])
        if len(names) > 10:
            msg += f"\n...and {len(names) - 10} more"
        reply = QMessageBox.question(
            self, "Confirm Delete", msg,
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
        )
        if reply == QMessageBox.StandardButton.Yes:
            for path in paths:
                try:
                    FileOperations.delete_file(path)
                except Exception as e:
                    QMessageBox.warning(self, "Error", f"Could not delete {os.path.basename(path)}: {e}")
            self.status_message.emit(f"Deleted {len(paths)} item(s)")

    def rename_selected(self):
        path = self._get_selected_path()
        if not path:
            return
        old_name = os.path.basename(path)
        new_name, ok = QInputDialog.getText(self, "Rename", "New name:", text=old_name)
        if ok and new_name and new_name != old_name:
            try:
                FileOperations.rename_file(path, new_name)
                self.status_message.emit(f"Renamed to {new_name}")
            except Exception as e:
                QMessageBox.warning(self, "Error", f"Rename failed: {e}")

    def create_new_folder(self):
        name, ok = QInputDialog.getText(self, "New Folder", "Folder name:", text="New Folder")
        if ok and name:
            try:
                FileOperations.create_folder(self.current_path(), name)
                self.status_message.emit(f"Created folder: {name}")
            except Exception as e:
                QMessageBox.warning(self, "Error", f"Could not create folder: {e}")

    # ─── Event Handlers ──────────────────────────────────

    def _on_double_click(self, index):
        path = self.model.filePath(index)
        if os.path.isdir(path):
            self.navigate_to(path)
        else:
            try:
                os.startfile(path)
            except Exception:
                pass

    def _on_click(self, index):
        path = self.model.filePath(index)
        self.file_selected.emit(path)

    def _open_selected(self):
        path = self._get_selected_path()
        if path:
            if os.path.isdir(path):
                self.navigate_to(path)
            else:
                try:
                    os.startfile(path)
                except Exception:
                    pass

    def _on_context_menu(self, pos):
        index = self.tree.indexAt(pos)
        filepath = self.model.filePath(index) if index.isValid() else None
        menu = FileContextMenu(filepath, self, self)
        menu.exec(self.tree.viewport().mapToGlobal(pos))

    def _update_status(self):
        path = self.current_path()
        try:
            items = os.listdir(path)
            files = sum(1 for i in items if os.path.isfile(os.path.join(path, i)))
            dirs = sum(1 for i in items if os.path.isdir(os.path.join(path, i)))
            self.status_message.emit(f"{len(items)} items ({dirs} folders, {files} files)")
        except Exception:
            self.status_message.emit(path)
