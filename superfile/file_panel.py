"""
SuperFile — File Panel
A tabbed file browser panel with tree view, address bar, and file operations.
"""

import os
from PySide6.QtCore import Qt, Signal, QModelIndex, QDir
from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QTabBar, QTreeView, QHeaderView,
    QAbstractItemView, QMessageBox, QInputDialog, QMenu
)
from PySide6.QtGui import QKeySequence, QShortcut

from .file_model import FileModel, FileOperations
from .address_bar import AddressBar
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

        # Address bar
        self.address_bar = AddressBar()
        self.address_bar.path_changed.connect(self.navigate_to)
        layout.addWidget(self.address_bar)

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

        # Column widths
        header = self.tree.header()
        header.setStretchLastSection(False)
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        header.setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(3, QHeaderView.ResizeMode.ResizeToContents)

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
        # Copy
        s = QShortcut(QKeySequence("Ctrl+C"), self)
        s.activated.connect(self.copy_selected)

        # Cut
        s = QShortcut(QKeySequence("Ctrl+X"), self)
        s.activated.connect(self.cut_selected)

        # Paste
        s = QShortcut(QKeySequence("Ctrl+V"), self)
        s.activated.connect(self.paste)

        # Rename
        s = QShortcut(QKeySequence("F2"), self)
        s.activated.connect(self.rename_selected)

        # Delete
        s = QShortcut(QKeySequence("Delete"), self)
        s.activated.connect(self.delete_selected)

        # Enter to open
        s = QShortcut(QKeySequence("Return"), self)
        s.activated.connect(self._open_selected)

        # Backspace to go up
        s = QShortcut(QKeySequence("Backspace"), self)
        s.activated.connect(self.address_bar.go_up)

    # ─── Tab Management ──────────────────────────────────

    def _add_tab(self, path):
        """Add a new tab for the given path."""
        path = os.path.normpath(path)
        name = os.path.basename(path) or path
        idx = self.tab_bar.addTab(name)
        self._tabs.append(path)
        self.tab_bar.setCurrentIndex(idx)
        self._navigate(path)

    def _close_tab(self, index):
        """Close a tab."""
        if self.tab_bar.count() <= 1:
            return  # Keep at least one tab
        self._tabs.pop(index)
        self.tab_bar.removeTab(index)

    def _on_tab_changed(self, index):
        """Handle tab switch."""
        if 0 <= index < len(self._tabs):
            self._navigate(self._tabs[index])

    def new_tab(self, path=None):
        """Open a new tab. If no path given, use current directory."""
        if path is None:
            path = self.current_path()
        self._add_tab(path)

    def close_current_tab(self):
        """Close the current tab."""
        self._close_tab(self.tab_bar.currentIndex())

    def next_tab(self):
        """Switch to next tab."""
        idx = self.tab_bar.currentIndex()
        if idx < self.tab_bar.count() - 1:
            self.tab_bar.setCurrentIndex(idx + 1)
        else:
            self.tab_bar.setCurrentIndex(0)

    def prev_tab(self):
        """Switch to previous tab."""
        idx = self.tab_bar.currentIndex()
        if idx > 0:
            self.tab_bar.setCurrentIndex(idx - 1)
        else:
            self.tab_bar.setCurrentIndex(self.tab_bar.count() - 1)

    # ─── Navigation ──────────────────────────────────────

    def navigate_to(self, path):
        """Navigate to a directory path."""
        path = os.path.normpath(path)
        if os.path.isdir(path):
            self._navigate(path)
            # Update current tab
            idx = self.tab_bar.currentIndex()
            if 0 <= idx < len(self._tabs):
                self._tabs[idx] = path
                self.tab_bar.setTabText(idx, os.path.basename(path) or path)

    def open_in_new_tab(self, path):
        """Open a path in a new tab."""
        self._add_tab(path)

    def _navigate(self, path):
        """Internal navigation — set tree root and address bar."""
        path = os.path.normpath(path)
        idx = self.model.index(path)
        if idx.isValid():
            self.tree.setRootIndex(idx)
            self.address_bar.set_path(path)
            self.directory_changed.emit(path)
            self._update_status()

    def current_path(self):
        """Get the current directory path."""
        idx = self.tab_bar.currentIndex()
        if 0 <= idx < len(self._tabs):
            return self._tabs[idx]
        return os.path.expanduser("~")

    def refresh(self):
        """Refresh the current view."""
        path = self.current_path()
        self.model.setRootPath("")
        self.model.setRootPath(path)
        self._navigate(path)

    # ─── File Operations ─────────────────────────────────

    def _get_selected_paths(self):
        """Get list of selected file paths."""
        indexes = self.tree.selectionModel().selectedRows(0)
        return [self.model.filePath(idx) for idx in indexes]

    def _get_selected_path(self):
        """Get single selected path, or None."""
        paths = self._get_selected_paths()
        return paths[0] if paths else None

    def copy_selected(self):
        """Copy selected files to clipboard."""
        self._clipboard = self._get_selected_paths()
        self._clipboard_cut = False
        if self._clipboard:
            self.status_message.emit(f"Copied {len(self._clipboard)} item(s)")

    def cut_selected(self):
        """Cut selected files to clipboard."""
        self._clipboard = self._get_selected_paths()
        self._clipboard_cut = True
        if self._clipboard:
            self.status_message.emit(f"Cut {len(self._clipboard)} item(s)")

    def paste(self):
        """Paste clipboard items to current directory."""
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
        """Check if clipboard has items."""
        return bool(self._clipboard)

    def delete_selected(self):
        """Delete selected files."""
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
        """Rename the selected file."""
        path = self._get_selected_path()
        if not path:
            return
        old_name = os.path.basename(path)
        new_name, ok = QInputDialog.getText(
            self, "Rename", "New name:", text=old_name
        )
        if ok and new_name and new_name != old_name:
            try:
                FileOperations.rename_file(path, new_name)
                self.status_message.emit(f"Renamed to {new_name}")
            except Exception as e:
                QMessageBox.warning(self, "Error", f"Rename failed: {e}")

    def create_new_folder(self):
        """Create a new folder in the current directory."""
        name, ok = QInputDialog.getText(
            self, "New Folder", "Folder name:", text="New Folder"
        )
        if ok and name:
            try:
                FileOperations.create_folder(self.current_path(), name)
                self.status_message.emit(f"Created folder: {name}")
            except Exception as e:
                QMessageBox.warning(self, "Error", f"Could not create folder: {e}")

    # ─── Event Handlers ──────────────────────────────────

    def _on_double_click(self, index):
        """Handle double-click on a file/folder."""
        path = self.model.filePath(index)
        if os.path.isdir(path):
            self.navigate_to(path)
        else:
            try:
                os.startfile(path)
            except Exception:
                pass

    def _on_click(self, index):
        """Handle single click — emit file selection for inspector."""
        path = self.model.filePath(index)
        self.file_selected.emit(path)

    def _open_selected(self):
        """Open selected item (Enter key)."""
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
        """Show context menu on right-click."""
        index = self.tree.indexAt(pos)
        filepath = self.model.filePath(index) if index.isValid() else None
        menu = FileContextMenu(filepath, self, self)
        menu.exec(self.tree.viewport().mapToGlobal(pos))

    def _update_status(self):
        """Update status bar with current directory info."""
        path = self.current_path()
        try:
            items = os.listdir(path)
            files = sum(1 for i in items if os.path.isfile(os.path.join(path, i)))
            dirs = sum(1 for i in items if os.path.isdir(os.path.join(path, i)))
            self.status_message.emit(f"{len(items)} items ({dirs} folders, {files} files)")
        except Exception:
            self.status_message.emit(path)
