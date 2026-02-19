"""
SuperFile — Navigation Sidebar
Left panel with collapsible sections: Recents, Bookmarks, Storage, Places, Favorites.
"""

import os
import string
import shutil
from PySide6.QtCore import Qt, Signal, QSize
from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QLineEdit, QTreeWidget, QTreeWidgetItem,
    QLabel, QScrollArea, QFrame, QHBoxLayout, QSizePolicy
)
from PySide6.QtGui import QIcon, QColor, QPixmap, QPainter, QFont

from .utils import format_file_size


def _color_icon(color_hex, size=16):
    """Create a simple colored square icon."""
    pixmap = QPixmap(size, size)
    pixmap.fill(QColor(color_hex))
    return QIcon(pixmap)


def _folder_icon():
    return _color_icon("#e8a838")


def _drive_icon():
    return _color_icon("#5a9fd4")


def _file_icon():
    return _color_icon("#8888aa")


def _star_icon():
    return _color_icon("#f0c040")


class SidebarSection(QWidget):
    """A collapsible section with a header and item list."""

    item_clicked = Signal(str)  # path

    def __init__(self, title, parent=None):
        super().__init__(parent)
        self._collapsed = False
        self._items = []

        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        # Header
        self.header = QLabel(f"  ▾  {title}")
        self.header.setFixedHeight(28)
        self.header.setCursor(Qt.CursorShape.PointingHandCursor)
        self.header.setStyleSheet("""
            QLabel {
                color: #6a6a8a;
                font-size: 11px;
                font-weight: bold;
                text-transform: uppercase;
                padding: 4px 8px;
                background-color: transparent;
            }
            QLabel:hover {
                color: #9a9abc;
            }
        """)
        self.header.mousePressEvent = lambda e: self._toggle()
        self._title = title
        layout.addWidget(self.header)

        # Items container
        self.items_widget = QWidget()
        self.items_layout = QVBoxLayout(self.items_widget)
        self.items_layout.setContentsMargins(0, 0, 0, 4)
        self.items_layout.setSpacing(0)
        layout.addWidget(self.items_widget)

    def _toggle(self):
        self._collapsed = not self._collapsed
        self.items_widget.setVisible(not self._collapsed)
        arrow = "▸" if self._collapsed else "▾"
        self.header.setText(f"  {arrow}  {self._title}")

    def add_item(self, label, path, icon=None, indent=0):
        """Add a clickable item to this section."""
        item = SidebarItem(label, path, icon, indent)
        item.clicked.connect(self.item_clicked.emit)
        self.items_layout.addWidget(item)
        self._items.append(item)

    def clear_items(self):
        """Remove all items."""
        for item in self._items:
            self.items_layout.removeWidget(item)
            item.deleteLater()
        self._items.clear()


class SidebarItem(QWidget):
    """A single clickable item in the sidebar."""

    clicked = Signal(str)  # path

    def __init__(self, label, path, icon=None, indent=0, parent=None):
        super().__init__(parent)
        self.path = path
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        self.setFixedHeight(26)

        layout = QHBoxLayout(self)
        layout.setContentsMargins(12 + indent * 16, 0, 8, 0)
        layout.setSpacing(6)

        if icon:
            icon_label = QLabel()
            icon_label.setPixmap(icon.pixmap(QSize(16, 16)))
            icon_label.setFixedSize(16, 16)
            layout.addWidget(icon_label)

        text_label = QLabel(label)
        text_label.setStyleSheet("""
            color: #c0c0d0;
            font-size: 12px;
            background-color: transparent;
        """)
        layout.addWidget(text_label)
        layout.addStretch()

        self._default_style = "background-color: transparent; border-radius: 4px;"
        self._hover_style = "background-color: #2a2a3e; border-radius: 4px;"
        self.setStyleSheet(self._default_style)

    def enterEvent(self, event):
        self.setStyleSheet(self._hover_style)

    def leaveEvent(self, event):
        self.setStyleSheet(self._default_style)

    def mousePressEvent(self, event):
        if event.button() == Qt.MouseButton.LeftButton and self.path:
            self.clicked.emit(self.path)


class NavigationSidebar(QWidget):
    """Left navigation sidebar with sections matching FilePilot."""

    navigate_to = Signal(str)  # emitted when user clicks a path

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setMinimumWidth(150)
        self.setMaximumWidth(400)
        self.setStyleSheet("""
            NavigationSidebar {
                background-color: #141420;
                border-right: 1px solid #2a2a3e;
            }
        """)

        self._setup_ui()

    def _setup_ui(self):
        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(0, 0, 0, 0)
        main_layout.setSpacing(0)

        # Filter / search bar
        self.filter_edit = QLineEdit()
        self.filter_edit.setPlaceholderText("🔍 Filter...")
        self.filter_edit.setStyleSheet("""
            QLineEdit {
                background-color: #1a1a2e;
                border: 1px solid #2a2a3e;
                border-radius: 4px;
                padding: 5px 8px;
                color: #8888aa;
                font-size: 12px;
                margin: 8px;
            }
            QLineEdit:focus {
                border-color: #5a5a8a;
                color: #c0c0d0;
            }
        """)
        main_layout.addWidget(self.filter_edit)

        # Scrollable area for sections
        scroll = QScrollArea()
        scroll.setWidgetResizable(True)
        scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        scroll.setStyleSheet("""
            QScrollArea {
                border: none;
                background-color: transparent;
            }
            QScrollArea > QWidget > QWidget {
                background-color: transparent;
            }
        """)

        scroll_content = QWidget()
        self.sections_layout = QVBoxLayout(scroll_content)
        self.sections_layout.setContentsMargins(0, 0, 0, 0)
        self.sections_layout.setSpacing(0)

        # === Recents ===
        self.recents_section = SidebarSection("Recents")
        self.recents_section.item_clicked.connect(self.navigate_to.emit)
        self.sections_layout.addWidget(self.recents_section)

        # === Bookmarks ===
        self.bookmarks_section = SidebarSection("Bookmarks")
        self.bookmarks_section.item_clicked.connect(self.navigate_to.emit)
        self._populate_bookmarks()
        self.sections_layout.addWidget(self.bookmarks_section)

        # === Storage ===
        self.storage_section = SidebarSection("Storage")
        self.storage_section.item_clicked.connect(self.navigate_to.emit)
        self._populate_storage()
        self.sections_layout.addWidget(self.storage_section)

        # === Places ===
        self.places_section = SidebarSection("Places")
        self.places_section.item_clicked.connect(self.navigate_to.emit)
        self._populate_places()
        self.sections_layout.addWidget(self.places_section)

        # === Favorites ===
        self.favorites_section = SidebarSection("Favorites")
        self.favorites_section.item_clicked.connect(self.navigate_to.emit)
        self.sections_layout.addWidget(self.favorites_section)

        self.sections_layout.addStretch()

        scroll.setWidget(scroll_content)
        main_layout.addWidget(scroll)

    def _populate_bookmarks(self):
        """Add common bookmark locations."""
        home = os.path.expanduser("~")
        user = os.path.basename(home)

        # OneDrive paths
        onedrive = os.path.join(home, "OneDrive")
        if os.path.exists(onedrive):
            self.bookmarks_section.add_item("OneDrive", onedrive, _drive_icon())

        # Check for common cloud storage
        for name in ["Google Drive", "Dropbox", "iCloudDrive"]:
            path = os.path.join(home, name)
            if os.path.exists(path):
                self.bookmarks_section.add_item(name, path, _drive_icon())

    def _populate_storage(self):
        """Add drive letters."""
        for letter in string.ascii_uppercase:
            drive = f"{letter}:\\"
            if os.path.exists(drive):
                try:
                    total, used, free = shutil.disk_usage(drive)
                    label = f"Local Disk ({letter}:)"
                    # Try to get volume name
                    try:
                        import ctypes
                        buf = ctypes.create_unicode_buffer(256)
                        ctypes.windll.kernel32.GetVolumeInformationW(
                            drive, buf, 256, None, None, None, None, 0
                        )
                        if buf.value:
                            label = f"{buf.value} ({letter}:)"
                    except Exception:
                        pass
                    self.storage_section.add_item(label, drive, _drive_icon())
                except Exception:
                    self.storage_section.add_item(f"({letter}:)", drive, _drive_icon())

    def _populate_places(self):
        """Add common places."""
        home = os.path.expanduser("~")
        user = os.path.basename(home)

        places = [
            ("This PC", "C:\\", _drive_icon()),
            (user, home, _folder_icon()),
            ("Desktop", os.path.join(home, "Desktop"), _folder_icon()),
            ("Downloads", os.path.join(home, "Downloads"), _folder_icon()),
            ("Documents", os.path.join(home, "Documents"), _folder_icon()),
            ("Music", os.path.join(home, "Music"), _folder_icon()),
            ("Pictures", os.path.join(home, "Pictures"), _folder_icon()),
            ("Videos", os.path.join(home, "Videos"), _folder_icon()),
        ]

        # Add recycle bin path if accessible
        recycle = "C:\\$Recycle.Bin"
        if os.path.exists(recycle):
            places.append(("$RecycleBin", recycle, _file_icon()))

        for label, path, icon in places:
            if os.path.exists(path):
                self.places_section.add_item(label, path, icon)

    _MAX_RECENTS = 8

    def add_recent(self, path):
        """Add a path to the recents section (max 8, no duplicates)."""
        path = os.path.normpath(path)
        # Check for duplicates
        for item in self.recents_section._items:
            if os.path.normpath(item.path) == path:
                return
        # Remove oldest if at limit
        if len(self.recents_section._items) >= self._MAX_RECENTS:
            oldest = self.recents_section._items[0]
            self.recents_section.items_layout.removeWidget(oldest)
            oldest.deleteLater()
            self.recents_section._items.pop(0)
        label = os.path.basename(path) or path
        self.recents_section.add_item(label, path, _folder_icon())

    def add_favorite(self, path):
        """Add a path to favorites."""
        label = os.path.basename(path) or path
        icon = _folder_icon() if os.path.isdir(path) else _file_icon()
        self.favorites_section.add_item(label, path, icon)
