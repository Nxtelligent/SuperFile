"""
SuperFile — Navigation Sidebar
Left panel with collapsible sections: Recents, Bookmarks, Storage, Places, Favorites.
"""

import os
import string
import shutil
from PySide6.QtCore import Qt, Signal, QSize, QFileInfo
from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QLineEdit, QTreeWidget, QTreeWidgetItem,
    QLabel, QScrollArea, QFrame, QHBoxLayout, QSizePolicy,
    QFileIconProvider
)
from PySide6.QtGui import QIcon, QColor, QPixmap, QPainter, QFont, QPalette

from .utils import format_file_size

# Global icon provider for system icons
_icon_provider = QFileIconProvider()


def _system_icon(path):
    """Get the real system icon for a file or folder path."""
    try:
        info = QFileInfo(path)
        return _icon_provider.icon(info)
    except Exception:
        return _icon_provider.icon(QFileIconProvider.IconType.Folder)


def _drive_icon_for(path):
    """Get system icon for a drive."""
    try:
        info = QFileInfo(path)
        return _icon_provider.icon(info)
    except Exception:
        return _icon_provider.icon(QFileIconProvider.IconType.Drive)


def _generic_folder_icon():
    return _icon_provider.icon(QFileIconProvider.IconType.Folder)


def _generic_drive_icon():
    return _icon_provider.icon(QFileIconProvider.IconType.Drive)


def _generic_file_icon():
    return _icon_provider.icon(QFileIconProvider.IconType.File)


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

    def add_storage_item(self, label, path, icon, used, total):
        """Add a storage item with a usage bar."""
        item = StorageItem(label, path, icon, used, total)
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
    """A single clickable item in the sidebar with hover highlight."""

    clicked = Signal(str)  # path

    def __init__(self, label, path, icon=None, indent=0, parent=None):
        super().__init__(parent)
        self.path = path
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        self.setFixedHeight(26)
        self.setAttribute(Qt.WidgetAttribute.WA_Hover, True)
        self._hovered = False

        layout = QHBoxLayout(self)
        layout.setContentsMargins(12 + indent * 16, 0, 8, 0)
        layout.setSpacing(6)

        if icon:
            icon_label = QLabel()
            icon_label.setPixmap(icon.pixmap(QSize(16, 16)))
            icon_label.setFixedSize(16, 16)
            icon_label.setStyleSheet("background-color: transparent;")
            layout.addWidget(icon_label)

        self._text_label = QLabel(label)
        self._text_label.setStyleSheet("""
            color: #c0c0d0;
            font-size: 12px;
            background-color: transparent;
        """)
        layout.addWidget(self._text_label)
        layout.addStretch()

    def enterEvent(self, event):
        self._hovered = True
        self.update()

    def leaveEvent(self, event):
        self._hovered = False
        self.update()

    def paintEvent(self, event):
        if self._hovered:
            painter = QPainter(self)
            painter.setRenderHint(QPainter.RenderHint.Antialiasing)
            painter.setBrush(QColor(42, 42, 62))  # #2a2a3e
            painter.setPen(Qt.PenStyle.NoPen)
            painter.drawRoundedRect(self.rect().adjusted(4, 0, -4, 0), 4, 4)
            painter.end()
        super().paintEvent(event)

    def mousePressEvent(self, event):
        if event.button() == Qt.MouseButton.LeftButton and self.path:
            self.clicked.emit(self.path)


class StorageItem(QWidget):
    """A storage drive item with icon, label, and usage bar."""

    clicked = Signal(str)  # path

    def __init__(self, label, path, icon, used, total, parent=None):
        super().__init__(parent)
        self.path = path
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        self.setFixedHeight(44)
        self.setAttribute(Qt.WidgetAttribute.WA_Hover, True)
        self._hovered = False
        self._used = used
        self._total = total

        layout = QHBoxLayout(self)
        layout.setContentsMargins(12, 4, 12, 4)
        layout.setSpacing(8)

        # Icon
        if icon:
            icon_label = QLabel()
            icon_label.setPixmap(icon.pixmap(QSize(18, 18)))
            icon_label.setFixedSize(18, 18)
            icon_label.setStyleSheet("background-color: transparent;")
            layout.addWidget(icon_label)

        # Right side: label + bar
        right = QWidget()
        right.setStyleSheet("background-color: transparent;")
        right_layout = QVBoxLayout(right)
        right_layout.setContentsMargins(0, 0, 0, 0)
        right_layout.setSpacing(2)

        # Label with size info
        size_text = f"{format_file_size(used)} / {format_file_size(total)}"
        name_label = QLabel(label)
        name_label.setStyleSheet("color: #c0c0d0; font-size: 11px; background-color: transparent;")
        right_layout.addWidget(name_label)

        # Usage bar container
        bar_widget = QWidget()
        bar_widget.setFixedHeight(6)
        bar_widget.setStyleSheet("background-color: transparent;")
        right_layout.addWidget(bar_widget)

        layout.addWidget(right, 1)

        # Size label on the right
        size_label = QLabel(size_text)
        size_label.setStyleSheet("color: #5a5a7a; font-size: 9px; background-color: transparent;")
        layout.addWidget(size_label)

        # Store bar info for painting
        self._bar_widget = bar_widget
        self._ratio = used / total if total > 0 else 0

    def enterEvent(self, event):
        self._hovered = True
        self.update()

    def leaveEvent(self, event):
        self._hovered = False
        self.update()

    def paintEvent(self, event):
        painter = QPainter(self)
        painter.setRenderHint(QPainter.RenderHint.Antialiasing)

        # Hover background
        if self._hovered:
            painter.setBrush(QColor(42, 42, 62))  # #2a2a3e
            painter.setPen(Qt.PenStyle.NoPen)
            painter.drawRoundedRect(self.rect().adjusted(4, 0, -4, 0), 4, 4)

        # Usage bar — map bar_widget position to StorageItem coordinates
        bar_pos = self._bar_widget.mapTo(self, self._bar_widget.rect().topLeft())
        bar_w = self._bar_widget.width()
        bar_h = self._bar_widget.height()

        if bar_w > 0:
            # Background track
            painter.setBrush(QColor(30, 30, 48))  # #1e1e30
            painter.setPen(Qt.PenStyle.NoPen)
            painter.drawRoundedRect(bar_pos.x(), bar_pos.y(), bar_w, bar_h, 3, 3)

            # Fill
            fill_w = int(bar_w * self._ratio)
            if fill_w > 0:
                # Color based on usage: blue → orange → red
                if self._ratio < 0.7:
                    color = QColor(90, 143, 212)  # blue
                elif self._ratio < 0.9:
                    color = QColor(232, 168, 56)  # orange
                else:
                    color = QColor(220, 80, 80)  # red
                painter.setBrush(color)
                painter.drawRoundedRect(bar_pos.x(), bar_pos.y(), fill_w, bar_h, 3, 3)

        painter.end()
        super().paintEvent(event)

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
            self.bookmarks_section.add_item("OneDrive", onedrive, _system_icon(onedrive))

        # Check for common cloud storage
        for name in ["Google Drive", "Dropbox", "iCloudDrive"]:
            path = os.path.join(home, name)
            if os.path.exists(path):
                self.bookmarks_section.add_item(name, path, _system_icon(path))

    def _populate_storage(self):
        """Add drive letters with usage bars."""
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
                    self.storage_section.add_storage_item(
                        label, drive, _drive_icon_for(drive), used, total
                    )
                except Exception:
                    self.storage_section.add_item(f"({letter}:)", drive, _generic_drive_icon())

    def _populate_places(self):
        """Add common places."""
        home = os.path.expanduser("~")
        user = os.path.basename(home)

        places = [
            ("This PC", "C:\\", _generic_drive_icon()),
            (user, home, _system_icon(home)),
            ("Desktop", os.path.join(home, "Desktop"), _system_icon(os.path.join(home, "Desktop"))),
            ("Downloads", os.path.join(home, "Downloads"), _system_icon(os.path.join(home, "Downloads"))),
            ("Documents", os.path.join(home, "Documents"), _system_icon(os.path.join(home, "Documents"))),
            ("Music", os.path.join(home, "Music"), _system_icon(os.path.join(home, "Music"))),
            ("Pictures", os.path.join(home, "Pictures"), _system_icon(os.path.join(home, "Pictures"))),
            ("Videos", os.path.join(home, "Videos"), _system_icon(os.path.join(home, "Videos"))),
        ]

        # Add recycle bin path if accessible
        recycle = "C:\\$Recycle.Bin"
        if os.path.exists(recycle):
            places.append(("$RecycleBin", recycle, _system_icon(recycle)))

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
        self.recents_section.add_item(label, path, _system_icon(path))

    def add_favorite(self, path):
        """Add a path to favorites."""
        label = os.path.basename(path) or path
        icon = _system_icon(path)
        self.favorites_section.add_item(label, path, icon)
