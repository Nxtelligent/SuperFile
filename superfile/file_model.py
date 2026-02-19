"""
SuperFile — File System Model
Wraps QFileSystemModel with additional features like folder size calculation.
"""

import os
import shutil
import threading
from PySide6.QtCore import Qt, QDir, Signal, QObject, QModelIndex
from PySide6.QtWidgets import QFileSystemModel

from .utils import format_file_size


class FolderSizeWorker(QObject):
    """Background worker to calculate folder sizes."""
    size_ready = Signal(str, int)  # (path, size_bytes)

    def calculate(self, path):
        """Calculate total size of a directory."""
        total = 0
        try:
            for dirpath, dirnames, filenames in os.walk(path):
                for f in filenames:
                    try:
                        fp = os.path.join(dirpath, f)
                        total += os.path.getsize(fp)
                    except (OSError, PermissionError):
                        pass
        except (OSError, PermissionError):
            pass
        self.size_ready.emit(path, total)


class FileModel(QFileSystemModel):
    """Enhanced file system model with folder size support."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setRootPath("")
        self.setFilter(QDir.Filter.AllEntries | QDir.Filter.NoDotAndDotDot)
        self.setNameFilterDisables(False)
        self._folder_sizes = {}
        self._size_worker = FolderSizeWorker()
        self._size_worker.size_ready.connect(self._on_size_ready)

    def _on_size_ready(self, path, size_bytes):
        """Handle folder size calculation result."""
        self._folder_sizes[path] = size_bytes
        # Find the index for this path and emit dataChanged
        idx = self.index(path)
        if idx.isValid():
            size_idx = self.index(idx.row(), 1, idx.parent())
            self.dataChanged.emit(size_idx, size_idx)

    def data(self, index, role=Qt.ItemDataRole.DisplayRole):
        """Override to show folder sizes."""
        if role == Qt.ItemDataRole.DisplayRole and index.column() == 1:
            path = self.filePath(index.siblingAtColumn(0))
            if self.isDir(index.siblingAtColumn(0)):
                cached = self._folder_sizes.get(path)
                if cached is not None and cached >= 0:
                    return format_file_size(cached)
                elif cached is None:
                    # Request background calculation
                    self._request_folder_size(path)
                    return ""
                else:
                    # In progress (-1)
                    return ""
        return super().data(index, role)

    def _request_folder_size(self, path):
        """Start a background thread to calculate folder size."""
        if path in self._folder_sizes:
            return
        self._folder_sizes[path] = -1  # Mark as in-progress
        thread = threading.Thread(
            target=self._size_worker.calculate,
            args=(path,),
            daemon=True
        )
        thread.start()


class FileOperations:
    """Static methods for file system operations."""

    @staticmethod
    def copy_file(src, dst_dir):
        """Copy a file or directory to destination directory."""
        name = os.path.basename(src)
        dst = os.path.join(dst_dir, name)
        # Handle name conflicts
        dst = FileOperations._unique_name(dst)
        if os.path.isdir(src):
            shutil.copytree(src, dst)
        else:
            shutil.copy2(src, dst)
        return dst

    @staticmethod
    def move_file(src, dst_dir):
        """Move a file or directory to destination directory."""
        name = os.path.basename(src)
        dst = os.path.join(dst_dir, name)
        dst = FileOperations._unique_name(dst)
        shutil.move(src, dst)
        return dst

    @staticmethod
    def delete_file(path):
        """Delete a file or directory (to recycle bin if possible, else permanent)."""
        try:
            from PySide6.QtCore import QFile
            if os.path.isdir(path):
                shutil.rmtree(path)
            else:
                QFile.moveToTrash(path)
        except Exception:
            if os.path.isdir(path):
                shutil.rmtree(path)
            else:
                os.remove(path)

    @staticmethod
    def rename_file(path, new_name):
        """Rename a file or directory."""
        parent = os.path.dirname(path)
        new_path = os.path.join(parent, new_name)
        os.rename(path, new_path)
        return new_path

    @staticmethod
    def create_folder(parent_dir, name="New Folder"):
        """Create a new folder."""
        path = os.path.join(parent_dir, name)
        path = FileOperations._unique_name(path)
        os.makedirs(path)
        return path

    @staticmethod
    def _unique_name(path):
        """Generate a unique name if path already exists."""
        if not os.path.exists(path):
            return path
        base, ext = os.path.splitext(path)
        counter = 1
        while os.path.exists(f"{base} ({counter}){ext}"):
            counter += 1
        return f"{base} ({counter}){ext}"
