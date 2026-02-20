"""
SuperFile — Dark Theme Stylesheet
Darker black palette matching FilePilot's aesthetic.
"""


def get_stylesheet():
    """Return the complete Qt stylesheet for the dark theme."""
    return """
    /* ===== Global ===== */
    QWidget {
        background-color: #161622;
        color: #c0c0d0;
        font-family: "JetBrains Mono", "Cascadia Code", "Consolas", monospace;
        font-size: 13px;
    }

    /* ===== Main Window ===== */
    QMainWindow {
        background-color: #111118;
    }

    QMainWindow::separator {
        background-color: #1e1e30;
        width: 2px;
        height: 2px;
    }

    QMainWindow::separator:hover {
        background-color: #5a5a8a;
    }

    /* ===== Menu Bar ===== */
    QMenuBar {
        background-color: #111118;
        border-bottom: 1px solid #1e1e30;
        padding: 2px;
    }

    QMenuBar::item {
        padding: 4px 10px;
        border-radius: 4px;
        color: #8888aa;
    }

    QMenuBar::item:selected {
        background-color: #1e1e30;
        color: #c0c0d0;
    }

    QMenu {
        background-color: #161622;
        border: 1px solid #2a2a3e;
        border-radius: 6px;
        padding: 4px;
    }

    QMenu::item {
        padding: 6px 24px 6px 12px;
        border-radius: 4px;
    }

    QMenu::item:selected {
        background-color: #2a2a3e;
        color: #ffffff;
    }

    QMenu::separator {
        height: 1px;
        background-color: #1e1e30;
        margin: 4px 8px;
    }

    /* ===== Tab Bar ===== */
    QTabBar {
        background-color: #111118;
        border: none;
    }

    QTabBar::tab {
        background-color: #111118;
        color: #6a6a8a;
        padding: 6px 16px;
        margin-right: 0;
        border: none;
        border-bottom: 2px solid transparent;
        min-width: 80px;
    }

    QTabBar::tab:selected {
        background-color: #161622;
        color: #e0e0e0;
        border-bottom: 2px solid #5a8fd4;
    }

    QTabBar::tab:hover:!selected {
        background-color: #1a1a28;
        color: #a0a0b8;
    }

    /* ===== Tree View / File List ===== */
    QTreeView {
        background-color: #161622;
        border: none;
        outline: none;
        selection-background-color: #2a3a5a;
        alternate-background-color: #14141f;
        gridline-color: #1e1e30;
    }

    QTreeView::item {
        padding: 2px 4px;
        border: none;
        height: 24px;
    }

    QTreeView::item:selected {
        background-color: #2a3a5a;
        color: #ffffff;
    }

    QTreeView::item:hover:!selected {
        background-color: #1e1e30;
    }

    QTreeView::branch {
        background-color: transparent;
    }

    QHeaderView {
        background-color: #111118;
    }

    QHeaderView::section {
        background-color: #111118;
        color: #6a6a8a;
        padding: 4px 8px;
        border: none;
        border-right: 1px solid #1e1e30;
        border-bottom: 1px solid #1e1e30;
        font-size: 11px;
        font-weight: normal;
    }

    QHeaderView::section:hover {
        background-color: #1a1a28;
        color: #a0a0b8;
    }

    /* ===== Scrollbars ===== */
    QScrollBar:vertical {
        background-color: transparent;
        width: 6px;
        margin: 0;
    }

    QScrollBar::handle:vertical {
        background-color: #2a2a3e;
        border-radius: 3px;
        min-height: 30px;
    }

    QScrollBar::handle:vertical:hover {
        background-color: #4a4a6a;
    }

    QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {
        height: 0;
    }

    QScrollBar:horizontal {
        background-color: transparent;
        height: 6px;
        margin: 0;
    }

    QScrollBar::handle:horizontal {
        background-color: #2a2a3e;
        border-radius: 3px;
        min-width: 30px;
    }

    QScrollBar::handle:horizontal:hover {
        background-color: #4a4a6a;
    }

    QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal {
        width: 0;
    }

    /* ===== Line Edit ===== */
    QLineEdit {
        background-color: #1a1a2a;
        border: 1px solid #2a2a3e;
        border-radius: 4px;
        padding: 5px 8px;
        color: #c0c0d0;
        selection-background-color: #3a4a6a;
    }

    QLineEdit:focus {
        border-color: #5a5a8a;
    }

    /* ===== Completer Popup ===== */
    QListView {
        background-color: #161622;
        border: 1px solid #2a2a3e;
        border-radius: 4px;
        padding: 2px;
        outline: none;
    }

    QListView::item {
        padding: 4px 8px;
        border-radius: 3px;
    }

    QListView::item:selected {
        background-color: #2a3a5a;
        color: #ffffff;
    }

    /* ===== Splitter ===== */
    QSplitter::handle {
        background-color: #1e1e30;
    }

    QSplitter::handle:hover {
        background-color: #5a5a8a;
    }

    QSplitter::handle:horizontal {
        width: 1px;
    }

    QSplitter::handle:vertical {
        height: 1px;
    }

    /* ===== Status Bar ===== */
    QStatusBar {
        background-color: #111118;
        border-top: 1px solid #1e1e30;
        color: #6a6a8a;
        font-size: 11px;
    }

    QStatusBar::item {
        border: none;
    }

    /* ===== Tool Bar ===== */
    QToolBar {
        background-color: #111118;
        border: none;
        padding: 0;
        spacing: 0;
    }

    QToolButton {
        background-color: transparent;
        border: none;
        border-radius: 3px;
        padding: 4px 6px;
        color: #6a6a8a;
        font-size: 12px;
    }

    QToolButton:hover {
        background-color: #1e1e30;
        color: #c0c0d0;
    }

    QToolButton:pressed {
        background-color: #2a3a5a;
    }

    /* ===== Push Button ===== */
    QPushButton {
        background-color: transparent;
        border: none;
        border-radius: 4px;
        padding: 4px 8px;
        color: #8888aa;
    }

    QPushButton:hover {
        background-color: #1e1e30;
        color: #c0c0d0;
    }

    QPushButton:pressed {
        background-color: #2a3a5a;
    }

    QPushButton:disabled {
        color: #3a3a4e;
    }

    /* ===== Labels ===== */
    QLabel {
        color: #c0c0d0;
        background-color: transparent;
    }

    /* ===== Text Edit (Inspector) ===== */
    QPlainTextEdit {
        background-color: #111118;
        color: #b0b0c0;
        border: none;
        font-family: "Cascadia Code", "Consolas", monospace;
        font-size: 12px;
        selection-background-color: #2a3a5a;
    }

    /* ===== ToolTip ===== */
    QToolTip {
        background-color: #1e1e30;
        color: #c0c0d0;
        border: 1px solid #2a2a3e;
        border-radius: 4px;
        padding: 4px 8px;
    }

    /* ===== Input Dialog / Message Box ===== */
    QInputDialog, QMessageBox {
        background-color: #161622;
    }
    """
