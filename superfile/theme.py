"""
SuperFile — Dark Theme Stylesheet
Inspired by FilePilot's modern dark aesthetic.
"""


def get_stylesheet():
    """Return the complete Qt stylesheet for the dark theme."""
    return """
    /* ===== Global ===== */
    QWidget {
        background-color: #1a1a2e;
        color: #e0e0e0;
        font-family: "Segoe UI", "Inter", sans-serif;
        font-size: 13px;
    }

    /* ===== Main Window ===== */
    QMainWindow {
        background-color: #1a1a2e;
    }

    QMainWindow::separator {
        background-color: #2a2a4a;
        width: 2px;
        height: 2px;
    }

    QMainWindow::separator:hover {
        background-color: #6c63ff;
    }

    /* ===== Menu Bar ===== */
    QMenuBar {
        background-color: #16162b;
        border-bottom: 1px solid #2a2a4a;
        padding: 2px;
    }

    QMenuBar::item {
        padding: 4px 10px;
        border-radius: 4px;
    }

    QMenuBar::item:selected {
        background-color: #2a2a4a;
    }

    QMenu {
        background-color: #1e1e3a;
        border: 1px solid #2a2a4a;
        border-radius: 6px;
        padding: 4px;
    }

    QMenu::item {
        padding: 6px 24px 6px 12px;
        border-radius: 4px;
    }

    QMenu::item:selected {
        background-color: #6c63ff;
        color: #ffffff;
    }

    QMenu::separator {
        height: 1px;
        background-color: #2a2a4a;
        margin: 4px 8px;
    }

    /* ===== Tab Bar ===== */
    QTabBar {
        background-color: transparent;
        border: none;
    }

    QTabBar::tab {
        background-color: #16162b;
        color: #8888aa;
        padding: 6px 16px;
        margin-right: 1px;
        border-top-left-radius: 6px;
        border-top-right-radius: 6px;
        min-width: 80px;
    }

    QTabBar::tab:selected {
        background-color: #1e1e3a;
        color: #e0e0e0;
        border-bottom: 2px solid #6c63ff;
    }

    QTabBar::tab:hover:!selected {
        background-color: #222244;
        color: #c0c0d0;
    }

    QTabBar::close-button {
        image: none;
        subcontrol-position: right;
        padding: 2px;
    }

    /* ===== Tree View / File List ===== */
    QTreeView {
        background-color: #1e1e3a;
        border: none;
        outline: none;
        selection-background-color: #6c63ff40;
        alternate-background-color: #1a1a35;
    }

    QTreeView::item {
        padding: 3px 4px;
        border: none;
    }

    QTreeView::item:selected {
        background-color: #6c63ff40;
        color: #ffffff;
    }

    QTreeView::item:hover:!selected {
        background-color: #2a2a4a;
    }

    QTreeView::branch {
        background-color: transparent;
    }

    QHeaderView::section {
        background-color: #16162b;
        color: #8888aa;
        padding: 5px 8px;
        border: none;
        border-right: 1px solid #2a2a4a;
        border-bottom: 1px solid #2a2a4a;
        font-size: 11px;
        font-weight: bold;
        text-transform: uppercase;
    }

    QHeaderView::section:hover {
        background-color: #222244;
        color: #c0c0d0;
    }

    /* ===== Scrollbars ===== */
    QScrollBar:vertical {
        background-color: transparent;
        width: 8px;
        margin: 0;
    }

    QScrollBar::handle:vertical {
        background-color: #3a3a5a;
        border-radius: 4px;
        min-height: 30px;
    }

    QScrollBar::handle:vertical:hover {
        background-color: #6c63ff;
    }

    QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {
        height: 0;
    }

    QScrollBar:horizontal {
        background-color: transparent;
        height: 8px;
        margin: 0;
    }

    QScrollBar::handle:horizontal {
        background-color: #3a3a5a;
        border-radius: 4px;
        min-width: 30px;
    }

    QScrollBar::handle:horizontal:hover {
        background-color: #6c63ff;
    }

    QScrollBar::add-line:horizontal, QScrollBar::sub-line:horizontal {
        width: 0;
    }

    /* ===== Line Edit (Address Bar) ===== */
    QLineEdit {
        background-color: #16162b;
        border: 1px solid #2a2a4a;
        border-radius: 6px;
        padding: 6px 10px;
        color: #e0e0e0;
        selection-background-color: #6c63ff;
    }

    QLineEdit:focus {
        border-color: #6c63ff;
    }

    /* ===== Completer Popup ===== */
    QListView {
        background-color: #1e1e3a;
        border: 1px solid #2a2a4a;
        border-radius: 6px;
        padding: 4px;
        outline: none;
    }

    QListView::item {
        padding: 4px 8px;
        border-radius: 4px;
    }

    QListView::item:selected {
        background-color: #6c63ff;
        color: #ffffff;
    }

    /* ===== Splitter ===== */
    QSplitter::handle {
        background-color: #2a2a4a;
    }

    QSplitter::handle:hover {
        background-color: #6c63ff;
    }

    QSplitter::handle:horizontal {
        width: 2px;
    }

    QSplitter::handle:vertical {
        height: 2px;
    }

    /* ===== Status Bar ===== */
    QStatusBar {
        background-color: #16162b;
        border-top: 1px solid #2a2a4a;
        color: #8888aa;
        font-size: 11px;
    }

    QStatusBar::item {
        border: none;
    }

    /* ===== Tool Bar ===== */
    QToolBar {
        background-color: #16162b;
        border-bottom: 1px solid #2a2a4a;
        padding: 2px 4px;
        spacing: 2px;
    }

    QToolButton {
        background-color: transparent;
        border: none;
        border-radius: 4px;
        padding: 4px 8px;
        color: #8888aa;
    }

    QToolButton:hover {
        background-color: #2a2a4a;
        color: #e0e0e0;
    }

    QToolButton:pressed {
        background-color: #6c63ff40;
    }

    /* ===== Push Button ===== */
    QPushButton {
        background-color: #2a2a4a;
        border: 1px solid #3a3a5a;
        border-radius: 6px;
        padding: 6px 16px;
        color: #e0e0e0;
    }

    QPushButton:hover {
        background-color: #3a3a5a;
        border-color: #6c63ff;
    }

    QPushButton:pressed {
        background-color: #6c63ff;
    }

    /* ===== Labels ===== */
    QLabel {
        color: #e0e0e0;
        background-color: transparent;
    }

    /* ===== Text Edit (Inspector) ===== */
    QPlainTextEdit {
        background-color: #16162b;
        color: #c0c0d0;
        border: none;
        font-family: "Cascadia Code", "Consolas", monospace;
        font-size: 12px;
        selection-background-color: #6c63ff40;
    }

    /* ===== Frame ===== */
    QFrame[frameShape="4"] {
        color: #2a2a4a;
    }

    /* ===== ToolTip ===== */
    QToolTip {
        background-color: #1e1e3a;
        color: #e0e0e0;
        border: 1px solid #3a3a5a;
        border-radius: 4px;
        padding: 4px 8px;
    }
    """
