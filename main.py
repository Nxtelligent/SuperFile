"""
SuperFile — Entry Point
Launch the application with: python main.py
"""

import sys
from PySide6.QtWidgets import QApplication
from superfile.app import MainWindow
from superfile.theme import get_stylesheet


def main():
    app = QApplication(sys.argv)
    app.setApplicationName("SuperFile")
    app.setOrganizationName("SuperFile")

    # Apply dark theme
    app.setStyleSheet(get_stylesheet())

    window = MainWindow()
    window.show()

    sys.exit(app.exec())


if __name__ == "__main__":
    main()
