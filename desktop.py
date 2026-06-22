import sys
from PySide6.QtWidgets import QApplication,QLabel,QMainWindow

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()

        self.setWindowTitle("Kubeguard-Lite Desktop")
        self.setMinimumSize(800,500)

        label = QLabel("Kubeguard-Lite Desktop 环境已就绪")
        label.setStyleSheet("font-size: 24px; padding: 40px;")
        self.setCentralWidget(label)

def main():
    app = QApplication(sys.argv)

    window = MainWindow()
    window.show()

    sys.exit(app.exec())

if __name__ == "__main__":
    main()