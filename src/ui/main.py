import sys
from PyQt5.QtWidgets import QMainWindow, QApplication
from PyQt5.uic import loadUi

from keyRing import KeyRing

import ui.keyRingManager as keyRingManager

class MainMenu(QMainWindow):
    
    def __init__(self, application, parent = None):
        super().__init__(parent)
        loadUi('src/ui/design/main.ui', self)
        self.application = application
        self.setupUi()

    def setupUi(self):
        self.btnPrkr.clicked.connect(lambda: self.showKeyRing(self.application.privateKeyRing))
        self.btnPukr.clicked.connect(lambda: self.showKeyRing(self.application.publicKeyRing))
        self.btnSend.clicked.connect(self.showSendMessage)
        self.btnReceive.clicked.connect(self.showReceiveMessage)

    def showKeyRing(self, keyRing: KeyRing):
        keyRingManager.KeyRingManager.launch(keyRing, self)
    
    def showSendMessage(self):
        pass
    
    def showReceiveMessage(self):
        pass

    @staticmethod
    def launch(app):
        qt = QApplication(sys.argv)
        win = MainMenu(app)
        win.show()
        sys.exit(qt.exec())