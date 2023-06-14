import sys
import datetime
from PyQt5.QtWidgets import QApplication, QDialog, QMainWindow
from PyQt5.QtCore import Qt, QAbstractTableModel, QVariant
from PyQt5.uic import loadUi

import constants
import exceptions
import keyRing
import app

class MainMenu(QMainWindow):
    
    def __init__(self, application, parent = None):
        super().__init__(parent)
        loadUi('main.ui', self)
        self.bind()
        self.application = application

    def bind(self):
        self.btnPrkr.clicked.connect(lambda: self.showKeyRing(application.privateKeyRing))
        self.btnPukr.clicked.connect(lambda: self.showKeyRing(application.publicKeyRing))
        self.btnSend.clicked.connect(self.showSendMessage)
        self.btnReceive.clicked.connect(self.showReceiveMessage)

    def showKeyRing(self, keyRing: keyRing.KeyRing):
        dialog = KeyRingManager(keyRing, self)
        dialog.exec()
    
    def showSendMessage(self):
        pass
    
    def showReceiveMessage(self):
        pass

class KeyRingModel(QAbstractTableModel):
    
    PRIVATE_COLUMNS = ['timestamp', 'name', 'email', 'id', 'algorithm']
    PUBLIC_COLUMNS = ['timestamp', 'email', 'id', 'algorithm']
    DISPLAY_NAME = {'timestamp': 'Creation date', 'name': 'Name', 'email': 'Email', 'id': 'Id', 'algorithm': 'Algorithm', 'publicKey': 'Public Key', 'privateKey': 'Encrypted private key'}

    def __init__(self, keyRing: keyRing.KeyRing):
        super().__init__()
        self.keyRing = keyRing
        self.columns = self.PRIVATE_COLUMNS if self.keyRing.isPrivate() else self.PUBLIC_COLUMNS
    
    def rowCount(self, parent = None):
        return len(self.keyRing.keys)
    
    def columnCount(self, parent = None):
        return len(self.columns)
    
    def data(self, index, role):
        if (role == Qt.DisplayRole):
            attr = getattr(self.keyRing.keys[index.row()], self.columns[index.column()])
            match self.columns[index.column()]:
                case 'timestamp':
                    attr = datetime.datetime.fromtimestamp(attr).strftime("%Y-%m-%d %H:%M:%S")
                case 'algorithm':
                    attr = 'RSA' if attr == constants.AlgorithmSet.RSA else 'DSA/ElGamal'
            return str(attr)
        return QVariant()
    
    def headerData(self, section, orientation, role):
        if (role == Qt.DisplayRole):
            return self.DISPLAY_NAME[self.columns[section]]
        return QVariant()

class KeyRingManager(QDialog):

    def __init__(self, keyRing: keyRing.KeyRing, parent = None):
        super().__init__(parent)
        loadUi('kmg.ui', self)
        self.keyRing = keyRing
        self.model = KeyRingModel(keyRing)
        self.setVis(keyRing.isPrivate())
        self.bind()

    def setVis(self, private: bool):
        pass

    def bind(self):
        self.tableView.setModel(self.model)
        self.tableView.resizeColumnsToContents()

if __name__ == '__main__':
    try:
        qt = QApplication(sys.argv)
        application = app.Application()
        win = MainMenu(application)
        win.show()
        sys.exit(qt.exec())
    except Exception as ex:
        exceptions.criticalError(ex)