from PyQt5.QtWidgets import QDialog
from PyQt5.QtCore import Qt, QAbstractTableModel, QVariant
from PyQt5.uic import loadUi

from constants import algorithmSetToString, timestampToString
from keyRing import KeyRing

import ui.keyDetails as keyDetails

class KeyRingModel(QAbstractTableModel):
    
    PRIVATE_COLUMNS = ['timestamp', 'name', 'email', 'id', 'algorithm']
    PUBLIC_COLUMNS = ['timestamp', 'email', 'id', 'algorithm']
    DISPLAY_NAME = {'timestamp': 'Creation date', 'name': 'Name', 'email': 'Email', 'id': 'Id', 'algorithm': 'Algorithm', 'publicKey': 'Public Key', 'privateKey': 'Encrypted private key'}

    def __init__(self, keyRing: KeyRing):
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
                    attr = timestampToString(attr)
                case 'algorithm':
                    attr = algorithmSetToString(attr)
            return attr
        return QVariant()
    
    def headerData(self, section, orientation, role):
        if (role == Qt.DisplayRole):
            return self.DISPLAY_NAME[self.columns[section]]
        return QVariant()

class KeyRingManager(QDialog):

    def __init__(self, keyRing: KeyRing, parent = None):
        super().__init__(parent)
        loadUi('src/ui/design/kmg.ui', self)
        self.keyRing = keyRing
        self.model = KeyRingModel(keyRing)
        self.setupUi()

    def setupUi(self):
        self.label.setText('Private key ring:' if self.keyRing.isPrivate() else 'Public key ring:')
        self.btnGenerate.setVisible(self.keyRing.isPrivate())
        self.tableView.setModel(self.model)
        self.tableView.resizeColumnsToContents()
        self.tableView.doubleClicked.connect(self.displayKeyDetails)
        self.btnGenerate.clicked.connect(self.generateKey)
        self.btnImport.clicked.connect(self.importKey)

    def displayKeyDetails(self, index):
        key = self.keyRing.keys[index.row()]
        keyDetails.KeyDetails.launch(key, self.keyRing, self)

    def generateKey(self):
        pass

    def importKey(self):
        pass

    @staticmethod
    def launch(keyRing: KeyRing, parent = None):
        KeyRingManager(keyRing, parent).exec()