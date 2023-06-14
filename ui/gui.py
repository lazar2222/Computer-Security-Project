import sys
import datetime
from PyQt5.QtWidgets import QApplication, QDialog, QMainWindow
from PyQt5.QtCore import Qt, QAbstractTableModel, QVariant
from PyQt5.uic import loadUi

import constants
import exceptions
import keys
import keyRing
import src.app as app

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
                    attr = constants.algorithmSetToString(attr)
            return attr
        return QVariant()
    
    def headerData(self, section, orientation, role):
        if (role == Qt.DisplayRole):
            return self.DISPLAY_NAME[self.columns[section]]
        return QVariant()

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

class KeyRingManager(QDialog):

    def __init__(self, keyRing: keyRing.KeyRing, parent = None):
        super().__init__(parent)
        loadUi('kmg.ui', self)
        self.keyRing = keyRing
        self.model = KeyRingModel(keyRing)
        self.setVis(keyRing.isPrivate())
        self.bind()

    def setVis(self, private: bool):
        self.btnGenerate.setVisible(private)
        self.label.setText('Private key ring:' if private else 'Public key ring:')

    def bind(self):
        self.tableView.setModel(self.model)
        self.tableView.resizeColumnsToContents()
        self.tableView.doubleClicked.connect(self.displayKeyDetails)

    def displayKeyDetails(self, index):
        key = self.keyRing.keys[index.row()]
        dialog = KeyDetails(key, self.keyRing, self)
        dialog.exec()

class KeyDetails(QDialog):

    def __init__(self, key: keys.PrivateKey, keyRing: keyRing.KeyRing = None, parent = None):
        super().__init__(parent)
        loadUi('kdet.ui', self)
        self.key = key
        self.keyRing = keyRing
        self.setVis(key.isPrivate(), keyRing != None)
        self.bind()
        self.populate(key, key.isPrivate())

    def setVis(self, private: bool, keyRing: bool):
        self.label.setText('Private key details:' if private else 'Public key details:')
        self.btnExpPrivate.setVisible(private)
        self.btnEdit.setVisible(keyRing)
        self.btnDelete.setVisible(keyRing)
        self.frameName.setVisible(private)
        self.framePrivate.setVisible(private)

    def bind(self):
        self.btnDecrypt.clicked.connect(self.decrypt)

    def populate(self, key: keys.PublicKey, private: bool):
        self.tbCreationDate.setText(datetime.datetime.fromtimestamp(key.timestamp).strftime("%Y-%m-%d %H:%M:%S"))
        self.tbEmail.setText(key.email)
        self.tbId.setText(str(key.id))
        self.tbAlgo.setText(constants.algorithmSetToString(key.algorithm))
        self.tbKeySize.setText(str(key.keySize()))
        pk = ''
        for k in key.publicKey.keys():
            v = key.publicKey[k]
            pk += f'{k:2}: {v}\n'
        self.textPublic.setPlainText(pk)
        if private:
            self.tbName.setText(key.name)
            self.textPrivate.setPlainText(key.privateKey)
        
    def decrypt(self):
        while True:
            password = PasswordDialog.passwordPrompt(self.key, self)
            if password == None:
                return
            try:
                privateDict = self.key.decryptKey(password)
                pk = ''
                for k in privateDict.keys():
                    v = privateDict[k]
                    pk += f'{k:2}: {v}\n'
                self.textPrivate.setPlainText(pk)
                self.btnDecrypt.setVisible(False)
                return
            except:
                exceptions.error('Wrong password or corrupted private key.')


class PasswordDialog(QDialog):

    def __init__(self, key: keys.PrivateKey, parent = None):
        super().__init__(parent)
        loadUi('password.ui', self)
        self.key = key
        self.bind()

    def bind(self):
        if self.key != None:
            self.btnDetails.clicked.connect(self.displayKeyDetails)
            self.tbId.setText(str(self.key.id))
        else:
            self.btnDetails.setVisible(False)
            self.tbId.setVisible(False)
            self.labelPass.setVisible(False)
            self.labelId.setVisible(False)

    def displayKeyDetails(self):
        dialog = KeyDetails(self.key, None, self)
        dialog.exec()

    @staticmethod
    def passwordPrompt(key: keys.PrivateKey, parent = None):
        dialog = PasswordDialog(key, parent)
        ret = dialog.exec()
        return dialog.tbPassword.text() if ret == 1 else None

if __name__ == '__main__':
    try:
        qt = QApplication(sys.argv)
        application = app.Application()
        win = MainMenu(application)
        win.show()
        sys.exit(qt.exec())
    except Exception as ex:
        exceptions.criticalError(ex)