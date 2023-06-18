from PyQt5.QtWidgets import QDialog, QFileDialog
from PyQt5.uic import loadUi

from constants import timestampToString, algorithmSetToString
from exceptions import error
from keys import PublicKey
from keyRing import KeyRing

import ui.passwordDialog as passwordDialog

class KeyDetails(QDialog):

    def __init__(self, key: PublicKey, keyRing: KeyRing = None, select: bool = False, parent = None):
        super().__init__(parent)
        loadUi('src/ui/design/kdet.ui', self)
        self.key = key
        self.keyRing = keyRing
        self.canSelect = select
        self.selected = None
        self.editing = False
        self.setupUi()

    def setupUi(self):
        private = self.key.isPrivate()
        keyRing = self.keyRing != None
        self.label.setText('Private key details:' if private else 'Public key details:')
        self.btnExpPrivate.setVisible(private)
        self.frameName.setVisible(private)
        self.framePrivate.setVisible(private)
        self.btnEdit.setVisible(keyRing)
        self.btnDelete.setVisible(keyRing)
        self.btnSelect.setVisible(self.canSelect)
        
        self.btnExpPrivate.clicked.connect(lambda: self.export(True))
        self.btnExpPublic.clicked.connect(lambda: self.export(False))
        self.btnEdit.clicked.connect(self.edit)
        self.btnDelete.clicked.connect(self.delete)
        self.btnDecrypt.clicked.connect(self.decrypt)
        self.btnSelect.clicked.connect(self.select)

        key = self.key
        self.tbCreationDate.setText(timestampToString(key.timestamp))
        self.tbEmail.setText(key.email)
        self.tbId.setText(str(key.id))
        self.tbAlgo.setText(algorithmSetToString(key.algorithm))
        self.tbKeySize.setText(str(key.keySize()))
        pk = ''
        for k in key.publicKey.keys():
            v = key.publicKey[k]
            pk += f'{k:2}: {v}\n'
        self.textPublic.setPlainText(pk)
        if private:
            self.tbName.setText(key.name)
            self.textPrivate.setPlainText(key.privateKey)
        
    def export(self, private: bool):
        title = 'Export private key' if private else 'Export public key'
        fname = QFileDialog.getSaveFileName(self, title, '.', 'Pem files (*.pem)', 'Pem files (*.pem)')[0]
        if fname != '':
            if private:
                self.key.exportPrivate(fname)
            else:
                self.key.exportPublic(fname)

    def edit(self):
        if self.editing:
            self.tbEmail.setReadOnly(True)
            self.tbName.setReadOnly(True)
            self.btnEdit.setText('Edit')
            self.editing = False
            self.key.email = self.tbEmail.text()
            if self.key.isPrivate():
                self.key.name = self.tbName.text()
            self.keyRing.save()
        else:
            self.tbEmail.setReadOnly(False)
            self.tbName.setReadOnly(False)
            self.btnEdit.setText('Save')
            self.editing = True

    def delete(self):
        self.keyRing.delete(self.key.id)
        self.close()

    def decrypt(self):
        while True:
            password = passwordDialog.PasswordDialog.launch(self.key, self)
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
            except Exception as ex:
                error(ex)

    def select(self):
        self.selected = self.key
        self.close()

    @staticmethod
    def launch(key: PublicKey, keyRing: KeyRing = None, select: bool = False, parent = None):
        kdet = KeyDetails(key, keyRing, select, parent)
        kdet.exec()
        return kdet.selected