from PyQt5.QtWidgets import QDialog
from PyQt5.uic import loadUi

from constants import timestampToString, algorithmSetToString
from exceptions import error
from keys import PublicKey
from keyRing import KeyRing

import ui.passwordDialog as passwordDialog

class KeyDetails(QDialog):

    def __init__(self, key: PublicKey, keyRing: KeyRing = None, parent = None):
        super().__init__(parent)
        loadUi('src/ui/design/kdet.ui', self)
        self.key = key
        self.keyRing = keyRing
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
        
        self.btnExpPrivate.clicked.connect(lambda: self.export(True))
        self.btnExpPublic.clicked.connect(lambda: self.export(False))
        self.btnEdit.clicked.connect(self.edit)
        self.btnDelete.clicked.connect(self.delete)
        self.btnDecrypt.clicked.connect(self.decrypt)

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
        
    def export(self, private):
        pass

    def edit(self):
        pass

    def delete(self):
        pass

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
            except:
                error('Wrong password or corrupted private key.')

    @staticmethod
    def launch(key: PublicKey, keyRing: KeyRing = None, parent = None):
        KeyDetails(key, keyRing, parent).exec()