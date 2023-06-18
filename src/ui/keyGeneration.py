from PyQt5.QtWidgets import QDialog
from PyQt5.uic import loadUi

from constants import AlgorithmSet, KeySize
from exceptions import error
from keys import PrivateKey

import ui.passwordDialog as passwordDialog

class KeyGeneration(QDialog):

    def __init__(self, parent = None):
        super().__init__(parent)
        loadUi('src/ui/design/gen.ui', self)
        self.key = None
        self.setupUi()

    def setupUi(self):
        self.btnGenerate.clicked.connect(self.generate)
        
    def generate(self):
        name = self.tbName.text()
        email = self.tbEmail.text()
        algo = AlgorithmSet(self.cbAlgo.currentIndex()+1)
        size = KeySize((self.cbSize.currentIndex()+1)*1024)
        password = passwordDialog.PasswordDialog.launch(None, self)
        if password == None:
            return
        if password == '':
            error(Exception('Password can not be empty.'))
            return
        self.key = PrivateKey.generateKey(name, email, algo, size, password)
        self.close()

    @staticmethod
    def launch(parent = None):
        dialog = KeyGeneration(parent)
        dialog.exec()
        return dialog.key