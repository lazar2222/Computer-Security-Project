from PyQt5.QtWidgets import QDialog
from PyQt5.uic import loadUi

from keys import PrivateKey

import ui.keyDetails as keyDetails

class PasswordDialog(QDialog):

    def __init__(self, key: PrivateKey, parent = None):
        super().__init__(parent)
        loadUi('src/ui/design/password.ui', self)
        self.key = key
        self.setupUi()

    def setupUi(self):
        key = self.key != None
        self.btnDetails.setVisible(key)
        self.tbId.setVisible(key)
        self.labelPass.setVisible(key)
        self.labelId.setVisible(key)
        self.btnDetails.clicked.connect(self.displayKeyDetails)
        if key:
            self.tbId.setText(str(self.key.id))

    def displayKeyDetails(self):
        keyDetails.KeyDetails.launch(self.key, None, False, self)

    @staticmethod
    def launch(key: PrivateKey, parent = None):
        dialog = PasswordDialog(key, parent)
        ret = dialog.exec()
        return dialog.tbPassword.text() if ret == 1 else None