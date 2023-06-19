import os
from PyQt5.QtWidgets import QDialog, QFileDialog
from PyQt5.uic import loadUi

from constants import AlgorithmSet
from exceptions import error

import ui.passwordDialog as passwordDialog
import ui.keyRingManager as keyRingManager

class SendMessage(QDialog):

    def __init__(self, application, parent = None):
        super().__init__(parent)
        loadUi('src/ui/design/send.ui', self)
        self.application = application
        self.source = 0
        self.fname = None
        self.privateKey = None
        self.publicKey = None
        self.setupUi()

    def setupUi(self):
        self.sourceTab.currentChanged.connect(self.changeSource)
        self.btnFile.clicked.connect(self.browseFile)
        self.btnPriv.clicked.connect(lambda: self.browseKey(True))
        self.btnPub.clicked.connect(lambda: self.browseKey(False))
        self.btnSend.clicked.connect(self.send)

    def changeSource(self, index: int):
        self.source = index
        self.lSource.setText('From: Text' if index == 0 else 'From: File')

    def browseFile(self):
        fname = QFileDialog.getOpenFileName(self, 'Open file to send', '.', 'All files (*.*)', 'All files (*.*)')[0]
        if fname != '':
            self.fname = fname
            self.lPath.setText(fname)

    def browseKey(self, private: bool):
        keyRing = self.application.privateKeyRing if private else self.application.publicKeyRing
        key = keyRingManager.KeyRingManager.launch(keyRing, True, self)
        if key != None:
            if private:
                self.privateKey = key
                self.lPriv.setText(str(key))
            else:
                self.publicKey = key
                self.lPub.setText(str(key))

    def send(self):
        if self.source == 0:
            text = self.tbText.toPlainText()
            if text == '':
                error(ValueError('Message text must not be empty.'))
                return
        else:
            if self.fname == None or not os.path.exists(self.fname):
                error(ValueError('Message file must exist.'))
                return
        if self.gbAuth.isChecked() and self.privateKey == None:
            error(ValueError('If authentication is enabled, a private key must be selected.'))
            return
        if self.gbEnc.isChecked() and self.publicKey == None:
            error(ValueError('If encryption is enabled, a public key must be selected.'))
            return
        if self.gbAuth.isChecked():
            while True:
                password = passwordDialog.PasswordDialog.launch(self.privateKey, self)
                if password == None:
                    return
                try:
                    self.privateKey.decryptKey(password)
                    break
                except Exception as ex:
                    error(ex)
        fname = QFileDialog.getSaveFileName(self, 'Save output file', '.', 'PGP files (*.pgp)', 'PGP files (*.pgp)')[0]
        if fname != '':
            try:
                self.application.send(
                    text = text if self.source == 0 else None,
                    fname = self.fname if self.source != 0 else None,
                    privateKey = self.privateKey if self.gbAuth.isChecked() else None,
                    password = password if self.gbAuth.isChecked() else None,
                    compression = self.gbComp.isChecked(),
                    publicKey = self.publicKey if self.gbEnc.isChecked() else None,
                    algorithm = AlgorithmSet.AES128 if self.cbAlgo.currentIndex() == 0 else AlgorithmSet.IDEA,
                    compat = self.gbCompat.isChecked(),
                    output = fname
                )
                self.close()
            except Exception as ex:
                error(ex)

    @staticmethod
    def launch(application , parent = None):
        SendMessage(application, parent).exec()