import os

from PyQt5.QtWidgets import QDialog, QFileDialog
from PyQt5.uic import loadUi

from constants import timestampToString, algorithmSetToString
from exceptions import error

import ui.keyDetails as keyDetails
import ui.passwordDialog as passwordDialog

class MessageDetails(QDialog):

    def __init__(self, application, fname, message, parent = None):
        super().__init__(parent)
        loadUi('src/ui/design/mdet.ui', self)
        self.application = application
        self.fname = fname
        self.message = message
        self.setupUi()

    def setupUi(self):
        self.label.setText(f'Message details: {os.path.basename(self.fname)}')
        message, bodyInfo,  header, encInfo, authInfo = self.message
        filename, timestamp, body = bodyInfo 
        sign, compress, encrypt, compat = header
        id, algo, key, status = encInfo
        authTimestamp, authId, authKey, authStatus = authInfo
        
        self.gbCompat.setTitle('Email compatibility: Enabled' if compat else 'Email compatibility: Disabled')
        self.gbEnc.setTitle('Encryption: Enabled' if encrypt else 'Encryption: Disabled')
        self.gbComp.setTitle('Compression: Enabled' if compress else 'Compression: Disabled')
        self.gbAuth.setTitle('Authentication: Enabled' if sign else 'Authentication: Disabled')
        self.gbCompat.setEnabled(compat)
        self.gbEnc.setEnabled(encrypt)
        self.gbComp.setEnabled(compress)
        self.gbAuth.setEnabled(sign)
        self.gbMsg.setEnabled(True)

        self.btnDet.clicked.connect(lambda: keyDetails.KeyDetails.launch(key, None, False, self))
        self.btnADet.clicked.connect(lambda: keyDetails.KeyDetails.launch(authKey, None, False, self))
        self.btnDec.clicked.connect(self.decrypt)
        self.btnPreview.clicked.connect(self.preview)
        self.btnSave.clicked.connect(self.save)

        if encrypt:
            self.lKeyId.setText(str(key) if key != None else str(id))
            self.lAlgo.setText(algorithmSetToString(algo))
            self.lEncStatus.setText(status)
            self.btnDet.setEnabled(key != None)
            self.btnDec.setEnabled(key != None and status != 'Ok')
            if status != 'Ok':
                self.gbAuth.setEnabled(False)
                self.gbMsg.setEnabled(False)
                return
        
        if sign:
            self.lAKey.setText(str(authKey) if authKey != None else str(authId))
            self.lTimestamp.setText(timestampToString(authTimestamp))
            self.lAuthStatus.setText(authStatus)
            self.btnADet.setEnabled(authKey != None)

        self.lMTimestamp.setText(timestampToString(timestamp))
        self.lMFilename.setText(filename)

    def decrypt(self):
        message, bodyInfo,  header, encInfo, authInfo = self.message
        id, algo, key, status = encInfo
        while True:
            password = passwordDialog.PasswordDialog.launch(key, self)
            if password == None:
                return
            try:
                key.decryptKey(password)
                msg = self.application.receive(self.fname, password)
                self.message = msg
                self.setupUi()
                return
            except Exception as ex:
                error(ex)

    def preview(self):
        message, bodyInfo,  header, encInfo, authInfo = self.message
        filename, timestamp, body = bodyInfo
        try:
            body = body.decode()
        except:
            error(Exception('Cannot preview the contents of the message as text.'))
            return
        self.plainTextEdit.setPlainText(body)
    

    def save(self):
        message, bodyInfo,  header, encInfo, authInfo = self.message
        fname = QFileDialog.getExistingDirectory(self, 'Chose a directory to save file to', '.')
        if fname != '':
            self.application.save(message, fname)

    @staticmethod
    def launch(application , parent = None):
        fname = QFileDialog.getOpenFileName(parent, 'Open message', '.', 'PGP files (*.pgp)', 'PGP files (*.pgp)')[0]
        if fname != '':
            msg = application.receive(fname)
            MessageDetails(application, fname, msg, parent).exec()