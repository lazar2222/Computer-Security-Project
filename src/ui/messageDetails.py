from PyQt5.QtWidgets import QDialog, QFileDialog
from PyQt5.uic import loadUi

#from constants import timestampToString, algorithmSetToString
#from exceptions import error
#from keys import PublicKey
#from keyRing import KeyRing

#import ui.passwordDialog as passwordDialog

class MessageDetails(QDialog):

    def __init__(self, application, message, parent = None):
        super().__init__(parent)
        loadUi('src/ui/design/mdet.ui', self)
        self.application = application
        self.message = message
        self.setupUi()

    def setupUi(self):
        pass

    @staticmethod
    def launch(application , parent = None):
        MessageDetails(application, None, parent).exec()