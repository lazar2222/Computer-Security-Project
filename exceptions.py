import sys
import traceback
from PyQt5.QtWidgets import QMessageBox

class InvalidAlgorithm(Exception):
    pass

class InvalidKeySize(Exception):
    pass

class InvalidPemFile(Exception):
    pass

class WrongPassword(Exception):
    pass

class DuplicateKey(Exception):
    pass

class NoKeys(Exception):
    pass

class MultipleKeys(Exception):
    pass

class InvalidKeyType(Exception):
    pass

def criticalError (exception: Exception):
    msg = QMessageBox()
    msg.setIcon(QMessageBox.Icon.Critical)
    msg.setWindowTitle('Critical error')
    msg.setText('A critical error has occurred.')
    if(exception.args != None):
        print = [str(d) for d in exception.args]
        msg.setInformativeText('\n'.join(print))
    msg.setDetailedText(''.join(traceback.format_exception(exception)))
    msg.exec()
    sys.exit(-1)