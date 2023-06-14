from constants import PUBLIC_KEY_RING, PRIVATE_KEY_RING
from exceptions import criticalError
from keys import PublicKey, PrivateKey
from keyRing import KeyRing

from ui.main import MainMenu

class Application:

    def __init__(self):
        self.setupGlobals()

    def setupGlobals(self):
        try:
            self.privateKeyRing = KeyRing(PRIVATE_KEY_RING, PrivateKey)
            self.publicKeyRing = KeyRing(PUBLIC_KEY_RING, PublicKey)
        except:
            criticalError(Exception('Error loading key rings.'))

    def launchGui(self):
        MainMenu.launch(self)

if __name__ == '__main__':
    try:
        app = Application()
        app.launchGui()
    except Exception as ex:
        criticalError(ex)