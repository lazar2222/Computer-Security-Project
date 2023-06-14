import constants
import exceptions
import keys
import keyRing

class Application:

    def __init__(self):
        self.setupGlobals()

    def setupGlobals(self):
        try:
            self.privateKeyRing = keyRing.KeyRing(constants.PRIVATE_KEY_RING, keys.PrivateKey)
            self.publicKeyRing = keyRing.KeyRing(constants.PUBLIC_KEY_RING, keys.PublicKey)
        except:
            exceptions.criticalError(Exception('Error loading key rings.'))