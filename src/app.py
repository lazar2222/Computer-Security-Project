from constants import PUBLIC_KEY_RING, PRIVATE_KEY_RING, AlgorithmSet
from exceptions import criticalError
from keys import PublicKey, PrivateKey
from keyRing import KeyRing
from message import MessageHandler

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

    def send(self, text: str, fname: str, privateKey: PrivateKey, password: str, compression: bool, publicKey: PublicKey, algorithm: AlgorithmSet, compat: bool, output: str):
        MessageHandler.send(text, fname, privateKey, password, compression, publicKey, algorithm, compat, output)

    def receive(self, path: str = None, password: str = None):
        return MessageHandler.receive(path, password, self.privateKeyRing, self.publicKeyRing)
    
    def save(self, message: bytes, path: str):
        MessageHandler.toFile(message, path)

if __name__ == '__main__':
    try:
        app = Application()
        app.launchGui()
    except Exception as ex:
        criticalError(ex)