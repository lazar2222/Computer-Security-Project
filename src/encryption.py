import os
import struct
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from constants import AlgorithmSet
from exceptions import InvalidAlgorithm, NoKeys, MultipleKeys
from keys import PublicKey
from keyRing import KeyRing

class MessageEncryption:

    @staticmethod
    def encrypt(message: bytes, publicKey: PublicKey, algorithm: AlgorithmSet):
        if algorithm != AlgorithmSet.AES128 and algorithm != AlgorithmSet.IDEA:
            raise InvalidAlgorithm('Only AES and IDEA are supported for message encryption.')
        
        sessionKey = os.urandom(16)
        encryptedSessionKey = publicKey.encrypt(sessionKey)

        padder = padding.PKCS7(128).padder()
        paddedData = padder.update(message) + padder.finalize()

        cipher = None
        match algorithm:
            case AlgorithmSet.AES128:
                cipher = Cipher(algorithms.AES(sessionKey), modes.ECB())
            case AlgorithmSet.IDEA:
                cipher = Cipher(algorithms.IDEA(sessionKey), modes.ECB())
        message = cipher.encryptor().update(paddedData) + cipher.encryptor().finalize()

        header = struct.pack('!QHB', publicKey.id, len(encryptedSessionKey), algorithm) + encryptedSessionKey
        
        return header + message
    
    @staticmethod
    def decrypt(message: bytes, password: str, primary: KeyRing):
        id, keyLen, algo = struct.unpack_from('!QHB', message)
        algo = AlgorithmSet(algo)
        message = message[11:]
        encryptedKey = message[:keyLen]
        message = message[keyLen:]
        
        key = None
        try:
            key = primary.lookup(id = id)
        except MultipleKeys:
            return (message, (id, algo, None, 'Unable to decrypt, there are multiple private keys with matching id.'))
        except NoKeys:
            return (message, (id, algo, None, 'Unable to decrypt, there are no keys with matching id.'))

        if password == None:
            return (message, (id, algo, key, 'Unable to decrypt, no password provided.'))

        sessionKey = key.decrypt(password, encryptedKey)

        match algo:
            case AlgorithmSet.AES128:
                cipher = Cipher(algorithms.AES(sessionKey), modes.ECB())
            case AlgorithmSet.IDEA:
                cipher = Cipher(algorithms.IDEA(sessionKey), modes.ECB())
        message = cipher.decryptor().update(message) + cipher.decryptor().finalize()

        unpadder = padding.PKCS7(128).unpadder()
        message = unpadder.update(message) + unpadder.finalize()

        return (message, (id, algo, key, 'Ok'))