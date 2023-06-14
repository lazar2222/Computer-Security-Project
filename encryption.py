import keys
import keyRings
import os
import random
import struct
from cryptography.hazmat.primitives.asymmetric import padding as aspad
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

class MessageEncryption:

    KEY_SIZE = 128

    def encrypt(self, message, publicKey: keys.PublicKey, algorithm:keys.AlgorithmSet):
        sessionKey = os.urandom(16)
        encryptedSessionKey = None
        publicKeyObject = keyRings.publicKeyObjectFromRingKey(publicKey)[1]
        match publicKey.algorithm:
            case keys.AlgorithmSet.RSA:
                encryptedSessionKey = publicKeyObject.encrypt(sessionKey,aspad.PKCS1v15())
            case keys.AlgorithmSet.DSA_ELGAMAL:
                msg = int.from_bytes(sessionKey,'big')
                encryptedSessionKey = publicKeyObject._encrypt(msg,random.randint(1, publicKeyObject.p-1))
                bytes1 = int.to_bytes(encryptedSessionKey[0],256,'big')
                bytes2 = int.to_bytes(encryptedSessionKey[1],256,'big')
                encryptedSessionKey = bytes1 + bytes2
        header = struct.pack('!Q',publicKey.id) + struct.pack('!H',len(encryptedSessionKey)) + struct.pack('!B', algorithm) + encryptedSessionKey
        padder = padding.PKCS7(128).padder()
        paddedData = padder.update(message) + padder.finalize()
        cipher = None
        match algorithm:
            case keys.AlgorithmSet.AES128:
                cipher = Cipher(algorithms.AES(sessionKey), modes.ECB())
            case keys.AlgorithmSet.IDEA:
                cipher = Cipher(algorithms.IDEA(sessionKey), modes.ECB())
        message = cipher.encryptor().update(paddedData) + cipher.encryptor().finalize()

        return header + message
    
    def decrypt(self, message, password, prkr: keyRings.PrivateKeyRing):
        id, keylen, algo = struct.unpack_from('!QHB', message)
        algo = keys.AlgorithmSet(algo)
        message = message[11:]
        encryptedKey = message[:keylen]
        message = message[keylen:]

        key = prkr.lookup(id = id)
        if len(key) != 1:
            pass
        key = key[0]
        privateKeyObject = keyRings.privateKeyObjectFromRingKey(key, 'asdf')[1]

        sessionKey = None
        match key.algorithm:
            case keys.AlgorithmSet.RSA:
                sessionKey = privateKeyObject.decrypt(encryptedKey,aspad.PKCS1v15())
            case keys.AlgorithmSet.DSA_ELGAMAL:
                bytes1 = encryptedKey[:256]
                bytes2 = encryptedKey[256:]
                int1 = int.from_bytes(bytes1,'big')
                int2 = int.from_bytes(bytes2,'big')
                sessionKey = privateKeyObject._decrypt((int1, int2))
                sessionKey = int.to_bytes(sessionKey, 16, 'big')
        
        match algo:
            case keys.AlgorithmSet.AES128:
                cipher = Cipher(algorithms.AES(sessionKey), modes.ECB())
            case keys.AlgorithmSet.IDEA:
                cipher = Cipher(algorithms.IDEA(sessionKey), modes.ECB())
        message = cipher.decryptor().update(message) + cipher.decryptor().finalize()

        unpadder = padding.PKCS7(128).unpadder()
        message = unpadder.update(message) + unpadder.finalize()

        return message

#me = MessageEncryption()
#ring = kr.PublicKeyRing()
#print(me.encrypt(b'Hello World', ring.lookup(email='a')[0], ds.AlgorithmSet.AES128))
#print(me.encrypt(b'Hello World', ring.lookup(email='a')[1], ds.AlgorithmSet.AES128))
#print(me.encrypt(b'Hello World', ring.lookup(email='a')[0], ds.AlgorithmSet.IDEA))
#print(me.encrypt(b'Hello World', ring.lookup(email='a')[1], ds.AlgorithmSet.IDEA))