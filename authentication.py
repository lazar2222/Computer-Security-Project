import time
import hashlib
import keyRings
import keys
import struct
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.utils import Prehashed
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.exceptions import InvalidSignature

class MessageAuthentication:

    def sign(self, message, privateKey: keys.PrivateKey, password):
        timestamp = int(time.time())
        hasher = hashlib.sha1()
        hasher.update(message)
        digest = hasher.digest()
        check = digest[:2]
        keyObject = keyRings.privateKeyObjectFromRingKey(privateKey, password)[0]
        signature = None
        match privateKey.algorithm:
            case keys.AlgorithmSet.RSA:
                signature = keyObject.sign(digest, padding=padding.PSS(padding.MGF1(hashes.SHA1()), padding.PSS.MAX_LENGTH), algorithm=Prehashed(hashes.SHA1()))
            case keys.AlgorithmSet.DSA_ELGAMAL:
                signature = keyObject.sign(digest, algorithm=Prehashed(hashes.SHA1()))
        header = struct.pack('!I', timestamp) + struct.pack('!Q',privateKey.id) + struct.pack('!H', len(signature)) + check + signature
        return header + message
    
    def verify(self, message, pukr: keyRings.PublicKeyRing):
        timestamp, id, sigLen = struct.unpack_from('!IQH', message)
        message = message[14:]
        foreignCheck = message[:2]
        message = message[2:]
        signature = message[:sigLen]
        message = message[sigLen:]

        hasher = hashlib.sha1()
        hasher.update(message)
        digest = hasher.digest()
        check = digest[:2]

        publicKey = pukr.lookup(id = id)
        if len(publicKey) != 1:
            pass
        publicKey = publicKey[0]
        keyObject = keyRings.publicKeyObjectFromRingKey(publicKey)[0]

        valid = True

        if check == foreignCheck:
            pass
        try:
            match publicKey.algorithm:
                case keys.AlgorithmSet.RSA:
                    keyObject.verify(signature, digest, padding=padding.PSS(padding.MGF1(hashes.SHA1()), padding.PSS.MAX_LENGTH), algorithm=Prehashed(hashes.SHA1()))
                case keys.AlgorithmSet.DSA_ELGAMAL:
                    keyObject.verify(signature, digest, algorithm=Prehashed(hashes.SHA1()))
        except InvalidSignature:
            valid = False

        return (message, valid)

#ma = messageAuthentication()
#ring = kr.PrivateKeyRing()
#print(ma.sign(b'Hello World',ring.lookup(name='a')[0],'asdf'))
#print(ma.sign(b'Hello World',ring.lookup(name='a')[1],'asdf'))