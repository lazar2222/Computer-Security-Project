import time
import hashlib
import struct

from exceptions import NoKeys, MultipleKeys
from keys import PrivateKey
from keyRing import KeyRing

class MessageAuthentication:

    @staticmethod
    def sign(message, privateKey: PrivateKey, password: str):
        timestamp = int(time.time())
        hasher = hashlib.sha1()
        hasher.update(message)
        digest = hasher.digest()
        check = digest[:2]

        signature = privateKey.sign(password, digest)
        
        header = struct.pack('!IQH', timestamp, privateKey.id, len(signature)) + check + signature
        return header + message
    
    @staticmethod
    def verify(message, primary: KeyRing, secondary: KeyRing):
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

        multiple = False
        zero = False
        key = None
        try:
            key = primary.lookup(id = id)
        except MultipleKeys:
            multiple = True
        except NoKeys:
            try:
                key = secondary.lookup(id = id)
            except MultipleKeys:
                multiple = True
            except NoKeys:
                zero = True
        
        preliminary = check == foreignCheck

        if key != None:
            valid = key.verify(signature, digest)

        status = 'Unknown status'

        if key != None:
            if preliminary:
                if valid:
                    status = 'The signature is valid.'
                else:
                    status = 'The signature is invalid, or the public key is corrupted.'
            else:
                if valid:
                    status = 'The signature is valid, but the public key is likely corrupted.'
                else:
                    status = 'The signature is invalid, the message has been modified.'
        else:
            if multiple:
                if preliminary:
                    status = 'The signature might be valid, but there are multiple keys with matching id.'
                else:
                    status = 'The signature is invalid, but there are multiple keys with matching id.'
            elif zero:
                if preliminary:
                    status = 'The signature might be valid, but the key cannot be found in either of the rings.'
                else:
                    status = 'The signature is invalid, but the key cannot be found in either of the rings.'
            else:
                if preliminary:
                    status = 'The signature might be valid, but there was an undefined error with the key.'
                else:
                    status = 'The signature is invalid, but there was an undefined error with the key.'

        return (message, timestamp, id, key, status)