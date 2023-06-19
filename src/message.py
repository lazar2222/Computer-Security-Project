import time
import os
import struct

from constants import AlgorithmSet
from keys import PrivateKey, PublicKey
from keyRing import KeyRing
from authentication import MessageAuthentication
from compression import MessageCompression
from encryption import MessageEncryption
from emailCompat import MessageEmailCompatibility

class MessageHandler:

    @staticmethod    
    def fromFile(path: str):
        filename = os.path.basename(path)
        timestamp = int(time.time())
        file = open(path, 'rb')
        message = filename.encode() + b'\x00' + struct.pack('!I', timestamp) + file.read()
        return message

    @staticmethod
    def fromText(text: str):
        filename = 'message.txt'
        timestamp = int(time.time())
        message = filename.encode() + b'\x00' + struct.pack('!I', timestamp) + text.encode()
        return message
    
    @staticmethod
    def fromPGP(path: str):
        file = open(path, 'rb')
        message = file.read()
        file.close()
        return message

    @staticmethod
    def toFile(message: str, folder: str):
        #dirname = os.path.dirname(folder)
        dirname = folder
        index = message.index(b'\x00')
        filename = message[:index].decode()
        message = message[index+1:]
        timestamp = struct.unpack_from('!I', message)[0]
        message = message[4:]

        dirname = os.path.join(dirname, filename)

        file = open(dirname, 'wb')
        file.write(message)
        file.close()

    @staticmethod
    def toText(message: str):
        index = message.index(b'\x00')
        filename = message[:index].decode()
        message = message[index+1:]
        timestamp = struct.unpack_from('!I', message)[0]
        message = message[4:]

        return (filename, timestamp, message)

    @staticmethod
    def toPGP(message: str, path: str):
        file = open(path, 'wb')
        file.write(message)
        file.close()

    @staticmethod
    def makeHeader(sign: bool, compress: bool, encrypt: bool, base64: bool):
        signByte = 'S' if sign else 's'
        compressByte = 'C' if compress else 'c'
        encryptByte = 'E' if encrypt else 'e'
        base64Byte = 'B' if base64 else 'b'

        header = signByte + compressByte + encryptByte + base64Byte
        return header.encode()

    @staticmethod
    def breakHeader(header: bytes):
        str = header.decode()
        sign = 'S' in str
        compress = 'C' in str
        encrypt = 'E' in str
        base64 = 'B' in str
        return (sign, compress, encrypt, base64)

    @staticmethod
    def send(text: str = None, path: str = None, privateKey: PrivateKey = None, password: str = None, compression: bool = False, publicKey: PublicKey = None, algorithm: AlgorithmSet = None, compat: bool = False, output: str = None):
        message = None
        if path != None:
            message = MessageHandler.fromFile(path)
        else:
            message = MessageHandler.fromText(text)

        if privateKey != None:
            message = MessageAuthentication.sign(message, privateKey, password)
        
        if compression:
            message = MessageCompression.compress(message)
        
        if publicKey != None:
            message = MessageEncryption.encrypt(message, publicKey, algorithm)

        if compat:
            message = MessageEmailCompatibility.encode(message)

        header = MessageHandler.makeHeader(privateKey != None, compression, publicKey != None, compat)

        message = header + message

        if output != None:
            MessageHandler.toPGP(message, output)

    @staticmethod
    def receive(path: str = None, password = None, privateKeyRing: KeyRing = None, publicKeyRing: KeyRing = None):
        message = None
        if path != None:
            message = MessageHandler.fromPGP(path)
        
        header = message[:4]
        message = message[4:]
        header = MessageHandler.breakHeader(header)
        sign, compress, encrypt, compat = header

        encInfo = (None, None, None, 'Ok')
        authInfo = (None, None, None, 'Ok')
        bodyInfo = (None, None, None)

        if compat:
            message = MessageEmailCompatibility.decode(message)

        if encrypt:
            message, encInfo = MessageEncryption.decrypt(message, password, privateKeyRing)

        if encInfo[3] != 'Ok':
            return (message, bodyInfo, header, encInfo, authInfo)

        if compress:
            message = MessageCompression.decompress(message)

        if sign:
            message, authInfo = MessageAuthentication.verify(message, publicKeyRing, privateKeyRing)

        bodyInfo = MessageHandler.toText(message)

        return (message, bodyInfo, header, encInfo, authInfo)

#mh = MessageHandler()
#puk = keyRings.PublicKeyRing()
#prk = keyRings.PrivateKeyRing()
#signOps = [None, prk.lookup(email='RSA')[0], prk.lookup(email='DSA')[0]]
#compOps = [None, True]
#encOps = [None, prk.lookup(email='RSA')[0], prk.lookup(email='DSA')[0]]
#encAlgOps = [keys.AlgorithmSet.AES128, keys.AlgorithmSet.IDEA]
#BaseOps = [None, True]
#mh.pipeline('requirements.txt', None, prk.lookup(email='RSA')[0], 'asdf', True, puk.lookup(email='RSA')[0], ds.AlgorithmSet.AES128, True, 'RSAYRSAAESY')
#for sign in signOps:
#    for com in compOps:
#        for enc in encOps:
#            for encalg in encAlgOps:
#                for base in BaseOps:
#                    mh.sendPipeline('requirements.txt', None, sign, 'asdf', com, enc, encalg, base, f'sign{sign.email if sign != None else None}com{com}enc{enc.email if enc != None else None}encalg{encalg}base{base}')
#                    print(mh.recievePipeline(f'sign{sign.email if sign != None else None}com{com}enc{enc.email if enc != None else None}encalg{encalg}base{base}' + f'{".txt" if base != None else ".bin"}', 'asdf', puk, prk))