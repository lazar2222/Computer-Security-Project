import time
import os
import struct
import authentication
import encryption
import compression
import emailCompat
import keyRings
import keys

class MessageHandler:
    
    def fromFile(self, path):
        filename = os.path.basename(path)
        timestamp = int(time.time())
        file = open(path, 'rb')
        message = filename.encode() + b'\x00' + struct.pack('!I', timestamp) + file.read()
        return message

    def fromText(self, text):
        filename = 'message.txt'
        timestamp = int(time.time())
        message = filename.encode() + b'\x00' + struct.pack('!I', timestamp) + text.encode()
        return message
    
    def fromPGP(self, path):
        file = open(path, 'rb')
        message = file.read()
        file.close()
        return message

    def toPGP(self, message, fname, base64):
        file = open(fname + ('.txt' if base64 else '.bin'), 'wb')
        file.write(message)
        file.close()

    def toFile(self, message, folder):
        dirname = os.path.dirname(folder)
        index = message.index(b'\x00')
        filename = message[:index].decode()
        message = message[index+1:]
        timestamp = struct.unpack_from('!I', message)[0]
        message = message[4:]

        dirname = os.path.join(dirname, filename)

        file = open(dirname, 'wb')
        file.write(message)
        file.close()

    def toText(self, message):
        index = message.index(b'\x00')
        filename = message[:index].decode()
        message = message[index+1:]
        timestamp = struct.unpack_from('!I', message)[0]
        message = message[4:].decode()

        return (filename, timestamp, message)

    def makeHeader(self, sign, compress, encrypt, base64):
        signByte = 'S' if sign else 's'
        compressByte = 'C' if compress else 'c'
        encryptByte = 'E' if encrypt else 'e'
        base64Byte = 'B' if base64 else 'b'

        header = signByte + compressByte + encryptByte + base64Byte
        return header.encode()

    def breakHeader(self, header: bytes):
        str = header.decode()
        sign = 'S' in str
        compress = 'C' in str
        encrypt = 'E' in str
        base64 = 'B' in str
        return (sign, compress, encrypt, base64)

    def sendPipeline(self, path = None, text = None, privateKey = None, password = None, compress = None, publicKey = None, algorithm = None, base64 = None, outPath = None):
        message = None
        if path != None:
            message = self.fromFile(path)
        else:
            message = self.fromText(text)

        if privateKey != None:
            ma = authentication.MessageAuthentication()
            message = ma.sign(message, privateKey, password)
        
        if compress != None:
            mc = compression.MessageCompression()
            message = mc.compress(message)
        
        if publicKey != None:
            me = encryption.MessageEncryption()
            message = me.encrypt(message, publicKey, algorithm)

        if base64 != None:
            mec = emailCompat.MessageEmailCompatibility()
            message = mec.encode(message)

        header = self.makeHeader(privateKey != None, compress != None, publicKey != None, base64 != None)

        message = header + message

        if outPath != None:
            self.toPGP(message, outPath, base64 != None)

    def recievePipeline(self, path = None, password = None, pukr: keyRings.PublicKeyRing = None, prkr: keyRings.PrivateKeyRing = None, savepath = None):
        message = None
        if path != None:
            message = self.fromPGP(path)
        
        header = message[:4]
        message = message[4:]

        sign, compress, encrypt, base64 = self.breakHeader(header)

        if base64:
            mec = emailCompat.MessageEmailCompatibility()
            message = mec.decode(message)

        if encrypt:
            me = encryption.MessageEncryption()
            message = me.decrypt(message, password, prkr)

        if compress:
            mc = compression.MessageCompression()
            message = mc.decompress(message)

        if sign:
            ma = authentication.MessageAuthentication()
            message, info = ma.verify(message, pukr)

        if savepath != None:
            self.toFile(message, savepath)
            
        return self.toText(message)

mh = MessageHandler()
puk = keyRings.PublicKeyRing()
prk = keyRings.PrivateKeyRing()
signOps = [None, prk.lookup(email='RSA')[0], prk.lookup(email='DSA')[0]]
compOps = [None, True]
encOps = [None, prk.lookup(email='RSA')[0], prk.lookup(email='DSA')[0]]
encAlgOps = [keys.AlgorithmSet.AES128, keys.AlgorithmSet.IDEA]
BaseOps = [None, True]
#mh.pipeline('requirements.txt', None, prk.lookup(email='RSA')[0], 'asdf', True, puk.lookup(email='RSA')[0], ds.AlgorithmSet.AES128, True, 'RSAYRSAAESY')
for sign in signOps:
    for com in compOps:
        for enc in encOps:
            for encalg in encAlgOps:
                for base in BaseOps:
                    mh.sendPipeline('requirements.txt', None, sign, 'asdf', com, enc, encalg, base, f'sign{sign.email if sign != None else None}com{com}enc{enc.email if enc != None else None}encalg{encalg}base{base}')
                    print(mh.recievePipeline(f'sign{sign.email if sign != None else None}com{com}enc{enc.email if enc != None else None}encalg{encalg}base{base}' + f'{".txt" if base != None else ".bin"}', 'asdf', puk, prk))