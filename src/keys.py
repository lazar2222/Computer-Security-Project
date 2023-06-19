import time
import json
import hashlib
import base64
import random
from abc import ABC, abstractclassmethod

PATCH = True

if PATCH:
    import Cryptodome.Math.Primality
    Cryptodome.Math.Primality.generate_probable_safe_prime = Cryptodome.Math.Primality.generate_probable_prime

from cryptography.hazmat.primitives import serialization, padding
from cryptography.hazmat.primitives.asymmetric import rsa, dsa
from cryptography.hazmat.primitives.asymmetric import padding as aspad
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.utils import Prehashed
from cryptography.exceptions import InvalidSignature
from Cryptodome.Cipher import CAST
from Cryptodome.PublicKey import ElGamal
from Cryptodome.Random import get_random_bytes

from constants import AlgorithmSet, KeySize, MODULUS_64BIT, RSA_EXPONENT
from exceptions import InvalidPemFile, InvalidAlgorithm, WrongPassword, InvalidKeySize

class PublicKey(ABC):
    
    ALGORITHM_MAP = {}

    def __init__(self, timestamp: int, id: int, publicKey: dict, email: str, algorithm: AlgorithmSet):
        self.timestamp = timestamp
        self.id = id
        self.publicKey = publicKey
        self.email = email
        self.algorithm = algorithm

    @staticmethod
    def importPublic(fname: str):
        f = open(fname, 'r')
        str = f.read()
        f.close()
        index = str.find('\n-----END PUBLIC KEY-----\n')
        if index == -1:
            raise InvalidPemFile('Not an PUBLIC KEY pem file.')
        key = serialization.load_pem_public_key(str.encode())
        rem = str[index + len('\n-----END PUBLIC KEY-----\n'):].split('\n')
        pars = {}
        for par in rem:
            index = par.find(':')
            if index != -1:
                first = par[:index].strip()
                second = par[index+1:].strip()
                pars[first] = second
        try:
            keyClass = PublicKey.ALGORITHM_MAP[AlgorithmSet(int(pars['algorithm']))]
            dict = keyClass.toDict(key, pars)
            return keyClass(int(pars['timestamp']), int(pars['id']), dict, pars['email'])
        except:
            raise InvalidPemFile('Failed to parse metadata.')
        
    @staticmethod
    def fromDict(dict: dict):
        keyClass = PublicKey.ALGORITHM_MAP[AlgorithmSet(int(dict['algorithm']))]
        return keyClass(dict['timestamp'], dict['id'], dict['publicKey'], dict['email'])

    @abstractclassmethod
    def toPublicSigningObject(self):
        pass

    @abstractclassmethod
    def toPublicEncryptionObject(self):
        pass

    @abstractclassmethod
    def verify(self, signature: bytes, digest: bytes):
        pass

    @abstractclassmethod
    def encrypt(self, data: bytes):
        pass

    def exportPublic(self, fname: str):
        file = self.toPublicSigningObject().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode()
        file += self.additionalMetadata()
        file += f'timestamp: {self.timestamp}\n'
        file += f'id: {self.id}\n'
        file += f'algorithm: {self.algorithm}\n'
        file += f'email: {self.email}\n'
        f = open(fname, 'w')
        f.write(file)
        f.close()

    def additionalMetadata(self):
        return ''
    
    def toSerializable(self):
        return {'timestamp': self.timestamp, 'id': self.id, 'email': self.email, 'algorithm': self.algorithm, 'publicKey': self.publicKey}
    
    def isPrivate(self):
        return False
    
    def keySize(self):
        obj = self.toPublicSigningObject()
        return obj.key_size
    
    def __repr__(self):
        return f'Email: {self.email}, id: {self.id},'

class RSAPublicKey(PublicKey):
    
    def __init__(self, timestamp: int, id: int, publicKey: dict, email: str):
        PublicKey.__init__(self, timestamp, id, publicKey, email, AlgorithmSet.RSA)

    @staticmethod
    def toDict(object: rsa.RSAPublicKey, meta = None):
        dict = {}
        dict['n'] = object.public_numbers().n
        dict['e'] = object.public_numbers().e
        return dict

    def toPublicSigningObject(self):
        return rsa.RSAPublicNumbers(self.publicKey['e'], self.publicKey['n']).public_key()

    def toPublicEncryptionObject(self):
        return self.toPublicSigningObject()

    def verify(self, signature: bytes, digest: bytes):
        keyObject = self.toPublicSigningObject()
        try:
            keyObject.verify(signature, digest, padding = aspad.PSS(aspad.MGF1(hashes.SHA1()), aspad.PSS.MAX_LENGTH), algorithm = Prehashed(hashes.SHA1()))
            return True
        except InvalidSignature:
            return False
        
    def encrypt(self, data: bytes):
        keyObject = self.toPublicEncryptionObject()
        return keyObject.encrypt(data, aspad.PKCS1v15())
        
class DSAEGPublicKey(PublicKey):
    
    def __init__(self, timestamp: int, id: int, publicKey: dict, email: str):
        PublicKey.__init__(self, timestamp, id, publicKey, email, AlgorithmSet.DSA_ELGAMAL)

    @staticmethod
    def toDict(object1: dsa.DSAPublicKey, object2: ElGamal.ElGamalKey | dict):
        dict = {}
        dict['p'] = object1.public_numbers().parameter_numbers.p
        dict['q'] = object1.public_numbers().parameter_numbers.q
        dict['g'] = object1.public_numbers().parameter_numbers.g
        dict['y'] = object1.public_numbers().y
        if type(object2) is not ElGamal.ElGamalKey:
            dict['ep'] = int(object2['ep'])
            dict['eg'] = int(object2['eg'])
            dict['ey'] = int(object2['ey'])
        else:
            dict['ep'] = object2.p._value
            dict['eg'] = object2.g._value
            dict['ey'] = object2.y._value
        return dict

    def toPublicSigningObject(self):
        parameterNumbers = dsa.DSAParameterNumbers(self.publicKey['p'], self.publicKey['q'], self.publicKey['g'])
        return dsa.DSAPublicNumbers(self.publicKey['y'], parameterNumbers).public_key()

    def toPublicEncryptionObject(self):
        return ElGamal.construct((self.publicKey['ep'], self.publicKey['eg'], self.publicKey['ey']))

    def additionalMetadata(self):
        file = f'ep: {self.publicKey["ep"]}\n'
        file += f'eg: {self.publicKey["eg"]}\n'
        file += f'ey: {self.publicKey["ey"]}\n'
        return file

    def verify(self, signature: bytes, digest: bytes):
        keyObject = self.toPublicSigningObject()
        try:
            keyObject.verify(signature, digest, algorithm = Prehashed(hashes.SHA1()))
            return True
        except InvalidSignature:
            return False  
    
    def encrypt(self, data: bytes):
        keyObject = self.toPublicEncryptionObject()
        msg = int.from_bytes(data, 'big')
        encryptedData = keyObject._encrypt(msg, random.randint(1, keyObject.p-1))
        bytes1 = int.to_bytes(encryptedData[0], 256, 'big')
        bytes2 = int.to_bytes(encryptedData[1], 256, 'big')
        return bytes1 + bytes2

class PrivateKey (PublicKey):

    ALGORITHM_MAP = {}

    def __init__(self, timestamp: int, id: int, publicKey: dict, privateKey: str, email: str, algorithm: AlgorithmSet, name: str):
        PublicKey.__init__(self, timestamp, id, publicKey, email, algorithm)
        self.privateKey = privateKey
        self.name = name

    @staticmethod
    def generateKey(name: str, email: str, algorithm: AlgorithmSet, size: KeySize, password:str):
        if algorithm in PrivateKey.ALGORITHM_MAP:
            return PrivateKey.ALGORITHM_MAP[algorithm].generateKey(name, email, size, password)
        else:
            raise InvalidAlgorithm('Only RSA and DSA/ElGamal are supported for key generation.')

    @staticmethod
    def encryptKey(key: dict, password: str):
        key = json.dumps(key).encode()
        castKey = hashlib.sha1()
        castKey.update(password.encode())
        castKey = castKey.digest()
        castKey = castKey[:16]
        castAlgo = CAST.new(castKey, CAST.MODE_ECB)
        padder = padding.PKCS7(128).padder()
        key = padder.update(key) + padder.finalize()
        key = castAlgo.encrypt(key)
        return base64.b64encode(key).decode()
    
    @staticmethod
    def importPrivate(fname: str):
        f = open(fname, 'r')
        str = f.read()
        f.close()
        index = str.find('\n-----END ENCRYPTED PRIVATE KEY-----\n')
        if index == -1:
            raise InvalidPemFile('Not an ENCRYPTED PRIVATE KEY pem file.')
        pem = str[len('-----BEGIN ENCRYPTED PRIVATE KEY-----\n'):index].replace('\n','')
        rem = str[index + len('\n-----END ENCRYPTED PRIVATE KEY-----\n'):].split('\n')
        pars = {}
        for par in rem:
            index = par.find(':')
            if index != -1:
                first = par[:index].strip()
                second = par[index+1:].strip()
                pars[first] = second
        try:
            keyClass = PrivateKey.ALGORITHM_MAP[AlgorithmSet(int(pars['algorithm']))]
            return keyClass(int(pars['timestamp']), int(pars['id']), json.loads(pars['publicKey']), pem, pars['email'], pars['name'])
        except:
            raise InvalidPemFile('Failed to parse metadata.')
    
    @staticmethod
    def fromDict(dict: dict):
        keyClass = PrivateKey.ALGORITHM_MAP[AlgorithmSet(int(dict['algorithm']))]
        return keyClass(dict['timestamp'], dict['id'], dict['publicKey'], dict['privateKey'], dict['email'], dict['name'])

    @abstractclassmethod
    def toPrivateSigningObject(self, password: str):
        pass

    @abstractclassmethod
    def toPrivateEncryptionObject(self, password: str):
        pass

    @abstractclassmethod
    def sign(self, password: str, digest: bytes):
        pass

    @abstractclassmethod
    def decrypt(self, password: str, data: bytes):
        pass

    def exportPrivate(self, fname: str):
        file = '-----BEGIN ENCRYPTED PRIVATE KEY-----\n'
        file += '\n'.join(self.privateKey[i:i+64] for i in range(0, len(self.privateKey), 64))
        file += '\n-----END ENCRYPTED PRIVATE KEY-----\n'
        file += f'timestamp: {self.timestamp}\n'
        file += f'id: {self.id}\n'
        file += f'algorithm: {self.algorithm}\n'
        file += f'publicKey: {json.dumps(self.publicKey)}\n'
        file += f'email: {self.email}\n'
        file += f'name: {self.name}\n'
        f = open(fname, 'w')
        f.write(file)
        f.close()

    def decryptKey(self, password: str):
        key = base64.b64decode(self.privateKey.encode())
        castKey = hashlib.sha1()
        castKey.update(password.encode())
        castKey = castKey.digest()
        castKey = castKey[:16]
        castAlgo = CAST.new(castKey, CAST.MODE_ECB)
        try:
            key = castAlgo.decrypt(key)
            unpadder = padding.PKCS7(128).unpadder()
            key = unpadder.update(key) + unpadder.finalize()
            key = json.loads(key.decode())
            return key
        except:
            raise WrongPassword('Wrong password or corrupted private key.')
        
    def toSerializable(self):
        dict = PublicKey.toSerializable(self)
        dict['privateKey'] = self.privateKey
        dict['name'] = self.name
        return dict
    
    def isPrivate(self):
        return True
    
    def __repr__(self):
        return f'Name: {self.name}, Email: {self.email}, Id: {self.id}'

class RSAPrivateKey(PrivateKey, RSAPublicKey):

    def __init__(self, timestamp: int, id: int, publicKey: dict, privateKey: str, email: str, name: str):
        PrivateKey.__init__(self, timestamp, id, publicKey, privateKey, email, AlgorithmSet.RSA, name)

    @staticmethod
    def generateKey(name: str, email: str, size: KeySize, password:str):
        if size != KeySize.KS_1024 and size != KeySize.KS_2048:
            raise InvalidKeySize('Key size must be 1024 or 2048 bits.')
        timestamp = int(time.time())
        key = rsa.generate_private_key(RSA_EXPONENT, size)
        id = key.public_key().public_numbers().n % MODULUS_64BIT
        publicKey = RSAPublicKey.toDict(key.public_key())
        privateKey = PrivateKey.encryptKey(RSAPrivateKey.toDict(key), password)
        return RSAPrivateKey(timestamp, id, publicKey, privateKey, email, name)

    @staticmethod
    def toDict(object: rsa.RSAPrivateKey, meta = None):
        dict = {}
        dict['p'] = object.private_numbers().p
        dict['q'] = object.private_numbers().q
        dict['d'] = object.private_numbers().d
        dict['dmp1'] = object.private_numbers().dmp1
        dict['dmq1'] = object.private_numbers().dmq1
        dict['iqmp'] = object.private_numbers().iqmp
        return dict

    def toPrivateSigningObject(self, password: str):
        public = self.toPublicSigningObject().public_numbers()
        private = self.decryptKey(password)
        private = rsa.RSAPrivateNumbers(private['p'], private['q'], private['d'], private['dmp1'], private['dmq1'], private['iqmp'], public)
        return private.private_key()

    def toPrivateEncryptionObject(self, password: str):
        return self.toPrivateSigningObject(password)

    def sign(self, password: str, digest: bytes):
        keyObject = self.toPrivateSigningObject(password)
        return keyObject.sign(digest, padding = aspad.PSS(aspad.MGF1(hashes.SHA1()), aspad.PSS.MAX_LENGTH), algorithm = Prehashed(hashes.SHA1()))
    
    def decrypt(self, password: str, data: bytes):
        keyObject = self.toPrivateEncryptionObject(password)
        return keyObject.decrypt(data, aspad.PKCS1v15())

class DSAEGPrivateKey(PrivateKey, DSAEGPublicKey):

    def __init__(self, timestamp: int, id: int, publicKey: dict, privateKey: str, email: str, name: str):
        PrivateKey.__init__(self, timestamp, id, publicKey, privateKey, email, AlgorithmSet.DSA_ELGAMAL, name)

    @staticmethod
    def generateKey(name: str, email: str, size: KeySize, password:str):
        if size != KeySize.KS_1024 and size != KeySize.KS_2048:
            raise InvalidKeySize('Key size must be 1024 or 2048 bits.')
        timestamp = int(time.time())
        key1 = dsa.generate_private_key(size)
        key2 = ElGamal.generate(size, get_random_bytes)
        id = key1.public_key().public_numbers().y % MODULUS_64BIT
        publicKey = DSAEGPublicKey.toDict(key1.public_key(), key2.publickey())
        privateKey = PrivateKey.encryptKey(DSAEGPrivateKey.toDict(key1, key2), password)
        return DSAEGPrivateKey(timestamp, id, publicKey, privateKey, email, name)

    @staticmethod
    def toDict(object1: dsa.DSAPrivateKey, object2: ElGamal.ElGamalKey | dict):
        dict = {}
        dict['x'] = object1.private_numbers().x
        dict['ex'] = object2.x._value
        return dict

    def toPrivateSigningObject(self, password: str):
        public = self.toPublicSigningObject().public_numbers()
        private = self.decryptKey(password)
        private = dsa.DSAPrivateNumbers(private['x'], public)
        return private.private_key()

    def toPrivateEncryptionObject(self, password: str):
        public = self.toPublicEncryptionObject()
        private = self.decryptKey(password)
        private = ElGamal.construct((public.p._value, public.g._value, public.y._value, private['ex']))
        return private

    def sign(self, password: str, digest: bytes):
        keyObject = self.toPrivateSigningObject(password)
        return keyObject.sign(digest, algorithm = Prehashed(hashes.SHA1()))

    def decrypt(self, password: str, data: bytes):
        keyObject = self.toPrivateEncryptionObject(password)
        bytes1 = data[:256]
        bytes2 = data[256:]
        int1 = int.from_bytes(bytes1,'big')
        int2 = int.from_bytes(bytes2,'big')
        decryptedData = keyObject._decrypt((int1, int2))
        return int.to_bytes(decryptedData, 16, 'big')

PublicKey.ALGORITHM_MAP = {AlgorithmSet.RSA: RSAPublicKey, AlgorithmSet.DSA_ELGAMAL: DSAEGPublicKey}
PrivateKey.ALGORITHM_MAP = {AlgorithmSet.RSA: RSAPrivateKey, AlgorithmSet.DSA_ELGAMAL: DSAEGPrivateKey}