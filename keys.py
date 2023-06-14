import time
import json
import hashlib
import base64
from abc import ABC, abstractclassmethod

from cryptography.hazmat.primitives import serialization, padding
from cryptography.hazmat.primitives.asymmetric import rsa, dsa
from Cryptodome.Cipher import CAST
from Cryptodome.PublicKey import ElGamal
from Cryptodome.Random import get_random_bytes

import constants
import exceptions

class PublicKey(ABC):
    
    ALGORITHM_MAP = {}

    def __init__(self, timestamp: int, id: int, publicKey: dict, email: str, algorithm: constants.AlgorithmSet):
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
            raise exceptions.InvalidPemFile('Not an PUBLIC KEY pem file.')
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
            keyClass = PublicKey.ALGORITHM_MAP[constants.AlgorithmSet(int(pars['algorithm']))]
            dict = keyClass.toDict(key, pars)
            return keyClass(int(pars['timestamp']), int(pars['id']), dict, pars['email'])
        except:
            raise exceptions.InvalidPemFile('Failed to parse metadata.')
        
    @staticmethod
    def fromDict(dict: dict):
        keyClass = PublicKey.ALGORITHM_MAP[constants.AlgorithmSet(int(dict['algorithm']))]
        return keyClass(dict['timestamp'], dict['id'], dict['publicKey'], dict['email'])

    @abstractclassmethod
    def toPublicSigningObject(self):
        pass

    @abstractclassmethod
    def toPublicEncryptionObject(self):
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

class RSAPublicKey(PublicKey):
    
    def __init__(self, timestamp: int, id: int, publicKey: dict, email: str):
        PublicKey.__init__(self, timestamp, id, publicKey, email, constants.AlgorithmSet.RSA)

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

        
class DSAEGPublicKey(PublicKey):
    
    def __init__(self, timestamp: int, id: int, publicKey: dict, email: str):
        PublicKey.__init__(self, timestamp, id, publicKey, email, constants.AlgorithmSet.DSA_ELGAMAL)

    @staticmethod
    def toDict(object1: dsa.DSAPublicKey, object2: ElGamal.ElGamalKey | dict):
        d = {}
        d['p'] = object1.public_numbers().parameter_numbers.p
        d['q'] = object1.public_numbers().parameter_numbers.q
        d['g'] = object1.public_numbers().parameter_numbers.g
        d['y'] = object1.public_numbers().y
        if type(object2) is dict:
            d['ep'] = int(object2['ep'])
            d['eg'] = int(object2['eg'])
            d['ey'] = int(object2['ey'])
        else:
            d['ep'] = object2.p._value
            d['eg'] = object2.g._value
            d['ey'] = object2.y._value
        return d

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

class PrivateKey (PublicKey):

    ALGORITHM_MAP = {}

    def __init__(self, timestamp: int, id: int, publicKey: dict, privateKey: str, email: str, algorithm: constants.AlgorithmSet, name: str):
        PublicKey.__init__(self, timestamp, id, publicKey, email, algorithm)
        self.privateKey = privateKey
        self.name = name

    @staticmethod
    def generateKey(name: str, email: str, algorithm: constants.AlgorithmSet, size: constants.KeySize, password:str):
        if algorithm in PrivateKey.ALGORITHM_MAP:
            return PrivateKey.ALGORITHM_MAP[algorithm].generateKey(name, email, size, password)
        else:
            raise exceptions.InvalidAlgorithm('Only RSA and DSA/ElGamal are supported for key generation.')

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
            raise exceptions.InvalidPemFile('Not an ENCRYPTED PRIVATE KEY pem file.')
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
            keyClass = PrivateKey.ALGORITHM_MAP[constants.AlgorithmSet(int(pars['algorithm']))]
            return keyClass(int(pars['timestamp']), int(pars['id']), json.loads(pars['publicKey']), pem, pars['email'], pars['name'])
        except:
            raise exceptions.InvalidPemFile('Failed to parse metadata.')
    
    @staticmethod
    def fromDict(dict: dict):
        keyClass = PrivateKey.ALGORITHM_MAP[constants.AlgorithmSet(int(dict['algorithm']))]
        return keyClass(dict['timestamp'], dict['id'], dict['publicKey'], dict['privateKey'], dict['email'], dict['name'])

    @abstractclassmethod
    def toPrivateSigningObject(self, password: str):
        pass

    @abstractclassmethod
    def toPrivateEncryptionObject(self, password: str):
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
            raise exceptions.WrongPassword('Wrong password or corrupted private key.')
        
    def toSerializable(self):
        dict = PublicKey.toSerializable(self)
        dict['privateKey'] = self.privateKey
        dict['name'] = self.name
        return dict

class RSAPrivateKey(PrivateKey, RSAPublicKey):

    def __init__(self, timestamp: int, id: int, publicKey: dict, privateKey: str, email: str, name: str):
        PrivateKey.__init__(self, timestamp, id, publicKey, privateKey, email, constants.AlgorithmSet.RSA, name)

    @staticmethod
    def generateKey(name: str, email: str, size: constants.KeySize, password:str):
        if size != constants.KeySize.KS_1024 and size != constants.KeySize.KS_2048:
            raise exceptions.InvalidKeySize('Key size must be 1024 or 2048 bits.')
        timestamp = int(time.time())
        key = rsa.generate_private_key(constants.RSA_EXPONENT, size)
        id = key.public_key().public_numbers().n % constants.MODULUS_64BIT
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

class DSAEGPrivateKey(PrivateKey, DSAEGPublicKey):

    def __init__(self, timestamp: int, id: int, publicKey: dict, privateKey: str, email: str, name: str):
        PrivateKey.__init__(self, timestamp, id, publicKey, privateKey, email, constants.AlgorithmSet.DSA_ELGAMAL, name)

    @staticmethod
    def generateKey(name: str, email: str, size: constants.KeySize, password:str):
        if size != constants.KeySize.KS_1024 and size != constants.KeySize.KS_2048:
            raise exceptions.InvalidKeySize('Key size must be 1024 or 2048 bits.')
        timestamp = int(time.time())
        key1 = dsa.generate_private_key(size)
        key2 = ElGamal.generate(size, get_random_bytes)
        id = key1.public_key().public_numbers().y % constants.MODULUS_64BIT
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


PublicKey.ALGORITHM_MAP = {constants.AlgorithmSet.RSA: RSAPublicKey, constants.AlgorithmSet.DSA_ELGAMAL: DSAEGPublicKey}
PrivateKey.ALGORITHM_MAP = {constants.AlgorithmSet.RSA: RSAPrivateKey, constants.AlgorithmSet.DSA_ELGAMAL: DSAEGPrivateKey}