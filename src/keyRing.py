import os
import json

from exceptions import InvalidKeyType, DuplicateKey, NoKeys, MultipleKeys
from keys import PublicKey, PrivateKey

class KeyRing:

    def __init__(self, fname: str, parentClass):
        self.fname = fname
        self.keys = []
        self.parentClass = parentClass
        if os.path.exists(self.fname):
            file = open(self.fname, 'r')
            self.keys = json.load(file)
            file.close()
        for i in range(len(self.keys)):
            self.keys[i] = parentClass.fromDict(self.keys[i])

    def save(self):
        res = []
        for key in self.keys:
            res.append(key.toSerializable())
        file = open(self.fname, 'w')
        json.dump(res, file)
        file.close()

    def insert(self, key: PublicKey):
        if type(key) != self.parentClass:
            if self.parentClass == PrivateKey:
                raise InvalidKeyType('Trying to insert public key into private ring.')
            else:
                raise InvalidKeyType('Trying to insert private key into public ring.')
        collision = list(filter(lambda x: x.id == key.id, self.keys))
        if len(collision) > 0:
            if collision[0].toSerializable() == key.toSerializable():
                raise DuplicateKey('Same key already exists.')
            else:
                raise DuplicateKey('Different key with same id already exists.')
        self.keys.append(key)
        self.save()

    def lookup(self, id: int = None, email: str = None, name: str = None):
        result = []
        if id != None:
            result += list(filter(lambda x: x.id == id, self.keys))
        if email != None:
            result += list(filter(lambda x: x.email == email, self.keys))
        if name != None:
            result += list(filter(lambda x: x.name == name, self.keys))
        if len(result) == 0:
            raise NoKeys('No keys match given criteria.')
        if len(result) != 1:
            raise MultipleKeys('Multiple keys match given criteria.')
        return result[0]

    def delete(self, id:int):
        self.keys = list(filter(lambda x: x.id != id, self.keys))

    def isPrivate(self):
        return self.parentClass == PrivateKey

#prKr = KeyRing('private.kr0', keys.PrivateKey)
#puKr = KeyRing('public.kr0', keys.PublicKey)

#print()
#print(*prKr.keys, sep='\n')  
#print()
#print(*puKr.keys, sep='\n')  

#import constants
#prKr.insert(keys.PrivateKey.generateKey('RSAname','RSA@a.b',constants.AlgorithmSet.RSA, constants.KeySize.KS_1024, 'asdf'))
#prKr.insert(keys.PrivateKey.generateKey('DSAname','DSA@a.b',constants.AlgorithmSet.DSA_ELGAMAL, constants.KeySize.KS_1024, 'asdf'))

#print()
#print(*prKr.keys, sep='\n')  
#print()
#print(*puKr.keys, sep='\n')  

#for key in prKr.keys:
#    key.exportPrivate(str(key.id) + '.pem')
#    key.exportPublic('public' + str(key.id) + '.pem')

#for key in puKr.keys:
#    key.exportPublic('public' + str(key.id) + '.rem')

#import os
#import traceback
#files = os.listdir('.')
#files = [file for file in files if file.endswith('.pem')]
#for file in files:
#    try:
#        if('public' in file):
#            puKr.insert(keys.PublicKey.importPublic(file))
#        else:
#            prKr.insert(keys.PrivateKey.importPrivate(file))
#    except:
#        traceback.print_exc()

#print()
#print(*prKr.keys, sep='\n')  
#print()
#print(*puKr.keys, sep='\n')  














#pkr = PrivateKeyRing()
#3pkr.generate('a','a',ds.AlgorithmSet.RSA,ds.KeySize.KS_1024, 'asdf')
#pkr.generate('a','a',ds.AlgorithmSet.DSA_ELGAMAL,ds.KeySize.KS_1024, 'asdf')