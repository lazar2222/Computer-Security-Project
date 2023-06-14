import zlib

class MessageCompression:

    def compress(self, message):
        return zlib.compress(message)
    
    def decompress(self, message):
        return zlib.decompress(message)