import zlib

class MessageCompression:

    @staticmethod
    def compress(message):
        return zlib.compress(message)
    
    @staticmethod
    def decompress(message):
        return zlib.decompress(message)