import base64

class MessageEmailCompatibility:

    @staticmethod
    def encode(message):
        return base64.b64encode(message)
    
    @staticmethod
    def decode(message):
        return base64.b64decode(message)