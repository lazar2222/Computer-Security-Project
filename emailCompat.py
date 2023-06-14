import base64

class MessageEmailCompatibility:

    def encode(self, message):
        return base64.b64encode(message)
    
    def decode(self, message):
        return base64.b64decode(message)