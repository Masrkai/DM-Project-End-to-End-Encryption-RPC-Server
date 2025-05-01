# message.py - Message classes
import json

class Message:
    """Base class for all message types"""
    def __init__(self, msg_type):
        self.type = msg_type

    def to_json(self):
        return json.dumps(self.__dict__)

    @classmethod
    def from_json(cls, json_data):
        if isinstance(json_data, str):
            data = json.loads(json_data)
        else:
            data = json_data
        return cls(**data)


class RegistrationMessage(Message):
    def __init__(self, username, public_key):
        super().__init__("registration")
        self.username = username
        self.public_key = public_key


class StatusMessage(Message):
    def __init__(self, status, message):
        super().__init__("status")
        self.status = status
        self.message = message


class UserListMessage(Message):
    def __init__(self, users):
        super().__init__("user_list")
        self.users = users


class ChatMessage(Message):
    def __init__(self, sender, recipient, encrypted_message, encrypted_key, nonce):
        super().__init__("message")
        self.sender = sender
        self.recipient = recipient
        self.encrypted_message = encrypted_message
        self.encrypted_key = encrypted_key
        self.nonce = nonce


class ErrorMessage(Message):
    def __init__(self, message):
        super().__init__("error")
        self.message = message


class KeyRequestMessage(Message):
    def __init__(self, username):
        super().__init__("key_request")
        self.username = username


class PublicKeyMessage(Message):
    def __init__(self, username, public_key):
        super().__init__("public_key")
        self.username = username
        self.public_key = public_key