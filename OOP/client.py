
# client.py - Client implementation
import socket
import threading
import json
from crypto import CryptoManager
from message import RegistrationMessage, ChatMessage, ErrorMessage

class ChatClient:
    def __init__(self, server_host='localhost', server_port=9090):
        self.server_host = server_host
        self.server_port = server_port
        self.socket = None
        self.username = None
        self.users = []
        self.crypto = CryptoManager()
        self.user_keys = {}  # username -> public_key
        self.running = False
        self.receive_thread = None

    def connect(self, username):
        """Connect to the server and register with username"""
        self.username = username
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        try:
            self.socket.connect((self.server_host, self.server_port))

            # Register with server
            reg_msg = RegistrationMessage(self.username, self.crypto.public_key_pem)
            self.socket.send(reg_msg.to_json().encode())

            # Check registration response
            response = json.loads(self.socket.recv(1024).decode())
            if response['status'] != 'success':
                print(f"Registration failed: {response['message']}")
                self.socket.close()
                return False

            print(f"Connected to server as {username}")

            # Start receiving thread
            self.running = True
            self.receive_thread = threading.Thread(target=self.receive_messages)
            self.receive_thread.daemon = True
            self.receive_thread.start()

            return True

        except Exception as e:
            print(f"Connection error: {e}")
            return False

    def receive_messages(self):
        """Process incoming messages from the server"""
        try:
            while self.running:
                data = self.socket.recv(8192)
                if not data:
                    break

                message = json.loads(data.decode())

                if message['type'] == 'user_list':
                    self.users = message['users']
                    print("\nOnline users:", ", ".join(self.users))
                    print(f"\n{self.username}> ", end="", flush=True)

                elif message['type'] == 'message':
                    sender = message['sender']

                    # Extract encrypted data
                    encrypted_data = {
                        'encrypted_message': message['encrypted_message'],
                        'encrypted_key': message['encrypted_key'],
                        'nonce': message['nonce']
                    }

                    # Decrypt the message
                    decrypted_message = self.crypto.decrypt_message(encrypted_data)

                    print(f"\n{sender}: {decrypted_message}")
                    print(f"{self.username}> ", end="", flush=True)

                elif message['type'] == 'error':
                    print(f"\nError: {message['message']}")
                    print(f"{self.username}> ", end="", flush=True)

        except Exception as e:
            if self.running:  # Only show error if not disconnected intentionally
                print(f"\nConnection to server lost: {e}")
        finally:
            self.running = False

    def send_message(self, recipient, message):
        """Encrypt and send a message to a recipient"""
        if recipient not in self.users:
            print(f"User {recipient} is not online.")
            return

        try:
            # For a real implementation, we would request the recipient's public key
            # from the server if we don't have it. For simplicity in this demo,
            # we'll use our own public key for demonstration purposes
            recipient_key = self.crypto.public_key_pem

            # Encrypt the message
            encrypted_data = self.crypto.encrypt_message(message, recipient_key)

            # Create and send the message
            chat_msg = ChatMessage(
                sender=self.username,
                recipient=recipient,
                **encrypted_data
            )

            self.socket.send(chat_msg.to_json().encode())

        except Exception as e:
            print(f"Error sending message: {e}")

    def close(self):
        """Close the connection and clean up"""
        self.running = False
        if self.socket:
            try:
                self.socket.close()
            except:
                pass
