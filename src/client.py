# client.py - Client implementation
import json
import socket
import threading

from crypto import CryptoManager
from color import ColorManager, COLORS
from message import RegistrationMessage, ChatMessage, KeyRequestMessage

class ChatClient:
    def __init__(self, server_host='localhost', server_port=9090):
        self.server_host = server_host
        self.server_port = server_port
        self.socket = None
        self.username = None
        self.users = []
        self.crypto = CryptoManager()
        self.user_keys = {}                  # username -> public_key
        self.color_manager = ColorManager()  # Use the separate color manager
        self.running = False
        self.receive_thread = None
        self.pending_messages = {}           # username -> [messages]

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
                self.print_system_message(f"Registration failed: {response['message']}")
                self.socket.close()
                return False

            self.print_system_message(f"Connected to server as {username}")

            # Start receiving thread
            self.running = True
            self.receive_thread = threading.Thread(target=self.receive_messages)
            self.receive_thread.daemon = True
            self.receive_thread.start()

            return True

        except Exception as e:
            self.print_system_message(f"Connection error: {e}")
            return False

    def print_system_message(self, message):
        """Print a system message in green"""
        self.color_manager.print_system_message(message)

    def print_user_message(self, username, message):
        """Print a user message with the user's color"""
        self.color_manager.print_user_message(username, message)

    def show_prompt(self):
        """Show the user input prompt"""
        self.color_manager.show_prompt(self.username)

    def receive_messages(self):
        """Process incoming messages from the server"""
        try:
            while self.running:
                data = self.socket.recv(8192)
                if not data:
                    break

                message = json.loads(data.decode())

                if message['type'] == 'user_list':
                    self.users = [u['username'] for u in message['users']]

                    # Update ColorManager with server-assigned colors
                    for u in message['users']:
                        self.color_manager.user_colors[u['username']] = u['color']

                    # Display online users with their colors
                    display = "Online users: " + " ".join(
                        f"{u['color']}{u['username']}{COLORS['RESET']}"
                        for u in message['users']
                    )
                    self.print_system_message(display)
                    self.show_prompt()

                elif message['type'] == 'public_key':
                    user = message['username']
                    public_key = message['public_key']
                    self.user_keys[user] = public_key

                    # Send pending messages with full encryption details
                    if user in self.pending_messages and self.pending_messages[user]:
                        for pending_message in self.pending_messages[user]:
                            success, encrypted_data = self._send_encrypted_message(user, pending_message)
                            if success:
                                self.print_user_message(self.username, pending_message)
                                self.print_system_message("Full encrypted message details:")
                                self.print_system_message(f"Encrypted message: {encrypted_data['encrypted_message']}")
                                self.print_system_message(f"Encrypted key: {encrypted_data['encrypted_key']}")
                                self.print_system_message(f"Nonce: {encrypted_data['nonce']}")
                        self.print_system_message(f"Sent pending message(s) to {user}")
                        self.pending_messages[user] = []
                    self.show_prompt()

                elif message['type'] == 'message':
                    sender = message['sender']

                    # Show full encrypted components
                    self.print_system_message(f"\nReceived raw encrypted data from {sender}:")
                    self.print_system_message(f"Encrypted message: {message['encrypted_message']}")
                    self.print_system_message(f"Encrypted key: {message['encrypted_key']}")
                    self.print_system_message(f"Nonce: {message['nonce']}")

                    # Decrypt and show plaintext
                    encrypted_data = {
                        'encrypted_message': message['encrypted_message'],
                        'encrypted_key': message['encrypted_key'],
                        'nonce': message['nonce']
                    }
                    try:
                        decrypted_message = self.crypto.decrypt_message(encrypted_data)
                        self.print_system_message(f"\nDecryption successful for {sender}:")
                        self.print_user_message(sender, decrypted_message)
                    except Exception as e:
                        self.print_system_message(f"\nDecryption failed: {str(e)}")
                        self.print_system_message("Raw encrypted data was:")
                        self.print_system_message(f"Encrypted message: {message['encrypted_message']}")
                        self.print_system_message(f"Encrypted key: {message['encrypted_key']}")
                        self.print_system_message(f"Nonce: {message['nonce']}")

                    self.show_prompt()

                elif message['type'] == 'error':
                    self.print_system_message(f"Error: {message['message']}")
                    self.show_prompt()

        except Exception as e:
            if self.running:
                self.print_system_message(f"Connection to server lost: {e}")
        finally:
            self.running = False


    def request_public_key(self, username):
        """Request public key for a specific user"""
        if username not in self.user_keys and username in self.users:
            key_request = KeyRequestMessage(username)
            try:
                self.socket.send(key_request.to_json().encode())
                return True
            except Exception as e:
                self.print_system_message(f"Error requesting key for {username}: {e}")
        return False

    def _send_encrypted_message(self, recipient, message):
        """Encrypt and send a message using recipient's public key"""
        try:
            recipient_key = self.user_keys[recipient]
            encrypted_data = self.crypto.encrypt_message(message, recipient_key)

            # Create and send the message
            chat_msg = ChatMessage(
                sender=self.username,
                recipient=recipient,
                **encrypted_data
            )

            self.socket.send(chat_msg.to_json().encode())
            return True, encrypted_data
        except Exception as e:
            self.print_system_message(f"Error sending encrypted message: {e}")
            return False, None

    def send_message(self, recipient, message):
        """Send a message to a recipient, requesting public key if needed"""
        if recipient not in self.users:
            self.print_system_message(f"User {recipient} is not online.")
            return False

        # If we already have the public key, send the message immediately
        if recipient in self.user_keys:
            success, encrypted_data = self._send_encrypted_message(recipient, message)
            if success:
                # Echo the message to ourselves to show it was sent
                self.print_user_message(self.username, message)
                # Show encrypted details
                self.print_system_message(f"Encrypted message (truncated): {encrypted_data['encrypted_message']}...")
                self.print_system_message(f"Encrypted key (truncated): {encrypted_data['encrypted_key']}...")
                self.print_system_message(f"Nonce (truncated): {encrypted_data['nonce']}...")
            return success

        # Otherwise, request the key and queue the message
        self.print_system_message(f"Requesting public key for {recipient}...")
        self.request_public_key(recipient)

        # Store the message to send later when we get the key
        if recipient not in self.pending_messages:
            self.pending_messages[recipient] = []
        self.pending_messages[recipient].append(message)

        self.print_system_message(f"Message queued and will be sent when {recipient}'s key is received")
        return True

    def close(self):
        """Close the connection and clean up"""
        self.running = False
        if self.socket:
            try:
                self.socket.close()
            except:
                pass