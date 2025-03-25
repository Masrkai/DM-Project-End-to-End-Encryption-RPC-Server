
# server.py - Server implementation
import socket
import threading
import json
from message import RegistrationMessage, StatusMessage, UserListMessage, ChatMessage, ErrorMessage

class Client:
    """Represents a connected client"""
    def __init__(self, socket, username, public_key):
        self.socket = socket
        self.username = username
        self.public_key = public_key


class ChatServer:
    def __init__(self, host='0.0.0.0', port=9090):
        self.host = host
        self.port = port
        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.clients = {}  # username -> Client object
        self.lock = threading.Lock()

    def start(self):
        """Start the server and listen for connections"""
        self.server_socket.bind((self.host, self.port))
        self.server_socket.listen(5)
        print(f"[*] Server started on {self.host}:{self.port}")

        try:
            while True:
                client_socket, address = self.server_socket.accept()
                print(f"[+] Connection from {address}")
                client_handler = threading.Thread(target=self.handle_client, args=(client_socket,))
                client_handler.daemon = True
                client_handler.start()
        except KeyboardInterrupt:
            print("[!] Server shutting down")
        finally:
            self._cleanup()

    def _cleanup(self):
        """Clean up resources before shutdown"""
        for client in self.clients.values():
            try:
                client.socket.close()
            except:
                pass
        self.server_socket.close()

    def handle_client(self, client_socket):
        """Handle client connection and messages"""
        username = None

        try:
            # Wait for registration
            registration_data = client_socket.recv(4096)
            reg_msg = json.loads(registration_data.decode())

            if reg_msg['type'] == 'registration':
                username = reg_msg['username']
                public_key = reg_msg['public_key']

                with self.lock:
                    # Check if username exists
                    if username in self.clients:
                        status_msg = StatusMessage("error", "Username already exists")
                        client_socket.send(status_msg.to_json().encode())
                        client_socket.close()
                        return

                    # Register client
                    client = Client(client_socket, username, public_key)
                    self.clients[username] = client

                    # Send success response
                    status_msg = StatusMessage("success", "Registered successfully")
                    client_socket.send(status_msg.to_json().encode())

                    # Broadcast user list update
                    self.broadcast_user_list()

            # Handle messages from client
            while True:
                message_data = client_socket.recv(8192)
                if not message_data:
                    break

                message_obj = json.loads(message_data.decode())

                if message_obj['type'] == 'message':
                    # Forward encrypted message to recipient
                    recipient = message_obj['recipient']
                    if recipient in self.clients:
                        recipient_client = self.clients[recipient]
                        # Forward the encrypted message
                        forward_data = {
                            'type': 'message',
                            'sender': username,
                            'encrypted_message': message_obj['encrypted_message'],
                            'encrypted_key': message_obj['encrypted_key'],
                            'nonce': message_obj['nonce']
                        }
                        recipient_client.socket.send(json.dumps(forward_data).encode())
                    else:
                        error_msg = ErrorMessage(f"User {recipient} not found")
                        client_socket.send(error_msg.to_json().encode())

        except Exception as e:
            print(f"[!] Error handling client: {e}")
        finally:
            with self.lock:
                if username and username in self.clients:
                    del self.clients[username]
                    self.broadcast_user_list()
            try:
                client_socket.close()
            except:
                pass
            print(f"[-] Connection closed for {username if username else 'unknown'}")

    def broadcast_user_list(self):
        """Send updated user list to all clients"""
        user_list = list(self.clients.keys())
        user_list_msg = UserListMessage(user_list)
        message_data = user_list_msg.to_json().encode()

        for client in self.clients.values():
            try:
                client.socket.send(message_data)
            except:
                pass  # If sending fails, we'll handle it in the client handler
