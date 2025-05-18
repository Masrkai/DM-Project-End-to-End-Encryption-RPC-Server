import time
import json
import queue
import socket
import threading
import streamlit as st

from color import ColorManager
from crypto import CryptoManager
from message import RegistrationMessage, ChatMessage, KeyRequestMessage

class StreamlitChatClient:
    def __init__(self, server_host='localhost', server_port=9090):
        self.server_host = server_host
        self.server_port = server_port
        self.socket = None
        self.username = None
        self.users = []
        self.crypto = CryptoManager()
        self.user_keys = {}  # username -> public_key
        self.color_manager = ColorManager()
        self.running = False
        self.receive_thread = None
        self.pending_messages = {}  # username -> [messages]
        self.message_queue = queue.Queue()
        self.connected = False

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
                st.error(f"Registration failed: {response['message']}")
                self.socket.close()
                return False

            # Start receiving thread
            self.running = True
            self.connected = True
            self.receive_thread = threading.Thread(target=self.receive_messages)
            self.receive_thread.daemon = True
            self.receive_thread.start()

            return True

        except Exception as e:
            st.error(f"Connection error: {e}")
            return False

    def receive_messages(self):
        """Process incoming messages from the server"""
        try:
            while self.running:
                data = self.socket.recv(8192)
                if not data:
                    break

                message = json.loads(data.decode())
                self.message_queue.put(message)

        except Exception as e:
            if self.running:
                self.message_queue.put({"type": "error", "message": f"Connection to server lost: {e}"})
        finally:
            self.running = False
            self.connected = False

    def request_public_key(self, username):
        """Request public key for a specific user"""
        if username not in self.user_keys and username in self.users:
            key_request = KeyRequestMessage(username)
            try:
                self.socket.send(key_request.to_json().encode())
                return True
            except Exception as e:
                self.message_queue.put({"type": "error", "message": f"Error requesting key for {username}: {e}"})
        return False

    def _send_encrypted_message(self, recipient, message):
        """Encrypt and send a message using recipient's public key"""
        try:
            recipient_key = self.user_keys[recipient]
            encrypted_data = self.crypto.encrypt_message(message, recipient_key)

            chat_msg = ChatMessage(
                sender=self.username,
                recipient=recipient,
                **encrypted_data
            )

            self.socket.send(chat_msg.to_json().encode())
            return True
        except Exception as e:
            self.message_queue.put({"type": "error", "message": f"Error sending encrypted message: {e}"})
            return False

    def send_message(self, recipient, message):
        """Send a message to a recipient, requesting public key if needed"""
        if recipient not in self.users:
            self.message_queue.put({"type": "error", "message": f"User {recipient} is not online."})
            return False

        if recipient in self.user_keys:
            success = self._send_encrypted_message(recipient, message)
            if success:
                self.message_queue.put({
                    "type": "message",
                    "sender": self.username,
                    "message": message
                })
            return success

        self.message_queue.put({"type": "info", "message": f"Requesting public key for {recipient}..."})
        self.request_public_key(recipient)

        if recipient not in self.pending_messages:
            self.pending_messages[recipient] = []
        self.pending_messages[recipient].append(message)

        self.message_queue.put({"type": "info", "message": f"Message queued and will be sent when {recipient}'s key is received"})
        return True

    def close(self):
        """Close the connection and clean up"""
        self.running = False
        if self.socket:
            try:
                self.socket.close()
            except:
                pass

def initialize_session_state():
    """Initialize session state variables"""
    if 'client' not in st.session_state:
        st.session_state.client = None
    if 'messages' not in st.session_state:
        st.session_state.messages = []
    if 'users' not in st.session_state:
        st.session_state.users = []
    if 'selected_user' not in st.session_state:
        st.session_state.selected_user = None
    if 'username' not in st.session_state:
        st.session_state.username = None
    if 'last_update' not in st.session_state:
        st.session_state.last_update = time.time()
    if 'debug' not in st.session_state:
        st.session_state.debug = []

def process_messages(client):
    """Process messages from the message queue"""
    try:
        while not client.message_queue.empty():
            message = client.message_queue.get_nowait()

            # Add message to debug log
            st.session_state.debug.append(f"Received: {message['type']}")

            if message['type'] == 'user_list':
                # Update users list
                new_users = [u['username'] for u in message['users']]
                st.session_state.debug.append(f"User list update: {new_users}")

                if new_users != st.session_state.users:
                    st.session_state.users = new_users
                    client.users = new_users
                    st.session_state.last_update = time.time()
                    st.rerun()

                # Update color mappings
                for u in message['users']:
                    client.color_manager.user_colors[u['username']] = u['color']

            elif message['type'] == 'public_key':
                user = message['username']
                public_key = message['public_key']
                client.user_keys[user] = public_key
                st.session_state.debug.append(f"Received public key for {user}")

                if user in client.pending_messages and client.pending_messages[user]:
                    for pending_message in client.pending_messages[user]:
                        client._send_encrypted_message(user, pending_message)
                    client.message_queue.put({"type": "info", "message": f"Sent pending message(s) to {user}"})
                    client.pending_messages[user] = []

            elif message['type'] == 'message':
                st.session_state.messages.append({
                    'sender': message['sender'],
                    'message': client.crypto.decrypt_message({
                        'encrypted_message': message['encrypted_message'],
                        'encrypted_key': message['encrypted_key'],
                        'nonce': message['nonce']
                    })
                })
                st.session_state.last_update = time.time()
                st.rerun()

            elif message['type'] in ['error', 'info']:
                st.session_state.messages.append({
                    'sender': 'System',
                    'message': message['message']
                })
                st.session_state.last_update = time.time()
                st.rerun()
    except queue.Empty:
        pass

def main():
    st.set_page_config(page_title="Secure Chat", page_icon="🔒", layout="wide")

    initialize_session_state()

    st.title("🔒 Secure Chat Application")

    # Login section
    if not st.session_state.username:
        with st.form("login_form"):
            username = st.text_input("Enter your username:")
            server_host = st.text_input("Server Host:", value="localhost")
            server_port = st.number_input("Server Port:", value=9090, min_value=1, max_value=65535)

            if st.form_submit_button("Connect"):
                if username:
                    client = StreamlitChatClient(server_host, server_port)
                    if client.connect(username):
                        st.session_state.client = client
                        st.session_state.username = username
                        st.rerun()
                    else:
                        st.error("Failed to connect to server")
                else:
                    st.error("Username cannot be empty")

    # Chat interface
    else:
        client = st.session_state.client

        # Sidebar for user list
        with st.sidebar:
            st.subheader("Online Users")
            if not st.session_state.users:
                st.info("No users online")
            else:
                for user in st.session_state.users:
                    if user != st.session_state.username:
                        if st.button(f"💬 {user}", key=f"user_{user}"):
                            st.session_state.selected_user = user
                            st.rerun()

            # Debug information
            if st.checkbox("Show Debug Info"):
                st.subheader("Debug Information")
                for msg in st.session_state.debug[-10:]:  # Show last 10 debug messages
                    st.text(msg)

        # Main chat area
        col1, col2 = st.columns([3, 1])

        with col1:
            # Display messages
            for msg in st.session_state.messages:
                if msg['sender'] == 'System':
                    st.info(msg['message'])
                else:
                    st.text(f"{msg['sender']}: {msg['message']}")

        with col2:
            # Message input
            if st.session_state.selected_user:
                st.subheader(f"Chat with {st.session_state.selected_user}")
                message = st.text_input("Type your message:", key="message_input")
                if st.button("Send") and message:
                    client.send_message(st.session_state.selected_user, message)
                    st.session_state.messages.append({
                        'sender': st.session_state.username,
                        'message': message
                    })
                    st.rerun()
            else:
                st.info("Select a user from the sidebar to start chatting")

        # Process messages
        process_messages(client)

        # Auto-refresh every 2 seconds
        if time.time() - st.session_state.last_update > 2:
            st.rerun()

        # Disconnect button
        if st.sidebar.button("Disconnect"):
            client.close()
            st.session_state.clear()
            st.rerun()

if __name__ == "__main__":
    main()