import grpc
import time
import asyncio
import logging
import argparse
import sys
import json
import os
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import base64
import os

# Import the generated protocol code
import secure_chat_pb2
import secure_chat_pb2_grpc

class SecureChatClient:
    def __init__(self, server_address, username):
        self.server_address = server_address
        self.username = username
        self.channel = None
        self.stub = None
        self.users = {}  # username -> UserInfo
        self.private_key = None
        self.public_key_pem = None
        self.running = True

        # Generate or load keys
        self._setup_keys()

    def _setup_keys(self):
        """Generate or load RSA keys for the user"""
        key_file = f"{self.username}_key.pem"

        if os.path.exists(key_file):
            # Load existing key
            with open(key_file, "rb") as f:
                self.private_key = serialization.load_pem_private_key(
                    f.read(),
                    password=None
                )
            logging.info("Loaded existing private key")
        else:
            # Generate new keys
            self.private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048
            )
            # Save private key
            with open(key_file, "wb") as f:
                f.write(self.private_key.private_bytes(
                    encoding=serialization.Encoding.PEM,
                    format=serialization.PrivateFormat.PKCS8,
                    encryption_algorithm=serialization.NoEncryption()
                ))
            logging.info("Generated and saved new private key")

        # Extract public key in PEM format
        public_key = self.private_key.public_key()
        self.public_key_pem = public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode('utf-8')

    async def connect(self):
        """Connect to the server and register the user"""
        self.channel = grpc.aio.insecure_channel(self.server_address)
        self.stub = secure_chat_pb2_grpc.SecureChatStub(self.channel)

        # Register with the server
        response = await self.stub.Register(
            secure_chat_pb2.RegisterRequest(
                username=self.username,
                public_key=self.public_key_pem
            )
        )

        if not response.success:
            print(f"Registration failed: {response.message}")
            return False

        print(f"Registration successful: {response.message}")

        # Store user information from response
        for user in response.users:
            self.users[user.username] = {
                'public_key': user.public_key
            }

        return True

    def encrypt_message(self, recipient, content):
        """Encrypt message for recipient using their public key"""
        if recipient == "ALL":
            # For broadcasts, encrypt for each recipient
            encrypted_data = {}
            iv = os.urandom(16)  # Use the same IV for all recipients
            iv_b64 = base64.b64encode(iv).decode('utf-8')

            for user, info in self.users.items():
                if user != self.username:  # Don't encrypt for self
                    encrypted_content = self._encrypt_for_user(user, content, iv)
                    encrypted_data[user] = encrypted_content

            return json.dumps(encrypted_data), iv_b64
        else:
            # Direct message
            iv = os.urandom(16)
            iv_b64 = base64.b64encode(iv).decode('utf-8')
            encrypted_content = self._encrypt_for_user(recipient, content, iv)
            return encrypted_content, iv_b64

    def _encrypt_for_user(self, username, content, iv):
        """Encrypt content for a specific user"""
        try:
            if username not in self.users:
                raise ValueError(f"Unknown user: {username}")

            # Get recipient's public key
            public_key_pem = self.users[username]['public_key']
            public_key = serialization.load_pem_public_key(public_key_pem.encode('utf-8'))

            # Generate random AES key
            aes_key = os.urandom(32)  # 256-bit key

            # Encrypt AES key with recipient's public key
            encrypted_key = public_key.encrypt(
                aes_key,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )

            # Encrypt message content with AES
            cipher = Cipher(algorithms.AES(aes_key), modes.CFB(iv))
            encryptor = cipher.encryptor()
            encrypted_content = encryptor.update(content.encode('utf-8')) + encryptor.finalize()

            # Package the encrypted data
            result = {
                'key': base64.b64encode(encrypted_key).decode('utf-8'),
                'content': base64.b64encode(encrypted_content).decode('utf-8')
            }

            return json.dumps(result)
        except Exception as e:
            logging.error(f"Encryption error for {username}: {str(e)}")
            raise

    def decrypt_message(self, sender, encrypted_content, iv_b64):
        """Decrypt message from sender"""
        try:
            # Parse the encrypted content
            if sender == "SERVER":
                # Server messages are not encrypted
                return encrypted_content

            # Convert IV from base64
            iv = base64.b64decode(iv_b64)

            # For broadcast messages
            if sender != self.username:
                try:
                    # Check if it's a broadcast message
                    broadcast_data = json.loads(encrypted_content)
                    if isinstance(broadcast_data, dict) and self.username in broadcast_data:
                        # Extract our copy from the broadcast
                        encrypted_data_str = broadcast_data[self.username]
                        encrypted_data = json.loads(encrypted_data_str)

                        # Get the key and content
                        encrypted_key = base64.b64decode(encrypted_data['key'])
                        encrypted_msg = base64.b64decode(encrypted_data['content'])
                    else:
                        # Direct message
                        encrypted_data = json.loads(encrypted_content)
                        encrypted_key = base64.b64decode(encrypted_data['key'])
                        encrypted_msg = base64.b64decode(encrypted_data['content'])
                except (json.JSONDecodeError, ValueError, KeyError) as e:
                    logging.error(f"Error parsing encrypted content: {str(e)}")
                    return f"[Decryption failed: Invalid format]"

                # Decrypt the AES key
                try:
                    aes_key = self.private_key.decrypt(
                        encrypted_key,
                        padding.OAEP(
                            mgf=padding.MGF1(algorithm=hashes.SHA256()),
                            algorithm=hashes.SHA256(),
                            label=None
                        )
                    )

                    # Decrypt the content with AES
                    cipher = Cipher(algorithms.AES(aes_key), modes.CFB(iv))
                    decryptor = cipher.decryptor()
                    decrypted_content = decryptor.update(encrypted_msg) + decryptor.finalize()

                    return decrypted_content.decode('utf-8')
                except Exception as e:
                    logging.error(f"Error decrypting message: {str(e)}")
                    return f"[Decryption failed: {str(e)}]"
            else:
                # Message from self, already has plaintext
                return encrypted_content
        except Exception as e:
            logging.error(f"Decryption error: {str(e)}")
            return f"[Decryption failed: {str(e)}]"

    async def chat_stream(self):
        """Handle the bidirectional chat stream"""
        async def send_messages(stream):
            while self.running:
                try:
                    recipient = "ALL"  # Default to broadcast
                    message = await asyncio.get_event_loop().run_in_executor(
                        None, lambda: input("")
                    )

                    if not message:
                        continue

                    # Check for commands
                    if message.startswith("/"):
                        parts = message.split(" ", 1)
                        command = parts[0][1:]

                        if command == "quit" or command == "exit":
                            self.running = False
                            break
                        elif command == "users":
                            print("Connected users:")
                            for user in self.users:
                                print(f"- {user}")
                            continue
                        elif command == "msg" and len(parts) > 1:
                            # Direct message: /msg username message
                            try:
                                rest = parts[1]
                                dm_parts = rest.split(" ", 1)
                                if len(dm_parts) < 2:
                                    print("Usage: /msg username message")
                                    continue

                                recipient = dm_parts[0]
                                message = dm_parts[1]

                                if recipient not in self.users:
                                    print(f"Unknown user: {recipient}")
                                    continue
                            except Exception as e:
                                print(f"Error parsing command: {str(e)}")
                                print("Usage: /msg username message")
                                continue
                        else:
                            print(f"Unknown command: {command}")
                            continue

                    # Encrypt the message
                    try:
                        encrypted_content, iv_b64 = self.encrypt_message(recipient, message)

                        # Send the message
                        await stream.write(secure_chat_pb2.ChatMessage(
                            sender=self.username,
                            recipient=recipient,
                            encrypted_content=encrypted_content,
                            iv=base64.b64decode(iv_b64) if iv_b64 else b'',
                            timestamp=int(time.time())
                        ))

                        # Echo own message in chat (if not a command)
                        if not message.startswith('/'):
                            print(f"You: {message}")
                    except Exception as e:
                        logging.error(f"Error encrypting/sending message: {str(e)}")
                        print(f"Failed to send message: {str(e)}")

                except Exception as e:
                    logging.error(f"Error in message loop: {str(e)}")

    async def receive_messages(self, stream):
        try:
            async for message in stream:
                sender = message.sender
                encrypted_content = message.encrypted_content
                iv_b64 = base64.b64encode(message.iv).decode('utf-8') if message.iv else None

                # Decrypt the message
                content = self.decrypt_message(sender, encrypted_content, iv_b64)

                # Display message
                if sender == "SERVER":
                    print(f"[SERVER] {content}")
                elif sender == self.username:
                    # Skip own messages as they're already echoed
                    pass
                else:
                    if message.recipient == "ALL":
                        print(f"{sender}: {content}")
                    else:
                        print(f"{sender} (DM): {content}")
        except Exception as e:
            if self.running:
                logging.error(f"Error receiving messages: {str(e)}")
                self.running = False

    async def run(self):
        """Run the chat client"""
        try:
            # Create the bidirectional stream
            stream = self.stub.ChatStream()

            # Send the initial message
            init_message = secure_chat_pb2.ChatMessage(
                sender=self.username,
                recipient="SERVER",
                encrypted_content="INIT",
                timestamp=int(time.time())
            )
            await stream.write(init_message)

            # Start tasks for sending and receiving
            send_task = asyncio.create_task(self.send_messages(stream))
            receive_task = asyncio.create_task(self.receive_messages(stream))

            # Wait for either task to complete
            done, pending = await asyncio.wait(
                [send_task, receive_task],
                return_when=asyncio.FIRST_COMPLETED
            )

            # Cancel the other task
            for task in pending:
                task.cancel()

            # Done with the stream
            await stream.done_writing()

        except Exception as e:
            logging.error(f"Stream error: {str(e)}")
        finally:
            self.running = False

    async def send_messages(self, stream):
        """Task for sending messages"""
        while self.running:
            try:
                recipient = "ALL"  # Default to broadcast
                message = await asyncio.get_event_loop().run_in_executor(
                    None, lambda: input("")
                )

                if not message:
                    continue

                # Check for commands
                if message.startswith("/"):
                    parts = message.split(" ", 1)
                    command = parts[0][1:]

                    if command == "quit" or command == "exit":
                        self.running = False
                        break
                    elif command == "users":
                        print("Connected users:")
                        for user in self.users:
                            print(f"- {user}")
                        continue
                    elif command == "msg" and len(parts) > 1:
                        # Direct message: /msg username message
                        try:
                            rest = parts[1].strip()
                            space_idx = rest.find(" ")
                            if space_idx == -1:
                                print("Usage: /msg username message")
                                continue

                            recipient = rest[:space_idx]
                            message = rest[space_idx+1:]

                            if recipient not in self.users:
                                print(f"Unknown user: {recipient}")
                                continue

                            print(f"Sending DM to {recipient}: {message}")
                        except Exception as e:
                            print(f"Error parsing command: {str(e)}")
                            continue
                    else:
                        print(f"Unknown command: {command}")
                        continue

                # Encrypt the message
                try:
                    if recipient == "ALL":
                        # For broadcasts, use a simple message for yourself
                        if not message.startswith('/'):
                            print(f"You: {message}")

                    # Encrypt for recipient(s)
                    iv = os.urandom(16)
                    iv_b64 = base64.b64encode(iv).decode('utf-8')

                    if recipient == "ALL":
                        # For broadcasts, encrypt for each recipient
                        encrypted_data = {}
                        for user, info in self.users.items():
                            if user != self.username:  # Don't encrypt for self
                                try:
                                    public_key_pem = info['public_key']
                                    public_key = serialization.load_pem_public_key(public_key_pem.encode('utf-8'))

                                    # Generate random AES key
                                    aes_key = os.urandom(32)  # 256-bit key

                                    # Encrypt AES key with recipient's public key
                                    encrypted_key = public_key.encrypt(
                                        aes_key,
                                        padding.OAEP(
                                            mgf=padding.MGF1(algorithm=hashes.SHA256()),
                                            algorithm=hashes.SHA256(),
                                            label=None
                                        )
                                    )

                                    # Encrypt message content with AES
                                    cipher = Cipher(algorithms.AES(aes_key), modes.CFB(iv))
                                    encryptor = cipher.encryptor()
                                    encrypted_content = encryptor.update(message.encode('utf-8')) + encryptor.finalize()

                                    # Package the encrypted data
                                    encrypted_data[user] = json.dumps({
                                        'key': base64.b64encode(encrypted_key).decode('utf-8'),
                                        'content': base64.b64encode(encrypted_content).decode('utf-8')
                                    })
                                except Exception as e:
                                    logging.error(f"Error encrypting for {user}: {str(e)}")

                        encrypted_content = json.dumps(encrypted_data)

                    else:
                        # Direct message to a single recipient
                        try:
                            public_key_pem = self.users[recipient]['public_key']
                            public_key = serialization.load_pem_public_key(public_key_pem.encode('utf-8'))

                            # Generate random AES key
                            aes_key = os.urandom(32)  # 256-bit key

                            # Encrypt AES key with recipient's public key
                            encrypted_key = public_key.encrypt(
                                aes_key,
                                padding.OAEP(
                                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                                    algorithm=hashes.SHA256(),
                                    label=None
                                )
                            )

                            # Encrypt message content with AES
                            cipher = Cipher(algorithms.AES(aes_key), modes.CFB(iv))
                            encryptor = cipher.encryptor()
                            encrypted_content = encryptor.update(message.encode('utf-8')) + encryptor.finalize()

                            # Package the encrypted data
                            encrypted_content = json.dumps({
                                'key': base64.b64encode(encrypted_key).decode('utf-8'),
                                'content': base64.b64encode(encrypted_content).decode('utf-8')
                            })
                        except Exception as e:
                            logging.error(f"Error encrypting for {recipient}: {str(e)}")
                            print(f"Failed to encrypt message: {str(e)}")
                            continue

                    # Send the message
                    await stream.write(secure_chat_pb2.ChatMessage(
                        sender=self.username,
                        recipient=recipient,
                        encrypted_content=encrypted_content,
                        iv=iv,
                        timestamp=int(time.time())
                    ))

                except Exception as e:
                    logging.error(f"Error sending message: {str(e)}")
                    print(f"Failed to send message: {str(e)}")

            except asyncio.CancelledError:
                break
            except Exception as e:
                logging.error(f"Error in send_messages: {str(e)}")

    async def close(self):
        """Close the connection"""
        if self.channel:
            await self.channel.close()

async def main():
    parser = argparse.ArgumentParser(description="Secure Chat Client")
    parser.add_argument("username", help="Your username")
    parser.add_argument("--server", default="localhost:50051", help="Server address (default: localhost:50051)")
    parser.add_argument("--force", action="store_true", help="Force new registration even if username exists")
    args = parser.parse_args()

    # Configure logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s',
        handlers=[logging.FileHandler(f"{args.username}_client.log"), logging.StreamHandler()]
    )

    # If force option is used, delete existing key
    if args.force and os.path.exists(f"{args.username}_key.pem"):
        os.remove(f"{args.username}_key.pem")
        logging.info(f"Removed existing key for {args.username}")

    # Create and start client
    client = SecureChatClient(args.server, args.username)

    try:
        # Connect and register
        if await client.connect():
            print("\n=== Secure Chat Connected ===")
            print("Type a message to send to everyone")
            print("Commands:")
            print("  /msg <username> <message> - Send direct message")
            print("  /users - List connected users")
            print("  /quit or /exit - Disconnect and exit")
            print("==============================\n")

            # Start chat
            await client.run()
    except Exception as e:
        logging.error(f"Client error: {str(e)}")
    finally:
        await client.close()
        print("Disconnected")

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\nExiting...")
        sys.exit(0)