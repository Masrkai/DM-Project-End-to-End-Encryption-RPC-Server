import grpc
import time
import asyncio
import logging
from concurrent import futures

# Import the generated protocol code
import secure_chat_pb2
import secure_chat_pb2_grpc

class SecureChatServicer(secure_chat_pb2_grpc.SecureChatServicer):
    def __init__(self):
        self.users = {}  # username -> UserInfo
        self.connections = {}  # username -> stream
        self.active_users = set()  # Set of active usernames
        logging.info("Chat server initialized")

    async def Register(self, request, context):
        username = request.username
        public_key = request.public_key
        peer = context.peer()

        # If user was previously registered but disconnected, allow re-registration
        if username in self.users and username not in self.active_users:
            logging.info(f"Re-registering previously disconnected user: {username}")
            # Update with new public key
            self.users[username] = secure_chat_pb2.UserInfo(
                username=username,
                public_key=public_key
            )
            self.active_users.add(username)
        elif username in self.active_users:
            logging.warning(f"Username '{username}' is already active")
            return secure_chat_pb2.RegisterResponse(
                success=False,
                message=f"Username '{username}' is already taken"
            )
        else:
            # Store user information for new user
            self.users[username] = secure_chat_pb2.UserInfo(
                username=username,
                public_key=public_key
            )
            self.active_users.add(username)
            logging.info(f"New user registered: {username} from {peer}")

        # Create response with list of existing users
        response = secure_chat_pb2.RegisterResponse(
            success=True,
            message=f"Welcome {username}!"
        )

        # Add all current active users to the response
        for user in self.active_users:
            response.users.append(self.users[user])

        return response

    async def ChatStream(self, request_iterator, context):
        # First message contains sender information
        first_message = await anext(request_iterator)
        sender = first_message.sender
        peer = context.peer()

        if sender not in self.users:
            # User not registered
            yield secure_chat_pb2.ChatMessage(
                sender="SERVER",
                recipient=sender,
                encrypted_content="ERROR: You must register first",
                timestamp=int(time.time())
            )
            return

        # Mark as active if not already
        if sender not in self.active_users:
            self.active_users.add(sender)

        # Store the connection for broadcasting
        self.connections[sender] = context

        try:
            # Send a welcome message
            yield secure_chat_pb2.ChatMessage(
                sender="SERVER",
                recipient=sender,
                encrypted_content=f"You are connected as {sender}",
                timestamp=int(time.time())
            )

            # Add context.cancel callback to handle disconnection
            def on_client_disconnected():
                logging.info(f"Client disconnected callback triggered for {sender}")
                asyncio.create_task(self.handle_disconnection(sender))

            context.add_done_callback(lambda _: on_client_disconnected())

            # Broadcast user joined
            await self.broadcast_user_status(sender, "joined")

            # Process incoming messages
            async for message in request_iterator:
                if message.recipient == "ALL":
                    # Forward to all connected users
                    for user in self.connections:
                        if user != sender and user in self.active_users:
                            try:
                                yield message
                            except Exception as e:
                                logging.error(f"Error forwarding to {user}: {str(e)}")
                else:
                    # Direct message to specific user
                    if message.recipient in self.connections and message.recipient in self.active_users:
                        # Note: The message is already encrypted
                        yield message
                    else:
                        # Recipient not found or not active
                        yield secure_chat_pb2.ChatMessage(
                            sender="SERVER",
                            recipient=sender,
                            encrypted_content=f"User {message.recipient} is not available",
                            timestamp=int(time.time())
                        )

        except Exception as e:
            logging.error(f"Error in ChatStream for {sender}: {str(e)}")
        finally:
            # Handle disconnection in finally block
            await self.handle_disconnection(sender)

    async def handle_disconnection(self, username):
        """Handle client disconnection"""
        if username in self.active_users:
            self.active_users.remove(username)
            logging.info(f"User marked inactive: {username}")

            if username in self.connections:
                del self.connections[username]
                logging.info(f"User connection removed: {username}")

            await self.broadcast_user_status(username, "left")

    async def broadcast_user_status(self, username, status):
        """Send a message to all users about a user joining or leaving"""
        for user in self.connections:
            if user != username and user in self.active_users:
                try:
                    await self.connections[user].write(secure_chat_pb2.ChatMessage(
                        sender="SERVER",
                        recipient=user,
                        encrypted_content=f"User {username} has {status} the chat",
                        timestamp=int(time.time())
                    ))
                except Exception as e:
                    logging.error(f"Error broadcasting to {user}: {str(e)}")

async def serve():
    server = grpc.aio.server(futures.ThreadPoolExecutor(max_workers=10))
    secure_chat_pb2_grpc.add_SecureChatServicer_to_server(
        SecureChatServicer(), server
    )

    # Use insecure port - no SSL needed
    # The encryption is handled at the application level
    server.add_insecure_port('[::]:50051')

    await server.start()
    logging.info("Server started on port 50051")

    try:
        await server.wait_for_termination()
    except KeyboardInterrupt:
        await server.stop(0)
        logging.info("Server stopped")

if __name__ == '__main__':
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(levelname)s - %(message)s'
    )
    asyncio.run(serve())