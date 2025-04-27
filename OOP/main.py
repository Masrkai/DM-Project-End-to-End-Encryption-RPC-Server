from client import ChatClient
from server import ChatServer
# from message import Message
# from crypto import CryptoManager

# main.py - Entry point
def start_server():
    """Initialize and start the server"""
    try:
        chat_server = ChatServer()
        chat_server.start()
    except Exception as e:
        print(f"Server error: {e}")

def start_client():
    """Initialize and start the client"""
    try:
        username = input("Enter your username: ").strip()
        if not username:
            print("Username cannot be empty")
            return

        chat_client = ChatClient()

        if chat_client.connect(username):
            print("Connected to server. Type 'quit' to exit.")
            print("To send a message, use format: @username message")

            try:
                while True:
                    message = input(f"{username}> ").strip()

                    if not message:
                        continue

                    if message.lower() == 'quit':
                        break

                    if message.startswith('@'):
                        try:
                            # Parse recipient and message
                            parts = message[1:].split(' ', 1)
                            if len(parts) != 2:
                                raise ValueError

                            recipient, content = parts
                            if not recipient or not content:
                                raise ValueError

                            chat_client.send_message(recipient, content)
                        except ValueError:
                            print("Invalid format. Use: @username message")
                    else:
                        print("Invalid format. Use: @username message")

            except KeyboardInterrupt:
                print("\nDisconnecting...")
            finally:
                chat_client.close()
    except Exception as e:
        print(f"Client error: {e}")

if __name__ == "__main__":
    try:
        while True:
            mode = input("Start as (s)erver or (c)lient? ").lower().strip()

            if mode == 's':
                start_server()
                break
            elif mode == 'c':
                start_client()
                break
            else:
                print("Invalid option. Choose 's' for server or 'c' for client.")
    except KeyboardInterrupt:
        print("\nExiting...")
