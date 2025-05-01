from client import ChatClient
from server import ChatServer

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
            chat_client.show_prompt()  # Show initial prompt

            try:
                while True:
                    message = input().strip()

                    if not message:
                        chat_client.show_prompt()  # Re-show prompt after empty input
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
                            chat_client.show_prompt()  # Show prompt again for next input
                        except ValueError:
                            chat_client.print_system_message("Invalid format. Use: @username message")
                            chat_client.show_prompt()
                    else:
                        chat_client.print_system_message("Invalid format. Use: @username message")
                        chat_client.show_prompt()

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