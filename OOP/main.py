
import os
import client
import message
import server
import crypto



# main.py - Entry point
def start_server():
    """Initialize and start the server"""
    server = ChatServer()
    server.start()

def start_client():
    """Initialize and start the client"""
    username = input("Enter your username: ")
    client = ChatClient()

    if client.connect(username):
        print("Connected to server. Type 'quit' to exit.")
        print("To send a message, use format: @username message")

        try:
            while True:
                message = input(f"{username}> ")

                if message.lower() == 'quit':
                    break

                if message.startswith('@'):
                    # Parse recipient and message
                    try:
                        recipient, content = message[1:].split(' ', 1)
                        client.send_message(recipient, content)
                    except ValueError:
                        print("Invalid format. Use: @username message")
                else:
                    print("Invalid format. Use: @username message")

        except KeyboardInterrupt:
            pass
        finally:
            client.close()

if __name__ == "__main__":
    mode = input("Start as (s)erver or (c)lient? ").lower()

    if mode == 's':
        start_server()
    elif mode == 'c':
        start_client()
    else:
        print("Invalid option. Choose 's' for server or 'c' for client.")