# Secure RPC Chat Application

This is an end-to-end encrypted chat application built with Python and gRPC that lets you chat securely from anywhere in the world with just an internet connection. No SSL certificates, DNS setup, or VPS hosting required.

## Features

- End-to-end encryption using RSA + AES
- Peer-to-peer direct messaging
- Group chat capability
- No server certificates or complex setup required
- RSA key pair management
- Command-based interface

## Setup Instructions

1. **Install the required packages**

```bash
pip install grpcio grpcio-tools cryptography
```

2. **Create the project structure**

Save the three files:
- `secure_chat.proto` - The protocol definition
- `server.py` - The chat server implementation
- `client.py` - The chat client implementation

3. **Generate the gRPC code**

```bash
python -m grpc_tools.protoc -I. --python_out=. --grpc_python_out=. secure_chat.proto
```

4. **Run the server**

```bash
python server.py
```

By default, the server runs on port 50051.

5. **Run the client**

```bash
python client.py your_username --server localhost:50051
```

Replace `your_username` with your desired username and adjust the server address if needed.

## Client Usage

Once connected, you can:
- Type a message and press Enter to send to everyone
- Use commands:
  - `/msg <username> <message>` - Send a private message to a specific user
  - `/users` - List all connected users
  - `/quit` or `/exit` - Disconnect and exit

## Security Notes

- The app generates a unique RSA key pair for each user when they first join
- Keys are stored in the local directory as `<username>_key.pem`
- All messages are encrypted with the recipient's public key
- Server acts only as a message relay and cannot decrypt any content
- Although no SSL/TLS is used for the transport, all chat content is end-to-end encrypted
- For enhanced security, be careful with your private key files

## How It Works

1. When a client connects, it registers with the server, providing its username and public key
2. The server shares the list of all connected users and their public keys
3. When sending a message, the client encrypts it with the recipient's public key
4. For broadcast messages, the client individually encrypts a copy for each recipient
5. The recipient decrypts messages using their private key
6. The server cannot read message content as it only sees encrypted data