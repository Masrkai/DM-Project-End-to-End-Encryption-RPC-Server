This implementation will focus on secure communication between clients through a central server.


This end-to-end encrypted chat system implements:

1. **Asymmetric encryption**: Each client generates an RSA key pair during initialization
2. **Session key encryption**: Messages are encrypted with AES-256 using a random session key
3. **Public key exchange**: Users share their public keys for secure key exchange
4. **Message forwarding**: The server forwards encrypted messages without being able to read them

### How It Works

1. **Server**: Acts as a relay between clients but cannot decrypt messages
   - Maintains a list of connected clients and their public keys
   - Forwards encrypted messages between clients
   - Broadcasts user list updates

2. **Client**: Handles encryption and decryption
   - Generates RSA key pair on startup
   - Encrypts messages with a random AES session key
   - Encrypts the session key with recipient's public key
   - Decrypts incoming messages using private key

### How to Use

0. go to Main_chat

1. Start the server:
   ```
   python chat.py
   ```
   Then select 's' for server mode

2. Start clients in separate terminal windows:
   ```
   python chat.py
   ```
   Then select 'c' for client mode and enter a username

3. Send messages using: `@username message`

This implementation demonstrates the core concepts of end-to-end encryption but has some simplifications. In a production environment, you would want to add:

- Certificate authentication to prevent man-in-the-middle attacks
- Message integrity verification
- Persistent user accounts and authentication
- Forward secrecy with ephemeral keys

Would you like me to explain any specific part of the implementation in more detail?