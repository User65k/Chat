# Simple PFS-P2P-LAN-Chat

- Encrypted Messages with PFS (using TLS)
- File Transfers
- Only Peers with a matching Password can join
- Peer to Peer
- Peer detection via UDP broadcasts
- Uses only Python (that uses OpenSSL)

## But why?

This Chat is for these poor Souls who need to
work on a local Network with a college
while being under survailance by the customer.

## Setup

Needs a dhparam.pem file. Generate it like this:

    openssl dhparam -5 -outform PEM -out dhparam.pem

1. Place the `dhparam.pem` next to `chat.py`
2. Configure `chat.py` to your needs. All Peers must have the same configuration.
   - Set `PORT`
   - Choose a `CHANNEL` (is broadcasted in clear)
   - Agree on a secret `PASSWORD`
3. Run it via 

    python3 chat.py