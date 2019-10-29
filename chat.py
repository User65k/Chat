"""
P2P LAN Chat.

Encrypts all Messages with TLS.
Peers need a shared Password (used with a HMAC) to join.

Can send files to a peer with
@<ip> <file_name>

Needs a dhparam.pem file. Generate it like this:

    openssl dhparam -5 -outform PEM -out dhparam.pem

"""

import socket
from select import select
import sys
import ssl  # crypt messages
import hmac  # limit who joins
import logging

PORT = 1337
CHANNEL = b"dchat"
PASSWORD = b"lol"


def addr_mac(ep):
    """Hash channel, ip and port with PW"""
    h = hmac.new(PASSWORD)
    h.update(CHANNEL)
    h.update(socket.inet_aton(ep[0]))
    h.update(ep[1].to_bytes(2, "big"))
    return h.digest()


def send_file(user_input, peers):
    """Send a File to a Peer"""
    from os.path import basename
    if user_input[0] != "@":
        return False
    space = user_input.find(" ")
    if space == -1:
        return False
    peer = user_input[1:space]
    filename = user_input[space+1:]
    for sock in peers:
        addr = sock.getpeername()[0]
        if addr == peer:
            try:
                with open(filename, 'rb') as f:
                    fc = f.read()
                    sock.send(b"\x00"+basename(filename).encode() +
                              b"\x00"+len(fc).to_bytes(4, "big", signed=False) + fc)
                    print("File sent")
                    return True
            except:
                logging.exception("send file failed")

    return False


def recv_file(data, peer_addr, sock):
    from os.path import basename
    if data[0] != 0:
        return False
    space = data.find(b"\x00", 1)
    if space == -1:
        return False
    fname = data[1:space]
    size = int.from_bytes(data[space+1:space+5], 'big', signed=False)
    content = data[space+5:]
    fname = peer_addr[0] + "_" + basename(fname.decode())
    missing = size - len(content)
    if missing > 0:
        content += sock.read(missing)
    with open(fname, "wb") as f:
        f.write(content)
    print("Saved "+fname)
    return True


sslContext = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
sslContext.options |= ssl.OP_NO_COMPRESSION
sslContext.options |= ssl.OP_NO_SSLv2
sslContext.options |= ssl.OP_NO_SSLv3
sslContext.options |= ssl.OP_NO_TLSv1
sslContext.options |= ssl.OP_NO_TLSv1_1
sslContext.verify_mode = ssl.CERT_NONE
sslContext.set_ciphers("ADH,AECDH:@SECLEVEL=0:@STRENGTH")  # +TLSv1.2
sslContext.load_dh_params("dhparam.pem")

with socket.socket() as server:
    server.bind(("", PORT))
    server.listen(10)

    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP) as pub:  # noqa: E501
        pub.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, True)
        pub.sendto(CHANNEL, ("<broadcast>", PORT))

    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP) as sub:  # noqa: E501
        sub.bind(("", PORT))

        peers = []
        try:
            while True:
                r = [server, sub, sys.stdin]
                r.extend(peers)
                r, _, _ = select(r, [], [])
                for s in r:
                    if s == server:
                        try:
                            newsocket, addr = server.accept()
                            # check client
                            digest = newsocket.recv(400)
                            verify = addr_mac(addr)
                            if not hmac.compare_digest(digest, verify):
                                newsocket.close()
                                logging.warning("client mac wrong")
                                continue
                            # check server (us)
                            ep = newsocket.getsockname()
                            newsocket.send(addr_mac(ep))
                            # talk
                            sslSocket = sslContext.wrap_socket(newsocket,
                                                               server_side=True
                                                               )
                            peers.append(sslSocket)
                            print(addr[0]+" joined")
                        except:
                            logging.exception("join failed")
                    elif s == sub:
                        data, addr = sub.recvfrom(400)
                        if not data == CHANNEL:
                            logging.warning("different channel")
                            continue
                        newsocket = socket.socket()
                        try:
                            newsocket.connect((addr[0], PORT))
                            # check client (us)
                            ep = newsocket.getsockname()
                            newsocket.send(addr_mac(ep))
                            # check server
                            digest = newsocket.recv(400)
                            verify = addr_mac(newsocket.getpeername())
                            if not hmac.compare_digest(digest, verify):
                                newsocket.close()
                                logging.warning("server mac wrong")
                                continue
                            # talk
                            sslSocket = sslContext.wrap_socket(newsocket,
                                                               server_side=False  # noqa: E501
                                                               )
                            peers.append(sslSocket)
                            print(addr[0]+" connected")
                        except:
                            logging.exception("connect failed")
                    elif s == sys.stdin:
                        data = sys.stdin.readline().rstrip()
                        if send_file(data, peers):
                            continue
                        data = data.encode()
                        for sock in peers:
                            try:
                                sock.send(data)
                            except:
                                peers.remove(sock)
                    else:
                        try:
                            data = s.read(4000)
                            addr = s.getpeername()
                            if data == b"":
                                print(addr[0]+": left")
                                peers.remove(s)
                                continue
                            if recv_file(data, addr, s):
                                continue
                            data = data.decode()
                            print(addr[0]+": "+data)
                        except:
                            logging.exception("peer failed")
                            peers.remove(s)
        except KeyboardInterrupt:
            pass

        for s in peers:
            s.close()
