import socket
import struct
import threading
import time
import sys
import subprocess
import random
from protocol_fsm import (
    ProtocolFSM, 
    Role, 
    CLIENT_HELLO, 
    CLIENT_DATA, 
    SERVER_AGGR_RESPONSE
)

SERVER_ADDR = ("localhost", 3490)
DIRECTION_C2S = 0

def send_msg(sock, msg: dict):
    payload = (
        struct.pack("!BBI", msg["opcode"], msg["client_id"], msg["round"])
        + bytes([msg["direction"]])
        + msg["iv"]
        + msg["ciphertext"]
        + msg["hmac"]
    )
    sock.sendall(struct.pack("!I", len(payload)) + payload)

def recv_msg(sock) -> dict:
    raw_len = sock.recv(4)
    if len(raw_len) < 4:
        raise RuntimeError("Connection closed")
    length = struct.unpack("!I", raw_len)[0]
    data = b""
    while len(data) < length:
        chunk = sock.recv(length - len(data))
        if not chunk:
            raise RuntimeError("Connection closed")
        data += chunk

    opcode, client_id, rnd = struct.unpack("!BBI", data[:6])
    direction = data[6]
    iv = data[7:23]
    ciphertext = data[23:-32]
    hmac = data[-32:]

    return {
        "opcode": opcode,
        "client_id": client_id,
        "round": rnd,
        "direction": direction,
        "iv": iv,
        "ciphertext": ciphertext,
        "hmac": hmac,
    }

def run_client(client_id):
    try:
        with open(f"keys/client_{client_id}.key", "rb") as f:
            master_key = f.read()

        fsm = ProtocolFSM(master_key, Role.CLIENT)
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect(SERVER_ADDR)

        # Handshake
        hello = fsm.encrypt_and_mac(
            opcode=CLIENT_HELLO,
            client_id=client_id,
            direction=DIRECTION_C2S,
            plaintext=b"HELLO",
        )
        send_msg(sock, hello)

        reply = recv_msg(sock)
        fsm.verify_and_decrypt(reply)
        print(f"Client {client_id}: Handshake success")

        # Loop 5 rounds
        for r in range(1, 6):
            val = 10 # Sending constant 10 for easier verification (Sum = 30)
            
            msg = fsm.encrypt_and_mac(
                opcode=CLIENT_DATA,
                client_id=client_id,
                direction=DIRECTION_C2S,
                plaintext=str(val).encode()
            )
            send_msg(sock, msg)

            reply = recv_msg(sock)
            plaintext = fsm.verify_and_decrypt(reply)
            
            if reply["opcode"] != SERVER_AGGR_RESPONSE:
                 raise RuntimeError(f"Unexpected opcode {reply['opcode']}")

            aggr_val = int(plaintext[:-1].decode())
            status = plaintext[-1]

            if aggr_val != 30: # 3 clients * 10
                 print(f"Client {client_id}: Round {r} Mismatch! Got {aggr_val}")
                 return False
            
            print(f"Client {client_id}: Round {r} OK (Aggr=30)")

        return True
    except Exception as e:
        print(f"Client {client_id}: Failed - {e}")
        return False
    finally:
        sock.close()

def main():
    print("Starting server...")
    server = subprocess.Popen([sys.executable, "-u", "server.py"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    time.sleep(2)

    threads = []
    results = {}

    def thread_target(cid):
        results[cid] = run_client(cid)

    print("Launching clients...")
    for i in range(1, 4):
        t = threading.Thread(target=thread_target, args=(i,))
        threads.append(t)
        t.start()

    for t in threads:
        t.join()

    server.terminate()
    try:
        server.wait(timeout=2)
    except subprocess.TimeoutExpired:
        server.kill()
    
    success = all(results.values()) and len(results) == 3
    if success:
        print("\nAll clients verified successfully.")
        sys.exit(0)
    else:
        print("\nVerification FAILED.")
        print(results)
        outs, errs = server.communicate()
        print("SERVER STDOUT:", outs)
        print("SERVER STDERR:", errs)
        sys.exit(1)

if __name__ == "__main__":
    main()
