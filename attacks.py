import socket
import struct
import sys
import time
import subprocess
from protocol_fsm import ProtocolFSM, Role, CLIENT_HELLO

SERVER_ADDR = ("localhost", 3490)
DIRECTION_C2S = 0

# -----------------------------------------------------------------------------
# Helpers to construct raw messages (simulating captured traffic)
# -----------------------------------------------------------------------------
def get_raw_msg(fsm, opcode, client_id, direction, plaintext):
    msg = fsm.encrypt_and_mac(opcode, client_id, direction, plaintext)
    payload = (
        struct.pack("!BBI", msg["opcode"], msg["client_id"], msg["round"])
        + bytes([msg["direction"]])
        + msg["iv"]
        + msg["ciphertext"]
        + msg["hmac"]
    )
    return struct.pack("!I", len(payload)) + payload

def send_raw(sock, raw_data):
    sock.sendall(raw_data)

# def recv_resp(sock):
#     try:
#         sock.settimeout(2)
#         raw_len = sock.recv(4)
#         if len(raw_len) < 4: return None
#         length = struct.unpack("!I", raw_len)[0]
#         data = b""
#         while len(data) < length:
#             chunk = sock.recv(length - len(data))
#             if not chunk: return None
#             data += chunk
#         return data
#     except (socket.timeout, ConnectionResetError, BrokenPipeError):
#         return None

def recv_resp(sock):
    try:
        sock.settimeout(2)
        raw_len = sock.recv(4)
        if len(raw_len) < 4:
            return None

        length = struct.unpack("!I", raw_len)[0]
        data = b""
        while len(data) < length:
            chunk = sock.recv(length - len(data))
            if not chunk:
                return None
            data += chunk
        return data

    except (
        socket.timeout,
        ConnectionResetError,
        ConnectionAbortedError,   # ✅ REQUIRED on Windows
        BrokenPipeError,
        OSError                  # ✅ optional safety net
    ):
        return None

# -----------------------------------------------------------------------------
# Attack Scenarios
# -----------------------------------------------------------------------------

def attack_hmac_tamper():
    print("\n--- [Attack 1] Incorrect HMAC Attack ---")
    # 1. Setup valid client state
    client_id = 1
    with open(f"keys/client_{client_id}.key", "rb") as f: master_key = f.read()
    fsm = ProtocolFSM(master_key, Role.CLIENT)
    
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.connect(SERVER_ADDR)
        
        # 2. Construct valid message
        raw = get_raw_msg(fsm, CLIENT_HELLO, client_id, DIRECTION_C2S, b"ATTACK1")
        
        # 3. Tamper with HMAC (last byte)
        # Structure: len(4) + header(7) + iv(16) + cipher(N) + hmac(32)
        tampered = bytearray(raw)
        tampered[-1] ^= 0xFF # Flip last bit of HMAC
        
        print("Sending tampered message...")
        send_raw(sock, tampered)
        
        # 4. Check if connection is closed
        resp = recv_resp(sock)
        if resp is None:
            print("SUCCESS: Server closed connection (or ignored) on invalid HMAC.")
            return True
        else:
            print("FAILURE: Server replied to invalid HMAC!")
            return False
    finally:
        sock.close()

def attack_replay():
    print("\n--- [Attack 2] Replay Attack ---")
    client_id = 1
    with open(f"keys/client_{client_id}.key", "rb") as f: master_key = f.read()
    fsm = ProtocolFSM(master_key, Role.CLIENT)
    
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.connect(SERVER_ADDR)
        
        # 1. Send valid message
        raw = get_raw_msg(fsm, CLIENT_HELLO, client_id, DIRECTION_C2S, b"ORIGINAL")
        print("Sending valid message (Round 0)...")
        send_raw(sock, raw)
        recv_resp(sock) # Consumption
        
        # 2. Replay same message
        print("Replaying same message (Round 0)...")
        send_raw(sock, raw)
        
        # 3. Expect silence/close
        resp = recv_resp(sock)
        if resp is None:
            print("SUCCESS: Server rejected replay.")
            return True
        else:
            print("FAILURE: Server accepted replay!")
            return False
    finally:
        sock.close()

def attack_reordering():
    print("\n--- [Attack 3] Message Reordering Attack ---")
    client_id = 1
    with open(f"keys/client_{client_id}.key", "rb") as f: master_key = f.read()
    fsm = ProtocolFSM(master_key, Role.CLIENT)
    
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.connect(SERVER_ADDR)
        
        # Generate Round 0 and Round 1
        msg0 = get_raw_msg(fsm, CLIENT_HELLO, client_id, DIRECTION_C2S, b"MSG0") # advances FSM to R1
        msg1 = get_raw_msg(fsm, CLIENT_HELLO, client_id, DIRECTION_C2S, b"MSG1") 
        
        # Send Round 1 FIRST (Skipping Round 0)
        print("Sending Round 1 message before Round 0...")
        send_raw(sock, msg1)
        
        resp = recv_resp(sock)
        if resp is None:
            print("SUCCESS: Server rejected out-of-order message.")
            return True
        else:
            print(f"FAILURE: Server accepted Round 1 without Round 0")
            return False
    finally:
        sock.close()

def attack_drop():
    print("\n--- [Attack 4] Key Desynchronization (Drop) ---")
    client_id = 1
    with open(f"keys/client_{client_id}.key", "rb") as f: master_key = f.read()
    fsm = ProtocolFSM(master_key, Role.CLIENT)
    
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.connect(SERVER_ADDR)
        
        # Generate Round 0 (to be dropped) and Round 1
        msg0 = get_raw_msg(fsm, CLIENT_HELLO, client_id, DIRECTION_C2S, b"DROP_ME")
        msg1 = get_raw_msg(fsm, CLIENT_HELLO, client_id, DIRECTION_C2S, b"ARRIVE")
        
        print("Dropping Round 0 message...")
        # Simulating drop by just NOT sending msg0
        
        print("Sending Round 1 message...")
        send_raw(sock, msg1)
        
        resp = recv_resp(sock)
        if resp is None:
            print("SUCCESS: Server rejected message due to key/state desync.")
            return True
        else:
            print("FAILURE: Server accepted message despite missing previous round!")
            return False
    finally:
        sock.close()
def attack_ciphertext_tamper():
    print("\n--- [Attack 5] Ciphertext Modification Attack ---")
    client_id = 1
    with open(f"keys/client_{client_id}.key", "rb") as f:
        master_key = f.read()

    fsm = ProtocolFSM(master_key, Role.CLIENT)

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.connect(SERVER_ADDR)

        # Construct valid message
        raw = get_raw_msg(fsm, CLIENT_HELLO, client_id, DIRECTION_C2S, b"CIPHER_ATTACK")

        # Layout:
        # len(4) | opcode(1) | cid(1) | round(4) | dir(1) | iv(16) | ciphertext | hmac(32)
        tampered = bytearray(raw)

        # Flip a bit inside ciphertext region (safe offset)
        tampered[4 + 7 + 16] ^= 0x01

        print("Sending ciphertext-tampered message...")
        send_raw(sock, tampered)

        resp = recv_resp(sock)
        if resp is None:
            print("SUCCESS: Server rejected modified ciphertext.")
            return True
        else:
            print("FAILURE: Server accepted modified ciphertext!")
            return False
    finally:
        sock.close()

def attack_reflection():
    print("\n--- [Attack 6] Reflection Attack ---")
    client_id = 1
    with open(f"keys/client_{client_id}.key", "rb") as f:
        master_key = f.read()

    fsm = ProtocolFSM(master_key, Role.CLIENT)

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        sock.connect(SERVER_ADDR)

        # Create valid CLIENT -> SERVER message
        raw = get_raw_msg(
            fsm,
            CLIENT_HELLO,
            client_id,
            DIRECTION_C2S,
            b"REFLECT_ME"
        )

        # Reflect attack: flip direction byte
        reflected = bytearray(raw)

        # Direction byte offset = len(4) + header(6) -> Index 10
        reflected[4 + 6] = 1  # Pretend SERVER -> CLIENT

        print("Sending reflected message (wrong direction)...")
        send_raw(sock, reflected)

        resp = recv_resp(sock)
        if resp is None:
            print("SUCCESS: Server rejected reflected message.")
            return True
        else:
            print("FAILURE: Server accepted reflected message!")
            return False
    finally:
        sock.close()

# -----------------------------------------------------------------------------
# Main Test Harness
# -----------------------------------------------------------------------------
def main():
    print("Starting Server for Attack Simulation...")
    # Restart server for fresh state for each test if needed, 
    # but one server instance should handle new connections cleanly.
    # We will just start it once.
    server = subprocess.Popen([sys.executable, "server.py"], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    time.sleep(2)
    
    try:
        results = []
        results.append(attack_hmac_tamper())
        results.append(attack_replay())
        results.append(attack_reordering())
        results.append(attack_drop())
        results.append(attack_ciphertext_tamper())
        results.append(attack_reflection())

        
        if all(results):
            print("\nALL ATTACKS CONFIRMED BLOCKED.")
            sys.exit(0)
        else:
            print("\nSOME ATTACKS SUCCEEDED (Protocol Vulnerable or Test Failed).")
            sys.exit(1)
            
    finally:
        server.terminate()
        try:
            out, err = server.communicate(timeout=2)
            # print("Server Log:", out) 
        except:
            server.kill()

if __name__ == "__main__":
    main()
