# protocol_fsm.py

import struct
import hashlib
from enum import Enum

from crypto_utils import (
    aes_encrypt,
    aes_decrypt,
    compute_hmac,
    pkcs7_pad,
    pkcs7_unpad,
    secure_random,
)

# ------------------------------------------------------------
# Roles and States
# ------------------------------------------------------------

class Role(Enum):
    CLIENT = 0
    SERVER = 1


class State(Enum):
    INIT = 0
    ACTIVE = 1
    TERMINATED = 2


# ------------------------------------------------------------
# Opcodes
# ------------------------------------------------------------

CLIENT_HELLO         = 10
SERVER_CHALLENGE     = 20
CLIENT_DATA          = 30
SERVER_AGGR_RESPONSE = 40
KEY_DESYNC_ERROR     = 50
TERMINATE            = 60

OPCODE_NAMES = {
    10: "CLIENT_HELLO",
    20: "SERVER_CHALLENGE",
    30: "CLIENT_DATA",
    40: "SERVER_AGGR_RESPONSE",
    50: "KEY_DESYNC_ERROR",
    60: "TERMINATE"
}


# ------------------------------------------------------------

def H(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


# ------------------------------------------------------------
# Protocol FSM
# ------------------------------------------------------------

class ProtocolFSM:
    def __init__(self, master_key: bytes, role: Role):
        self.role = role
        self.state = State.INIT
        self.round = 0

        self.c2s_enc = H(master_key + b"C2S-ENC")[:16]
        self.c2s_mac = H(master_key + b"C2S-MAC")

        self.s2c_enc = H(master_key + b"S2C-ENC")[:16]
        self.s2c_mac = H(master_key + b"S2C-MAC")

    # --------------------------------------------------------
    # Key selection
    # --------------------------------------------------------

    def _incoming_keys(self):
        return (self.c2s_enc, self.c2s_mac) if self.role == Role.SERVER \
               else (self.s2c_enc, self.s2c_mac)

    def _outgoing_keys(self):
        return (self.c2s_enc, self.c2s_mac) if self.role == Role.CLIENT \
               else (self.s2c_enc, self.s2c_mac)

    # --------------------------------------------------------
    # INBOUND message
    # --------------------------------------------------------

    def verify_and_decrypt(self, msg: dict) -> bytes:
        if self.state == State.TERMINATED:
            raise RuntimeError("Protocol terminated")

        # 🔒 strict replay protection
        if msg["round"] != self.round:
            self.state = State.TERMINATED
            raise RuntimeError("Round mismatch")

        enc_key, mac_key = self._incoming_keys()

        mac_data = (
            struct.pack("!BBI",
                msg["opcode"],
                msg["client_id"],
                msg["round"],
            )
            + bytes([msg["direction"]])
            + msg["iv"]
            + msg["ciphertext"]
        )

        if compute_hmac(mac_key, mac_data) != msg["hmac"]:
            self.state = State.TERMINATED
            raise RuntimeError("HMAC verification failed")

        plaintext = pkcs7_unpad(
            aes_decrypt(enc_key, msg["iv"], msg["ciphertext"])
        )

        # 🔑 evolve keys + advance round HERE ONLY
        self._evolve_keys(
            incoming=True, 
            iv=msg["iv"], 
            ciphertext=msg["ciphertext"], 
            plaintext=plaintext,
            opcode=msg["opcode"]
        )
        self.round += 1

        if self.state == State.INIT:
            self.state = State.ACTIVE

        if msg["opcode"] == TERMINATE:
            self.state = State.TERMINATED

        return plaintext

    # --------------------------------------------------------
    # OUTBOUND message
    # --------------------------------------------------------

    def encrypt_and_mac(self, opcode, client_id, direction, plaintext):
        if self.state == State.TERMINATED:
            raise RuntimeError("Cannot send after termination")

        enc_key, mac_key = self._outgoing_keys()

        iv = secure_random(16)
        ciphertext = aes_encrypt(enc_key, iv, pkcs7_pad(plaintext))

        mac_data = (
            struct.pack("!BBI",
                opcode,
                client_id,
                self.round,   # 👈 current round
            )
            + bytes([direction])
            + iv
            + ciphertext
        )

        tag = compute_hmac(mac_key, mac_data)

        # 🔑 evolve keys + advance round HERE TOO
        self._evolve_keys(
            incoming=False, 
            iv=iv, 
            ciphertext=ciphertext, 
            plaintext=plaintext, 
            opcode=opcode
        )
        self.round += 1

        return {
            "opcode": opcode,
            "client_id": client_id,
            "round": self.round - 1, # wire round is pre-increment
            "direction": direction,
            "iv": iv,
            "ciphertext": ciphertext,
            "hmac": tag,
        }

    # --------------------------------------------------------
    # Key evolution
    # --------------------------------------------------------

    def _evolve_keys(self, incoming: bool, iv: bytes, ciphertext: bytes, plaintext: bytes, opcode: int):
        # Correctly selecting keys based on Role + Direction
        # Incoming:
        #   Server: Client->Server (c2s)
        #   Client: Server->Client (s2c)
        # Outgoing:
        #   Server: Server->Client (s2c)
        #   Client: Client->Server (c2s)
        
        is_c2s = False
        
        if self.role == Role.SERVER:
            if incoming: is_c2s = True   # Server receiving (Incoming C2S)
            else:        is_c2s = False  # Server sending (Outgoing S2C)
        else: # CLIENT
            if incoming: is_c2s = False  # Client receiving (Incoming S2C)
            else:        is_c2s = True   # Client sending (Outgoing C2S)

        # C2S Evolution: Enc <- H(Enc || Ciphertext), Mac <- H(Mac || Nonce/IV)
        if is_c2s:
            self.c2s_enc = H(self.c2s_enc + ciphertext)[:16]
            self.c2s_mac = H(self.c2s_mac + iv)
            
        # S2C Evolution: Enc <- H(Enc || Plaintext), Mac <- H(Mac || Plaintext)
        # SPECIAL CASE FOR AGGR RESPONSE:
        # S2C_Enc_{R+1} = H(S2C_Enc_R || AggregatedData_R)
        # S2C_Mac_{R+1} = H(S2C_Mac_R || StatusCode_R)
        else:
            if opcode == SERVER_AGGR_RESPONSE:
                # In SERVER_AGGR_RESPONSE, plaintext = aggregated_value || status_code
                # We assume status code is last 1 byte, aggregated value is rest.
                # Client code ensures this structure
                if len(plaintext) < 1:
                     # Fallback for empty (should not happen in valid proto)
                    status_code = b""
                    aggr_data = plaintext
                else:
                    status_code = plaintext[-1:]
                    aggr_data = plaintext[:-1]

                self.s2c_enc = H(self.s2c_enc + aggr_data)[:16]
                self.s2c_mac = H(self.s2c_mac + status_code)
            else:
                # Default behavior for other S2C messages (e.g. handshake)
                self.s2c_enc = H(self.s2c_enc + plaintext)[:16]
                self.s2c_mac = H(self.s2c_mac + plaintext)
