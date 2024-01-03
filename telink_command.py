
from crypto import telink_aes_ivm_decrypt, telink_aes_ivm_encrypt, make_ivm
from config import MESH_VENDOR_ID

PLAIN_HEADER_LEN_COMMAND = 3

def telink_decrypt_command(session_key: bytes, command: bytes) -> bytes: # OK!
    return telink_aes_ivm_decrypt(session_key, make_ivm(command[0] | (command[1] << 8) | (command[2] << 16)), command, plain_header_len=PLAIN_HEADER_LEN_COMMAND)

def telink_encrypt_command(session_key: bytes, command: int, mesh_address: int, payload: bytes, sequence_number: int = -1) -> bytes: # OK!
    assert len(payload) == 10

    if sequence_number < 0:
        global sequence_number_counter
        sequence_number = sequence_number_counter
        sequence_number_counter += 1

    ble_data = bytes([
        sequence_number & 0xff,
        (sequence_number >> 8) & 0xff,
        (sequence_number >> 16) & 0xff,
        0,
        0,
        mesh_address & 0xff,
        (mesh_address >> 8) & 0xff,
        command | 0xc0,
        MESH_VENDOR_ID & 0xff,
        (MESH_VENDOR_ID >> 8) & 0xff]) + payload

    return telink_aes_ivm_encrypt(session_key, make_ivm(sequence_number), ble_data, plain_header_len=PLAIN_HEADER_LEN_COMMAND)
