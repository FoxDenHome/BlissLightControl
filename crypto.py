from Cryptodome.Cipher import AES
from config import MESH_NAME, MESH_PASSWORD

BLE_GATT_OP_PAIR_ENC_REQ = b"\x0C"
BLE_GATT_OP_PAIR_ENC_RSP = b"\x0D"
BLE_GATT_OP_PAIR_ENC_FAIL = b"\x0E"

sequence_number_counter = 0

def pad_to_len(data: bytes, pad_to: int) -> bytes:
    if len(data) > pad_to:
        raise ValueError('data length exceeds padding length')
    if len(data) == pad_to:
        return data
    return (data + b"\0"*pad_to)[:pad_to]

def pad_to_16(data: bytes) -> bytes:
    return pad_to_len(data, 16)

def telink_aes_base_encrypt(key: bytes, data: bytes) -> bytes: # OK!
    cipher = AES.new(key[::-1], AES.MODE_ECB) # type: ignore[reportUnknownMemberType]
    return cipher.encrypt(data[::-1])

def telink_aes_att_encrypt(key: bytes, data: bytes) -> bytes: # OK!
    return telink_aes_base_encrypt(key, data)[::-1]

def telink_aes_ivm_decrypt(key: bytes, ivm: bytes, payload: bytes, plain_header_len: int) -> bytes: # OK!
    payload_list = bytearray(payload)
    offset_after_check = plain_header_len + 2
    encrypted_len = len(payload) - offset_after_check

    # Stage 2
    ivm_padded = pad_to_16(b"\x00" + ivm)
    encrypted = telink_aes_att_encrypt(key, ivm_padded)
    for i in range(encrypted_len):
        payload_list[i + offset_after_check] ^= encrypted[i]

    # Stage 1
    ivm_padded = pad_to_16(ivm + bytes([encrypted_len]))
    encrypted_list = list(telink_aes_att_encrypt(key, ivm_padded))
    for i in range(encrypted_len):
        encrypted_list[i] ^= payload_list[i + offset_after_check]
    encrypted = telink_aes_att_encrypt(key, bytes(encrypted_list))

    if bytes(payload_list[plain_header_len:plain_header_len+2]) != encrypted[0:2]:
      raise ValueError('Excepted encryption match')

    return bytes(payload_list)

def telink_aes_ivm_encrypt(key: bytes, ivm: bytes, payload: bytes, plain_header_len: int) -> bytes: # OK!
    payload_list = list(payload)
    offset_after_check = plain_header_len + 2
    encrypted_len = len(payload) - offset_after_check

    # Stage 1
    ivm_padded = pad_to_16(ivm + bytes([encrypted_len]))

    encrypted_list = list(telink_aes_att_encrypt(key, ivm_padded))
    for i in range(encrypted_len):
        encrypted_list[i] ^= payload_list[i + offset_after_check]
    encrypted = telink_aes_att_encrypt(key, bytes(encrypted_list))

    for i in range(2):
        payload_list[i + plain_header_len] = encrypted[i]

    # Stage 2
    ivm_padded = pad_to_16(b"\x00" + ivm)
    encrypted = telink_aes_att_encrypt(key, ivm_padded)
    for i in range(encrypted_len):
        payload_list[i + offset_after_check] ^= encrypted[i]

    return bytes(payload_list)

def bytes_xor(a: bytes, b: bytes) -> bytes: # OK!
    return bytes([x ^ y for x, y in zip(a, b)])

def create_login(login_random: bytes) -> bytes: # OK!
    mesh_xor = bytes_xor(MESH_NAME, MESH_PASSWORD)
    padded_login_random = pad_to_16(login_random)
    encrypt = telink_aes_base_encrypt(padded_login_random, mesh_xor)
    return BLE_GATT_OP_PAIR_ENC_REQ + login_random + encrypt[8:16][::-1]

def derive_session_key(login_random: bytes, login_response: bytes) -> bytes: # OK!
    assert login_response[0] == BLE_GATT_OP_PAIR_ENC_RSP[0]
    resp_data = login_response[1:]

    mesh_xor = bytes_xor(MESH_NAME, MESH_PASSWORD)
    padded_device_random = pad_to_16(resp_data[:8])

    encrypt_check = telink_aes_base_encrypt(padded_device_random, mesh_xor)
    assert encrypt_check[8:16][::-1] == resp_data[8:16]

    session_key_base = login_random + resp_data[:8]
    return telink_aes_base_encrypt(mesh_xor, session_key_base)[::-1]

def make_ivm(sequence_number: int, mac: bytes) -> bytes: # OK!
    return mac[::-1][:4] + bytes([1, sequence_number & 0xff, (sequence_number >> 8) & 0xff, (sequence_number >> 16) & 0xff])

def make_ivs(mac: bytes, data: bytes) -> bytes: # OK!
    return mac[::-1][:3] + data[:5]
