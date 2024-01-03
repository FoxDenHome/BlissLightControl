
from crypto import telink_aes_ivm_decrypt, telink_aes_ivm_encrypt, make_ivm, make_ivs, create_login, derive_session_key, pad_to_len
from bleak import BleakClient, BleakGATTCharacteristic
from os import urandom

PLAIN_HEADER_LEN_COMMAND = 3
PLAIN_HEADER_LEN_NOTIFY = 5

SERVICE_UUID = "00010203-0405-0607-0809-0a0b0c0d1910"
CHARACTERISTIC_PAIR_UUID = "00010203-0405-0607-0809-0a0b0c0d1914"
CHARACTERISTIC_COMMAND_UUID = "00010203-0405-0607-0809-0a0b0c0d1912"
CHARACTERISTIC_NOTIFY_UUID = "00010203-0405-0607-0809-0a0b0c0d1911"

class TelinkSession:
    address: str
    mac: bytes
    session_key: bytes
    client: BleakClient
    sequence_number: int

    mesh_address: int = 65535
    vendor_id: int = 0x00e0

    def __init__(self, address: str):
        self.address = address
        self.sequence_number = 1337

    def set_mac(self, mac: str):
        self.mac = bytes.fromhex(mac.replace(":", "").replace(" ", ""))

    async def connect(self):
        self.client = BleakClient(self.address, services=[SERVICE_UUID])
        await self.client.connect()
    
        login_random = urandom(8)
        login_packet = create_login(login_random)

        await self.client.write_gatt_char(CHARACTERISTIC_PAIR_UUID, login_packet)
        login_response = await self.client.read_gatt_char(CHARACTERISTIC_PAIR_UUID)
        
        self.session_key = derive_session_key(login_random, login_response)

    def ready(self) -> bool:
        return self.mesh_address != 65535

    async def enable_notify(self):
        await self.client.start_notify(CHARACTERISTIC_NOTIFY_UUID, lambda *args, **kwargs: self.handle_notify(*args, **kwargs))
        await self.client.write_gatt_char(CHARACTERISTIC_NOTIFY_UUID, b"\x01", response=True)
        await self.send_command(0xE4, b"", response=False)

    def handle_notify(self, sender: BleakGATTCharacteristic, data: bytearray):
        decrypted = self._decrypt_notify(data)
        if len(decrypted) < 20:
            return

        self.vendor_id = decrypted[8] | (decrypted[9] << 8)
        self.mesh_address = decrypted[3] | (decrypted[4] << 8)

        notify_extra = decrypted[10:]
        print("NE", notify_extra.hex())

    def _decrypt_notify(self, notify: bytes) -> bytes:
        return telink_aes_ivm_decrypt(self.session_key, make_ivs(self.mac, notify), notify, plain_header_len=PLAIN_HEADER_LEN_NOTIFY)

    def _encrypt_command(self, command: int, payload: bytes) -> bytes:
        assert len(payload) <= 10
        payload = pad_to_len(payload, 10)

        sequence_number = self.sequence_number
        self.sequence_number += 1

        ble_data = bytes([
            sequence_number & 0xff,
            (sequence_number >> 8) & 0xff,
            (sequence_number >> 16) & 0xff,
            0,
            0,
            self.mesh_address & 0xff,
            (self.mesh_address >> 8) & 0xff,
            command | 0xc0,
            self.vendor_id & 0xff,
            (self.vendor_id >> 8) & 0xff,
        ]) + payload

        return telink_aes_ivm_encrypt(self.session_key, make_ivm(sequence_number, self.mac), ble_data, plain_header_len=PLAIN_HEADER_LEN_COMMAND)

    async def send_command(self, command: int, payload: bytes, response: bool):
        await self.client.write_gatt_char(CHARACTERISTIC_COMMAND_UUID, data=self._encrypt_command(command, payload), response=response)
