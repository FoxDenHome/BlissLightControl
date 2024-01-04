
from crypto import telink_aes_ivm_decrypt, telink_aes_ivm_encrypt, make_ivm, make_ivs, create_login, derive_session_key, pad_to_len
from bleak import BleakClient, BleakScanner
from bleak.backends.device import BLEDevice
from bleak.backends.characteristic import BleakGATTCharacteristic
from os import urandom
from dataclasses import dataclass

PLAIN_HEADER_LEN_COMMAND = 3
PLAIN_HEADER_LEN_NOTIFY = 5

COMMAND_FIND_MESH = 0xE4

SERVICE_UUID = "00010203-0405-0607-0809-0a0b0c0d1910"
CHARACTERISTIC_PAIR_UUID = "00010203-0405-0607-0809-0a0b0c0d1914"
CHARACTERISTIC_COMMAND_UUID = "00010203-0405-0607-0809-0a0b0c0d1912"
CHARACTERISTIC_NOTIFY_UUID = "00010203-0405-0607-0809-0a0b0c0d1911"

MESH_ADDRESS_UNKNOWN = -1
MESH_ADDRESS_BROADCAST = 0xFFFF

class TelinkSession:
    session_key: bytes
    client: BleakClient
    mac: bytes
    sequence_number: int
    vendor_id: int
    mesh_address: int = MESH_ADDRESS_UNKNOWN

    def __init__(self, session_key: bytes, client: BleakClient, vendor_id: int, mac: bytes):
        super().__init__()
        self.session_key = session_key
        self.client = client
        self.vendor_id = vendor_id
        self.mac = mac
        self.sequence_number = 1337


    async def enable_notify(self):
        await self.client.start_notify(CHARACTERISTIC_NOTIFY_UUID, lambda char, bytes: self.handle_notify(char, bytes)) # pyright: ignore[reportUnknownMemberType]
        await self.client.write_gatt_char(CHARACTERISTIC_NOTIFY_UUID, b"\x01", response=True)
        await self.send_command(COMMAND_FIND_MESH, b"", mesh_address=MESH_ADDRESS_BROADCAST)

    def handle_notify(self, sender: BleakGATTCharacteristic, data: bytearray):
        decrypted = self._decrypt_notify(bytes(data))
        if len(decrypted) < 20:
            return

        self.vendor_id = decrypted[8] | (decrypted[9] << 8)
        self.mesh_address = decrypted[3] | (decrypted[4] << 8)

        notify_extra = decrypted[10:]
        print("NE", notify_extra.hex())

    async def send_command(self, command: int, payload: bytes, response: bool = False, mesh_address: int | None = None):
      await self.client.write_gatt_char(CHARACTERISTIC_COMMAND_UUID, data=self._encrypt_command(command=command, payload=payload, mesh_address=mesh_address), response=response)

    def _decrypt_notify(self, notify: bytes) -> bytes:
        return telink_aes_ivm_decrypt(self.session_key, make_ivs(self.mac, notify), notify, plain_header_len=PLAIN_HEADER_LEN_NOTIFY)

    def _encrypt_command(self, command: int, payload: bytes, mesh_address: int | None = None) -> bytes:
        if len(payload) > 10:
            raise ValueError('payload must be less than 10 bytes')
        payload = pad_to_len(payload, 10)

        if not mesh_address:
            mesh_address = self.mesh_address

        if mesh_address == MESH_ADDRESS_UNKNOWN:
            raise ValueError('mesh_address is unknown')

        sequence_number = self.sequence_number
        self.sequence_number += 1

        ble_data = bytes([
            sequence_number & 0xff,
            (sequence_number >> 8) & 0xff,
            (sequence_number >> 16) & 0xff,
            0,
            0,
            mesh_address & 0xff,
            (mesh_address >> 8) & 0xff,
            command | 0xc0,
            self.vendor_id & 0xff,
            (self.vendor_id >> 8) & 0xff,
        ]) + payload

        return telink_aes_ivm_encrypt(self.session_key, make_ivm(sequence_number, self.mac), ble_data, plain_header_len=PLAIN_HEADER_LEN_COMMAND)

    def ready(self) -> bool:
        return self.mesh_address != MESH_ADDRESS_UNKNOWN


TELINK_VENDOR_ID = 0x0211

@dataclass
class TelinlkDevice:
    device: BLEDevice
    name: str
    vendor_id: int
    mac: bytes

class TelinkSessionConnector:
    def __init__(self):
        super().__init__()

    async def find(self, name: str | None = None) -> list[TelinlkDevice]:
        returned_devices: list[TelinlkDevice] = []
        devices = await BleakScanner.discover(return_adv=True) # pyright: ignore[reportUnknownMemberType]
        for data in devices.values():
            device, adv = data
            if not adv.local_name:
                continue
            if name and adv.local_name != name:
                continue
            if TELINK_VENDOR_ID not in adv.manufacturer_data:
                continue
            manufacturer_data = adv.manufacturer_data[TELINK_VENDOR_ID]
            if len(manufacturer_data) < 5:
                continue
            packet_vendor_id = manufacturer_data[0] | (manufacturer_data[1] << 8)
            if packet_vendor_id != TELINK_VENDOR_ID:
                continue
            returned_devices.append(TelinlkDevice(
                device=device,
                name=adv.local_name,
                vendor_id=packet_vendor_id,
                mac=bytes([
                    0xA4,
                    0xC1,
                    0x38,
                    manufacturer_data[4],
                    manufacturer_data[3],
                    manufacturer_data[2],
                ])
            ))
        return returned_devices

    async def connect(self, device: TelinlkDevice) -> TelinkSession:
        client = BleakClient(device.device, services=[SERVICE_UUID])
        _ = await client.connect() # pyright: ignore[reportUnknownMemberType]

        mesh_name = device.name.encode('ascii')

        login_random = urandom(8)
        login_packet = create_login(login_random, mesh_name)

        await client.write_gatt_char(CHARACTERISTIC_PAIR_UUID, login_packet)
        login_response = await client.read_gatt_char(CHARACTERISTIC_PAIR_UUID) # pyright: ignore[reportUnknownMemberType]

        session_key = derive_session_key(login_random, mesh_name, bytes(login_response))

        return TelinkSession(session_key, client, device.vendor_id, device.mac)
