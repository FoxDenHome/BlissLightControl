#!/usr/bin/env python3

from binascii import unhexlify

from bleak import BleakClient
from crypto import create_login, derive_session_key, telink_aes_ivm_decrypt, make_ivm
from telink import TelinkSession, TelinkSessionConnector, PLAIN_HEADER_LEN_COMMAND
from light import Light
from asyncio import run as asyncio_run, sleep
from config import LIGHT_NAME

def decrypt_command(session: TelinkSession, command: bytes) -> bytes:
    return telink_aes_ivm_decrypt(session.session_key, make_ivm(command[0] | (command[1] << 8) | (command[2] << 16), session.mac), command, plain_header_len=PLAIN_HEADER_LEN_COMMAND)

def selftest():
    mesh_name = b"HMS56WVBEQN2FBG\0"
    # captured from own light
    login_bytes = unhexlify("0cc0b2dbfba6faed7847a9e6d5233fa800")
    login_random = login_bytes[1:9]
    assert login_bytes == create_login(login_random, mesh_name)

    session_key = derive_session_key(login_random, mesh_name, unhexlify("0d0b18cb58e4a456a1ef14cfe37592e387"))
    assert session_key == unhexlify("c53a8fc8702193e0f581b62f00cec197")

    dummy_session = TelinkSession(session_key=session_key, client=BleakClient(address_or_ble_device='dummy'), vendor_id=0x0211, mac=unhexlify("a4c138d5fde8"))


    dummy_session.vendor_id = 0x0211
    assert decrypt_command(dummy_session, unhexlify("9a4af31e31ca29db8f123a5f2fe0f6075dd2d9a8")) == unhexlify("9a4af31e314300f01102440a0000000000000000")
    dummy_session.sequence_number = 0xf34a9a
    assert dummy_session._encrypt_command(command=0xF0, mesh_address=0x0043, payload=unhexlify("440a0000000000000000")) == unhexlify("9a4af31e31ca29db8f123a5f2fe0f6075dd2d9a8") # pyright: ignore[reportPrivateUsage]

async def main():
    print("Self-test...")
    selftest()
    print("Self-test OK!")

    session_connector = TelinkSessionConnector()

    devices = await session_connector.find(LIGHT_NAME)
    if not devices:
        print("No devices found")
        return

    session = await session_connector.connect(device=devices[0])
    await session.enable_notify()

    while not session.ready():
        print("SM", session.mesh_address)
        await sleep(1)

    light = Light(session=session)

    colorcycles = [
        [255, 0, 0],
        [255, 255, 0],
        [0, 255, 0],
        [0, 255, 255],
        [0, 0, 255],
        [255, 0, 255],
    ]
    while True:
        for color in colorcycles:
            await light.set_direct(red=color[0], green=color[1], blue=color[2], laser=0, motor=0, brightness=255, breathe=False)
            await sleep(2)

if __name__ == "__main__":
    asyncio_run(main())
