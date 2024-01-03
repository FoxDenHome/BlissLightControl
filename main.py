#!/usr/bin/env python3

from binascii import unhexlify
from crypto import create_login, derive_session_key
from telink_command import telink_decrypt_command, telink_encrypt_command

LIGHT_MESH_ADDRESS = 0x0043 # TODO: Figure this out if it changes?

COMMAND_LIGHT_CONTROL = 0xF0 # -16 signed

def selftest():
    # captured from own light
    login_bytes = unhexlify("0cc0b2dbfba6faed7847a9e6d5233fa800")
    login_random = login_bytes[1:9]
    assert login_bytes == create_login(login_random)

    session_key = derive_session_key(login_random, unhexlify("0d0b18cb58e4a456a1ef14cfe37592e387"))
    assert session_key == unhexlify("c53a8fc8702193e0f581b62f00cec197")

    assert telink_decrypt_command(session_key, unhexlify("9a4af31e31ca29db8f123a5f2fe0f6075dd2d9a8")) == unhexlify("9a4af31e314300f01102440a0000000000000000")
    assert telink_encrypt_command(session_key, command=COMMAND_LIGHT_CONTROL, mesh_address=0x0043, sequence_number=0xf34a9a, payload=unhexlify("440a0000000000000000")) == unhexlify("9a4af31e31ca29db8f123a5f2fe0f6075dd2d9a8")

def main():
    print("Self-test...")
    selftest()
    print("Self-test OK!")

if __name__ == "__main__":
    main()
