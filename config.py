from binascii import unhexlify

MESH_NAME = b"HMS56WVBEQN2FBG\0" # grabbed from android app fuckery with my own light
MESH_PASSWORD = b"123\0\0\0\0\0\0\0\0\0\0\0\0\0" # always seems to be this
MESH_VENDOR_ID = 0x0211 #0x00e0
LIGHT_MAC = unhexlify("a4 c1 38 d5 fd e8".replace(" ", ""))
