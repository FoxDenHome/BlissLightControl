from telink import TelinkSession

COMMAND_LIGHT_CONTROL = 0xF0 # -16 signed

class Light:
    session: TelinkSession

    def __init__(self, session: TelinkSession):
        super().__init__()
        self.session = session

    # 9a4af31e314300f0
    # 1102440a0000000000000000

    async def _send_command(self, payload: bytes, response: bool = False):
        await self.session.send_command(command=COMMAND_LIGHT_CONTROL, payload=payload, response=response)

    async def set_direct(self, red: int, green: int, blue: int, laser: int, motor: int, brightness: int, breathe: bool):
        # All the ints are 0-255 (motor regulates the speed, others are brightness)
        await self._send_command(payload=bytes([
            71,
            red,
            green,
            blue,
            laser,
            motor,
            brightness,
            1 if breathe else 0,
        ]))

    async def set_onoff(self, on: bool):
        await self._send_command(payload=bytes([
            65,
            1 if on else 0,
            1,
        ]))

    async def set_scene(self, scene: int):
        await self._send_command(payload=bytes([
            65,
            scene,
            0,
        ]))
