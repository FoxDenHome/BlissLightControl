from telink import TelinkSession

COMMAND_LIGHT_CONTROL = 0xF0 # -16 signed

class Light:
    session: TelinkSession

    def __init__(self, session: TelinkSession):
        self.session = session

    # 9a4af31e314300f0
    # 1102440a0000000000000000
        
    async def _send_command(self, payload: bytes, response: bool = False):
        await self.session.send_command(command=COMMAND_LIGHT_CONTROL, payload=payload, response=response)

    async def set_diy_overall(self, red: int, green: int, blue: int, speed: int, brightness: int, diy_id: int = 10, selected_effect: int = 0xFF, index: int = 0):
        await self._send_command(payload=bytes([
            24,
            diy_id,
            1,
            selected_effect,
            index,
            red,
            green,
            blue,
            speed,
            brightness,
        ]))

    async def set_onoff(self, on: bool):
        await self._send_command(payload=bytes([
            65,
            1 if on else 0,
            1,
        ]))

    async def set_scene(self, scene: int):
        if scene == 0:
            await self.set_onoff(on=False)
            return
        await self._send_command(payload=bytes([
            17,
            scene,
        ]))
