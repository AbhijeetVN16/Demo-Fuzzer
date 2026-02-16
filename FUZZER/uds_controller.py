import time
import can
import isotp

class UDSController:
    def __init__(self, interface="vcan0", rxid=0x7E8, txid=0x7E0):
        self.interface = interface
        try:
            self.bus = can.Bus(interface, bustype="socketcan")
            self.link = isotp.CanStack(
                bus=self.bus,
                address=isotp.Address(isotp.AddressingMode.Normal_11bits, rxid=rxid, txid=txid),
                params={'stmin': 0, 'blocksize': 8}
            )
        except Exception as e:
            raise ConnectionError(f"Failed to initialize CAN: {e}")

    def send_recv(self, payload, timeout=0.8):
        self.link.send(payload)
        start = time.time()
        while time.time() - start < timeout:
            self.link.process()
            if self.link.available():
                return self.link.recv()
            time.sleep(0.01)
        return None

    def check_alive(self):
        return self.send_recv(bytes([0x3E, 0x00])) is not None
