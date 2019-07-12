import fcntl
import itertools
import os
from struct import Struct
from sys import version_info as sys_version
class StructHack(Struct):
    """Python <2.7.4 doesn't support struct unpack from bytearray."""
    def unpack_from(self, buf, offset=0):
        buf = buffer(buf)

        return Struct.unpack_from(self, buf, offset)

from io import FileIO
from time import sleep

from evdev import InputDevice
from pyudev import Context, Monitor

from ..backend import Backend
from ..exceptions import DeviceError
from ..device import DS4Device
from ..utils import zero_copy_slice


IOC_RW = 3221243904
HIDIOCSFEATURE = lambda size: IOC_RW | (0x06 << 0) | (size << 16)
HIDIOCGFEATURE = lambda size: IOC_RW | (0x07 << 0) | (size << 16)

if sys_version[:3] <= (2, 7, 4):
    S16LE = StructHack("<h")
else:
    S16LE = Struct("<h")

class FakeDS4Report(object):
    __slots__ = ["left_analog_x",
                 "left_analog_y",
                 "right_analog_x",
                 "right_analog_y",
                 "dpad_up",
                 "dpad_down",
                 "dpad_left",
                 "dpad_right",
                 "button_cross",
                 "button_circle",
                 "button_square",
                 "button_triangle",
                 "button_l1",
                 "button_r1",
                 "button_l2",
                 "button_r2",
                 "button_share",
                 "button_options",
                 "button_l3",
                 "button_r3",
                 "button_ps",
                 "button_trackpad",
                 "l2_analog",
                 "r2_analog",
                 "timestamp",
                 "battery",
                 "plug_usb",
                 "plug_audio",
                 "plug_mic"]

    def __init__(self, *args, **kwargs):
        for i, value in enumerate(args):
            setattr(self, self.__slots__[i], value)


class FakeDS4Device(DS4Device):
    def __init__(self, name, addr, type, hidraw_device, event_device):
        try:
            self.report_fd = os.open(hidraw_device, os.O_RDWR | os.O_NONBLOCK)
            self.fd = FileIO(self.report_fd, "rb+", closefd=False)
            self.input_device = InputDevice(event_device)
            self.input_device.grab()
        except (OSError, IOError) as err:
            raise DeviceError(err)

        self.buf = bytearray(self.report_size)

        super(FakeDS4Device, self).__init__(name, addr, type)

    def parse_report(self, buf):
        """parse a buffer containing a hid report."""
        dpad = buf[5] % 16

        return FakeDS4Report(
            # left analog stick
            buf[1], buf[2],
            # right analog stick
            buf[3], buf[4],
            # dpad up, down, left, right
            (dpad in (0, 1, 7)), (dpad in (3, 4, 5)),
            (dpad in (5, 6, 7)), (dpad in (1, 2, 3)),
            # buttons cross, circle, square, triangle
            (buf[5] & 32) != 0, (buf[5] & 64) != 0,
            (buf[5] & 16) != 0, (buf[5] & 128) != 0,
            # l1, r1 buttons
            (buf[6] & 1) != 0, (buf[6] & 2) != 0,
            # r1, r2 buttons
            (buf[6] & 4) != 0, (buf[6] & 8) != 0,
            # share and option buttons
            (buf[6] & 16) != 0, (buf[6] & 32) != 0,
            # l3 and r3 buttons
            (buf[6] & 64) != 0, (buf[6] & 128) != 0,
            # ps and trackpack buttons
            (buf[7] & 1) != 0, (buf[7] & 2) != 0,
            # l2 analog, r2 analog
            buf[8], buf[9],
            # timestamp and battery
            buf[7] >> 2,
            buf[30] % 16,
            # external inputs (usb, audio, mic)
            (buf[30] & 16) != 0, (buf[30] & 32) != 0,
            (buf[30] & 64) != 0
        )

    def read_report(self):
        try:
            ret = self.fd.readinto(self.buf)
        except IOError:
            return

        # Disconnection
        if ret == 0:
            return

        # Invalid report size or id, just ignore it
        if ret < self.report_size or self.buf[0] != self.valid_report_id:
            return False

        if self.type == "bluetooth":
            # Cut off bluetooth data
            buf = zero_copy_slice(self.buf, 2)
        else:
            buf = self.buf

        return self.parse_report(buf)

    def read_feature_report(self, report_id, size):
        op = HIDIOCGFEATURE(size + 1)
        buf = bytearray(size + 1)
        buf[0] = report_id

        return fcntl.ioctl(self.fd, op, bytes(buf))

    def write_report(self, report_id, data):
        hid = bytearray((report_id,))
        self.fd.write(hid + data)

    def close(self):
        try:
            # Reset LED to original hidraw pairing colour.
            self.set_led(0, 0, 1)

            self.fd.close()
            self.input_device.ungrab()
        except IOError:
            pass


class FakeUSBDS4Device(FakeDS4Device):
    __type__ = "usb"

    report_size = 64
    valid_report_id = 0x01

    def set_operational(self):
        # Get the bluetooth MAC
        #addr = self.read_feature_report(0x81, 6)[1:]
        addr = [0,0,0,0,0,0]
        addr = ["{0:02x}".format(c) for c in bytearray(addr)]
        addr = ":".join(reversed(addr)).upper()

        self.device_name = "{0} {1}".format(addr, self.device_name)
        self.device_addr = addr

HID_DEVICES = {
    "Sony Computer Entertainment Wireless Controller": FakeUSBDS4Device
}


class FakeBackend(Backend):
    __name__ = "hidraw"

    def setup(self):
        pass

    def _get_future_devices(self, context):
        """Return a generator yielding new devices."""
        monitor = Monitor.from_netlink(context)
        monitor.filter_by("hidraw")
        monitor.start()

        self._scanning_log_message()
        for device in iter(monitor.poll, None):
            if device.action == "add":
                # Sometimes udev rules has not been applied at this point,
                # causing permission denied error if we are running in user
                # mode. With this sleep this will hopefully not happen.
                sleep(1)

                yield device
                self._scanning_log_message()

    def _scanning_log_message(self):
        self.logger.info("Scanning for fake ds4 devices")

    @property
    def devices(self):
        """Wait for new DS4 devices to appear."""
        context = Context()

        existing_devices = context.list_devices(subsystem="hidraw")
        future_devices = self._get_future_devices(context)

        for hidraw_device in itertools.chain(existing_devices, future_devices):
            hid_device = hidraw_device.parent
            if hid_device.subsystem != "hid":
                continue

            cls = HID_DEVICES.get(hid_device.get("HID_NAME"))
            if not cls:
                continue

            for child in hid_device.parent.children:
                event_device = child.get("DEVNAME", "")
                if event_device.startswith("/dev/input/event"):
                    break
            else:
                continue


            try:
                device_addr = hid_device.get("HID_UNIQ", "").upper()
                if device_addr:
                    device_name = "{0} {1}".format(device_addr,
                                                   hidraw_device.sys_name)
                else:
                    device_name = hidraw_device.sys_name

                yield cls(name=device_name,
                          addr=device_addr,
                          type=cls.__type__,
                          hidraw_device=hidraw_device.device_node,
                          event_device=event_device)

            except DeviceError as err:
                self.logger.error("Unable to open DS4 device: {0}", err)
