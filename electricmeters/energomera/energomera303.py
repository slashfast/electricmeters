# Copyright (c) 2024 Vladislav Trofimenko <foss@slashfast.dev>
#
# Permission is hereby granted, free of charge, to any person obtaining
# a copy of this software and associated documentation files (the
# "Software"), to deal in the Software without restriction, including
# without limitation the rights to use, copy, modify, merge, publish,
# distribute, sublicense, and/or sell copies of the Software, and to
# permit persons to whom the Software is furnished to do so, subject to
# the following conditions:
#
# The above copyright notice and this permission notice shall be
# included in all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
# EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
# MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
# NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
# LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
# OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
# WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

import os
import time
import traceback
from datetime import date, timedelta
from functools import wraps
from logging import DEBUG, ERROR, INFO
from math import log10, trunc
from typing import Callable

from electricmeters.__main__ import logger
from electricmeters.config import MeterConfig
from electricmeters.energomera.config import Config
from electricmeters.meter import AbstractMeter

_SOH = b"\x01"
_STX = b"\x02"
_ETX = b"\x03"
_ACK = b"\x06"
_POST_INIT = b"\x21"  # !
_EOL = b"\x0d\x0a"  # \r\n
_INIT = b"\x2f\x3f"  # / ?
_CMD_SOHR = b"\x01\x52\x31\x02"  # SOH R 1 STX

WTZ = "#" if os.name == "nt" else "-"


def _delay(foo: Callable) -> Callable:
    @wraps(foo)
    def wrapper(self, *args, **kwargs):
        time.sleep(self.request_delay)
        return foo(self, *args, **kwargs)

    return wrapper


class Energomera303(AbstractMeter):
    def __init__(
        self,
        host: str,
        port: int,
        address: str | int,
        password: str = None,
        metric_prefix: int = 1000,
        debug: bool = False,
        session=True,
        timeout: int = 35,
        request_delay: float = 0.5,
    ):
        self.request_delay = request_delay
        self._session = session
        self._is_session = False

        if isinstance(address, int):
            address = str(address)

        if len(address) < 9:
            raise ValueError("Address length must be 9")

        if metric_prefix == 10 ** log10(metric_prefix):
            if metric_prefix >= 1000:
                self._metric_prefix = 1000 / metric_prefix
            else:
                self._metric_prefix = metric_prefix * 1000
        else:
            logger.debug(
                f'Incorrect metric prefix "{metric_prefix}" will be ignored',
                extra={"address": address},
            )
            self._metric_prefix = 1000

        address = address[-9:]

        super().__init__(
            host,
            port,
            address,
            password,
            timeout=timeout,
            metric_prefix=metric_prefix,
            debug=debug,
        )

    def open(self):
        self._socket.connect((self.host, self.port))

        if self._session:
            self.start_session()

    def start_session(self):
        if not self._is_session:
            response = self.request(_INIT, self.address, _POST_INIT, _EOL)
            self.log(DEBUG, f"Init response: {response}")
            response = self.request(_ACK, "051", _EOL)
            self.log(DEBUG, f"Acknowledge response: {response}")

            if self.password is not None:
                response = self.request(
                    _SOH, "P1", _STX, f"({self.password})", _ETX, bcc=True
                )
                self.log(DEBUG, f"Password response: {response}")

            self._is_session = True
            self.log(DEBUG, "Session started")
        else:
            raise Exception("Session already started")

    def stop_session(self):
        if self._is_session:
            self.request(_SOH, "B0", _ETX, bcc=True, decode=False, read=False)
            self._is_session = False
            self.log(DEBUG, "Session closed")

    def close(self):
        if self._session:
            self.stop_session()

        self._socket.close()

    def _read_socket(self):
        buffer = b""

        try:
            while True:
                self._socket.settimeout(self.timeout)
                data = self._socket.recv(72)

                if self.debug:
                    unpacked_data = self._unpack_message(data)
                    self.log(
                        DEBUG,
                        f'Recv: {self.pretty_hex(unpacked_data)}\t'
                        f'{unpacked_data.decode('ascii').replace('\r\n',
                                                                 '<CR><LF>')}',
                    )

                if data is None:
                    self.log(5, "DATA IS NONE")

                if data:
                    buffer += data

                self._socket.settimeout(None)

                try:
                    first_byte = self._unpack_message(buffer[0].to_bytes())

                    if first_byte == _ACK:
                        self.log(5, "ACK found")
                        break

                    elif is_stx := first_byte == _STX or first_byte == _SOH:
                        self.log(
                            5,
                            "First is STX" if is_stx else "First is SOH",
                        )

                        if self._unpack_message(buffer[-2].to_bytes()) == _ETX:
                            self.log(5, "ETX found")
                            break

                    elif first_byte == b"\x2f":
                        self.log(5, "First is /")

                        if self._unpack_message(buffer[-2:]) == _EOL:
                            self.log(5, "EOL found")
                            break
                    else:
                        self.log(5, f"First byte: {first_byte}")

                except IndexError:
                    pass
        except Exception as e:
            self.log(ERROR, f"{e}")

        self._socket.settimeout(None)

        return buffer

    @staticmethod
    def bcc(data: bytes):
        return Energomera303.parity_check((sum(data) & 0x7F)).to_bytes()

    def _pack_message(self, *args, parity_check=True, bcc=True):
        packed = b""
        for arg in args:
            if arg is None:
                continue
            if isinstance(arg, str):
                arg = bytes(map(ord, arg))

            packed += arg

        self.log(5, f"Before pack: {self.pretty_hex(packed)}")

        if parity_check:
            self.log(5, f"Before parity check: {self.pretty_hex(packed)}")

            packed = bytes(map(self.parity_check, packed))

            self.log(5, f"After parity check: {self.pretty_hex(packed)}")

        if bcc:
            self.log(5, f"Before BCC: {self.pretty_hex(packed)}")

            packed += self.bcc(packed[1:])

            self.log(5, f"After BCC: {self.pretty_hex(packed)}")

        self.log(DEBUG, f"After pack: {self.pretty_hex(packed)}")

        return packed

    def _unpack_message(self, data: bytes):
        self.log(5, f"Before unpack: {self.pretty_hex(data)}")

        data = bytes(map(lambda x: self.parity_check(x, True), data))

        self.log(5, f"After unpack: {self.pretty_hex(data)}")

        return data

    @_delay
    def request(
        self,
        *args,
        parity_check=True,
        bcc=False,
        decode=True,
        read=True,
        raw=None,
    ):
        if isinstance(raw, bytes):
            self._socket.sendall(raw)
        else:
            self._socket.sendall(
                self._pack_message(*args, parity_check=parity_check, bcc=bcc)
            )

        time.sleep(0.02)

        if read:
            response = self._read_socket()
            self.log(5, f"Raw response {repr(response)}")

            if len(response) > 0:
                response = self._unpack_message(response)
                hex_response = self.pretty_hex(response)
                if decode:
                    try:
                        response = response.decode("ascii")
                        self.log(
                            DEBUG,
                            f'Response: {hex_response}\t'
                            f'{response.replace('\r\n', '<CR><LF>')}',
                        )
                    except UnicodeDecodeError:
                        self.log(DEBUG, f"Skip decode {response}")
                return response[:-1] if bcc else response

            raise ValueError("Error while read data from socket")

    def to_meter_prefix(self, value: float, trunc_value=True) -> int | float:
        result = value * self._metric_prefix
        return trunc(result) if trunc_value else result

    def read_energy(self, *payload: int, value="", trunc_value=True):
        if payload[0] == 69:
            value = (date.today() - timedelta(days=1)).strftime(
                f"%{WTZ}d.%{WTZ}m.%y"
            )

        parameter = f"{bytes(payload).decode("ascii")}({value})"
        self.log(DEBUG, f"Prepared parameter: {parameter}")
        response = self.request(_SOH, "R1", _STX, parameter, _ETX, bcc=True)
        response = response[6:-2]
        response = response.split("\r\n")
        response = iter(
            map(
                lambda x: self.to_meter_prefix(
                    float(x.strip("()\r\n")), trunc_value=trunc_value
                ),
                response,
            )
        )
        return {
            f"tariff{index}": {"active+": value}
            for index, value in enumerate(response)
        }
        # return {
        #     "tariff0": {"active+": next(response)},
        #     "tariff1": {"active+": next(response)},
        #     "tariff2": {"active+": next(response)},
        #     "tariff3": {"active+": next(response)},
        #     "tariff4": {"active+": next(response)},
        #     "tariff5": {"active+": next(response)},
        # }

    @staticmethod
    def parity_check(target: int, reverse=False):
        if reverse:
            return (
                target & ~(1 << 7) if target.bit_count() % 2 == 0 else target
            )
        return target | (1 << 7) if target.bit_count() % 2 != 0 else target

    @staticmethod
    def pretty_hex(data: bytes):
        return " ".join(f"{ch:02X}" for ch in data)

    @staticmethod
    @AbstractMeter.json_output
    def compose(config: Config) -> list[dict]:
        result = []
        for converter in config.converters:
            converter_result = {
                "ip": converter.ip,
                "port": converter.port,
                "groups": [],
            }
            for group in converter.groups:
                group_result = {"name": group.name, "meters": []}
                for retry in range(1, config.max_retries + 1):
                    logger.info(f"Попытка {retry}", extra={"address": ""})
                    index = 0
                    for _ in range(len(group.meters)):
                        meter: MeterConfig = group.meters[index]
                        password = meter.password or config.password
                        address = meter.serial_number
                        em_result = {"meter": address}
                        time.sleep(config.delay)
                        em = None
                        try:
                            em = Energomera303(
                                address=address,
                                password=password,
                                host=converter.ip,
                                port=converter.port,
                                session=config.session,
                                debug=config.debug,
                                metric_prefix=config.metric_prefix,
                                timeout=config.timeout,
                                request_delay=config.request_delay,
                            )
                            em.log(INFO, "Initialized")
                            # emulate
                            # if (
                            #     random.random() < 0.5
                            # ):
                            #     raise TimeoutError("timeout")
                            # else:
                            #     em.log(INFO, "Reading started")
                            #     for payload in config.payload_list:
                            #         hex_payload = hex(
                            #         int.from_bytes(payload)
                            #         )
                            #         payload_key = f"payload_{hex_payload}"
                            #         em_result[payload_key] = 1
                            em.open()
                            em_result["address"] = em.address

                            for payload in config.payload_list:
                                payload_str = hex(int.from_bytes(payload))
                                payload_key = f"payload_{payload_str}"
                                em_result[payload_key] = em.read_energy(
                                    *payload
                                )
                            group.meters.remove(meter)
                            em.log(INFO, "Reading completed")
                        except Exception as e:
                            if em:
                                em.log(DEBUG, f"{e}")

                            if config.debug:
                                traceback.print_exc()

                            if retry == config.max_retries:
                                em_result["error"] = f"{e}"

                            index += 1

                            if retry != config.max_retries:
                                continue

                        finally:
                            if em:
                                try:
                                    em._socket.getpeername()
                                    em.close()
                                except OSError:
                                    pass

                        group_result["meters"].append(em_result)

                    if not group.meters:
                        break

                converter_result["groups"].append(group_result)

            result.append(converter_result)

        return result
