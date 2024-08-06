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

import socket
import time
import traceback
from functools import reduce
from itertools import batched
from logging import DEBUG, INFO

from electricmeters.__main__ import logger
from electricmeters.mercury import MeterConfig, Config
from electricmeters.meter import AbstractMeter


# from random import SystemRandom

# random = SystemRandom()


class Mercury236(AbstractMeter):
    """
    Mercury meter
    """

    def __init__(
        self,
        host: str,
        port: int,
        address: int,
        password: str,
        *,
        access_level: int = 1,
        timeout: int = 30,
        metric_prefix: int = 1,
        debug: bool = False,
    ):
        if (address_length := len(f"{address}")) == 8:
            address = address % 1000
            if address == 0:
                address = 1
            elif address > 240:
                address = address % 100
        elif address_length > 3:
            raise ValueError(f"Invalid address length: {address_length}")
        elif 1 > address or address > 240:
            raise ValueError("Address must be >= 1 and <= 240")

        super().__init__(
            host,
            port,
            address,
            password,
            timeout=timeout,
            metric_prefix=metric_prefix,
            debug=debug,
        )

        self.access_level = access_level
        self._socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._socket.settimeout(self.timeout)

    def open(self):
        self._socket.connect((self.host, self.port))
        self.request(0x01, self.access_level, *self.password)

    def close(self):
        self.request(0x02)
        self._socket.close()

    def request(self, *args):
        self._socket.sendall(self._pack_message(self.address, *args))
        self.log(DEBUG, f"{args} sent to {self.address}")
        response = self._read_socket()

        if len(response) > 1:
            address, data = self._unpack_message(response)
            if address == self.address:
                return data

        raise ValueError("Error while read data from socket")

    def _read_socket(self):
        data = ""
        buffer = b""

        while not data:
            self._socket.settimeout(self.timeout)
            data = self._socket.recv(1000)
            if data:
                buffer += data

        self._socket.settimeout(None)

        return buffer

    def read(self, *args, raw=False, order: list[int] = None):
        response = self.request(*args)

        if raw:
            return response
        else:
            return self._decode_response(response, order)

    def read_energy(
        self,
        request_code: int = 0x05,
        array: int = 0x00,
        month: int = 0x01,
        tariff: int = 0x00,
    ):
        if request_code not in {0, 1, 2, 3, 4, 5, 6, 9, 10, 11, 12, 13}:
            raise ValueError("Invalid request code")

        if tariff not in {0, 1, 2, 3, 4, 6}:
            raise ValueError("Invalid tariff number")

        if array in {3, 11}:
            if 0 < month < 13:
                array = (array << 4) | month
            else:
                raise ValueError("Invalid month number")
        elif array == 6:
            raise NotImplementedError()
        elif array in {0, 1, 2, 4, 5, 9, 10, 11, 12, 13}:
            array = (array << 4) | 0
        else:
            raise ValueError("Invalid array number")

        data = self.read(request_code, array, tariff, order=[1, 0, 3, 2])

        if request_code == 5:
            return {
                "active+": next(data) / self.metric_prefix
                if self.metric_prefix > 1
                else next(data),
                "active-": next(data) / self.metric_prefix
                if self.metric_prefix > 1
                else next(data),
                "reactive+": next(data) / self.metric_prefix
                if self.metric_prefix > 1
                else next(data),
                "reactive-": next(data) / self.metric_prefix
                if self.metric_prefix > 1
                else next(data),
            }
        else:
            raise NotImplementedError("Request code is not implemented")

    def read_unsafe(self, *args, order: list[int] = None):
        data = self.read(*args, order=order)
        return {
            index: value / self.metric_prefix
            if self.metric_prefix > 1
            else value
            for index, value in enumerate(data)
        }

    def _pack_message(self, *args, crc=True):
        message = bytes(args)
        self.log(DEBUG, f"Before pack: {self.pretty_hex(message)}")
        result = message + Mercury236.crc16(message) if crc else message
        self.log(DEBUG, f"After pack: {self.pretty_hex(result)}")
        return result

    def _unpack_message(self, message: bytes):
        self.log(DEBUG, f"Before unpack: {self.pretty_hex(message)}")
        address = int.from_bytes(message[:1], "big")
        data = list(message[1:])
        self.log(DEBUG, f"After unpack: {address} {data}")
        return address, data

    @staticmethod
    def _decode_response(data, order: list[int] = None):
        for chunk in batched(data[:-2], 4):
            if isinstance(order, list) and len(order) == 4:
                chunk = [
                    chunk[order[0]],
                    chunk[order[1]],
                    chunk[order[2]],
                    chunk[order[3]],
                ]

            chunk = [value for value in chunk if value > 0]

            if len(chunk) == 0 or chunk == [255, 255, 255, 255]:
                chunk = [0]

            yield reduce(lambda x, y: x << 8 | y, chunk)

    @staticmethod
    def crc16(data):
        crc = 0xFFFF
        data_length = len(data)
        i = 0
        while i < data_length:
            j = 0
            crc = crc ^ data[i]
            while j < 8:
                if crc & 0x1:
                    mask = 0xA001
                else:
                    mask = 0x00
                crc = ((crc >> 1) & 0x7FFF) ^ mask
                j += 1
            i += 1
        if crc < 0:
            crc -= 256

        return bytes((crc % 256, crc // 256))

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
                    for _ in group.meters:
                        meter: MeterConfig = group.meters[index]
                        password = meter.password or config.password
                        address = meter.address or meter.serial_number
                        em_result = {"meter": address}
                        time.sleep(config.delay)
                        em = None
                        try:
                            em = Mercury236(
                                address=address,
                                access_level=config.access_level,
                                password=password,
                                host=converter.ip,
                                port=converter.port,
                                debug=config.debug,
                                metric_prefix=config.metric_prefix,
                                timeout=config.timeout,
                            )
                            em.log(INFO, "Initialized")
                            # emulate
                            # if random.random() < 0.5:
                            #     raise TimeoutError("timeout")
                            # else:
                            #     em.log(INFO, "Reading started")
                            #     for payload in config.payload_list:
                            #         hex_payload = hex(
                            #             int.from_bytes(payload)
                            #         )
                            #         payload_key = f"payload_{hex_payload}"
                            #         if (
                            #             config.response_template
                            #             == "read_energy"
                            #             and len(payload) == 4
                            #         ):
                            #             em_result[payload_key] = 1
                            #         elif config.response_template is None:
                            #             em_result[payload_key] = 1
                            #         else:
                            #             raise ValueError("Invalid payload")
                            em.open()
                            em_result["address"] = em.address

                            for payload in config.payload_list:
                                hex_payload = hex(int.from_bytes(payload))
                                payload_key = f"payload_{hex_payload}"
                                if (
                                    meter.response_template == "read_energy"
                                    and len(payload) == 4
                                ):
                                    em_result[payload_key] = em.read_energy(
                                        *payload
                                    )
                                elif meter.response_template is None:
                                    em_result[payload_key] = em.read_unsafe(
                                        *payload
                                    )
                                else:
                                    raise ValueError("Invalid payload")
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
