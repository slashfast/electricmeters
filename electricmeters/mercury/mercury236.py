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
import inspect
import json
import logging
import socket
from argparse import Namespace
from functools import reduce
from itertools import batched

from electricmeters.crc16 import crc16

logger = logging.getLogger(__name__)


class Mercury236:

    def __init__(self, ip: str, port: int, address: int, access_level: int = 1, password: str = '111111'):
        self._is_socket_open = False

        self.address = address % 1000
        if self.address == 0:
            self.address = 1
        elif self.address > 240:
            self.address = address % 100

        self.access_level = access_level
        self.password = [int(c) for c in password]
        if len(password) != 6:
            raise ValueError('Password length must be equal to 6')

        self.ip = ip
        self.port = port
        self._socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._socket_timeout = 5
        self._socket.settimeout(self._socket_timeout)

    def open(self):
        self._socket.connect((self.ip, self.port))
        self.request(0x01, self.access_level, *self.password)
        self._is_socket_open = True

    def close(self):
        self.request(0x02)
        self._socket.close()
        self._is_socket_open = False

    def request(self, *args):
        caller_name = inspect.stack()[1][3]
        print(f'Request caller: {caller_name}')
        self._socket.sendall(self._pack_message(self.address, *args))

        response = self._read_socket()

        if len(response) > 1:
            address, data = self._unpack_message(response)
            if address == self.address:
                return data

        raise ValueError(f"Error while read data from socket")

    def _read_socket(self):
        data = ''
        buffer = b''

        while not data:
            self._socket.settimeout(1)
            data = self._socket.recv(1000)
            if data:
                buffer += data

        self._socket.settimeout(self._socket_timeout)

        return buffer

    def read(self, *args, raw=False):
        response = self.request(*args)

        if raw:
            return response
        else:
            return self._decode_response(response)

    def read_unsafe(self, *args):
        data = self.read(*args)
        return {i: value for i, value in enumerate(data)}

    def read_energy(self, request_code: int = 0x05, array: int = 0x00, month: int = 1, tariff: int = 0x00):
        if request_code not in [0, 1, 2, 3, 4, 5, 6, 9, 10, 11, 12, 13]:
            raise ValueError('Invalid request code')

        if tariff not in [0, 1, 2, 3, 4, 6]:
            raise ValueError('Invalid tariff number')

        if array in [3, 11]:
            if 0 < month < 13:
                array = (array << 4) | month
            else:
                raise ValueError('Invalid month number')
        elif array == 6:
            raise NotImplementedError()
        elif array in [0, 1, 2, 4, 5, 9, 10, 11, 12, 13]:
            pass
        else:
            raise ValueError('Invalid array number')

        data = self.read(request_code, array, tariff)

        if request_code == 5:
            return {
                'active+': next(data),
                'active-': next(data),
                'reactive+': next(data),
                'reactive-': next(data)
            }
        else:
            raise NotImplementedError()

    def __enter__(self):
        self.open()
        return self

    def __exit__(self, *args):
        self.close()
        return self

    @staticmethod
    def _pack_message(*args, crc=True):
        caller_name = inspect.stack()[1][3]
        message = bytes(args)
        print(f'Before pack ({caller_name}): {hex(int.from_bytes(message))}')
        result = message + crc16(message) if crc else message
        print(f'After pack ({caller_name}): {hex(int.from_bytes(result))}')
        return result

    @staticmethod
    def _unpack_message(message: bytes):
        caller_name = inspect.stack()[1][3]
        print(f'Before unpack ({caller_name}): {hex(int.from_bytes(message))}')
        address = int.from_bytes(message[:1], 'big')
        data = list(message[1:])
        print(f'After unpack ({caller_name}): {hex(address), hex(int.from_bytes(data))}')
        return address, data

    @staticmethod
    def _decode_response(data):
        for chunk in batched(data[:-2], 4):
            chunk = [value for value in chunk if value > 0]

            if len(chunk) == 0 or chunk == [255, 255, 255, 255]:
                chunk = [0]

            yield reduce(lambda x, y: x << 8 | y, chunk)

    @staticmethod
    def compose(config: dict):
        print(config)
        converters = config['converters']
        response_template = config['response_template']
        result = []

        for converter in converters:
            ip = converter['ip']
            port = converter['port']
            meters = converter['meters']

            converter_result = {
                'ip': ip,
                'port': port
            }

            meters_results = []

            for meter in meters:
                address = meter['address']
                access_level = meter['access_level']
                password = meter['password']
                payload = meter['payload']
                hex_payload = hex(int.from_bytes(payload))

                em_result = {
                    'address': address,
                    'access_level': access_level,
                    'password': password
                }

                try:
                    with Mercury236(ip, port, address, access_level, password) as em:
                        if response_template == 'read_energy' and len(payload) == 4:
                            em_result[f'tariff{payload[3]}'] = em.read_energy(*payload)
                        elif response_template == '':
                            em_result[f'response_{hex_payload}'] = em.read_unsafe(*payload)
                except Exception as e:
                    em_result[f'error'] = f'{e}'
                    Mercury236.log_error(address, ip, port, e)
                meters_results.append(em_result)

            converter_result['meters'] = meters_results

            result.append(converter_result)

        print(json.dumps(result))

    @staticmethod
    def cli(args: Namespace):
        result = []
        for address, ip, port in zip(args.address, args.ip, args.port):
            try:
                with Mercury236(ip, port, address, args.access_level, args.password) as em:
                    if args.response_template == 'read_energy' and len(args.payload) == 4:
                        result.append({
                            f'energy_meter': {
                                'address': address,
                                'ip': ip,
                                'port': port,
                                'access_level': args.access_level,
                                'password': args.password
                            },
                            f'tariff{args.payload[3]}': em.read_energy(*args.payload)
                        })
                    elif args.response_template is None:
                        result.append({
                            f'energy_meter': {
                                'address': address,
                                'ip': ip,
                                'port': port,
                                'access_level': args.access_level,
                                'password': args.password
                            },
                            f'response': em.read_unsafe(*args.payload)
                        })

            except Exception as e:
                Mercury236.log_error(address, ip, port, e)

        if len(result) > 0:
            if args.output_format == 'json':
                result = json.dumps(result)

            if args.output is not None:
                with open(args.output, 'w', encoding='utf8') as output:
                    output.write(result)
            else:
                print(result)

    @staticmethod
    def log_error(address, ip, port, e):
        logger.error(f'{address}:{ip}:{port} - {e}')
