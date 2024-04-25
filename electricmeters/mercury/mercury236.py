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
import time
import traceback
from argparse import Namespace
from datetime import datetime
from functools import reduce
from itertools import batched
from math import log10

from electricmeters.crc16 import crc16

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s | %(levelname)s | %(message)s')


class Mercury236:
    def __init__(self, ip: str, port: int, address: int, access_level: int = 1, password: str = '111111',
                 metric_prefix: int = 1,
                 debug: bool = False):
        self._debug = debug
        self._is_socket_open = False

        self._metric_prefix = 1
        if metric_prefix == 10 ** log10(metric_prefix):
            self._metric_prefix = metric_prefix
        elif self._debug:
            logger.debug(f'Incorrect metric prefix "{metric_prefix}" will be ignored')

        self._address = address % 1000
        if self._address == 0:
            self._address = 1
        elif self._address > 240:
            self._address = address % 100

        self._access_level = access_level
        self._password = [int(c) for c in password]
        if len(password) != 6:
            raise ValueError('Password length must be equal to 6')

        self._ip = ip
        self._port = port
        self._socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._socket_timeout = 5
        self._socket.settimeout(self._socket_timeout)

    @property
    def address(self):
        return self._address

    def open(self):
        self._socket.connect((self._ip, self._port))
        self.request(0x01, self._access_level, *self._password)
        self._is_socket_open = True

    def close(self):
        self.request(0x02)
        self._socket.close()
        self._is_socket_open = False

    def request(self, *args):
        caller_name = inspect.stack()[1][3]
        if self._debug:
            logger.debug(f'Request caller: {caller_name}')
        self._socket.sendall(self._pack_message(self._address, *args, debug=self._debug))

        response = self._read_socket()

        if len(response) > 1:
            address, data = self._unpack_message(response, debug=self._debug)
            if address == self._address:
                return data

        raise ValueError(f"Error while read data from socket")

    def _read_socket(self):
        data = ''
        buffer = b''

        while not data:
            self._socket.settimeout(self._socket_timeout)
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

    def read_unsafe(self, *args, order: list[int] = None):
        data = self.read(*args, order=order)
        return {i: value / self._metric_prefix if self._metric_prefix > 1 else value for i, value in enumerate(data)}

    def read_energy(self, request_code: int = 0x05, array: int = 0x00, month: int = 0x01, tariff: int = 0x00):
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
            array = (array << 4) | 0
        else:
            raise ValueError('Invalid array number')

        data = self.read(request_code, array, tariff, order=[1, 0, 3, 2])

        if request_code == 5:
            return {
                'active+': next(data) / self._metric_prefix if self._metric_prefix > 1 else next(data),
                'active-': next(data) / self._metric_prefix if self._metric_prefix > 1 else next(data),
                'reactive+': next(data) / self._metric_prefix if self._metric_prefix > 1 else next(data),
                'reactive-': next(data) / self._metric_prefix if self._metric_prefix > 1 else next(data)
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
    def _pack_message(*args, crc=True, debug=False):
        caller_name = inspect.stack()[1][3]
        message = bytes(args)
        if debug:
            logger.debug(f'Before pack ({caller_name}): {hex(int.from_bytes(message))}')
        result = message + crc16(message) if crc else message
        if debug:
            logger.debug(f'After pack ({caller_name}): {hex(int.from_bytes(result))}')
        return result

    @staticmethod
    def _unpack_message(message: bytes, debug: bool = False):
        caller_name = inspect.stack()[1][3]
        if debug:
            logger.debug(f'Before unpack ({caller_name}): {hex(int.from_bytes(message))}')
        address = int.from_bytes(message[:1], 'big')
        data = list(message[1:])
        if debug:
            logger.debug(f'After unpack ({caller_name}): {hex(address), hex(int.from_bytes(data))}')
        return address, data

    @staticmethod
    def _decode_response(data, order: list[int] = None):
        for chunk in batched(data[:-2], 4):
            if isinstance(order, list) and len(order) == 4:
                chunk = [chunk[order[0]], chunk[order[1]], chunk[order[2]], chunk[order[3]]]

            chunk = [value for value in chunk if value > 0]

            if len(chunk) == 0 or chunk == [255, 255, 255, 255]:
                chunk = [0]

            yield reduce(lambda x, y: x << 8 | y, chunk)

    @staticmethod
    def compose(config: dict):
        max_retries = config.get('max_retries', 3)
        silent = config.get('silent', True)
        if not silent:
            logger.info(config)
        converters = config['converters']
        response_template = config.get('response_template', None)
        global_params = {
            'access_level': config.get('access_level', None),
            'password': config.get('password', None),
            'payload': config.get('payload', None),
            'bytes_order': config.get('bytes_order', None)
        }

        output_filename = config.get('output_filename', None)

        timestamp = config.get('timestamp', False)
        delay = config.get('delay', 0)
        pretty = config.get('pretty', False)

        if response_template == '':
            response_template = None
        debug = config.get('debug', False)
        metric_prefix = config.get('metric_prefix', 1)

        result = []
        for converter in converters:
            ip = converter['ip']
            port = converter['port']

            try:
                groups = converter['groups']
            except KeyError:
                groups = [{'group': None, 'meters': converter['meters']}]

            converter_result = {
                'ip': ip,
                'port': port,
                'groups': []
            }

            for group in groups:
                group_result = {
                    'name': group['group'],
                    'meters': []
                }

                for meter in group['meters']:
                    serial_number = None
                    if isinstance(meter, int):
                        address = meter
                        access_level = global_params['access_level']
                        password = global_params['password']
                        payload = global_params['payload']
                        bytes_order = global_params['bytes_order']
                    else:
                        serial_number = meter.get('serial_number', None)
                        address = meter['address']
                        access_level = meter.get('access_level', global_params['access_level'])
                        password = meter.get('password', global_params['password'])
                        payload = meter.get('payload', global_params['payload'])
                        bytes_order = meter.get('order', global_params['bytes_order'])

                    if access_level is None:
                        raise ValueError('The parameter "access_level" is missing')
                    if password is None:
                        raise ValueError('The parameter "password" is missing')
                    if payload is None:
                        raise ValueError('The parameter "payload" is missing')

                    hex_payload = hex(int.from_bytes(payload))

                    em_result = {}

                    if isinstance(serial_number, int):
                        em_result['serial_number'] = serial_number
                    else:
                        em_result['address'] = address

                    if delay > 0:
                        time.sleep(delay)

                    for retries in range(max_retries):
                        try:
                            with Mercury236(ip, port, address, access_level, password, metric_prefix, debug) as em:
                                em_result['address'] = em.address
                                if response_template == 'read_energy' and len(payload) == 4:
                                    em_result[f'tariff{payload[3]}'] = em.read_energy(*payload)
                                elif response_template is None:
                                    em_result[f'response_{hex_payload}'] = em.read_unsafe(*payload, order=bytes_order)
                            break
                        except Exception as e:
                            if retries == max_retries - 1:
                                em_result[f'error'] = f'{e}'
                                if not silent:
                                    Mercury236.log_error(address, ip, port, e)
                            if debug:
                                traceback.print_exc()

                    group_result['meters'].append(em_result)
                converter_result['groups'].append(group_result)

            result.append(converter_result)

        json_output = json.dumps(result, indent=2 if pretty else None)
        if silent:
            print(json_output)
        else:
            logger.info(json_output)

        if output_filename is not None:
            date = f'_{datetime.now().strftime("%d_%m_%y_%H_%M_%S")}' if timestamp else ''
            with open(f'{output_filename}{date}.json', 'w', encoding='utf8') as output:
                output.write(json_output)

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
