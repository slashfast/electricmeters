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
import os
import socket
import time
import traceback
from datetime import datetime, date, timedelta
from math import log10, trunc

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO, format='%(asctime)s | %(levelname)s | %(message)s')

_SOH = b'\x01'
_STX = b'\x02'
_ETX = b'\x03'
_ACK = b'\x06'
_POST_INIT = b'\x21'  # !
_EOL = b'\x0D\x0a'  # \r\n
_INIT = b'\x2f\x3f'  # / ?
_CMD_SOHR = b'\x01\x52\x31\x02'  # SOH R 1 STX

_VERBOSE_DEBUG = True


class Energomera303:
    def __init__(self, host: str, port: int, address: str, password: str = None,
                 metric_prefix: int = 1000,
                 debug: bool = False, session=False, timeout: int = 35):
        self._debug = debug

        if self._debug:
            logger.setLevel(logging.DEBUG)

        self._is_socket_open = False
        self._session = session
        self._is_session = False

        if isinstance(address, int):
            address = str(address)

        if len(address) < 9:
            raise ValueError('Address length must be 9')

        if metric_prefix == 10 ** log10(metric_prefix):
            if metric_prefix >= 1000:
                self._metric_prefix = 1000 / metric_prefix
            else:
                self._metric_prefix = metric_prefix * 1000
        else:
            logger.debug(f'Incorrect metric prefix "{metric_prefix}" will be ignored')
            self._metric_prefix = 1000

        self._wtz = '#' if os.name == 'nt' else '-'
        self._address = address[-9:]
        self._password = password
        self._host = host
        self._port = port
        self._socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._socket_timeout = timeout
        self._socket.settimeout(self._socket_timeout)

    @property
    def address(self):
        return self._address

    def open(self):
        self._socket.connect((self._host, self._port))
        self._is_socket_open = True

        if self._session:
            self.start_session()

    def start_session(self):
        if not self._is_session:
            response = self.request(_INIT, self._address, _POST_INIT, _EOL)
            logger.debug(f'Init response: {response}')
            response = self.request(_ACK, '051', _EOL)
            logger.debug(f'Acknowledge response: {response}')

            if self._password is not None:
                response = self.request(_SOH, 'P1', _STX, f'({self._password})', _ETX, bcc=True)
                logger.debug(f'Password response: {response}')

            self._is_session = True
        else:
            raise Exception('Session already started')

    def stop_session(self):
        if self._is_session:
            self.request(_SOH, 'B0', _ETX, bcc=True, decode=False, read=False)
            self._is_session = False
        else:
            raise Exception('Session is not started')

    def close(self):
        if self._session:
            self.stop_session()

        self._socket.close()

    def _read_socket(self):
        buffer = b''

        try:
            while True:
                self._socket.settimeout(self._socket_timeout)
                data = self._socket.recv(72)

                if _VERBOSE_DEBUG:
                    unpacked_data = self._unpack_message(data)
                    logger.debug(
                        f'Recv: {self.pretty_hex(unpacked_data)}\t{unpacked_data.decode('ascii').replace('\r\n',
                                                                                                         '<CR><LF>')}')

                if data is None and self._debug and _VERBOSE_DEBUG:
                    logger.critical('DATA IS NONE')

                if data:
                    buffer += data

                self._socket.settimeout(None)

                try:
                    first_byte = self._unpack_message(buffer[0].to_bytes())

                    if first_byte == _ACK:
                        logger.debug("ACK found")
                        break

                    elif is_stx := first_byte == _STX or first_byte == _SOH:
                        if _VERBOSE_DEBUG:
                            logger.debug("First is STX" if is_stx else "First is SOH")

                        if self._unpack_message(buffer[-2].to_bytes()) == _ETX:
                            logger.debug("ETX found")
                            break

                    elif first_byte == b'\x2f':
                        if _VERBOSE_DEBUG:
                            logger.debug("First is /")

                        if self._unpack_message(buffer[-2:]) == _EOL:
                            logger.debug("EOL found")
                            break
                    else:
                        if _VERBOSE_DEBUG:
                            logger.debug(f"First byte: {first_byte}")

                except IndexError:
                    pass
        except Exception as e:
            logger.error(e)

        self._socket.settimeout(None)

        return buffer

    @staticmethod
    def bcc(data: bytes):
        bcc = Energomera303.parity_check((sum(data) & 0x7F)).to_bytes()

        if _VERBOSE_DEBUG:
            logger.debug(f"BCC input: {repr(data)}")
            logger.debug(f'BCC: {repr(bcc)}')

        return bcc

    def _pack_message(self, *args, parity_check=True, bcc=True):
        caller_name = inspect.stack()[1][3]
        packed = b''
        for arg in args:
            if arg is None:
                continue
            if isinstance(arg, str):
                arg = bytes(map(ord, arg))

            packed += arg

        if _VERBOSE_DEBUG:
            logger.debug(f'Before pack ({caller_name}): {self.pretty_hex(packed)}\t{packed}')

        if parity_check:
            if _VERBOSE_DEBUG:
                logger.debug(f'Before parity check ({caller_name}): {self.pretty_hex(packed)}\t{packed}')

            packed = bytes(map(self.parity_check, packed))

            if _VERBOSE_DEBUG:
                logger.debug(f'After parity check ({caller_name}): {self.pretty_hex(packed)}\t{packed}')

        if bcc:
            if _VERBOSE_DEBUG:
                logger.debug(f'Before BCC ({caller_name}): {self.pretty_hex(packed)}\t{packed}')

            packed += self.bcc(packed[1:])

            if _VERBOSE_DEBUG:
                logger.debug(f'After BCC ({caller_name}): {self.pretty_hex(packed)}\t{packed}')

        logger.debug(f'After pack ({caller_name}): {self.pretty_hex(packed)}\t{packed}')
        return packed

    def _unpack_message(self, data: bytes):
        caller_name = inspect.stack()[1][3]

        if _VERBOSE_DEBUG:
            logger.debug(f'Before unpack ({caller_name}): {self.pretty_hex(data)}\t{data}')

        data = bytes(map(lambda x: self.parity_check(x, True), data))

        if _VERBOSE_DEBUG:
            logger.debug(f'After unpack ({caller_name}): {self.pretty_hex(data)}\t{data}')

        return data

    def request(self, *args, parity_check=True, bcc=False, decode=True, read=True, raw=None):
        caller_name = inspect.stack()[1][3]

        logger.debug(f'Request caller: {caller_name}')

        if isinstance(raw, bytes):
            self._socket.sendall(raw)
        else:
            self._socket.sendall(self._pack_message(*args, parity_check=parity_check, bcc=bcc))

        time.sleep(0.02)

        if read:
            response = self._read_socket()
            if _VERBOSE_DEBUG:
                logger.debug(f'Raw response {repr(response)}')

            if len(response) > 0:
                response = self._unpack_message(response)
                hex_response = self.pretty_hex(response)
                if decode:
                    try:
                        response = response.decode('ascii')
                        logger.debug(f'Response: {hex_response}\t{response.replace('\r\n', '<CR><LF>')}')
                    except UnicodeDecodeError:
                        logger.debug(f'Skip decode {response}')
                return response[:-1] if bcc else response

            # raise ValueError(f"Error while read data from socket")

    def to_meter_prefix(self, value: float, trunc_value=True) -> int | float:
        result = value * self._metric_prefix
        return trunc(result) if trunc_value else result

    def read_energy(self, *selectors: str, value='', trunc_value=True):
        payload = ''.join(selectors)

        if payload == 'NDPE':
            value = (date.today() - timedelta(days=1)).strftime(f'%{self._wtz}d.%{self._wtz}m.%y')

        parameter = f'E{payload}({value})'
        logger.debug(f'Prepared parameter: {parameter}')
        response = self.request(_SOH, 'R1', _STX, parameter, _ETX, bcc=True)
        response = response[6:-2]
        response = response.split('\r\n')
        response = iter(
            map(lambda x: self.to_meter_prefix(float(x.strip('()\r\n')), trunc_value=trunc_value), response))

        if payload == 'NDPE':
            return {
                'tariff0': {
                    'active+': next(response)
                },
                'tariff1': {
                    'active+': next(response)
                },
                'tariff2': {
                    'active+': next(response)
                },
                'tariff3': {
                    'active+': next(response)
                },
                'tariff4': {
                    'active+': next(response)
                },
                'tariff5': {
                    'active+': next(response)
                }
            }
        return response

    @staticmethod
    def parity_check(target: int, reverse=False):
        if reverse:
            return target & ~(1 << 7) if target.bit_count() % 2 == 0 else target
        return target | (1 << 7) if target.bit_count() % 2 != 0 else target

    @staticmethod
    def pretty_hex(data: bytes):
        return ' '.join(f'{ch:02X}' for ch in data)

    @staticmethod
    def compose(config: dict):
        max_retries = config.get('max_retries', 3)
        silent = config.get('silent', True)
        if not silent:
            logger.info(config)
        converters = config['converters']
        response_template = config.get('response_template', None)
        trunc_value = config.get('trunc', True)
        global_params = {
            'password': config.get('password', None),
            'payload_list': config.get('payload_list', None),
        }

        session = config.get('session', True)

        output_filename = config.get('output_filename', None)

        timestamp = config.get('timestamp', False)
        delay = config.get('delay', 0)
        timeout = config.get('timeout', 35)
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
                for retry in range(max_retries):
                    for meter in group['meters'].copy():
                        done = False
                        if isinstance(meter, int):
                            address = meter
                            password = global_params['password']
                            payload_list = global_params['payload_list']
                        else:
                            address = meter['address']
                            password = meter.get('password', global_params['password'])
                            payload_list = meter.get('payload_list', global_params['payload_list'])

                        if password is None:
                            raise ValueError('password is missing')
                        if payload_list is None:
                            raise ValueError('payload_list is missing')
                        if response_template not in ['read_energy']:
                            raise ValueError(f'unknown template: {response_template}')

                        em_result = {
                            'address': address
                        }

                        if delay > 0:
                            time.sleep(delay)

                        try:
                            with Energomera303(ip, port, address, password, metric_prefix, debug=debug,
                                               session=session,
                                               timeout=timeout) as em:
                                for payload in payload_list:
                                    em_result['address'] = em.address
                                    em_result[f'payload_{payload}'] = em.read_energy(*payload, trunc_value=trunc_value)
                            group['meters'].remove(meter)
                            done = True
                        except Exception as e:
                            if retry == max_retries - 1:
                                em_result[f'error'] = f'{e}'
                                done = True
                            if not silent:
                                Energomera303.log_error(address, ip, port, e)
                            if debug:
                                traceback.print_exc()
                        if done:
                            group_result['meters'].append(em_result)
                    converter_result['groups'].append(group_result)
                    if len(group['meters']) == 0:
                        break
            result.append(converter_result)

        json_output = json.dumps(result, indent=2 if pretty else None)

        if silent:
            print(json_output)
        else:
            logger.info(json_output)

        if output_filename is not None:
            current_date = f'_{datetime.now().strftime("%d_%m_%y_%H_%M_%S")}' if timestamp else ''
            with open(f'{output_filename}{current_date}.json', 'w', encoding='utf8') as output:
                output.write(json_output)

    @staticmethod
    def log_error(address, ip, port, e):
        logger.error(f'{address}:{ip}:{port} - {e}')

    def __enter__(self):
        self.open()
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.close()
