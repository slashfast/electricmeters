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
from math import log10

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s | %(levelname)s | %(message)s')

_SOH = b'\x01'
_STX = b'\x02'
_ETX = b'\x03'
_ACK = b'\x06'
_POST_INIT = b'\x21'  # !
_EOL = b'\x0D\x0a'  # \r\n
_INIT = b'\x2f\x3f'  # / ?
_CMD_SOHR = b'\x01\x52\x31\x02'  # SOH R 1 STX

_VERBOSE_DEBUG = False


class Energomera303:
    def __init__(self, host: str, port: int, address: str, password: str = None,
                 metric_prefix: int = 1,
                 debug: bool = False, session=False):
        self._debug = debug
        self._is_socket_open = False
        self._session = session
        self._is_session = False

        if isinstance(address, int):
            address = str(address)

        if len(address) < 9:
            raise ValueError('Address length must be 9')

        self._metric_prefix = 1
        if metric_prefix == 10 ** log10(metric_prefix):
            self._metric_prefix = metric_prefix
        elif self._debug:
            logger.warning(f'Incorrect metric prefix "{metric_prefix}" will be ignored')

        self._wtz = '#' if os.name == 'nt' else '-'
        self._address = address[-9:]
        self._password = password
        self._host = host
        self._port = port
        self._socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._socket_timeout = 35
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
            if self._debug:
                logger.debug(f'Init response: {response}')
            response = self.request(_ACK, '051', _EOL)
            if self._debug:
                logger.debug(f'Acknowledge response: {response}')
            if self._password is not None:
                response = self.request(_SOH, 'P1', _STX, f'({self._password})', _ETX, bcc=True)
                if self._debug:
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

                if self._debug and _VERBOSE_DEBUG:
                    unpacked_data = self._unpack_message(data)
                    logger.warning(
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
                        if self._debug:
                            logger.warning("ACK found")
                        break

                    elif is_stx := first_byte == _STX or first_byte == _SOH:
                        if self._debug and _VERBOSE_DEBUG:
                            logger.warning("First is STX" if is_stx else "First is SOH")
                        if self._unpack_message(buffer[-2].to_bytes()) == _ETX:
                            if self._debug:
                                logger.warning("ETX found")
                            break

                    elif first_byte == b'\x2f':
                        if self._debug and _VERBOSE_DEBUG:
                            logger.warning("First is /")
                        if self._unpack_message(buffer[-2:]) == _EOL:
                            if self._debug:
                                logger.warning("EOL found")
                            break
                    else:
                        if self._debug and _VERBOSE_DEBUG:
                            logger.warning(f"First byte: {first_byte}")

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
        if self._debug and _VERBOSE_DEBUG:
            logger.debug(f'Before pack ({caller_name}): {self.pretty_hex(packed)}\t{packed}')

        if parity_check:
            if self._debug and _VERBOSE_DEBUG:
                logger.debug(
                    f'Before parity check ({caller_name}): {self.pretty_hex(packed)}\t{packed}')
            packed = bytes(map(self.parity_check, packed))
            if self._debug and _VERBOSE_DEBUG:
                logger.debug(f'After parity check ({caller_name}): {self.pretty_hex(packed)}\t{packed}')

        if bcc:
            if self._debug and _VERBOSE_DEBUG:
                logger.debug(f'Before BCC ({caller_name}): {self.pretty_hex(packed)}\t{packed}')
            packed += self.bcc(packed[1:])
            if self._debug and _VERBOSE_DEBUG:
                logger.debug(f'After BCC ({caller_name}): {self.pretty_hex(packed)}\t{packed}')

        if self._debug:
            logger.debug(f'After pack ({caller_name}): {self.pretty_hex(packed)}\t{packed}')
        return packed

    def _unpack_message(self, data: bytes):
        caller_name = inspect.stack()[1][3]
        if self._debug and _VERBOSE_DEBUG:
            logger.debug(f'Before unpack ({caller_name}): {self.pretty_hex(data)}\t{data}')

        data = bytes(map(lambda x: self.parity_check(x, True), data))

        if self._debug and _VERBOSE_DEBUG:
            logger.debug(f'After unpack ({caller_name}): {self.pretty_hex(data)}\t{data}')
        return data

    def request(self, *args, parity_check=True, bcc=False, decode=True, read=True, raw=None):
        caller_name = inspect.stack()[1][3]
        if self._debug:
            logger.debug(f'Request caller: {caller_name}')
        if isinstance(raw, bytes):
            self._socket.sendall(raw)
        else:
            self._socket.sendall(self._pack_message(*args, parity_check=parity_check, bcc=bcc))

        time.sleep(0.02)

        if read:
            response = self._read_socket()
            if self._debug and _VERBOSE_DEBUG:
                logger.debug(f'Raw response {repr(response)}')
            if len(response) > 0:
                response = self._unpack_message(response)
                hex_response = self.pretty_hex(response)
                if decode:
                    try:
                        response = response.decode('ascii')
                        if self._debug:
                            logger.debug(
                                f'Response: {hex_response}\t{response.replace('\r\n', '<CR><LF>')}')
                    except UnicodeDecodeError:
                        if self._debug:
                            logger.debug(f'Skip decode {response}')
                return response[:-1] if bcc else response

            # raise ValueError(f"Error while read data from socket")

    def read_energy(self, *selectors: str, value=''):
        payload = ''.join(selectors)

        if payload == 'NDPE':
            value = (date.today() - timedelta(days=1)).strftime(f'%{self._wtz}d.%{self._wtz}m.%y')

        parameter = f'E{payload}({value})'
        if self._debug:
            logger.debug(f'Prepared parameter: {parameter}')
        response = self.request(_SOH, 'R1', _STX, parameter, _ETX, bcc=True)
        response = response[6:-2]
        response = response.split('\r\n')
        response = iter(map(lambda x: float(x.strip('()\r\n')), response))

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
        silent = dict.get(config, 'silent', True)
        if not silent:
            logger.info(config)
        converters = config['converters']
        response_template = dict.get(config, 'response_template', None)

        password = dict.get(config, 'password', None)
        payload = dict.get(config, 'payload', None)
        bytes_order = dict.get(config, 'order', None)
        session = dict.get(config, 'session', True)
        output_filename = dict.get(config, 'output_filename', None)

        timestamp = dict.get(config, 'timestamp', False)
        delay = dict.get(config, 'delay', 0)
        pretty = dict.get(config, 'pretty', False)

        if response_template == '':
            response_template = None
        debug = dict.get(config, 'debug', False)
        metric_prefix = dict.get(config, 'metric_prefix', 1)

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
                    if isinstance(meter, int):
                        address = meter
                    else:
                        address = meter['address']
                        password = dict.get(meter, 'password', password)
                        payload = dict.get(meter, 'payload', payload)

                        bytes_order = dict.get(meter, 'order', bytes_order)

                    if password is None:
                        raise ValueError('The parameter "password" is missing')
                    if payload is None:
                        raise ValueError('The parameter "payload" is missing')

                    # hex_payload = hex(int.from_bytes(payload))

                    em_result = {
                        'address': address
                    }

                    time.sleep(delay)

                    try:
                        with Energomera303(ip, port, address, password, metric_prefix, debug=debug,
                                           session=session) as em:
                            em_result['address'] = em.address
                            if response_template == 'read_energy':
                                em_result |= em.read_energy(*payload)
                            else:
                                raise ValueError('Template must be specified')
                    except Exception as e:
                        em_result[f'error'] = f'{e}'
                        Energomera303.log_error(address, ip, port, e)
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
