import json
from abc import ABC, abstractmethod
from datetime import datetime
from typing import Callable

from electricmeters.__main__ import logger
from electricmeters.config import Config


class AbstractMeter(ABC):
    """
    Abstract meter
    """

    def __init__(
        self,
        host: str,
        port: int,
        address: int,
        password: str,
        *,
        timeout: int = 30,
        metric_prefix: int = 1,
        debug: bool = False,
    ):
        self.host = host
        self.port = port
        self.address = address
        self.password = password
        self.timeout = timeout
        self.metric_prefix = metric_prefix
        self.debug = debug
        self._log_info = {"address": address}
        self._socket = None

    @abstractmethod
    def open(self): ...

    @abstractmethod
    def close(self): ...

    @abstractmethod
    def request(self): ...

    @abstractmethod
    def _read_socket(self): ...

    @staticmethod
    @abstractmethod
    def _pack_message(self): ...

    @staticmethod
    @abstractmethod
    def _unpack_message(self): ...

    @staticmethod
    def json_output(foo: Callable[[Config], list[dict]]) -> Callable:
        def wrapper(*args, **kwargs):
            conf = args[0]
            result = foo(*args, **kwargs)
            json_output = json.dumps(result, indent=2 if conf.pretty else None)

            if not conf.silent:
                print(json_output)

            if conf.output_filename is not None:
                date = ""

                if conf.timestamp:
                    date = f'_{datetime.now().strftime("%d_%m_%y_%H_%M_%S")}'

                with open(
                    f"{conf.output_filename}{date}.json",
                    "w",
                    encoding="utf8",
                ) as output:
                    output.write(json_output)

        return wrapper

    @staticmethod
    @abstractmethod
    def compose(self) -> dict: ...

    def log(self, level: int, message: str) -> None:
        logger.log(level, message, extra=self._log_info)

    @staticmethod
    def pretty_hex(data: bytes) -> str:
        return " ".join(f"{ch:02X}" for ch in data)
