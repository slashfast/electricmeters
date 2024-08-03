from dataclasses import dataclass


@dataclass(frozen=True, slots=True, kw_only=True)
class MeterConfig:
    serial_number: int
    password: str = None

    @staticmethod
    def force_dict(value: dict | int) -> dict:
        """
        Convert the serial number to dict if it is represented as a whole number
        :param value:
        :return:
        """

        if isinstance(value, dict):
            return value
        elif isinstance(value, int):
            return {"serial_number": value}

        raise TypeError("Supported only integers and dicts")


@dataclass(frozen=True, slots=True, kw_only=True)
class GroupConfig:
    name: str = None
    meters: list[MeterConfig]


@dataclass(frozen=True, slots=True, kw_only=True)
class ConverterConfig:
    ip: str
    port: int
    groups: list[GroupConfig]


@dataclass(frozen=True, slots=True, kw_only=True)
class Config:
    brand: str
    model: str
    converters: list[ConverterConfig]
    response_template: str
    payload_list: list[str | list[int]] = None
    password: str = None
    max_retries: int = 3
    silent: bool = True
    output_filename: str = None
    timestamp: bool = False
    delay: int = 0
    timeout: int = 30
    pretty: bool = False
    trunc_values: bool = True
    metric_prefix: int = 1
    debug: bool = False

    def __post_init__(self):
        if not self.password and not all(
            meter.password
            for converter in self.converters
            for group in converter.groups
            for meter in group.meters
        ):
            raise ValueError("A password must be set")

        if not self.payload_list and not all(
            meter.password
            for converter in self.converters
            for group in converter.groups
            for meter in group.meters
        ):
            raise ValueError("A password must be set")

        for idx, payload in enumerate(self.payload_list):
            if isinstance(payload, str):
                self.payload_list[idx] = [ord(ch) for ch in payload]
