from dataclasses import dataclass

from electricmeters.config import Config, MeterConfig


@dataclass(frozen=True, slots=True)
class MeterConfig(MeterConfig):
    address: int


@dataclass(frozen=True, slots=True)
class Config(Config):
    access_level: int = 1
