from dataclasses import dataclass

from electricmeters.config import Config


@dataclass(frozen=True, slots=True)
class Config(Config):
    session: bool = False
