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

import argparse
import logging
import tomllib
from importlib import import_module
from pathlib import Path

import electricmeters
from electricmeters.config import ConverterConfig, GroupConfig

LOG_FMT = "%(asctime)s %(address)s %(levelname)s %(message)s"
logger = logging.getLogger("electricmeters")


def get_parser():
    parser = argparse.ArgumentParser(
        prog="electricmeters",
        description="Electric energy meter data receiver",
    )

    (
        parser.add_subparsers(help="sub-commands help", dest="subparser")
        .add_parser("compose", help="Compose request from config")
        .add_argument(
            "config", type=Path, nargs="?", default="em-compose.toml"
        )
    )

    return parser


def compose(path: Path):
    config_dict = tomllib.load(path.open("rb"))
    brand = config_dict["brand"]
    model = config_dict["model"]
    class_name = f"{brand}{model}".capitalize()

    if config_dict.get("trace", False):
        logger.setLevel(5)
    elif config_dict.get("debug", False):
        logger.setLevel("DEBUG")

    try:
        em_module = import_module(f"electricmeters.{brand}")
    except ModuleNotFoundError:
        raise NotImplementedError(f'electric meter "{brand}"')

    try:
        em = getattr(em_module, class_name)
    except AttributeError:
        try:
            class_name = model
            em = getattr(em_module, class_name)
        except AttributeError:
            raise NotImplementedError(f'model "{class_name}"')

    config = electricmeters.config.Config
    meter_config = electricmeters.config.MeterConfig

    try:
        meter_config_module = getattr(em_module, "config")
        config = meter_config_module.Config
        meter_config = meter_config_module.MeterConfig
    except AttributeError:
        # fallback to base config
        pass

    config_dict["converters"] = [
        ConverterConfig(
            ip=converter["ip"],
            port=converter["port"],
            groups=[
                GroupConfig(
                    name=group["name"],
                    meters=[
                        meter_config(**meter_config.force_dict(meter))
                        for meter in group["meters"]
                    ],
                )
                for group in converter.get(
                    "groups", [{"name": None, "meters": converter["meters"]}]
                )
            ],
        )
        for converter in config_dict["converters"]
    ]
    em.compose(config(**config_dict))


if __name__ == "__main__":
    handler = logging.StreamHandler()
    handler.setFormatter(logging.Formatter(LOG_FMT))
    logger.addHandler(handler)

    arg_parser = get_parser()
    args = arg_parser.parse_args()

    if args.subparser == "compose":
        compose(args.config)
    else:
        arg_parser.print_help()
