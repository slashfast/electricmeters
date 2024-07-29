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
from pathlib import Path

from electricmeters import mercury, compose


def get_parser():
    parser = argparse.ArgumentParser(
        prog="electricmeters",
        description="Electric energy meter data receiver",
    )
    subparsers = parser.add_subparsers(
        help="sub-commands help", dest="subparser"
    )
    compose_parser = subparsers.add_parser(
        "compose", help="Compose request from config"
    )
    compose_parser.add_argument(
        "config", type=Path, nargs="?", default="em-compose.toml"
    )

    mercury_parser = subparsers.add_parser(
        "mercury", help="Mercury energy meter"
    )
    mercury_parser.add_argument(
        "--model",
        type=str,
        default="236",
        choices=["236"],
        help="Model number",
        required=True,
    )
    mercury_parser.add_argument(
        "--address", type=int, nargs="+", help="Device address", required=True
    )
    mercury_parser.add_argument(
        "--ip",
        type=str,
        nargs="+",
        help="RS485-TCP/IP Converter IP",
        required=True,
    )
    mercury_parser.add_argument(
        "--port",
        type=int,
        nargs="+",
        help="RS485-TCP/IP Converter port",
        required=True,
    )
    mercury_parser.add_argument(
        "--access-level",
        type=int,
        choices=[1, 2],
        default=1,
        help="Access level (for Mercury 236)",
    )
    mercury_parser.add_argument(
        "--password",
        type=str,
        default="111111",
        help="Device password (for Mercury 236)",
    )
    mercury_parser.add_argument(
        "--output-format",
        type=str,
        choices=["json"],
        default="json",
        help="Output format",
    )
    mercury_parser.add_argument(
        "--output", type=str, default=None, help="Output file path"
    )
    mercury_parser.add_argument(
        "--payload",
        type=int,
        nargs=4,
        default=[5, 0, 1, 0],
        required=True,
        help="Payload by byte sequence",
    )
    mercury_parser.add_argument(
        "--response-template",
        type=str,
        default=None,
        help="Specify answer structure",
    )

    return parser


if __name__ == "__main__":
    arg_parser = get_parser()
    args = arg_parser.parse_args()

    if args.subparser is None:
        arg_parser.print_help()
    elif args.subparser == "compose":
        compose(args)
    elif args.subparser == "mercury":
        mercury.cli(args)
