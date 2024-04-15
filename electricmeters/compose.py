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

import tomllib
from argparse import Namespace
from importlib import import_module


def compose(args: Namespace):
    with open(args.config, 'rb') as config:
        config = tomllib.load(config)

    brand = config["brand"]
    model = config['model']
    class_name = f'{brand}{model}'.capitalize()

    try:
        em_module = import_module(f'electricmeters.{brand}')
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

    em.compose(config)
