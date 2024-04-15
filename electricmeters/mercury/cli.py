from argparse import Namespace


def cli(args: Namespace):
    if args.model == '236':
        from .mercury236 import Mercury236
        Mercury236.cli(args)
