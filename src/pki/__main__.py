#!/usr/bin/env python3
from sys import argv
from __init__ import CLI

def main(*args):
    return CLI(args[0])(*args[1:])

if __name__ == '__main__':
    exit(main(*argv))
