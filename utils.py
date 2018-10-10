# !/usr/bin/python2
from __future__ import print_function

__version__ = "1.0"
__copyright__ = "Vladimir Kushnir aka Kvantum i(c)2017"

__all__ = ['eprint', 'sprint', 'str_to_bool']

import os, sys


# import datetime

def str_to_bool(value):
    return str(value).lower() in ("yes", "y", "true", "t", "1")


def eprint(*args, **kwargs):
    # print(datetime.datetime.now(), ":", *args, file=sys.stderr, **kwargs)
    print("err:", *args, file=sys.stderr, **kwargs)


def sprint(*args, **kwargs):
    # print(datetime.datetime.now(), ":", *args, file=sys.stdout, **kwargs)
    print("std:", *args, file=sys.stdout, **kwargs)
