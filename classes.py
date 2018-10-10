#!/usr/bin/python2
""" CLASSES """

__all__ = ['ValueError', 'DeviceError', 'DiffError', 'FileError', 'ConfigError']


class ValueError(Exception):
    def __init__(self, msg):
        self.msg = msg

    def __str__(self):
        return self.msg


class DeviceError(Exception):
    def __init__(self, msg):
        self.msg = msg

    def __str__(self):
        return self.msg


class DiffError(Exception):
    def __init__(self, msg):
        self.msg = msg

    def __str__(self):
        return self.msg


class FileError(Exception):
    def __init__(self, msg):
        self.msg = msg

    def __str__(self):
        return self.msg


class ConfigError(Exception):
    def __init__(self, msg):
        self.msg = msg

    def __str__(self):
        return self.msg


class PushoverError(Exception):
    def __init__(self, msg):
        self.msg = msg

    def __str__(self):
        return self.msg
