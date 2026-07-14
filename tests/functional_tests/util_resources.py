#!/usr/bin/env python3

import errno
import os


def _wallet_directory():
    wallet_directory = os.environ['WALLET_DIRECTORY']
    assert wallet_directory != ''
    return wallet_directory


def remove_file(name):
    try:
        os.unlink(_wallet_directory() + '/' + name)
    except OSError as e:
        if e.errno != errno.ENOENT:
            raise


def remove_wallet_files(name):
    for suffix in ['', '.keys']:
        remove_file(name + suffix)


def file_exists(name):
    return os.path.isfile(_wallet_directory() + '/' + name)
