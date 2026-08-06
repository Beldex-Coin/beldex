#!/usr/bin/env python3

from collections.abc import Mapping


def _normalize(value, ignore_order):
    if isinstance(value, Mapping):
        return tuple(sorted((key, _normalize(val, ignore_order)) for key, val in value.items()))
    if isinstance(value, (list, tuple)):
        items = [_normalize(item, ignore_order) for item in value]
        if ignore_order:
            return tuple(sorted(items, key=repr))
        return tuple(items)
    if isinstance(value, set):
        return tuple(sorted((_normalize(item, ignore_order) for item in value), key=repr))
    return value


class DeepDiff(dict):
    def __init__(self, actual, expected, ignore_order=True):
        super().__init__()
        if _normalize(actual, ignore_order) != _normalize(expected, ignore_order):
            self['values_changed'] = {
                'root': {
                    'old_value': actual,
                    'new_value': expected,
                }
            }
