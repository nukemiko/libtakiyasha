# -*- coding: utf-8 -*-
from __future__ import annotations

import re
from functools import lru_cache
from pathlib import Path
from typing import Literal, NamedTuple

__all__ = ['version', 'version_info', 'progname']


class _VersionInfo(NamedTuple):
    major: int
    minor: int = None
    micro: int = None
    epoch: int | None = None
    is_pre: bool = False
    pre_type: Literal['alpha', 'beta', 'rc'] | None = None
    pre_num: int | None = None
    is_post: bool = False
    post_num1: int | None = None
    post_num2: int | None = None
    is_dev: bool = False
    dev_num: int | None = None
    local_identifier: str | None = None


_VERSION_PATTERN_STR = r"""
    v?
    (?:
        (?:(?P<epoch>[0-9]+)!)?                           # epoch
        (?P<release>[0-9]+(?:\.[0-9]+)*)                  # release segment
        (?P<pre>                                          # pre-release
            [-_\.]?
            (?P<pre_l>(a|b|c|rc|alpha|beta|pre|preview))
            [-_\.]?
            (?P<pre_n>[0-9]+)?
        )?
        (?P<post>                                         # post release
            (?:-(?P<post_n1>[0-9]+))
            |
            (?:
                [-_\.]?
                (?P<post_l>post|rev|r)
                [-_\.]?
                (?P<post_n2>[0-9]+)?
            )
        )?
        (?P<dev>                                          # dev release
            [-_\.]?
            (?P<dev_l>dev)
            [-_\.]?
            (?P<dev_n>[0-9]+)?
        )?
    )
    (?:\+(?P<local>[a-z0-9]+(?:[-_\.][a-z0-9]+)*))?       # local version
"""
_VERSION_PATTERN = re.compile(r"^\s*" + _VERSION_PATTERN_STR + r"\s*$", re.VERBOSE | re.IGNORECASE)


@lru_cache
def version() -> str:
    with open(Path(__file__).parent / 'VERSION', encoding='utf-8') as version_file:
        return version_file.readline().strip()


@lru_cache
def version_info() -> _VersionInfo:
    result = _VERSION_PATTERN.search(version()).groupdict()
    params: dict[str, str | int | bool | None] = {}
    for k, v in result.items():
        if k == 'epoch':
            if v is not None:
                params['epoch'] = int(v)
        elif k == 'release':
            rel = [int(_) for _ in v.split('.', maxsplit=3)]
            rel += [0] * (3 - len(rel))
            params['major'] = int(rel[0])
            params['minor'] = int(rel[1])
            params['micro'] = int(rel[2])
        elif k == 'pre':
            if v is not None:
                params['is_pre'] = True
        elif k == 'pre_l' and params.get('is_pre', False):
            if v == 'a':
                params['pre_type'] = 'alpha'
            elif v == 'b':
                params['pre_type'] = 'beta'
            elif v in ('c', 'rc'):
                params['pre_type'] = 'rc'
        elif k == 'pre_n' and params.get('is_pre', False):
            if v is not None:
                params['pre_num'] = int(v)
        elif k == 'post':
            if v is not None:
                params['is_post'] = True
        elif k == 'post_n1' and params.get('is_post', False):
            if v is not None:
                params['post_num1'] = int(v)
        elif k == 'post_n2' and params.get('is_post', False):
            if v is not None:
                params['post_num2'] = int(v)
        elif k == 'dev':
            if v is not None:
                params['is_dev'] = True
        elif k == 'dev_n' and params.get('is_dev', False):
            if v is not None:
                params['dev_num'] = int(v)
        elif k == 'local':
            params['local_identifier'] = v
            break

    return _VersionInfo(**params)


def progname() -> str:
    last_parent_path: Path | None = None
    for parent in Path(__file__).parents:
        if last_parent_path is not None:
            if (last_parent_path / '__init__.py').exists() and (last_parent_path / 'VERSION').exists():
                return last_parent_path.name
        last_parent_path = parent
    else:
        raise RuntimeError('cannot get the program name')
