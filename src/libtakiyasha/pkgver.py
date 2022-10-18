# -*- coding: utf-8 -*-
from __future__ import annotations

from pathlib import Path

__all__ = ['version', 'progname']


def version() -> str:
    with open(Path(__file__).parent / 'VERSION', encoding='utf-8') as version_file:
        return version_file.readline().strip()


def progname() -> str:
    last_parent_path: Path | None = None
    for parent in Path(__file__).parents:
        if last_parent_path is not None:
            if (last_parent_path / '__init__.py').exists() and (last_parent_path / 'VERSION').exists():
                return last_parent_path.name
        last_parent_path = parent
    else:
        raise RuntimeError('cannot get the program name')
