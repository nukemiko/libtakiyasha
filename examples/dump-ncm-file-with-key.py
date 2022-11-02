#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from __future__ import annotations

import argparse
import os
import re
import shutil
import sys
from datetime import datetime
from pathlib import Path

from libtakiyasha.exceptions import LibTakiyashaException
from libtakiyasha.ncm import NCM

try:
    from mutagen import flac, mp3, id3
except ImportError:
    mutagen_available = False
else:
    mutagen_available = True

try:
    from tqdm import tqdm
except ImportError:
    tqdm_available = False
else:
    tqdm_available = True

progname = Path(sys.argv[0]).name

template_string_pattern = re.compile('{title}|{artist}|{album}|{time}')

hexnumstr_array_sep_pattern = re.compile(', ?|,? ')
hexnumstr_pattern = re.compile('^0x[0-9a-z]{,2}$', flags=re.IGNORECASE)

if sys.platform.startswith('win'):
    illegal_filename_chars_pattern = re.compile(r'[\x00-\x31~"#%&*:<>?/\\|]+')
else:
    illegal_filename_chars_pattern = re.compile(r'[\x00/]')


def hexstring2bytes(hexstring: str, paramname: str) -> bytes:
    try:
        return bytes.fromhex(hexstring)
    except ValueError:
        hexnum_strings = hexnumstr_array_sep_pattern.split(hexstring)
        hexnums: list[int] = []
        for item in hexnum_strings:
            try:
                hexnums.append(int(item, base=16))
            except ValueError:
                print(f"错误：在参数 '{paramname}' 中发现无效的十六进制数字 '{item}'")
                sys.exit(1)
        return bytes(hexnums)


def str_shorten(s, maxlen: int = 30, lr_maxkeeplen: int = 10) -> str:
    string = str(s)
    maxlen = int(maxlen)
    lr_maxkeeplen = int(lr_maxkeeplen)

    if len(string) > maxlen:
        return string[:lr_maxkeeplen] + '...' + string[-lr_maxkeeplen:]
    return string


ap = argparse.ArgumentParser(prog=progname,
                             add_help=False,
                             formatter_class=argparse.RawTextHelpFormatter,
                             usage='%(prog)s [-h] [-t 模板| --template 模板] '
                                   '(-k 核心密钥 | --core-key 核心密钥) '
                                   'NCM 文件... '
                                   '[输出目录]'
                             )
required_optargs = ap.add_argument_group('必需选项和参数')
required_optargs.add_argument('-k', '--core-key',
                              dest='core_key_str',
                              metavar='核心密钥',
                              required=True,
                              help="解密文件所需的密钥，使用十六进制表示法。\n"
                                   "可以接受以下形式：\n"
                                   "  -k a1b1c4d5e1f4\n"
                                   "  -k 0x11,0x45,0x14,0Xc1,0x9F,0x19,0xab\n"
                                   "不区分大小写，包含的空格会被去除。"
                              )
required_optargs.add_argument('sources_or_target',
                              metavar='NCM 文件... [输出目录]',
                              nargs='+',
                              type=Path,
                              help='所有输入文件的路径。如果最后一个路径指向一个目录，那么它会被用作\n'
                                   '所有输入文件的输出目录；否则，输出目录为当前目录。\n'
                                   '除最后一个参数外，所有路径必须指向一个文件。'
                              )

optional_optargs = ap.add_argument_group('可选选项和参数')
optional_optargs.add_argument('-h', '--help',
                              action='help',
                              help='显示帮助信息并退出'
                              )
optional_optargs.add_argument('-t', '--template',
                              dest='target_filename_template',
                              metavar='模板',
                              default='',
                              help='以 <模板> 规定的格式设定输出文件的名称。\n'
                                   '模板字符串中的可用字段：\n'
                                   '  {title} - 标题\n'
                                   '  {artist} - 歌手（艺术家）\n'
                                   '  {album} - 专辑\n'
                                   '  {time} - 文件生成的时间，使用 ISO 8601 表示法\n'
                                   "例如，将歌曲标题作为输出文件名：-t '{title}'\n"
                                   '如果未指定此选项，那么将会根据源文件名决定输出文件名。'
                              )
optional_optargs.add_argument('-n', '--no-tag',
                              action='store_false',
                              dest='with_tag',
                              help='不要向输出文件中写入标签信息'
                              )


def main():
    optargs = ap.parse_intermixed_args()

    core_key_str: str = optargs.core_key_str
    core_key = hexstring2bytes(core_key_str, '-k/--core-key')

    sources_or_target: list[Path] = optargs.sources_or_target
    targetdir = sources_or_target.pop(-1)
    if not targetdir.is_dir():
        sources_or_target.append(targetdir)
        targetdir = Path.cwd()

    target_filename_template = optargs.target_filename_template
    if target_filename_template != '' and not template_string_pattern.search(target_filename_template):
        print(f"错误：文件名模板字符串 '{target_filename_template}' 不包含任何字段")
        sys.exit(1)
    target_filename_template = illegal_filename_chars_pattern.sub(
        '%%', target_filename_template
    )

    with_tag: bool = optargs.with_tag

    total = len(sources_or_target)
    succeeds: list[tuple[Path, Path]] = []
    fails: list[tuple[Path, str]] = []

    for current, sourcepath in enumerate(sources_or_target, start=1):
        sourcepath_dirname = sourcepath.parent
        sourcepath_filename = sourcepath.name
        sourcepath_display = os.path.join(str_shorten(sourcepath_dirname), str_shorten(sourcepath_filename))

        termcols, termls = shutil.get_terminal_size()
        print('=' * termcols)
        print(f"[{current}/{total}]输入文件：'{sourcepath_display}'")

        errmsg = ''
        if not sourcepath.exists():
            errmsg = '路径不存在'
        elif not sourcepath.is_file():
            errmsg = '路径不是一个文件'
        if errmsg:
            print(f"跳过 '{sourcepath_display}'：{errmsg}")
            fails.append((sourcepath, errmsg))
            continue

        try:
            ncmfile = NCM.from_file(sourcepath, core_key=core_key)
            ncmfile_size = ncmfile.seek(0, 2)
            ncmfile.seek(0, 0)
        except LibTakiyashaException as exc:
            errmsg = f'{type(exc).__name__}: {exc}'
            print(f"跳过 '{sourcepath}'：{errmsg}")
            fails.append((sourcepath, errmsg))
            continue

        ncm_tag = ncmfile.ncm_tag
        targetfile_format = ncm_tag.format.upper()
        if not targetfile_format:
            header_4bytes = ncmfile.read(4)
            if header_4bytes.startswith(b'fLaC'):
                targetfile_format = 'FLAC'
            elif header_4bytes.startswith((b'ID3', b'\xff\xfb', b'\xff\xf3', b'\xff\xf2')):
                targetfile_format = 'MP3'
        print(f"输出文件格式：{targetfile_format.strip() if targetfile_format.strip() else '未知'}")

        title = str(ncm_tag.musicName) if ncm_tag.musicName else None
        if ncm_tag.artist:
            artist_names_ids = list(ncm_tag.artist)
            artist_names: list[str] = []
            for item in artist_names_ids:
                if len(item) < 1:
                    continue
                artist_names.append(str(item[0]))
            artist = '、'.join(artist_names)
        else:
            artist = None
        album = str(ncm_tag.album) if ncm_tag.album else None

        print(f"标题：{title if title else '无'}")
        print(f"歌手：{artist if artist else '无'}")
        print(f"专辑：{album if album else '无'}")

        targetpath_filename = sourcepath.stem + f'.{targetfile_format.lower() if targetfile_format.strip() else "unknown"}'
        if target_filename_template:
            targetpath_filename = target_filename_template.format(
                title=title,
                artist=artist,
                album=album,
                time=datetime.now().isoformat(timespec='seconds')
            ) + f'.{targetfile_format.lower() if targetfile_format.strip() else "unknown"}'
        targetpath_filename_display = str_shorten(targetpath_filename)
        targetpath = targetdir / targetpath_filename
        print(f"输出文件名：{targetpath_filename}")
        print(f"输出文件所在目录：{targetdir}")

        if tqdm_available:
            with tqdm(total=ncmfile_size,
                      unit='B',
                      unit_scale=True,
                      desc=targetpath_filename_display
                      ) as pbar:
                with open(targetpath, 'wb') as targetfile:
                    for blk in ncmfile:
                        targetfile.write(blk)
                        pbar.update(len(blk))
        else:
            with open(targetpath, 'wb') as targetfile:
                for blk in ncmfile:
                    targetfile.write(blk)
            print('音频数据已取出')

        if with_tag:
            if mutagen_available:
                try:
                    cover_data = ncmfile.cover_data
                    metadata = ncm_tag.to_mutagen_style_dict()
                    if targetfile_format.upper() == 'FLAC':
                        tag = flac.FLAC(targetpath)
                        for key, value in metadata.items():
                            tag[key] = value
                        picture = flac.Picture()
                        picture.data = cover_data
                        picture.type = 3
                        if cover_data.startswith(b'\x89PNG'):
                            picture.mime = 'image/png'
                        elif cover_data.startswith(b'\xff\xd8\xff'):
                            picture.mime = 'image/jpeg'
                        tag.add_picture(picture)
                        tag.save(targetpath)
                    elif targetfile_format.upper() == 'MP3':
                        tag = mp3.MP3(targetpath)
                        for key, value in metadata.items():
                            id3frame_cls = getattr(id3, key[:4])
                            id3frame = tag.get(key)
                            if id3frame is None:
                                tag[key] = id3frame_cls(text=value, desc='comment')
                            elif id3frame.text:
                                id3frame.text = value
                                tag[key] = id3frame
                        picture = id3.APIC()
                        picture.data = cover_data
                        picture.type = 3
                        if cover_data.startswith(b'\x89PNG'):
                            picture.mime = 'image/png'
                        elif cover_data.startswith(b'\xff\xd8\xff'):
                            picture.mime = 'image/jpeg'
                        tag['APIC:'] = picture
                        tag.save(targetpath)
                    else:
                        print('未嵌入标签信息，因为输出文件格式未知')
                except Exception as exc:
                    print(f'未能嵌入标签信息：{type(exc).__name__}: {exc}')
                else:
                    print('已嵌入标签信息')
            else:
                print("未嵌入标签信息，因为缺少依赖关系“mutagen”")

        succeeds.append((sourcepath, targetpath))

        if current == total:
            termcols, termls = shutil.get_terminal_size()
            print('=' * termcols)


if __name__ == '__main__':
    main()
