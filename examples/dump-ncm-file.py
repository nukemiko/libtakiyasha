#!/usr/bin/env python3
from __future__ import annotations

import argparse
import shutil
import sys
from pathlib import Path

from libtakiyasha.ncm import NCM

progname = Path(sys.argv[0]).name

try:
    from mutagen import flac, id3, mp3
except ImportError:
    print(f'{progname}：缺少依赖关系：mutagen', file=sys.stderr)
    print(f"{progname}：请使用 'pip install -U mutagen' 安装后再次运行本程序。")
    sys.exit(1)
try:
    from tqdm import tqdm
except ImportError:
    print(f'{progname}：缺少依赖关系：tqdm', file=sys.stderr)
    print(f"{progname}：请使用 'pip install -U tqdm' 安装后再次运行本程序。")
    sys.exit(1)


def str_shorten(s, maxlen: int = 30, lr_maxkeeplen: int = 10) -> str:
    string = str(s)
    maxlen = int(maxlen)
    lr_maxkeeplen = int(lr_maxkeeplen)

    if len(string) > maxlen:
        return string[:lr_maxkeeplen] + '...' + string[-lr_maxkeeplen:]
    return string


ap = argparse.ArgumentParser(
    prog=progname,
    formatter_class=argparse.RawTextHelpFormatter,
    add_help=False
)
ap.add_argument('-t', '--filename-template',
                metavar='TEMPLATE',
                dest='target_filename_template',
                default=None,
                help='如果指定此选项，为输出文件的名称（不含扩展名）统一应用一个模板。\n'
                     '如果解析模板字符串时出错，将会使用默认值“<去除扩展名的输入文件名>.<输出文件格式>”代替。\n'
                     '可用模板关键字：\n'
                     '  {title} - 标题\n'
                     '  {artist} - 歌手（艺术家）\n'
                     '  {album} - 专辑'
                )
ap.add_argument('-h', '--help',
                action='help',
                help='显示此帮助信息并退出'
                )
ap.add_argument('core_key',
                metavar='<CORE KEY>',
                help='解密音频数据所需的核心密钥，以十六进制形式表示。'
                )
ap.add_argument('sourcefiles_targetdir',
                metavar='NCMFILES',
                type=Path,
                nargs='+',
                help='所有输入文件的路径。最后一个路径如果指向目录，将会用于保存输出文件；\n'
                     '否则，将输出文件保存到当前工作目录下。\n'
                     '除了最后一个路径，其他路径必须指向文件。'
                )

optargs: dict[str, str | Path | list[Path]] = vars(ap.parse_intermixed_args())

try:
    core_key: bytes = bytes.fromhex(optargs['core_key'])
except ValueError:
    print(f"{progname}：错误：输入了无效的核心密钥（第一个位置参数）", file=sys.stderr)
    print(f"{progname}：使用 '{progname} -h' 查看帮助信息。", file=sys.stderr)
    sys.exit(1)

sourcefiles: list[Path] = optargs['sourcefiles_targetdir']

targetdir: Path = sourcefiles.pop(-1)
if not targetdir.is_dir():
    sourcefiles.append(targetdir)
    targetdir = Path.cwd()
target_filename_template: str | None = optargs['target_filename_template']

total_tasks = len(sourcefiles)
finished_tasks: list[tuple[Path, Path | str | Exception]] = []
for taskno, source_path in enumerate(sourcefiles, start=1):
    columns, lines = shutil.get_terminal_size()
    print(f'=' * columns)
    print(f"{progname}：正在进行：第 {taskno} 个任务，共 {total_tasks} 个")

    source_filename = source_path.name
    if not source_path.exists():
        print(f"{progname}：跳过路径 '{source_path}'：路径不存在", file=sys.stderr)
        finished_tasks.append((source_path, '路径不存在'))
        print(f'=' * columns)
        continue
    elif source_path.is_dir():
        print(f"{progname}：跳过路径 '{source_path}'：路径指向一个目录而不是文件", file=sys.stderr)
        finished_tasks.append((source_path, '路径指向一个目录而不是文件'))
        print(f'=' * columns)
        continue

    try:
        ncmfile = NCM.from_file(source_path, core_key=core_key)
    except Exception as exc:
        print(f"{progname}：跳过文件 '{str_shorten(source_filename)}'：解析文件时出现错误：{exc}", file=sys.stderr)
        finished_tasks.append((source_path, exc))
        print(f'=' * columns)
        continue
    else:
        print(f"{progname}：成功打开文件 '{str_shorten(source_filename)}'")

    ncm_tag = ncmfile.ncm_tag

    target_filename_stem = source_path.stem
    if target_filename_template is not None:
        try:
            title = '未知标题'
            artist = '未知歌手'
            album = '未知专辑'

            if ncm_tag.musicName:
                title = ncm_tag.musicName
            artists_list = ncm_tag.artist
            artists_names = [_[0] for _ in artists_list]
            if len(artists_names) != 0:
                artist = '、'.join(artists_names)
            if ncm_tag.album:
                album = ncm_tag.album

            target_filename_stem = target_filename_template.format_map(
                {
                    'title' : title,
                    'artist': artist,
                    'album' : album
                }
            )
        except Exception as exc:
            print(f"{progname}：使用自定义文件名模板为 '{str_shorten(source_filename)}' 设置输出文件名时出错：{exc}")
    target_filename = f'{target_filename_stem}.{ncm_tag.format}'
    print(f"{progname}：设定 '{str_shorten(source_filename)}' 的输出文件名为 '{target_filename}'")

    target_path = targetdir / target_filename

    ncmfile_len: int = ncmfile.seek(0, 2)

    print(f"{progname}：将 '{str_shorten(source_filename)}' 输出到 '{str_shorten(target_filename)}'...")
    with open(target_path, mode='w+b') as targetfd:
        with tqdm(total=ncmfile_len,
                  desc=f"{progname}：{str_shorten(target_filename)}",
                  unit='B',
                  unit_scale=True,
                  unit_divisor=1024
                  ) as pbar:
            ncmfile.seek(0, 0)
            for blk in ncmfile:
                targetfd.write(blk)
                pbar.update(len(blk))
            finished_tasks.append((source_path, target_path))
        print(f"{progname}：成功将 '{str_shorten(source_filename)}' 输出到 '{str_shorten(target_filename)}'！")

        try:
            mutagen_style_dict = ncm_tag.to_mutagen_style_dict()
            cover_data = ncmfile.cover_data

            if ncm_tag.format.lower() == 'flac':
                targetfd.seek(0, 0)
                flactag = flac.FLAC(targetfd)
                targetfd.seek(0, 0)
                flactag.update(mutagen_style_dict)
                if cover_data:
                    picture = flac.Picture()
                    picture.data = cover_data
                    picture.type = 3
                    if cover_data.startswith(b'\x89PNG'):
                        picture.mime = 'image/png'
                    elif cover_data.startswith(b'\xff\xd8\xff'):
                        picture.mime = 'image/jpeg'
                    flactag.add_picture(picture)
                flactag.save(targetfd)
            elif ncm_tag.format.lower() == 'mp3':
                targetfd.seek(0, 0)
                mp3tag = mp3.MP3(targetfd)
                targetfd.seek(0, 0)
                mp3tag.update(mutagen_style_dict)
                if cover_data:
                    picture = id3.APIC()
                    picture.data = cover_data
                    picture.type = 3
                    if cover_data.startswith(b'\x89PNG'):
                        picture.mime = 'image/png'
                    elif cover_data.startswith(b'\xff\xd8\xff'):
                        picture.mime = 'image/jpeg'
                    mp3tag['APIC:'] = picture
                mp3tag.save(targetfd)
        except Exception as exc:
            print(f"{progname}：设定输出文件 '{str_shorten(target_filename)}' 的标签和封面信息时出错：{exc}")
        else:
            print(f"{progname}：成功为 '{str_shorten(target_filename)}' 设定了标签和封面信息")

        print(f"{progname}：任务完成：'{str_shorten(source_filename)}' -> '{str_shorten(target_filename)}'")
        print(f'=' * columns)
