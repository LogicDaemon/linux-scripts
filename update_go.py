#!/usr/bin/env python3
from __future__ import annotations, generator_stop

import hashlib
import platform
import re
import sys
from pathlib import Path
import tarfile
from threading import Event
import threading
from typing import Deque, Dict, NamedTuple, Optional
from collections import deque

import appdirs
import httpx
import lxml.html
try:
    from rich import progress
except ImportError:
    from pip._vendor.rich import progress  # pyright: ignore


class GoDownload(NamedTuple):
    url: httpx.URL
    name: str
    sha256: str
    size: int


def machine_to_arch(machine: str) -> str:
    # https://stackoverflow.com/questions/45125516/possible-values-for-uname-m
    for pat, arch in [
        ('x86_64', 'x86-64'),
            # windows only: ('AMD64', 'x86-64'),
        ('aarch64|armv8', 'ARM64'),
        ('armv[67]', 'ARMv6'),
        ('i[3-6]86|x86', 'x86'),
    ]:
        if re.search(f'^({pat})', machine, re.I):
            return arch
    raise ValueError(f'Unsupported machine: {machine}')


def norm(text: str) -> str:
    return re.sub(r"\s+", " ", text or "").strip()


def size_to_bytes(size_str: str) -> int:
    prefixes = 'KMGT'
    size_str = size_str.strip().upper()
    match = re.match(r'(\d+(?:\.\d+)?)([' + prefixes + r']?B)', size_str)
    if not match:
        raise ValueError(f'Invalid size format: {size_str}')
    number, unit = match.groups()
    number = float(number)
    units = ['B'] + [p + 'B' for p in prefixes]
    unit_multipliers = {u: 1024**i for i, u in enumerate(units)}
    return int(number * unit_multipliers[unit])


def find_download(client: httpx.Client, arch: str) -> GoDownload:
    # //*[@id="go1.25.0"]/div[2]/div/table/tbody/tr[6]/td[1]/a
    # #go1\.25\.0 > div.expanded > div > table > tbody > tr:nth-child(6) > td.filename > a
    # <tr class=" ">
    #   <td class="filename"><a class="download" href="/dl/go1.25.0.linux-386.tar.gz">go1.25.0.linux-386.tar.gz</a></td>
    #   <td>Archive</td>
    #   <td>Linux</td>
    #   <td>x86</td>
    #   <td>56MB</td>
    #   <td><tt>8c602dd9d99bc9453b3995d20ce4baf382cc50855900a0ece5de9929df4a993a</tt></td>
    # </tr>
    # //*[@id="go1.25.0"]/div[2]/div/table/tbody/tr[7]/td[1]/a
    #go1\.25\.0 > div.expanded > div > table > tbody > tr:nth-child(7) > td.filename > a
    # <tr class="highlight ">
    #   <td class="filename"><a class="download" href="/dl/go1.25.0.linux-amd64.tar.gz">go1.25.0.linux-amd64.tar.gz</a></td>
    #   <td>Archive</td>
    #   <td>Linux</td>
    #   <td>x86-64</td>
    #   <td>57MB</td>
    #   <td><tt>2852af0cb20a13139b3448992e69b868e50ed0f8a1e5940ee1de9e19a123b613</tt></td>
    # </tr>
    url = 'https://go.dev/dl/'
    page = client.get(url)
    tree = lxml.html.fromstring(page.text)

    table_xpath = ("//h2[@id='stable']/following-sibling::div[1]"
                   "//table[contains(concat(' ', normalize-space(@class), ' '),"
                   " ' downloadtable ')][1]")
    column_numbers: Dict[str, Optional[int]] = {
        "File name": None,
        "Kind": None,
        "OS": None,
        "Arch": None,
        "Size": None,
        "SHA256 Checksum": None,
    }
    for table in tree.xpath(table_xpath):
        assert isinstance(table, lxml.html.HtmlElement)
        for i, header in enumerate(table.xpath(".//th")):
            col_name = norm(header.text_content())
            if col_name == 'Other Ports':
                break
            if col_name in column_numbers:
                column_numbers[col_name] = i
            else:
                print('Unexpected column:', col_name, file=sys.stderr)
        for tr in table.xpath(".//tr"):
            tds = tr.xpath('./td')
            if len(tds) < 6:
                continue
            kind = norm(tds[column_numbers['Kind']].text_content())
            os_name = norm(tds[column_numbers['OS']].text_content())
            arch_text = norm(tds[column_numbers['Arch']].text_content())
            if kind == 'Archive' and os_name == 'Linux' and arch_text == arch:
                a = tds[column_numbers['File name']].xpath(
                    ".//a[@class='download']")
                if not a:
                    continue
                a = a[0]

                sha_cell = tds[column_numbers['SHA256 Checksum']]
                sha = (
                    norm(sha_cell.xpath('string(.//tt)')) or
                    norm(sha_cell.text_content()))
                return GoDownload(
                    url=page.url.join(a.get('href')),
                    name=norm(a.text_content()),
                    sha256=sha,
                    size=size_to_bytes(norm(tds[4].text_content())))

    raise ValueError(f'No stable Linux archive found for arch={arch}')


def file_hash_matches(path: Path, expected_sha256: str,
                      prog: progress.Progress) -> bool:
    sha256 = hashlib.sha256()
    task = prog.add_task(f'Verifying {path} ...', total=path.stat().st_size)
    with path.open('rb') as f:
        while True:
            data = f.read1()
            if not data:
                break
            sha256.update(data)
            prog.update(task, advance=len(data))
    actual_sha256 = sha256.hexdigest()
    if actual_sha256 == expected_sha256:
        return True
    print(
        f'File {path} is outdated (SHA256 does not match).',
        f'Expected: {expected_sha256}',
        f'Actual:   {actual_sha256}',
        sep='\n',
        end='',
        file=sys.stderr)
    return False


def writer_thread(path: Path, prog: progress.Progress, size: int,
                  queue: Deque[bytes], event: Event, completed: Event) -> None:
    with path.open('wb') as f:
        task = prog.add_task(path.name, total=size)
        # if not prog.tasks[task].started:
        #     prog.start_task(task)
        while not completed.is_set() or queue:
            if not queue:
                event.wait(1)
            event.clear()
            if not queue:
                continue
            chunk = queue.popleft()
            f.write(chunk)
            prog.update(task, advance=len(chunk))
        prog.update(task, completed=size)


def download(client: httpx.Client, prog: progress.Progress,
             download: GoDownload, path: Path) -> None:
    queue: Deque[bytes] = deque()
    event = Event()
    completed = Event()
    with client.stream("GET", download.url) as response:
        response.raise_for_status()
        wt = threading.Thread(
            target=writer_thread,
            args=(path, prog, download.size, queue, event, completed))
        wt.start()
        for chunk in response.iter_bytes():
            if not wt.is_alive():
                raise RuntimeError("Writer thread has terminated unexpectedly.")
            queue.append(chunk)
            event.set()
    if queue:
        event.set()
        print(
            'Received all data, waiting for writer thread to finish...',
            file=sys.stderr)
    completed.set()
    event.set()
    wt.join()
    print(f'Downloaded {download.url} to {path}', file=sys.stderr)


def safe_extract(tar: tarfile.TarFile,
                 prog: progress.Progress,
                 dest: Path = ".",
                 members=None,
                 *,
                 numeric_owner: bool = False) -> None:
    task = prog.add_task(
        f'Validating {tar.name} ...', total=len(tar.getmembers()))
    total_size = 0
    for member in tar.getmembers():
        member_path = dest.parent / member.name
        total_size += member.size
        if not member_path.resolve().relative_to(dest.resolve()):
            raise RuntimeError(
                "Attempted Path Traversal in Tar File: {member.name}")
        prog.update(task, advance=1)
    prog.update(task, completed=prog.tasks[task].total)
    # assume that creating a file takes the same time as writing 2KiB
    file_creation_overhead = 2 * 1024
    prog_size = total_size + len(tar.getmembers()) * file_creation_overhead
    task = prog.add_task(f'Extracting {tar.name} ...', total=prog_size)

    def update_progress_filter(
        tarinfo: tarfile.TarInfo,
        path: str  # pylint: disable=unused-argument
    ) -> Optional[tarfile.TarInfo]:
        prog.update(task, advance=tarinfo.size + file_creation_overhead)
        return tarinfo

    tar.extractall(
        dest.parent,
        members,
        numeric_owner=numeric_owner,
        filter=update_progress_filter)
    prog.update(task, completed=prog_size)


def clean_dir(path: Path) -> None:
    for item in path.iterdir():
        if item.is_dir():
            clean_dir(item)
            item.rmdir()
        elif item.is_file() or item.is_symlink():
            item.unlink()
        else:
            print(
                f'Warning: skipping unknown file type: {item}', file=sys.stderr)


def install_go(tarball_path: Path, prog: progress.Progress) -> None:
    # https://golang.google.cn/doc/install
    dest = Path('/usr/local/go')
    if dest.exists():
        # Clean up existing installation
        print(
            f'Removing existing Go installation at {dest} ...', file=sys.stderr)
        clean_dir(dest)
    else:
        dest.mkdir(exist_ok=True)
    print(f'Extracting {tarball_path} to {dest} ...', file=sys.stderr)
    with tarfile.open(tarball_path, 'r:gz') as tar:
        safe_extract(tar, prog, dest)


def main() -> int:
    with progress.Progress(
            progress.TextColumn("[progress.description]{task.description}"),
            progress.BarColumn(),
            progress.DownloadColumn(),
            progress.TransferSpeedColumn(),
            progress.TimeRemainingColumn(),
    ) as prog:
        with httpx.Client(follow_redirects=True, http2=True) as client:
            stable = find_download(client, machine_to_arch(platform.machine()))
            downloads_dir = Path(appdirs.user_cache_dir()) / 'go-updater'
            downloads_dir.mkdir(parents=True, exist_ok=True)
            download_path = downloads_dir / stable.name
            if (download_path.exists() and
                    file_hash_matches(download_path, stable.sha256, prog)):
                print(
                    f'File {stable.name} is up to date (SHA256 matches).',
                    file=sys.stderr)
                download_skipped = True
            else:
                download(client, prog, stable, download_path)
                download_skipped = False
        if (not download_skipped and
                not file_hash_matches(download_path, stable.sha256, prog)):
            print(
                f'Downloaded file {download_path} is corrupted.',
                file=sys.stderr)
            return 1
        install_go(download_path, prog)


if __name__ == "__main__":
    sys.exit(main())
