"""Inspect the Web entry point used by the panel."""

from html.parser import HTMLParser
import hashlib
from pathlib import Path
import re
from urllib.parse import urlsplit


ENTRY_ASSET = re.compile(r'/assets/index-([\w-]{1,120})\.(js|css)', re.ASCII)
SERVED_ASSET_PART = re.compile(r'[a-zA-Z0-9_.-]+')


class WebEntry(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.assets: set[str] = set()
        self.has_script = False
        self.scripts: set[str] = set()
        self.styles: set[str] = set()

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        fields = dict(attrs)
        asset = fields.get('src') if tag == 'script' else fields.get('href') if tag == 'link' else None
        if asset and asset.startswith('/assets/'):
            path = urlsplit(asset).path
            self.assets.add(path)
            self.has_script |= tag == 'script'
            match = ENTRY_ASSET.fullmatch(path)
            if match and tag == 'script' and match[2] == 'js':
                self.scripts.add(match[1])
            if match and 'stylesheet' in (fields.get('rel') or '').lower().split() and match[2] == 'css':
                self.styles.add(match[1])

    @classmethod
    def parse(cls, html: str) -> 'WebEntry':
        entry = cls()
        entry.feed(html)
        entry.close()
        return entry

    @classmethod
    def read(cls, index: Path) -> 'WebEntry':
        return cls.parse(index.read_text(encoding='utf-8'))

    def served_assets(self) -> list[str]:
        if not self.has_script:
            raise ValueError('Panel homepage does not reference a built script')
        if len(self.assets) > 32:
            raise ValueError('Panel homepage references more than 32 assets')
        assets = sorted(self.assets)
        for asset in assets:
            parts = asset.removeprefix('/assets/').split('/')
            if any(part in ('.', '..') or not SERVED_ASSET_PART.fullmatch(part) for part in parts):
                raise ValueError('Panel homepage references an invalid asset path')
        return assets

    def missing_assets(self, directory: Path) -> list[str]:
        assets = (directory / 'assets').resolve()
        missing = []
        for asset in sorted(self.assets):
            parts = asset.removeprefix('/assets/').split('/')
            if any(part in ('', '.', '..') or '\\' in part or ':' in part for part in parts):
                missing.append(asset)
                continue
            candidate = assets.joinpath(*parts).resolve()
            if not candidate.is_relative_to(assets) or not candidate.is_file():
                missing.append(asset)
        return missing

    def build(self) -> str | None:
        if len(self.scripts) == len(self.styles) == 1:
            return f'{next(iter(self.scripts))} / {next(iter(self.styles))}'
        return None


def check_web_bundle(directory: Path) -> str:
    index = directory / 'index.html'
    if not index.is_file():
        raise ValueError(f'Web entry is missing: {index}')
    entry = WebEntry.read(index)
    if not entry.has_script:
        raise ValueError(f'Web entry does not reference a built script: {index}')
    if missing := entry.missing_assets(directory):
        raise ValueError(f"Web asset is missing: {directory / missing[0].lstrip('/')}")
    return f'present ({len(entry.assets)} entry assets)'


def web_bundle_status(directory: Path) -> dict:
    try:
        entry = WebEntry.read(directory / 'index.html')
        if not entry.has_script:
            return {'status': 'unbuilt', 'build': None}
        status = 'missing-assets' if entry.missing_assets(directory) else 'ready'
        return {'status': status, 'build': entry.build()}
    except FileNotFoundError:
        return {'status': 'missing-entry', 'build': None}
    except (OSError, ValueError):
        return {'status': 'unreadable', 'build': None}


def matches_packaged_web(directory: Path, expected: dict[str, str]) -> bool | None:
    """Compare files served by this node with the running backend's build manifest."""
    try:
        root = directory.resolve()
        for name, digest in expected.items():
            parts = name.split('/')
            if any(part in ('', '.', '..') or '\\' in part or ':' in part for part in parts):
                return None
            path = root.joinpath(*parts).resolve()
            if not path.is_relative_to(root):
                return None
            if not path.is_file():
                return False
            with path.open('rb') as stream:
                if hashlib.file_digest(stream, 'sha256').hexdigest() != digest:
                    return False
    except (OSError, ValueError, RuntimeError):
        return None
    return True
