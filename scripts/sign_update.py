"""Sign the version, database schema and native archive hashes for a GitHub release."""
import argparse
import json
from pathlib import Path
import sys
import time

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import load_pem_private_key

from scripts.verify_release import TARGETS, package_names, verify_release

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))
from spearmint.peer.protocol import wire_b64
from spearmint.platforms import check_private
from spearmint.update_release import INDEX, RELEASE_PUBLIC_KEY, Asset, Release, signed_bytes


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('directory', type=Path, help='Directory containing the three verified archives and their sidecars')
    parser.add_argument('--tag', required=True)
    parser.add_argument('--commit', required=True)
    parser.add_argument('--key', required=True, type=Path, help='Private PEM key kept outside the project directory')
    parser.add_argument('--output', type=Path, default=Path('work/tmp/package-build') / INDEX)
    options = parser.parse_args()
    version = options.tag.removeprefix('v').partition('-')[0]
    source = options.key.resolve(strict=True)
    repo = Path(__file__).resolve().parents[1]
    if source.is_relative_to(repo):
        parser.error('Keep the private signing key outside the repository')
    check_private(source, 0o600, False)
    key = load_pem_private_key(source.read_bytes(), password=None)
    if not isinstance(key, Ed25519PrivateKey) or key.public_key().public_bytes_raw() != RELEASE_PUBLIC_KEY:
        parser.error('The key does not match Spearmint’s update verification key')
    report = verify_release(options.directory, version, options.commit, TARGETS)
    for target in TARGETS:
        manifest = options.directory / package_names(version, options.commit, target)[2]
        if json.loads(manifest.read_bytes()).get('grove_update') != 1:
            parser.error('Build all three archives with Grove update support before signing')
    index = {'tag': options.tag, 'version': version, 'commit': options.commit,
             'schema': report['schema'], 'sequence': int(time.time()),
             'packages': {item['target']: {'sha256': item['sha256'], 'size': (options.directory / item['archive']).stat().st_size}
                          for item in report['packages']}}
    signature = wire_b64(key.sign(signed_bytes(index)))
    Release.model_validate({**index, 'signature': signature,
                            'packages': {target: Asset(id=1, **value) for target, value in index['packages'].items()}})
    options.output.parent.mkdir(parents=True, exist_ok=True)
    options.output.write_text(json.dumps({'release': index, 'signature': signature}, indent=2) + '\n', encoding='utf-8')


if __name__ == '__main__':
    main()