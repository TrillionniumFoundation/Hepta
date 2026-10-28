"""Verify ordered evidence partitions; optionally write their exact archive."""
import argparse
from hashlib import sha256
import json
from pathlib import Path

def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--directory', type=Path, default=Path(__file__).resolve().parent)
    parser.add_argument('--output', type=Path, help='Create the reconstructed archive; existing paths are refused')
    args = parser.parse_args()
    manifest = json.loads((args.directory / 'raw-evidence-manifest.json').read_text())
    full, total, seen = sha256(), 0, set()
    destination = args.output.open('xb') if args.output else None
    try:
        for part in manifest['parts']:
            name = part['name']
            if Path(name).name != name or name in seen:
                raise ValueError('invalid or duplicate partition name')
            seen.add(name)
            digest, size = sha256(), 0
            with (args.directory / name).open('rb') as stream:
                while block := stream.read(1024 * 1024):
                    digest.update(block)
                    full.update(block)
                    size += len(block)
                    if destination:
                        destination.write(block)
            if size != part['bytes'] or digest.hexdigest() != part['sha256']:
                raise ValueError('partition identity mismatch: ' + name)
            total += size
        if total != manifest['archive']['bytes'] or full.hexdigest() != manifest['archive']['sha256']:
            raise ValueError('reconstructed archive identity mismatch')
    finally:
        if destination:
            destination.close()
    print(json.dumps({'verified': True, 'partitions': len(seen), 'archive_bytes': total,
        'archive_sha256': full.hexdigest(), 'source_commit': manifest['source_commit'],
        'ndu_experiment_source_commit': manifest['ndu_experiment_source_commit'],
        'output': str(args.output) if args.output else None}, indent=2))

if __name__ == '__main__':
    main()
