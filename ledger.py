"""Local evidence freshness checker. Does not assess truth or sign attestations."""
import argparse
import copy
import datetime as dt
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat
import sys

VERSION = '0.1.0'
MAX_JSON = 1024 * 1024
MAX_FILE = 64 * 1024 * 1024
MAX_ITEMS = 500
MAX_TOTAL = 256 * 1024 * 1024
BASE_KEYS = {'id', 'criterion', 'artifact', 'evidence', 'method', 'status', 'checker', 'checker_version'}
DIGEST = re.compile(r'^[0-9a-f]{64}$')

class Invalid(ValueError):
    pass

def pairs(items):
    result = {}
    for k, v in items:
        if k in result:
            raise Invalid('duplicate JSON key')
        result[k] = v
    return result

def text(value, limit=2000):
    if not isinstance(value, str) or not value.strip() or len(value) > limit:
        raise Invalid('invalid string')
    if any(ord(c) < 32 or ord(c) == 127 for c in value):
        raise Invalid('control character')
    return value

def relpath(value):
    text(value, 500)
    p = PurePosixPath(value)
    if p.is_absolute() or '\\' in value or ':' in value or any(s in ('', '.', '..') for s in value.split('/')):
        raise Invalid('path must be normalized and relative')
    return p

def read_safe(root, name, limit=MAX_FILE):
    """Read regular files only; POSIX dir_fd/O_NOFOLLOW protect each path component."""
    p = relpath(name)
    root = Path(root)
    if root.is_symlink():
        raise Invalid('root must not be a symlink')
    if not hasattr(os, 'O_NOFOLLOW') or os.open not in os.supports_dir_fd:
        raise Invalid('secure path traversal requires POSIX dir_fd/O_NOFOLLOW')
    fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        for part in p.parts[:-1]:
            nxt = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd)
            os.close(fd)
            fd = nxt
        filefd = os.open(p.parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fd)
        with os.fdopen(filefd, 'rb') as stream:
            before = os.fstat(stream.fileno())
            if not stat.S_ISREG(before.st_mode) or before.st_size > limit:
                raise Invalid('not a regular file or size limit exceeded')
            data = stream.read(limit + 1)
            after = os.fstat(stream.fileno())
            if len(data) > limit or (before.st_size, before.st_mtime_ns, before.st_ctime_ns) != (after.st_size, after.st_mtime_ns, after.st_ctime_ns):
                raise Invalid('file too large or changed while reading')
            return data
    finally:
        os.close(fd)

def load(root, name):
    try:
        return json.loads(read_safe(root, name, MAX_JSON).decode('utf-8'), object_pairs_hook=pairs,
                          parse_constant=lambda x: (_ for _ in ()).throw(Invalid('non-finite number')))
    except (UnicodeError, ValueError, RecursionError) as exc:
        raise Invalid('invalid JSON') from exc

def digest(data):
    return hashlib.sha256(data).hexdigest()

def canonical(obj):
    return json.dumps(obj, sort_keys=True, ensure_ascii=True, separators=(',', ':')).encode()

def validate(doc, sealed=False):
    expected = {'version', 'requirements'} | ({'recorded_at', 'tool_version', 'spec_sha256'} if sealed else set())
    if not isinstance(doc, dict) or set(doc) != expected or type(doc['version']) is not int or doc['version'] != 1:
        raise Invalid('unsupported document structure')
    rows = doc['requirements']
    if not isinstance(rows, list) or not 1 <= len(rows) <= MAX_ITEMS:
        raise Invalid('requirements must be nonempty and bounded')
    seen = set()
    for row in rows:
        keys = BASE_KEYS | ({'artifact_sha256', 'evidence_sha256'} if sealed else set())
        if not isinstance(row, dict) or set(row) != keys:
            raise Invalid('invalid requirement structure')
        for key in BASE_KEYS - {'evidence'}:
            text(row[key])
        if not re.fullmatch(r'[A-Za-z0-9_-]{1,64}', row['id']) or row['id'] in seen:
            raise Invalid('duplicate or invalid requirement id')
        seen.add(row['id'])
        relpath(row['artifact'])
        if row['method'] not in ('manual', 'automated') or row['status'] not in ('pass', 'fail', 'pending', 'blocked'):
            raise Invalid('invalid method or status')
        if row['evidence'] is not None:
            relpath(row['evidence'])
        if row['status'] in ('pass', 'fail') and row['evidence'] is None:
            raise Invalid('decided checks require evidence')
        if sealed:
            for key in ('artifact_sha256', 'evidence_sha256'):
                value = row[key]
                if value is not None and (not isinstance(value, str) or not DIGEST.fullmatch(value)):
                    raise Invalid('invalid digest')
            if not row['artifact_sha256'] or (row['evidence'] is not None) != (row['evidence_sha256'] is not None):
                raise Invalid('missing digest')
    if sealed:
        if not isinstance(doc['spec_sha256'], str) or not DIGEST.fullmatch(doc['spec_sha256']):
            raise Invalid('invalid spec digest')
        text(doc['tool_version'], 50)
        try:
            stamp = dt.datetime.fromisoformat(doc['recorded_at'])
            if stamp.tzinfo is None:
                raise ValueError()
        except (TypeError, ValueError):
            raise Invalid('invalid timestamp')
    return doc

class Fingerprints:
    """Bound total reads and avoid re-reading one path for every requirement."""
    def __init__(self, root):
        self.root = root
        self.used = 0
        self.cache = {}

    def get(self, name, nonempty=False):
        if name not in self.cache:
            data = read_safe(self.root, name, min(MAX_FILE, MAX_TOTAL - self.used))
            self.used += len(data)
            self.cache[name] = (digest(data), len(data))
        value, length = self.cache[name]
        if nonempty and length == 0:
            raise Invalid('evidence must not be empty')
        return value


def snapshot(root, spec):
    """Capture caller-supplied verdicts; never runs the named checker."""
    validate(spec)
    result = copy.deepcopy(spec)
    result.update(recorded_at=dt.datetime.now(dt.timezone.utc).isoformat(), tool_version=VERSION,
                  spec_sha256=digest(canonical(spec)))
    files = Fingerprints(root)
    for row in result['requirements']:
        row['artifact_sha256'] = files.get(row['artifact'])
        row['evidence_sha256'] = files.get(row['evidence'], nonempty=True) if row['evidence'] else None
    return validate(result, True)

def verify(root, spec, ledger):
    validate(spec)
    validate(ledger, True)
    spec_current = digest(canonical(spec)) == ledger['spec_sha256']
    expected = {r['id']: r for r in spec['requirements']}
    results = []
    files = Fingerprints(root)
    for row in ledger['requirements']:
        issues = []
        if row['id'] not in expected or any(row[k] != expected[row['id']][k] for k in BASE_KEYS):
            issues.append('requirement_changed')
        for kind in ('artifact', 'evidence'):
            if row[kind] is None:
                continue
            try:
                if files.get(row[kind], nonempty=(kind == 'evidence')) != row[kind + '_sha256']:
                    issues.append(kind + '_changed')
            except (OSError, Invalid):
                issues.append(kind + '_unreadable_or_unsafe')
        state = 'stale' if issues else ('recorded_pass_current' if row['status'] == 'pass' else row['status'])
        results.append({'id': row['id'], 'state': state, 'method': row['method'], 'issues': issues})
    missing = sorted(set(expected) - {r['id'] for r in ledger['requirements']})
    current = spec_current and not missing and all(r['state'] == 'recorded_pass_current' for r in results)
    return {'all_recorded_passes_current': current, 'spec_current': spec_current,
            'missing_requirements': missing, 'requirements': results,
            'notice': 'Hashes verify freshness only. Verdicts and evidence are self-reported, not authenticated or semantically verified.'}

def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('command', choices=['snapshot', 'verify'])
    parser.add_argument('--root', required=True, help='trusted local project directory')
    parser.add_argument('--spec', required=True, help='relative spec path under root')
    parser.add_argument('--ledger', help='relative ledger path for verify')
    args = parser.parse_args(argv)
    try:
        spec = load(args.root, args.spec)
        if args.command == 'snapshot':
            result = snapshot(args.root, spec)
            code = 0
        else:
            if not args.ledger:
                raise Invalid('--ledger is required')
            result = verify(args.root, spec, load(args.root, args.ledger))
            code = 0 if result['all_recorded_passes_current'] else 1
        print(json.dumps(result, ensure_ascii=True, indent=2))
        return code
    except (Invalid, OSError) as exc:
        print(json.dumps({'error': 'invalid_input', 'detail': str(exc)}, ensure_ascii=True), file=sys.stderr)
        return 2

if __name__ == '__main__':
    sys.exit(main())
