"""Aggregate common/combined nginx access logs using only the standard library.

The signed action supplies all arguments. The host executor must validate the
path, verify the script digest, run Python with -I, and enforce the action timeout.
"""

import argparse
import collections
import datetime
import json
import os
import re
import stat
import sys


ALLOWED_ROOTS = ('/var/log/nginx', '/data/logs/nginx')
MAX_BYTES = 67108864
MAX_LINE_BYTES = 65536
METHODS = {'GET', 'HEAD', 'POST', 'PUT', 'DELETE', 'CONNECT', 'OPTIONS', 'TRACE', 'PATCH'}
ENTRY = re.compile(
    rb'^\S+ \S+ \S+ \[(?P<time>[^\]\r\n]{1,40})\] '
    rb'"(?P<request>(?:[^"\\]|\\.)*)" '
    rb'(?P<status>[1-5][0-9]{2}) (?P<size>[0-9]{1,20}|-)(?:\s|$)'
)


def summarize(stream, hour, max_lines, max_bytes):
    """Read a bounded binary stream and return aggregate values without entries."""
    statuses = collections.Counter()
    methods = collections.Counter()
    scanned_bytes = 0
    scanned_lines = 0
    malformed = 0
    requests = 0
    bytes_sent = 0
    scan_limited = False
    while scanned_lines < max_lines and scanned_bytes < max_bytes:
        remaining = max_bytes - scanned_bytes
        line = stream.readline(min(remaining + 1, MAX_LINE_BYTES + 1))
        if not line:
            break
        if len(line) > remaining or len(line) > MAX_LINE_BYTES:
            scan_limited = True
            break
        scanned_bytes += len(line)
        scanned_lines += 1
        entry = ENTRY.match(line)
        if entry is None:
            malformed += 1
            continue
        try:
            timestamp = datetime.datetime.strptime(
                entry.group('time').decode('ascii'), '%d/%b/%Y:%H:%M:%S %z'
            )
        except (UnicodeError, ValueError):
            malformed += 1
            continue
        if hour is not None and timestamp.strftime('%Y-%m-%dT%H') != hour:
            continue
        method = entry.group('request').split(b' ', 1)[0].decode('ascii', 'replace')
        methods[method if method in METHODS else 'OTHER'] += 1
        statuses[entry.group('status').decode('ascii')] += 1
        size = entry.group('size')
        bytes_sent += 0 if size == b'-' else int(size)
        requests += 1
    else:
        # Report reaching a bound even when EOF might coincide with that bound.
        scan_limited = True
    return {
        'hour': hour,
        'requests': requests,
        'statuses': dict(statuses),
        'methods': dict(methods),
        'bytes_sent': bytes_sent,
        'scanned_lines': scanned_lines,
        'scanned_bytes': scanned_bytes,
        'malformed_lines': malformed,
        'scan_limited': scan_limited,
    }


def main():
    parser = argparse.ArgumentParser(description='Aggregate bounded nginx access logs.')
    parser.add_argument('--path', required=True)
    parser.add_argument('--hour')
    parser.add_argument('--max-lines', type=int, required=True)
    parser.add_argument('--max-bytes', type=int, required=True)
    args = parser.parse_args()
    if not 1 <= args.max_lines <= 1000000 or not 1 <= args.max_bytes <= MAX_BYTES:
        parser.error('Scan limits are outside the signed action bounds.')
    if args.hour is not None:
        if not re.fullmatch(r'[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}', args.hour):
            parser.error('The hour must use YYYY-MM-DDTHH.')
        try:
            datetime.datetime.strptime(args.hour, '%Y-%m-%dT%H')
        except ValueError:
            parser.error('The hour must be a valid calendar hour.')
    resolved = os.path.realpath(args.path)
    if not any(resolved.startswith(root + os.sep) for root in ALLOWED_ROOTS):
        parser.error('The path is outside the signed log roots.')
    try:
        descriptor = os.open(resolved, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW)
        with os.fdopen(descriptor, 'rb') as stream:
            if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
                parser.error('The path must be an existing regular file.')
            opened_path = os.path.realpath('/proc/self/fd/' + str(stream.fileno()))
            if not any(opened_path.startswith(root + os.sep) for root in ALLOWED_ROOTS):
                parser.error('The opened file is outside the signed log roots.')
            result = summarize(stream, args.hour, args.max_lines, args.max_bytes)
    except OSError:
        print('Unable to read the access log.', file=sys.stderr)
        return 1
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == '__main__':
    sys.exit(main())
