"""Validate the public catalog and smoke-test local read-only actions."""

import gzip
import json
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile


def main():
    cli = str(Path(sys.argv[1]).resolve())
    catalog = Path(sys.argv[2]).resolve()

    def run(*args):
        result = subprocess.run([cli, 'catalog', *args], capture_output=True, text=True)
        if result.returncode:
            raise RuntimeError(result.stdout + result.stderr)
        return result.stdout

    validated = run('validate', '--dir', str(catalog))
    if validated.strip() != 'catalog generic-ops: 90 actions valid':
        raise RuntimeError('Unexpected catalog validation result: ' + validated)
    print(validated, end='')

    def smoke(directory, action, *parameters):
        args = ['try', action, '--dir', str(directory)]
        for parameter in parameters:
            args.extend(['--param', parameter])
        result = json.loads(run(*args))
        if not result['ok'] or result['exit_code'] != 0 or result['stderr']:
            raise RuntimeError(f'{action}: unexpected result: {result}')
        print(f'{action}: ok')
        return result

    for action in ('system_load', 'disk_usage', 'ports_listening'):
        result = smoke(catalog, action)
        if not result['stdout'] or result['truncated']:
            raise RuntimeError(f'{action}: expected nonempty, untruncated output')

    with tempfile.TemporaryDirectory(prefix='allowops-examples-') as temporary:
        root = Path(temporary)
        local_catalog = root / 'catalog'
        shutil.copytree(catalog, local_catalog)
        logs = root / 'logs'
        logs.mkdir()
        plain = logs / 'app.log'
        plain.write_text('keep first\nskip\nkeep last\n', encoding='utf-8')
        archived = logs / 'app.log.gz'
        with gzip.open(archived, 'wt', encoding='utf-8') as stream:
            stream.write('keep archived\n')

        # Change only the copied log roots; the public catalog stays unchanged.
        action_file = local_catalog / 'actions' / 'log_search.yaml'
        action = action_file.read_text(encoding='utf-8')
        original = '  allowed_roots: [/var/log, /data/logs]'
        if action.count(original) != 1:
            raise RuntimeError('Expected one log_search allowed_roots declaration')
        action_file.write_text(
            action.replace(original, '  allowed_roots: ' + json.dumps([str(logs)])),
            encoding='utf-8',
        )
        parameters = (f'path_glob={logs}/*.log*', 'pattern=keep', 'fixed=true')
        result = smoke(local_catalog, 'log_search', *parameters)
        expected = (
            f'{plain}:1:keep first\n{plain}:3:keep last\n'
            f'{archived}:1:keep archived\n'
        )
        if result['stdout'] != expected or result['truncated']:
            raise RuntimeError(f'log_search: expected {expected!r}, got {result}')
        counted = smoke(local_catalog, 'log_search', *parameters, 'count=true')
        if counted['stdout'] != '3\n' or counted['truncated']:
            raise RuntimeError(f'log_search count: expected 3 matches, got {counted}')
        empty = smoke(local_catalog, 'log_search', f'path_glob={logs}/*.log*', 'pattern=absent')
        if empty['stdout'] or empty['truncated']:
            raise RuntimeError(f'log_search: expected no matches, got {empty}')
        limited = smoke(local_catalog, 'log_search', *parameters, 'max_matches=1')
        if not limited['truncated'] or not limited['resource_limit_reached']:
            raise RuntimeError(f'log_search: expected a resource limit marker, got {limited}')


if __name__ == '__main__':
    try:
        main()
    except (RuntimeError, ValueError) as error:
        print(error, file=sys.stderr)
        sys.exit(1)
