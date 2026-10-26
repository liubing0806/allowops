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
    if validated.strip() != 'catalog generic-ops: 106 actions valid':
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
        action_file = local_catalog / 'actions' / 'log_grep.yaml'
        action = action_file.read_text(encoding='utf-8')
        original = '  allowed_roots: [/var/log, /data/logs]'
        if action.count(original) != 1:
            raise RuntimeError('Expected one log_grep allowed_roots declaration')
        action_file.write_text(
            action.replace(original, '  allowed_roots: ' + json.dumps([str(logs)])),
            encoding='utf-8',
        )
        parameters = (f'path_glob={logs}/*.log*', 'pattern=keep', 'fixed=true')
        result = smoke(local_catalog, 'log_grep', *parameters)
        expected = (
            f'{plain}:1:keep first\n{plain}:3:keep last\n'
            f'{archived}:1:keep archived\n'
        )
        if result['stdout'] != expected or result['truncated']:
            raise RuntimeError(f'log_grep: expected {expected!r}, got {result}')
        counted = smoke(local_catalog, 'log_grep', *parameters, 'count=true')
        if counted['stdout'] != '3\n' or counted['truncated']:
            raise RuntimeError(f'log_grep count: expected 3 matches, got {counted}')
        empty = smoke(local_catalog, 'log_grep', f'path_glob={logs}/*.log*', 'pattern=absent')
        if empty['stdout'] or empty['truncated']:
            raise RuntimeError(f'log_grep: expected no matches, got {empty}')
        limited = smoke(local_catalog, 'log_grep', *parameters, 'max_matches=1')
        if not limited['truncated'] or not limited['resource_limit_reached']:
            raise RuntimeError(f'log_grep: expected a resource limit marker, got {limited}')

        # log_sources, log_search, log_stats and log_patterns (log_query
        # builtin): point the copied app source at the temporary logs; records
        # carry Logback timestamps.
        app_logs = root / 'app-logs'
        app_logs.mkdir()
        (app_logs / 'app.log').write_text(
            '2026-10-23 10:00:00.000 [main] ERROR c.y.App - update failed password=hunter2\n'
            'java.lang.IllegalStateException: boom\n'
            '\tat com.example.Foo.bar(Foo.java:10)\n'
            '2026-10-23 10:01:00.000 [main] INFO  c.y.App - ok\n'
            '2026-10-23 10:02:00.000 [main] ERROR c.y.App - update failed password=hunter3\n',
            encoding='utf-8',
        )
        for name in ('log_sources', 'log_search', 'log_stats', 'log_patterns', 'log_export'):
            action_file = local_catalog / 'actions' / f'{name}.yaml'
            action = action_file.read_text(encoding='utf-8')
            original = '  allowed_roots: [/data/logs]' if name == 'log_export' else '  allowed_roots: [/var/log, /data/logs]'
            if action.count(original) != 1 or action.count('/data/logs/app/') != 2:
                raise RuntimeError(f'Expected one {name} allowed_roots declaration and two app paths')
            action_file.write_text(
                action.replace(original, '  allowed_roots: ' + json.dumps([str(root)]))
                .replace('/data/logs/app/', f'{app_logs}/')
                .replace('/var/log/nginx/', f'{root}/nginx/'),
                encoding='utf-8',
            )
        listed = json.loads(smoke(local_catalog, 'log_sources')['stdout'])
        app = next(source for source in listed['sources'] if source['name'] == 'app')
        if app['status'] != 'ok' or app['files'] != 1 or app['earliest'] != '2026-10-23T10:00:00+08:00':
            raise RuntimeError(f'log_sources: unexpected app source {listed}')
        found = json.loads(smoke(
            local_catalog, 'log_search', 'source=app', 'since=2026-10-23T09:59:00+08:00',
            'until=2026-10-23T10:30:00+08:00', 'pattern=Foo.java:10', 'fixed=true',
        )['stdout'])
        records = found['records']
        if found['matched'] != 1 or len(records) != 1 or 'IllegalStateException' not in records[0]['text'] \
                or 'hunter2' in records[0]['text']:
            raise RuntimeError(f'log_search: expected one redacted stack trace record, got {found}')
        window = ('source=app', 'since=2026-10-23T09:59:00+08:00', 'until=2026-10-23T10:30:00+08:00')
        errors = json.loads(smoke(local_catalog, 'log_search', *window, 'level=["ERROR"]')['stdout'])
        counted = json.loads(smoke(local_catalog, 'log_stats', *window, 'level=["ERROR"]', 'bucket=1m')['stdout'])
        if errors['matched'] != 2 or counted['matched'] != 2 or sum(b['count'] for b in counted['histogram']) != 2 \
                or counted['by_level'] != {'ERROR': 2} or counted['bucket'] != '1m0s' or 'update failed' in json.dumps(counted):
            raise RuntimeError(f'log_stats: expected two ERROR records without log text, got {counted} and {errors}')
        grouped = json.loads(smoke(local_catalog, 'log_patterns', *window)['stdout'])
        top = grouped['patterns'][0]
        if grouped['records'] != 3 or top['count'] != 2 or top['template'] != '<_> [main] ERROR c.y.App - update failed <_>' \
                or 'hunter' in json.dumps(grouped):
            raise RuntimeError(f'log_patterns: expected a redacted two-record template, got {grouped}')
        # log_export: one line per record, oldest first, newlines escaped,
        # then a trailer line; limit=1 leaves a next_cursor.
        exported = smoke(local_catalog, 'log_export', *window)['stdout'].splitlines()
        if len(exported) != 4 or not exported[0].startswith('2026-10-23T10:00:00+08:00 2026-10-23 10:00:00.000') \
                or '\\njava.lang.IllegalStateException: boom\\n\tat com.example.Foo.bar' not in exported[0] \
                or 'hunter' in '\n'.join(exported) or not exported[1].endswith('INFO  c.y.App - ok') \
                or not exported[3].startswith('# matched=3 ') or 'next_cursor' in exported[3]:
            raise RuntimeError(f'log_export: unexpected output {exported}')
        first = smoke(local_catalog, 'log_export', *window, 'limit=1')['stdout'].splitlines()
        cursor = next((f[len('next_cursor='):] for f in first[-1].split() if f.startswith('next_cursor=')), '')
        rest = smoke(local_catalog, 'log_export', *window, 'limit=1', f'cursor={cursor}')['stdout'].splitlines()
        if len(first) != 2 or not cursor or rest[:-1] != exported[1:2] or 'next_cursor=' not in rest[-1]:
            raise RuntimeError(f'log_export: unexpected pages {first} {rest}')

        # app_config_view: structured credentials are redacted and the exit
        # code does not depend on the match filter.
        configs = root / 'configs'
        configs.mkdir()
        (configs / 'app.properties').write_text(
            'server.port=8080\ndb.password=hunter2\n"secretKey": "jsonvalue"\n'
            '<password>xmlvalue</password>\n<entry name="password" value="attrvalue"/>\n',
            encoding='utf-8',
        )
        (configs / 'private.pem').write_text(
            '-----BEGIN PRIVATE KEY-----\nTWFuIGlzIGRpc3Rpbmd1aXNoZWQsIG5vdCBvbmx5IGJ5IGhpcw\nabcDEF123xyz98==\n'
            '-----END PRIVATE KEY-----\n',
            encoding='utf-8',
        )
        for name in ('app_config_view', 'app_config_keys'):
            action_file = local_catalog / 'actions' / f'{name}.yaml'
            action = action_file.read_text(encoding='utf-8')
            original = '    allowed_roots: [/etc/app, /opt/app/config]'
            if action.count(original) != 1:
                raise RuntimeError(f'Expected one {name} allowed_roots declaration')
            action_file.write_text(
                action.replace(original, '    allowed_roots: ' + json.dumps([str(configs)])),
                encoding='utf-8',
            )
        viewed = smoke(local_catalog, 'app_config_view', f'path={configs}/app.properties')
        for secret in ('hunter2', 'jsonvalue', 'xmlvalue', 'attrvalue'):
            if secret in viewed['stdout']:
                raise RuntimeError(f'app_config_view leaked {secret!r}: {viewed}')
        if 'server.port=8080' not in viewed['stdout']:
            raise RuntimeError(f'app_config_view: expected server.port line, got {viewed}')
        for pattern in ('hunter2', 'absent'):
            probe = smoke(local_catalog, 'app_config_view', f'path={configs}/app.properties', f'match={pattern}')
            if probe['stdout']:
                raise RuntimeError(f'app_config_view: match={pattern} must not reveal redacted values: {probe}')
        keys = smoke(local_catalog, 'app_config_keys', f'path={configs}/app.properties')
        if keys['stdout'] != 'server.port\ndb.password\n':
            raise RuntimeError(f'app_config_keys: unexpected keys {keys}')
        pem = subprocess.run(
            [cli, 'catalog', 'try', 'app_config_keys', '--dir', str(local_catalog), '--param', f'path={configs}/private.pem'],
            capture_output=True, text=True,
        )
        if 'TWFu' in pem.stdout or 'abcDEF' in pem.stdout:
            raise RuntimeError('app_config_keys printed private key content: ' + pem.stdout)


if __name__ == '__main__':
    try:
        main()
    except (RuntimeError, ValueError) as error:
        print(error, file=sys.stderr)
        sys.exit(1)
