"""Check the agent_upgrade example script against stub package managers."""

from pathlib import Path
import subprocess
import sys
import tempfile

SCRIPT = Path(__file__).resolve().parents[2] / 'examples' / 'catalog' / 'scripts' / 'agent_upgrade.sh'
RESTART = ('systemd-run --on-active=5 --timer-property=AccuracySec=1s '
           '/usr/bin/systemctl restart allowops-agent.service')

# Stubs use shell builtins only; PATH contains nothing but the stub directory.
QUERY = '''#!/bin/sh
echo "${0##*/} $*" >> "$STUB/calls"
[ -f "$STUB/installed" ] || exit 1
read -r v < "$STUB/installed"
printf %s "$v"
'''
INSTALL = '''#!/bin/sh
echo "${0##*/} $*" >> "$STUB/calls"
case " $* " in *" install "*|*" upgrade "*) [ ! -f "$STUB/after" ] || { read -r v < "$STUB/after"; echo "$v" > "$STUB/installed"; } ;; esac
'''
LOG = '''#!/bin/sh
echo "${0##*/} $*" >> "$STUB/calls"
'''


def run(family, installed, after, version='0.2.0'):
    with tempfile.TemporaryDirectory(prefix='allowops-agent-upgrade-') as temporary:
        stub = Path(temporary)
        tools = {'systemd-run': LOG}
        if family == 'deb':
            tools.update({'dpkg-query': QUERY, 'apt-get': INSTALL})
        else:
            tools.update({'rpm': QUERY, 'yum': INSTALL})
        for name, body in tools.items():
            (stub / name).write_text(body, encoding='utf-8')
            (stub / name).chmod(0o755)
        if installed:
            (stub / 'installed').write_text(installed + '\n', encoding='utf-8')
        if after:
            (stub / 'after').write_text(after + '\n', encoding='utf-8')
        result = subprocess.run(['/bin/sh', str(SCRIPT), version], capture_output=True, text=True,
                                env={'PATH': str(stub), 'STUB': str(stub)})
        calls = (stub / 'calls').read_text(encoding='utf-8').splitlines() if (stub / 'calls').exists() else []
        return result, [call for call in calls if not call.startswith(('dpkg-query', 'rpm'))]


def expect(name, outcome, code, calls):
    result, actual = outcome
    if result.returncode != code or actual != calls:
        raise RuntimeError(f'{name}: expected exit {code} and calls {calls}, '
                           f'got exit {result.returncode} calls {actual} '
                           f'stdout {result.stdout!r} stderr {result.stderr!r}')
    print(f'agent_upgrade {name}: ok')


def main():
    expect('deb upgrade', run('deb', '0.1.0', '0.2.0'), 0, [
        'apt-get update -q',
        'apt-get install -y -q allowops-agent=0.2.0',
        RESTART])
    expect('rpm upgrade', run('rpm', '0.1.0', '0.2.0'), 0, [
        'yum -q clean expire-cache',
        'yum upgrade -y -q allowops-agent-0.2.0',
        RESTART])
    # The requested version is already installed: nothing to install or restart.
    expect('deb current', run('deb', '0.2.0', None), 0, [])
    expect('rpm current', run('rpm', '0.2.0', None), 0, [])
    # yum upgrade never downgrades and may exit 0; the agent is not restarted.
    expect('rpm older request', run('rpm', '0.3.0', None), 1, [
        'yum -q clean expire-cache',
        'yum upgrade -y -q allowops-agent-0.2.0'])
    expect('deb wrong version', run('deb', '0.1.0', '0.1.0'), 1, [
        'apt-get update -q',
        'apt-get install -y -q allowops-agent=0.2.0'])


if __name__ == '__main__':
    try:
        main()
    except RuntimeError as error:
        print(error, file=sys.stderr)
        sys.exit(1)
