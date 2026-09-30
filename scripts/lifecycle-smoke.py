"""Execute fnOS lifecycle scripts against temporary mixed-version fixtures.

Uses Git Bash on Windows. Identity, ownership, flock and /proc/kill are mocked;
this checks real shell control flow, not Linux permissions or kernel locking.
Never contacts a NAS, launches the service, or changes host networking.
"""
import argparse
import hashlib
import os
import pathlib
import shutil
import subprocess
import tempfile


ROOT = pathlib.Path(__file__).resolve().parents[1]


def posix(path):
    path = pathlib.Path(path).resolve().as_posix()
    if len(path) > 2 and path[1] == ':':
        return '/' + path[0].lower() + path[2:]
    return path


def write(path, text):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding='utf-8', newline='\n')
    path.chmod(0o755)


class Fixture:
    def __init__(self, parent, source, bash):
        self.root = pathlib.Path(tempfile.mkdtemp(prefix='lifecycle-', dir=parent))
        self.bash = bash
        self.cmd = self.root / 'incoming' / 'cmd'
        self.app = self.root / 'old-app'
        self.data = self.root / 'fn-wireguard'
        self.etc = self.root / 'etc'
        self.proc = self.root / 'mock-proc'
        self.mock = self.root / 'mock-bin'
        self.events = self.root / 'events'
        self.error = self.root / 'error'
        for directory in [self.cmd, self.app / 'server', self.data, self.etc, self.proc, self.mock]:
            directory.mkdir(parents=True, exist_ok=True)
        # The only source adaptation is the process-filesystem seam. The mock
        # below models /proc executable symlinks with ordinary fixture files,
        # avoiding a Windows symlink-creation privilege requirement.
        for script in source.iterdir():
            if script.is_file():
                text = script.read_text(encoding='utf-8-sig').replace('/proc/', '${MOCK_PROC}/')
                write(self.cmd / script.name, text)
        write(self.app / 'server' / 'fn-wireguard', '#!/bin/bash\nexit 77\n')
        write(self.app / 'server' / 'run-service', '#!/bin/bash\nexit 77\n')
        # Model existing application data without ever inspecting actual keys.
        (self.data / 'master.key').write_bytes(b'fixture-key-contents-32-bytes!!!!')
        (self.data / 'state.db').write_bytes(b'fixture-existing-database')
        self.before = {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in self.data.iterdir()}
        write(self.mock / 'id', '#!/bin/bash\nif [ "${1:-}" = -u ]; then echo 0; fi\nexit 0\n')
        write(self.mock / 'stat', '''#!/bin/bash
case "$2" in
  %u:%a) echo 0:755 ;;
  %h:%u) echo 1:0 ;;
  *) /usr/bin/stat "$@" ;;
esac
''')
        for command in ['chown', 'chmod']:
            write(self.mock / command, '#!/bin/bash\nprintf "%s\\n" "' + command + ':$*" >> "$MOCK_EVENTS"\nexit 0\n')
        write(self.mock / 'flock', '#!/bin/bash\nprintf "flock:%s\\n" "$*" >> "$MOCK_EVENTS"\n[ "${MOCK_BUSY:-0}" != 1 ]\n')
        write(self.mock / 'readlink', '''#!/bin/bash
case "$1" in
  "$MOCK_PROC"/*/exe) cat "${1%exe}exe-target" ;;
  *) /usr/bin/readlink "$@" ;;
esac
''')
        for command in ['setpriv', 'ip']:
            write(self.mock / command, '#!/bin/bash\nprintf "%s\\n" "' + command + ':$*" >> "$MOCK_EVENTS"\nexit 77\n')
        write(self.mock / 'sysctl', '''#!/bin/bash
printf 'sysctl:%s\\n' "$*" >> "$MOCK_EVENTS"
if [ "$1" = -n ]; then printf '%s\\n' "${MOCK_FORWARD:-1}"; exit 0; fi
[ "${MOCK_FORWARD_FAIL:-0}" != 1 ]
''')
        self.bash_env = self.root / 'bash-env'
        write(self.bash_env, '''kill() {
  case "${2:-}" in ''|*[!0-9]*) return 1 ;; esac
  case "$1" in
    -0) [ -d "$MOCK_PROC/$2" ] ;;
    -TERM) printf 'kill:TERM:%s\\n' "$2" >> "$MOCK_EVENTS"; rm -f -- "$MOCK_PROC/$2/exe" "$MOCK_PROC/$2/exe-target"; rmdir -- "$MOCK_PROC/$2" ;;
    *) return 1 ;;
  esac
}
function [() {
  if builtin [ "$#" -eq 3 ] && builtin [ "$1" = -L ]; then
    case "$2" in "$MOCK_PROC"/*/exe) builtin [ -f "$2" ]; return ;; esac
  fi
  builtin [ "$@"
}
''')
        self.env = dict(os.environ, TRIM_APPDEST=posix(self.app), TRIM_PKGVAR=posix(self.data),
                        TRIM_PKGETC=posix(self.etc), TRIM_USERNAME='fnwireguard', TRIM_GROUPNAME='fnwireguard',
                        TRIM_TEMP_LOGFILE=posix(self.error), MOCK_BIN=posix(self.mock), MOCK_PROC=posix(self.proc),
                        MOCK_EVENTS=posix(self.events), BASH_ENV=posix(self.bash_env), MOCK_BUSY='0')

    def process(self, foreign=False, deleted=False):
        directory = self.proc / '43210'
        directory.mkdir()
        (directory / 'exe').write_text('process metadata only')
        target = '/unrelated/service' if foreign else posix(self.app / 'server' / 'fn-wireguard')
        (directory / 'exe-target').write_text(target + (' (deleted)' if deleted else ''), encoding='utf-8')
        (self.etc / 'app.pid').write_text('43210\n')

    def run(self, script, *arguments, busy=False):
        env = dict(self.env, MOCK_BUSY='1' if busy else '0')
        result = subprocess.run([self.bash, '-c', 'export PATH="$MOCK_BIN:$PATH"; /bin/bash "$@"',
                                 'lifecycle-smoke', posix(self.cmd / script), *arguments],
                                env=env, capture_output=True, text=True, encoding='utf-8', errors='replace', timeout=8)
        error = self.error.read_text(encoding='utf-8', errors='replace') if self.error.exists() else ''
        return result.returncode, error + result.stderr

    def unchanged(self):
        assert self.before == {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in self.data.iterdir()}, 'application data changed'

    def trace(self):
        return self.events.read_text(encoding='utf-8') if self.events.exists() else ''


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--cmd-dir', default='packaging/fnos/cmd', help='incoming package cmd directory')
    parser.add_argument('--bash', default='C:/Program Files/Git/bin/bash.exe')
    parser.add_argument('--expect-old-regression', action='store_true', help='require legacy incoming upgrade to fail with missing lock helper')
    args = parser.parse_args()
    source = (ROOT / args.cmd_dir).resolve()
    assert source.is_dir(), source
    bash = args.bash if pathlib.Path(args.bash).exists() else shutil.which('bash')
    assert bash, 'Git Bash executable not found'
    local = ROOT / '.local'
    local.mkdir(exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='lifecycle-suite-', dir=local) as directory:
        parent = pathlib.Path(directory)
        if args.expect_old_regression:
            fixture = Fixture(parent, source, bash)
            code, error = fixture.run('upgrade_init')
            assert code != 0 and '生命周期锁程序缺失' in error, (code, error)
            fixture.unchanged()
            print('PASS negative regression: incoming upgrade fails against old payload without lifecycle-lock')
            return
        checks = []
        for version in ['0.1.1', 'broken-0.1.2']:
            fixture = Fixture(parent, source, bash)
            # Old payload deliberately has no newly introduced lifecycle helper.
            if version == 'broken-0.1.2':
                write(fixture.cmd / 'main', '#!/bin/bash\nprintf "untrusted-main-invoked\\n" >> "$MOCK_EVENTS"\nexit 99\n')
            code, error = fixture.run('upgrade_init')
            assert code == 0, (version, code, error)
            assert 'flock:' in fixture.trace(), 'upgrade_init did not acquire lifecycle lock'
            assert 'untrusted-main-invoked' not in fixture.trace(), 'upgrade called untrusted main'
            fixture.unchanged()
            checks.append('incoming upgrade handles ' + version + ' payload without new helpers')
        for script, arguments, expected in [('main', ('stop',), 0), ('main', ('status',), 3), ('uninstall_init', (), 0)]:
            fixture = Fixture(parent, source, bash)
            code, error = fixture.run(script, *arguments)
            assert code == expected, (script, arguments, code, error)
            fixture.unchanged()
            checks.append(script + ' ' + ' '.join(arguments) + ' safely handles absent helper/service')
        for script, arguments in [('upgrade_init', ()), ('main', ('stop',)), ('uninstall_init', ())]:
            fixture = Fixture(parent, source, bash)
            fixture.process()
            code, error = fixture.run(script, *arguments, busy=True)
            assert code != 0 and 'kill:TERM' not in fixture.trace(), (script, code, error, fixture.trace())
            assert (fixture.etc / 'app.pid').exists(), 'busy lock modified process state'
            fixture.unchanged()
            checks.append(script + ' rejects busy lock before stopping')
        for deleted in [False, True]:
            fixture = Fixture(parent, source, bash)
            fixture.process(deleted=deleted)
            code, error = fixture.run('upgrade_init')
            assert code == 0 and 'kill:TERM:43210' in fixture.trace(), (deleted, code, error, fixture.trace())
            fixture.unchanged()
            checks.append('upgrade stops verified ' + ('deleted' if deleted else 'current') + ' executable')
        fixture = Fixture(parent, source, bash)
        fixture.process(foreign=True)
        code, error = fixture.run('upgrade_init')
        assert code == 0 and 'kill:TERM' not in fixture.trace(), (code, error, fixture.trace())
        fixture.unchanged()
        checks.append('foreign PID is never signaled')
        for script in ['install_callback', 'upgrade_callback']:
            fixture = Fixture(parent, source, bash)
            code, error = fixture.run(script, busy=True)
            assert code != 0 and 'flock:' in fixture.trace(), (script, code, error)
            assert posix(fixture.app) not in fixture.trace(), 'busy callback changed application files'
            fixture.unchanged()
            checks.append(script + ' rejects busy lock before application metadata changes')

            fixture = Fixture(parent, source, bash)
            (fixture.app / 'public').mkdir()
            write(fixture.app / 'public' / 'index.html', '<html>fixture</html>')
            write(fixture.app / 'server' / 'fn-wireguard-maintenance', '#!/bin/bash\nexit 77\n')
            write(fixture.app / 'server' / 'prepare-data',
                  '#!/bin/bash\nprintf "maintenance:called\\n" >> "$MOCK_EVENTS"\n')
            code, error = fixture.run(script)
            assert code == 0, (script, code, error)
            trace = fixture.trace()
            assert trace.index('flock:') < trace.index('maintenance:called'), trace
            assert not (fixture.app / 'server' / 'lifecycle-lock').exists()
            fixture.unchanged()
            checks.append(script + ' reaches maintenance with new payload and no separate lock helper')
        for current, failure in [('1', '0'), ('0', '0'), ('0', '1')]:
            fixture = Fixture(parent, source, bash)
            fixture.env['MOCK_FORWARD'] = current
            fixture.env['MOCK_FORWARD_FAIL'] = failure
            write(fixture.app / 'server' / 'fn-wireguard-maintenance', '#!/bin/bash\nexit 77\n')
            write(fixture.app / 'server' / 'prepare-data', '#!/bin/bash\nexit 0\n')
            # Avoid needing a real Unix-domain socket or Windows symlink privilege.
            write(fixture.mock / 'ln', '#!/bin/bash\nexit 0\n')
            code, error = fixture.run('main', 'start')
            trace = fixture.trace()
            assert code != 0, 'mock runtime must never start'
            assert 'sysctl:-n net.ipv4.ip_forward' in trace, (trace, error)
            assert ('sysctl:-w net.ipv4.ip_forward=1' in trace) == (current == '0'), trace
            if failure == '1':
                assert 'setpriv:' not in trace and '无法启用 IPv4 转发' in error, (trace, error)
            fixture.unchanged()
            checks.append('startup forwarding current=' + current + ' failure=' + failure)
        print('PASS', len(checks), 'executed lifecycle checks (Git Bash with mocked NAS metadata/process seams)')
        for check in checks:
            print(' -', check)


if __name__ == '__main__':
    main()
