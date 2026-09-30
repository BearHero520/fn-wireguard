"""Black-box configuration round trips against two isolated development servers.

Usage: python scripts/import-smoke.py --binary .local/fn-wireguard.exe
No host networking changes; secrets are compared in memory and never printed.
"""
import argparse
import configparser
import contextlib
import http.cookiejar
import json
import pathlib
import secrets
import socket
import subprocess
import tempfile
import time
import urllib.error
import urllib.request


class Client:
    def __init__(self, origin):
        self.origin = origin
        self.csrf = ''
        self.opener = urllib.request.build_opener(
            urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))

    def request(self, method, path, body=None, expected=(200,)):
        headers = {'Origin': self.origin}
        if body is not None:
            headers['Content-Type'] = 'application/json'
        if self.csrf:
            headers['X-CSRF-Token'] = self.csrf
        request = urllib.request.Request(self.origin + '/api' + path,
            data=None if body is None else json.dumps(body).encode(),
            headers=headers, method=method)
        try:
            response = self.opener.open(request, timeout=20)
        except urllib.error.HTTPError as error:
            response = error
        with response:
            status = response.status
            content = response.read()
            assert status in expected, f'{method} {path}: unexpected status {status}'
            assert 'no-store' in response.headers.get('Cache-Control', ''), 'API cache policy'
            return json.loads(content) if content else None

    def initialize(self, data_dir, password):
        bootstrap = (data_dir / 'bootstrap-token').read_text().strip()
        session = self.request('POST', '/setup', {'Token': bootstrap,
            'Username': 'import-test-admin', 'Password': password})
        self.csrf = session['csrfToken']

    def login(self, password):
        session = self.request('POST', '/login', {
            'Username': 'import-test-admin', 'Password': password})
        self.csrf = session['csrfToken']

    def preview(self, kind, config, expected=(200,), **fields):
        return self.request('POST', '/import/preview',
            {'kind': kind, 'config': config, **fields}, expected)

    def apply(self, token, expected=(200, 201)):
        return self.request('POST', '/import/apply', {'previewToken': token}, expected)


def client_values(config):
    parser = configparser.ConfigParser(interpolation=None)
    parser.read_string(config)
    return parser


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--binary', required=True)
    args = parser.parse_args()
    root = pathlib.Path(__file__).resolve().parents[1]
    binary = (root / args.binary).resolve()
    local = root / '.local'
    local.mkdir(exist_ok=True)
    rejected = (400, 403, 409, 422)
    checks = []
    password = 'import-test-' + secrets.token_urlsafe(24)
    with tempfile.TemporaryDirectory(prefix='import-smoke-', dir=local) as temp, contextlib.ExitStack() as cleanup:
        base = pathlib.Path(temp)
        assert base.resolve().is_relative_to(local.resolve())
        clients = []
        for label in ('a', 'b'):
            data_dir = base / label
            data_dir.mkdir()
            with socket.socket() as sock:
                sock.bind(('127.0.0.1', 0))
                port = sock.getsockname()[1]
            origin = f'http://127.0.0.1:{port}'
            log = cleanup.enter_context(open(data_dir / 'server.log', 'ab', buffering=0))
            process = subprocess.Popen([str(binary), '--mode', 'development',
                '--auth-mode', 'local', '--listen', f'127.0.0.1:{port}',
                '--data-dir', str(data_dir), '--web-dir', str(root / 'web/dist')],
                cwd=root, stdout=log, stderr=log)
            def stop(proc=process):
                if proc.poll() is None:
                    proc.terminate()
                    try:
                        proc.wait(timeout=20)
                    except subprocess.TimeoutExpired:
                        proc.kill()
                        proc.wait(timeout=10)
            cleanup.callback(stop)
            client = Client(origin)
            for _ in range(100):
                assert process.poll() is None, 'isolated server exited before ready'
                try:
                    client.request('GET', '/setup')
                    break
                except urllib.error.URLError:
                    time.sleep(0.1)
            else:
                raise AssertionError('isolated server did not become ready')
            client.initialize(data_dir, password)
            clients.append(client)
        a, b = clients
        settings = a.request('GET', '/settings')
        settings['endpoint'] = 'vpn.example.test:51820'
        a.request('PUT', '/settings', settings)
        peer1 = a.request('POST', '/peers', {'name': 'Roundtrip phone',
            'deviceType': 'phone'}, (201,))
        config1 = a.request('POST', f"/peers/{peer1['id']}/config")['config']
        server_config = a.request('POST', '/server/config')['config']
        server_public = a.request('GET', '/overview')['server']['publicKey']
        before = b.request('GET', '/settings')
        before_peers = b.request('GET', '/peers')
        preview = b.preview('server', server_config)
        assert preview['kind'] == 'server' and preview['previewToken']
        assert b.request('GET', '/settings') == before
        assert b.request('GET', '/peers') == before_peers
        checks.append('server preview has no persisted side effects')
        b.apply(preview['previewToken'])
        imported = b.request('GET', '/peers')
        assert len(imported) == 1 and imported[0]['publicKey'] == peer1['publicKey']
        assert imported[0]['hasConfig'] is False
        b.request('POST', f"/peers/{imported[0]['id']}/config", expected=rejected)
        assert b.request('GET', '/overview')['server']['publicKey'] == server_public
        checks.append('server import preserves server identity and public-only peers')
        b.apply(preview['previewToken'], rejected)
        checks.append('applied preview token cannot be reused')
        # WireGuard server files do not encode the server's public DNS endpoint.
        # Configure deployment-specific reachability before exporting clients.
        imported_settings = b.request('GET', '/settings')
        imported_settings['endpoint'] = settings['endpoint']
        b.request('PUT', '/settings', imported_settings)
        restored = b.preview('client', config1, name='Restored phone', deviceType='phone')
        b.apply(restored['previewToken'])
        imported = b.request('GET', '/peers')
        assert len(imported) == 1 and imported[0]['hasConfig'] is True
        exported = b.request('POST', f"/peers/{imported[0]['id']}/config")['config']
        original_values, restored_values = client_values(config1), client_values(exported)
        assert original_values['Interface']['PrivateKey'] == restored_values['Interface']['PrivateKey']
        assert original_values['Peer']['PresharedKey'] == restored_values['Peer']['PresharedKey']
        checks.append('client import restores existing peer private key and preshared key')
        peer2 = a.request('POST', '/peers', {'name': 'Second peer',
            'deviceType': 'computer'}, (201,))
        config2 = a.request('POST', f"/peers/{peer2['id']}/config")['config']
        pending = b.preview('client', config2, name='Second imported', deviceType='computer')
        other_session = Client(b.origin)
        other_session.login(password)
        other_session.apply(pending['previewToken'], rejected)
        assert len(b.request('GET', '/peers')) == 1
        checks.append('preview apply requires its originating session')
        b.request('PATCH', f"/peers/{imported[0]['id']}", {'name': 'Changed after preview'})
        b.apply(pending['previewToken'], rejected)
        assert len(b.request('GET', '/peers')) == 1
        checks.append('changed state invalidates stale preview')
        fresh = b.preview('client', config2, name='Second imported', deviceType='computer')
        b.apply(fresh['previewToken'])
        assert len(b.request('GET', '/peers')) == 2
        checks.append('new client import creates distinct peer')
        snapshot = b.request('GET', '/peers')
        b.preview('server', server_config, rejected)
        checks.append('server import refuses nonempty target')
        unsafe = config1.replace('[Interface]', '[Interface]\nPostUp = touch /tmp/never-run')
        b.preview('client', unsafe, rejected)
        assert b.request('GET', '/peers') == snapshot
        checks.append('config hooks rejected without state changes')
        wrong_server = config1.replace(server_public, peer2['publicKey'])
        b.preview('client', wrong_server, rejected)
        checks.append('client config for another server rejected')
        conflicting = config2.replace(peer2['address'], peer1['address'])
        b.preview('client', conflicting, rejected)
        checks.append('conflicting client address rejected')
        duplicate = b.preview('client', config2, expected=rejected)
        checks.append('duplicate configured peer rejected')
        assert b.request('GET', '/peers') == snapshot
        assert b.request('GET', '/overview')['server']['running'] is False
        checks.append('rejected imports leave records and development networking unchanged')
        assert b.request('POST', '/server/config')['config']
        checks.append('imported server supports subsequent configuration export')
    print(f'PASS {len(checks)} configuration import/export checks')
    for check in checks:
        print(' - ' + check)


if __name__ == '__main__':
    main()
