"""Exercise the real HTTP API against an isolated local development database.

Usage: python scripts/smoke-test.py --binary .local/fn-wireguard.exe
Never uses the application's real data directory or modifies host networking.
"""
import argparse
import configparser
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


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--binary', required=True)
    args = parser.parse_args()
    root = pathlib.Path(__file__).resolve().parents[1]
    binary = (root / args.binary).resolve()
    local = root / '.local'
    local.mkdir(exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='api-smoke-', dir=local) as temp:
        data = pathlib.Path(temp).resolve()
        assert data.is_relative_to(local.resolve())
        with socket.socket() as sock:
            sock.bind(('127.0.0.1', 0))
            port = sock.getsockname()[1]
        origin = f'http://127.0.0.1:{port}'
        jar = http.cookiejar.CookieJar()
        client = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar))
        csrf = ''
        checks = []
        process = None
        log = open(data / 'test-server.log', 'ab', buffering=0)

        def request(method, path, body=None, expected=200, token=True, headers=None):
            hdrs = {'Origin': origin}
            if body is not None:
                hdrs['Content-Type'] = 'application/json'
            if token and csrf:
                hdrs['X-CSRF-Token'] = csrf
            hdrs.update(headers or {})
            req = urllib.request.Request(origin + '/api' + path,
                data=None if body is None else json.dumps(body).encode(),
                headers=hdrs, method=method)
            try:
                resp = client.open(req, timeout=15)
            except urllib.error.HTTPError as error:
                resp = error
            payload = resp.read()
            assert resp.status == expected, f'{method} {path}: expected {expected}, got {resp.status}'
            assert 'no-store' in resp.headers.get('Cache-Control', ''), 'API response must not be cached'
            return json.loads(payload) if payload else None

        def start():
            nonlocal process
            process = subprocess.Popen([str(binary), '--data-dir', str(data),
                '--listen', f'127.0.0.1:{port}', '--mode', 'development',
                '--web-dir', str(root / 'web' / 'dist')],
                stdout=log, stderr=log)
            for _ in range(100):
                if process.poll() is not None:
                    raise AssertionError('server exited before becoming ready')
                try:
                    request('GET', '/setup')
                    return
                except (urllib.error.URLError, ConnectionError, TimeoutError):
                    time.sleep(0.1)
            raise AssertionError('server readiness timeout')

        def stop():
            if process and process.poll() is None:
                process.terminate()
                process.wait(timeout=10)

        try:
            start()
            request('GET', '/peers', expected=401)
            assert request('GET', '/setup')['initialized'] is False
            password = secrets.token_urlsafe(24)
            request('POST', '/setup', {'token': 'wrong', 'username': 'smoke-admin', 'password': password}, expected=401)
            bootstrap = (data / 'bootstrap-token').read_text().strip()
            session = request('POST', '/setup', {'token': bootstrap, 'username': 'smoke-admin', 'password': password})
            csrf = session['csrfToken']
            assert not (data / 'bootstrap-token').exists()
            assert any(c.name == 'fnwg_session' and c.has_nonstandard_attr('HttpOnly') for c in jar)
            checks.append('bootstrap, authenticated session, HttpOnly cookie')
            request('POST', '/peers', {'name': 'blocked', 'deviceType': 'phone'}, expected=403, token=False)
            request('POST', '/peers', {'name': 'blocked', 'deviceType': 'phone'}, expected=403,
                headers={'Origin': 'https://untrusted.example'})
            checks.append('CSRF and cross-origin rejection')
            settings = request('GET', '/settings')
            invalid = dict(settings, dns='1.1.1.1\n')
            request('PUT', '/settings', invalid, expected=400)
            assert settings['dns'] == '', 'new instances should use automatic DNS'
            settings['endpoint'] = 'vpn.example.com'
            settings = request('PUT', '/settings', settings)
            assert settings['endpoint'] == 'vpn.example.com:51820'
            assert request('GET', '/overview')['server']['endpoint'] == settings['endpoint']
            first = request('POST', '/peers', {'name': '验证手机', 'deviceType': 'phone'}, expected=201)
            second = request('POST', '/peers', {'name': '验证电脑', 'deviceType': 'computer'}, expected=201)
            assert first['address'] != second['address']
            assert 'privateKey' not in first and 'presharedKey' not in first
            export = request('POST', f"/peers/{first['id']}/config", {})
            config = configparser.ConfigParser(interpolation=None)
            config.read_string(export['config'])
            private = config['Interface']['PrivateKey']
            psk = config['Peer']['PresharedKey']
            assert config['Peer']['Endpoint'] == settings['endpoint']
            assert config['Interface']['Address'] == first['address']
            assert 'DNS' not in config['Interface'], 'automatic DNS must omit the override'
            assert len(private) == 44 and len(psk) == 44
            for path in data.iterdir():
                if path.is_file():
                    raw = path.read_bytes()
                    assert private.encode() not in raw and psk.encode() not in raw, 'secret stored as plaintext'
            checks.append('settings validation, unique address allocation, encrypted storage, real client config')
            settings = request('PUT', '/settings', dict(settings, dns='192.168.50.1'))
            manual = request('POST', f"/peers/{first['id']}/config", {})
            assert 'DNS = 192.168.50.1\n' in manual['config']
            settings = request('PUT', '/settings', dict(settings, dns=''))
            automatic = request('POST', f"/peers/{first['id']}/config", {})
            assert '\nDNS =' not in automatic['config']
            checks.append('bare host endpoint normalization, immediate overview refresh, manual/automatic DNS export')
            settings = request('PUT', '/settings', dict(settings, endpoint='vpn.example.com:53210', listenPort=53210))
            assert request('GET', '/overview')['server']['endpoint'] == 'vpn.example.com:53210'
            client_export = request('POST', f"/peers/{first['id']}/config", {})
            assert 'Endpoint = vpn.example.com:53210\n' in client_export['config']
            server_export = request('POST', '/server/config', {})
            assert 'ListenPort = 53210\n' in server_export['config']
            request('POST', '/server/port-check', {'port': 53210}, expected=403, token=False)
            request('POST', '/server/port-check', {'port': 65536}, expected=400)
            probe = request('POST', '/server/port-check', {'port': 53210})
            assert probe['state'] == 'unknown' and probe['actualPort'] == 0, 'development runtime must not claim a port is active'
            settings = request('PUT', '/settings', dict(settings, endpoint='vpn.example.com:443'))
            assert 'Endpoint = vpn.example.com:443\n' in request('POST', f"/peers/{first['id']}/config", {})['config']
            assert 'ListenPort = 53210\n' in request('POST', '/server/config', {})['config']
            checks.append('new service/public ports in real exports, independent NAT port, protected diagnostics')
            edited = request('PATCH', f"/peers/{first['id']}", {'enabled': False, 'name': '停用的手机'})
            assert edited['enabled'] is False
            overview = request('GET', '/overview')
            assert overview['stats']['totalPeers'] == 2 and overview['stats']['onlinePeers'] == 0
            assert overview['server']['available'] is False and overview['server']['running'] is False
            audit = request('GET', '/audit')
            assert len(audit) >= 4 and private not in json.dumps(audit) and psk not in json.dumps(audit)
            checks.append('peer mutation, honest unavailable status, audit without secrets')
            stop()
            start()
            assert request('GET', '/setup')['initialized'] is True
            assert len(request('GET', '/peers')) == 2
            assert request('GET', '/settings') == settings
            assert request('GET', '/overview')['server']['endpoint'] == settings['endpoint']
            checks.append('SQLite persistence across process restart')
            request('DELETE', f"/peers/{second['id']}")
            assert len(request('GET', '/peers')) == 1
            request('POST', '/logout', {})
            request('GET', '/peers', expected=401)
            session = request('POST', '/login', {'username': 'smoke-admin', 'password': password})
            csrf = session['csrfToken']
            assert request('GET', '/session')['username'] == 'smoke-admin'
            checks.append('delete, logout invalidation, subsequent login')
        except Exception:
            print((data / 'test-server.log').read_text(errors='replace'))
            raise
        finally:
            stop()
            log.close()
        for check in checks:
            print('PASS ' + check)
        print(f'PASS {len(checks)} integration groups; isolated data removed')


if __name__ == '__main__':
    main()
