import tarfile,io,struct,pathlib,re,hashlib,json,subprocess,tempfile
root=pathlib.Path(__file__).resolve().parents[1]
version=re.search(r'Version\s*=\s*"([^"]+)"',(root/'internal/buildinfo/info.go').read_text(encoding='utf-8')).group(1)
js_assets=list((root/'web/dist/assets').glob('index-*.js'))
assert len(js_assets)==1,js_assets
expected_asset='public/assets/'+js_assets[0].name
for arch,machine,platform in [('amd64',62,'x86'),('arm64',183,'arm')]:
 p=root/'dist'/('fn-wireguard-'+arch+'.fpk')
 with tarfile.open(p,'r:*') as t, tempfile.TemporaryDirectory(prefix='fpk-audit-') as temporary:
  members=t.getmembers()
  for m in members:
   assert m.uid==0 and m.gid==0,m.name
   if m.isdir(): assert m.mode==0o755,(m.name,oct(m.mode))
   if m.name.startswith('cmd/') and m.isfile():
    content=t.extractfile(m).read()
    assert m.mode==0o755,(m.name,oct(m.mode))
    assert b'\r' not in content,m.name
    assert content == (root/'packaging/fnos'/m.name).read_bytes(),m.name
    script=pathlib.Path(temporary)/pathlib.Path(m.name).name
    script.write_bytes(content)
    subprocess.run(['C:/Program Files/Git/bin/bash.exe','-n',str(script)],check=True)
   if m.name.startswith(('config/','wizard/')) and m.isfile():
    json.loads(t.extractfile(m).read())
  app=t.extractfile('app.tgz').read()
  manifest=t.extractfile('manifest').read()
  checksum=re.search(rb'(?m)^checksum\s*=\s*([0-9a-fA-F]{32})',manifest).group(1).decode()
  assert checksum==hashlib.md5(app).hexdigest()
  assert re.search(rb'(?m)^version\s*=\s*'+re.escape(version.encode())+rb'\s*$',manifest)
  assert re.search(rb'(?m)^platform\s*=\s*'+platform.encode()+rb'\s*$',manifest)
  with tarfile.open(fileobj=io.BytesIO(app),mode='r:*') as a:
   binary=a.getmember('server/fn-wireguard');b=a.extractfile(binary).read()
   assert b[:4]==b'\x7fELF' and b[4]==2 and b[5]==1
   assert struct.unpack('<H',b[18:20])[0]==machine and binary.mode==0o755
   launcher=a.getmember('server/run-service');content=a.extractfile(launcher).read()
   assert launcher.mode==0o755 and b'\r' not in content
   assert b'--secure-cookie' not in content and b'--auth-mode fnos' in content and b'--unix-socket' in content
   script=pathlib.Path(temporary)/'run-service'
   script.write_bytes(content)
   subprocess.run(['C:/Program Files/Git/bin/bash.exe','-n',str(script)],check=True)
   names=[m.name for m in a.getmembers()]
   for member in a.getmembers():
    assert member.uid==0 and member.gid==0,member.name
    if member.isdir(): assert member.mode==0o755,(member.name,oct(member.mode))
   maintenance=a.getmember('server/fn-wireguard-maintenance');maintenance_bytes=a.extractfile(maintenance).read()
   assert maintenance.mode==0o755 and maintenance_bytes[:4]==b'\x7fELF'
   assert struct.unpack('<H',maintenance_bytes[18:20])[0]==machine
   for helper in ('prepare-data',):
    member=a.getmember('server/'+helper);content=a.extractfile(member).read()
    assert member.mode==0o755 and b'\r' not in content
    script=pathlib.Path(temporary)/helper;script.write_bytes(content)
    subprocess.run(['C:/Program Files/Git/bin/bash.exe','-n',str(script)],check=True)
   assert b'--service-binary' in a.extractfile('server/prepare-data').read()
   assert 'server/lifecycle-lock' not in names
   for command in ('main', 'upgrade_init', 'uninstall_init', 'install_callback', 'upgrade_callback'):
    assert b'flock -n 9' in t.extractfile('cmd/'+command).read(),command
   assert b'9>&-' in t.extractfile('cmd/main').read()
   assert b'sysctl -w net.ipv4.ip_forward=1' in t.extractfile('cmd/main').read()
   assert expected_asset in names and 'public/index.html' in names
   for source in (root/'web/dist').rglob('*'):
    if source.is_file():
     archive_name='public/'+source.relative_to(root/'web/dist').as_posix()
     assert a.extractfile(archive_name).read()==source.read_bytes(),archive_name
   entry=json.loads(a.extractfile('ui/config').read())['.url']['fn-wireguard.main']
   assert entry['gatewayPrefix']=='/app/fn-wireguard' and entry['gatewaySocket']=='app.sock'
 print(arch,'PASS gzip/TAR, ELF64',machine,'platform',platform,'root ownership,755 executables, LF/bash-n, exact latest web assets, fnOS Unix socket/gateway, HTTP compatible launcher, JSON, manifest MD5')
 print(hashlib.sha256(p.read_bytes()).hexdigest()+'  '+p.name)
actual=[]
for line in (root/'dist/SHA256SUMS.txt').read_text().splitlines():
 digest,name=line.split('  ',1)
 assert hashlib.sha256((root/'dist'/name).read_bytes()).hexdigest()==digest
 actual.append(name)
assert sorted(actual)==['fn-wireguard-amd64.fpk','fn-wireguard-arm64.fpk']
print('SHA256SUMS verified for both final artifacts')
