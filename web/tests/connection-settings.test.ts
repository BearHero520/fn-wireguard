import {test} from 'node:test';
import assert from 'node:assert/strict';
import {connectionDraft,connectionSettings} from '../src/connection-settings.ts';

const saved={endpoint:'vpn.example.com:51820',listenPort:51820,address:'10.66.66.1/24',dns:'',allowedIPs:'10.66.66.0/24',persistentKeepalive:25};

test('editing the service port updates the exported endpoint and survives form reloads',()=>{
 const draft=connectionDraft(saved);
 assert.equal(draft.endpoint,'vpn.example.com');
 draft.listenPort=55555;
 const next=connectionSettings(draft);
 assert.equal(next.endpoint,'vpn.example.com:55555');
 assert.equal(next.listenPort,55555);
 assert.equal(connectionDraft(next).endpoint,'vpn.example.com');
 assert.equal(connectionDraft(next).customPublicPort,false);
 assert.deepEqual(Object.keys(next).sort(),Object.keys(saved).sort());
 assert.deepEqual(connectionSettings(connectionDraft(next)),next);
});

test('existing NAT mappings retain their public port when the NAS port changes',()=>{
 const draft=connectionDraft({...saved,endpoint:'vpn.example.com:443'});
 assert.equal(draft.customPublicPort,true);
 draft.listenPort=55555;
 assert.equal(connectionSettings(draft).endpoint,'vpn.example.com:443');
 draft.publicPort=12345;
 assert.equal(connectionSettings(draft).endpoint,'vpn.example.com:12345');
 draft.customPublicPort=false;
 assert.equal(connectionSettings(draft).endpoint,'vpn.example.com:55555');
});

test('IPv4, domain and IPv6 hosts round trip without appending a port in the input',()=>{
 for(const host of ['192.0.2.1','vpn.example.com','2001:db8::1234']) {
  const draft=connectionDraft({...saved,endpoint:host});
  draft.listenPort=23456;
  const next=connectionSettings(draft);
  assert.equal(next.endpoint,host.includes(':')?`[${host}]:23456`:`${host}:23456`);
  assert.equal(connectionDraft(next).endpoint,host);
 }
});

test('host input rejects embedded ports, URLs and control characters',()=>{
 for(const endpoint of ['vpn.example.com:51820','[2001:db8::1]:51820','https://vpn.example.com','vpn.example.com\n','']) {
  assert.throws(()=>connectionSettings({...connectionDraft(saved),endpoint}),/只填写域名或 IP/);
 }
 for(const port of [0,65536,1.5,NaN]) {
  assert.throws(()=>connectionSettings({...connectionDraft(saved),listenPort:port}),/1–65535/);
 }
});
