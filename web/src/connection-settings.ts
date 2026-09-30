import type {Settings} from './api';

// Keep the API's WireGuard endpoint intact, but edit its host and port separately.
export type ConnectionDraft = Settings & {publicPort:number; customPublicPort:boolean};

export function connectionDraft(settings:Settings):ConnectionDraft {
 const match = settings.endpoint.match(/^\[([^\]]+)\]:(\d+)$/) || settings.endpoint.match(/^([^:]+):(\d+)$/);
 const publicPort = match ? Number(match[2]) : settings.listenPort;
 return {...settings, endpoint:match ? match[1] : settings.endpoint, publicPort, customPublicPort:publicPort!==settings.listenPort};
}

export function connectionEndpoint(draft:ConnectionDraft):string {
 const host = draft.endpoint.replace(/^ +| +$/g,'').replace(/^\[([^\]]+)\]$/,'$1');
 if (!host) return '';
 return `${host.includes(':') ? `[${host}]` : host}:${draft.customPublicPort ? draft.publicPort : draft.listenPort}`;
}

export function connectionSettings(draft:ConnectionDraft):Settings {
 const host = draft.endpoint.replace(/^ +| +$/g,'');
 if (!host || /[\s/\\]/.test(host) || (host.match(/:/g)?.length===1) || /^\[.*\]:/.test(host)) {
  throw new Error('公网连接地址只填写域名或 IP，端口请在端口输入框中填写。');
 }
 const {publicPort,customPublicPort,...settings} = draft;
 const port = customPublicPort ? publicPort : settings.listenPort;
 if (!Number.isInteger(port) || port<1 || port>65535) throw new Error('连接端口必须是 1–65535 之间的整数。');
 return {...settings, endpoint:connectionEndpoint(draft)};
}
