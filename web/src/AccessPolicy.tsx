import {useEffect,useState} from 'react';
import {Check,LoaderCircle,Plus,RefreshCw,ShieldCheck,X} from 'lucide-react';
import {api,translateError,type Peer} from './api';

export type AccessMode='inherit'|'lan'|'selected'|'custom';
interface LANDevice {ip:string;mac?:string;name:string;status:string}
interface LANInfo {available:boolean;reason?:string;subnet:string;address:string;interface:string;scanSubnet?:string;devices:LANDevice[]}
export function accessLabel(mode?:string,targets?:string[]){return mode==='lan'?'整个家庭局域网':mode==='selected'?`指定 ${targets?.length||0} 台设备`:mode==='custom'?'自定义路由':'跟随默认设置'}

export function AccessPolicy({mode,targets,onChange,peer=false,disabled=false,defaultLabel}:{mode:AccessMode;targets:string[];onChange:(mode:AccessMode,targets:string[])=>void;peer?:boolean;disabled?:boolean;defaultLabel?:string}){
 const [lan,setLAN]=useState<LANInfo|null>(null),[loading,setLoading]=useState(true),[scanning,setScanning]=useState(false),[error,setError]=useState(''),[ip,setIP]=useState('');
 useEffect(()=>{let current=true;api<LANInfo>('/lan').then(v=>{if(current)setLAN(v)}).catch(e=>{if(current)setError(e.message)}).finally(()=>{if(current)setLoading(false)});return()=>{current=false}},[]);
 const scan=async()=>{setScanning(true);setError('');try{const value=await api<LANInfo>('/lan/scan','POST');setLAN(value);if(!value.available)setError(translateError(value.reason||'无法发现局域网设备。'))}catch(e){setError(e instanceof Error?e.message:'设备发现失败，请重试。')}finally{setScanning(false)}};
 const toggle=(value:string)=>onChange(mode,targets.includes(value)?targets.filter(t=>t!==value):[...targets,value]);
 const add=()=>{const value=ip.trim();if(!/^(\d{1,3}\.){3}\d{1,3}$/.test(value)||value.split('.').some(n=>Number(n)>255)){setError('请输入有效的局域网 IPv4 地址。');return}if(!targets.includes(value))onChange(mode,[...targets,value]);setIP('');setError('')};
 const options: {value:AccessMode;label:string;description:string}[]=[...(peer?[{value:'inherit' as const,label:'跟随默认设置',description:defaultLabel||'使用连接设置中的默认访问范围'}]:[]),{value:'lan',label:'整个家庭局域网',description:'访问 NAS 和家庭网段内的其他设备'},{value:'selected',label:'仅指定设备',description:'只允许访问勾选或手动添加的 IP'},...(!peer?[{value:'custom' as const,label:'自定义路由',description:'兼容已有配置，需自行配置转发'}]:[])];
 return <div className="access-policy">
  <div className="access-options" role="radiogroup" aria-label={peer?'此客户端的访问范围':'默认访问范围'}>{options.map(option=><label className={`access-option ${mode===option.value?'selected':''}`} key={option.value}><input type="radio" name={peer?'peer-access':'default-access'} checked={mode===option.value} disabled={disabled} onChange={()=>onChange(option.value,[])}/><span><strong>{option.label}</strong><small>{option.description}</small></span></label>)}</div>
  {mode==='inherit'?<p className="form-help">默认设置变化后，此客户端的权限会同步更新。</p>:mode==='custom'?<p className="form-help">此模式保留手动路由，不自动配置局域网转发或设备访问限制。</p>:<>
   <div className="lan-network"><ShieldCheck size={19}/><span>{loading?'正在识别家庭网络…':lan?.available?`家庭网段 ${lan.subnet} · NAS ${lan.address}`:translateError(lan?.reason||'未识别到家庭网络')}<small>{lan?.available?'权限由 NAS 执行；客户端需重新导入配置，以更新访问路由。':'请在飞牛 NAS 上使用；无法识别网段时不会猜测访问范围。'}</small></span></div>
   {mode==='selected'&&<><div className="lan-discovery-head"><div><strong>选择局域网设备</strong><p>设备未被发现也可手动添加 IP，建议在路由器中固定设备地址。</p></div><button className="button secondary" type="button" disabled={disabled||scanning||loading||!lan?.available} onClick={()=>void scan()}>{scanning?<LoaderCircle className="spin" size={17}/>:<RefreshCw size={17}/>} {scanning?'正在探查…':'探查局域网'}</button></div>
    <div className="lan-device-list">{lan?.devices.map(device=><label className="lan-device" key={device.ip}><input type="checkbox" checked={targets.includes(device.ip)} disabled={disabled} onChange={()=>toggle(device.ip)}/><span><strong>{device.name}</strong><small>{device.ip}{device.mac?` · ${device.mac}`:''}</small></span><em>{device.status==='local'?'本机':device.status==='responded'?'有响应':'邻居记录'}</em></label>)}{!loading&&!lan?.devices.length&&<p className="form-help">尚无设备记录，可探查网络或手动添加。</p>}</div>
    <p className="form-help">邻居记录不代表设备当前在线。{lan?.scanSubnet?`本次探查范围：${lan.scanSubnet}。`:'每次探查最多覆盖 NAS 所在的 254 个地址。'}</p>
    <label htmlFor={peer?'peer-target-ip':'default-target-ip'}>手动添加设备 IP</label><div className="manual-target"><input id={peer?'peer-target-ip':'default-target-ip'} value={ip} onChange={e=>setIP(e.target.value)} disabled={disabled} placeholder="例如 192.168.50.10" autoComplete="off" onKeyDown={e=>{if(e.key==='Enter'){e.preventDefault();add()}}}/><button type="button" className="button secondary" disabled={disabled||!ip.trim()||targets.length>=128} onClick={add}><Plus size={17}/>添加</button></div>
    <div className="selected-targets" aria-label="已选设备">{targets.map(target=><button type="button" key={target} disabled={disabled} onClick={()=>toggle(target)} aria-label={`移除 ${target}`}>{target}<X size={14}/></button>)}</div><p className="form-help">已选 {targets.length} 台设备{targets.length===0?'，请至少选择一台。':'。未选中 NAS 时，客户端无法访问 NAS 本机服务。'}</p>
   </>}
  </>}
  {error&&<div className="notice error" role="alert">{error}</div>}
 </div>
}

export function PeerAccessForm({peer,defaultLabel,onClose,onSaved,onBusy}:{peer:Peer;defaultLabel:string;onClose:()=>void;onSaved:()=>void;onBusy:(busy:boolean)=>void}){
 const [mode,setMode]=useState<AccessMode>((peer.accessMode||'inherit') as AccessMode),[targets,setTargets]=useState(peer.allowedDevices||[]),[busy,setBusy]=useState(false),[error,setError]=useState('');
 const save=async()=>{setBusy(true);onBusy(true);setError('');try{await api(`/peers/${encodeURIComponent(peer.id)}`,'PATCH',{accessMode:mode,allowedDevices:targets});onSaved()}catch(e){setError(e instanceof Error?e.message:'保存失败，请重试。')}finally{setBusy(false);onBusy(false)}};
 return <><p className="form-help">设置「{peer.name}」连接 VPN 后可以访问哪些家庭设备。独立设置会覆盖全局默认范围。</p><AccessPolicy peer mode={mode} targets={targets} onChange={(m,t)=>{setMode(m);setTargets(t);setError('')}} disabled={busy} defaultLabel={defaultLabel}/>{error&&<div className="notice error" role="alert">{error}</div>}<div className="notice"><ShieldCheck size={19}/><span>服务运行时，保存会立即更新服务端权限。之后请重新导出并导入该客户端配置。</span></div><div className="dialog-actions"><button type="button" className="button secondary" onClick={onClose} disabled={busy}>取消</button><button type="button" className="button primary" onClick={()=>void save()} disabled={busy||(mode==='selected'&&!targets.length)}>{busy?<LoaderCircle className="spin" size={18}/>:<Check size={18}/>}保存权限</button></div></>
}
