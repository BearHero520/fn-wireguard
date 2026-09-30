export type DeviceType = 'phone'|'computer'|'tablet'|'other';
export interface Peer {accessMode?:string;allowedDevices?:string[];hasConfig?:boolean;id:string;name:string;deviceType:DeviceType;address:string;publicKey:string;enabled:boolean;createdAt:string;lastHandshake:string|null;receivedBytes:number;sentBytes:number;online:boolean}
export interface Audit {id:string;action:string;target:string;createdAt:string}
export interface Overview {server:{running:boolean;available:boolean;reason:string;interface:string;publicKey:string;listenPort:number;actualListenPort:number;address:string;endpoint:string};stats:{totalPeers:number;enabledPeers:number;onlinePeers:number;receivedBytes:number;sentBytes:number};recentActivity:Audit[]}
export interface Settings {accessMode?:string;allowedDevices?:string[];lanSubnet?:string;lanAddress?:string;lanInterface?:string;endpoint:string;listenPort:number;address:string;dns:string;allowedIPs:string;persistentKeepalive:number}
export interface Session {username:string;csrfToken:string}
const prefix=location.pathname.startsWith('/app/fn-wireguard')?'/app/fn-wireguard':'';
export class ApiError extends Error {status:number;constructor(message:string,status:number){super(message);this.status=status}}
let csrf='';
export function setCsrf(value:string){csrf=value}
export async function api<T>(path:string,method='GET',body?:unknown):Promise<T>{
 const response=await fetch(`${prefix}/api${path}`,{method,credentials:'same-origin',headers:{...(body!==undefined?{'Content-Type':'application/json'}:{}),...(method!=='GET'?{'X-CSRF-Token':csrf}:{})},body:body!==undefined?JSON.stringify(body):undefined});
 const data=await response.json().catch(()=>({error:'服务器响应格式异常，请重试。'}));
 if(!response.ok){if(response.status===401||(response.status===403&&String(data.error).includes('administrator session')))dispatchEvent(new Event('fnwg-session-lost'));throw new ApiError(translateError(data.error||'请求失败，请重试。'),response.status);}
 return data as T;
}
export function translateError(raw:string):string{
 if(raw.startsWith("invalid or duplicate LAN device:"))return "设备 IP 不在家庭网段内、为保留地址或重复："+raw.split(":").slice(1).join(":");
 const known:Record<string,string>={
 'update check could not reach GitHub':'暂时无法连接 GitHub，请检查 NAS 的网络连接后重试。也可通过 GitHub 项目入口查看版本。',
 'GitHub update checks are rate limited':'GitHub 请求次数已达限制，请稍后再试，或前往发布页面查看。',
 'GitHub update service is unavailable':'GitHub 更新服务暂不可用，请稍后再试。',
 'invalid GitHub release response':'GitHub 返回的版本信息不完整，暂时无法判断是否有更新。请查看发布页面。',
 'invalid installed version':'无法识别当前应用版本，请查看 GitHub 发布页面。',
 'LAN discovery requires the NAS runtime':'局域网发现需要在飞牛 NAS 上运行。',
 'no private IPv4 LAN found on the default gateway interface':'未在默认网关接口发现家庭 IPv4 网段，请检查 NAS 网络设置。',
 'LAN network is not detected':'未识别到家庭网段，请重新保存连接设置。',
 'select 1–128 LAN devices':'请选择 1–128 台局域网设备。',
 'LAN scan is cooling down; retry after 10 seconds':'探查间隔至少为 10 秒，请稍后再试。',
 'enable LAN access before setting client permissions':'请先在连接设置中启用局域网访问，再设置客户端权限。',
 'nft is required for LAN access':'系统缺少 nft，无法配置局域网访问权限。',
 'LAN firewall table is not owned by this application':'发现同名防火墙表，但无法确认它属于本应用，已取消更改。请检查应用日志中的规则归属信息。',
 'runtime state is unresolved; successfully stop or restart the server before changing peers':'上次操作未能恢复服务状态，请先在概览中停止服务并重新启动，再修改客户端权限或设备。',
 'runtime state is unresolved; successfully stop or restart the server before changing settings':'上次操作未能恢复服务状态，请先在概览中成功停止服务，再修改连接设置。',
 'IPv4 forwarding is disabled; restart the NAS application to prepare LAN access':'IPv4 转发未开启，请在飞牛应用中心重启此应用后重试。',
 'LAN network changed; stop the server and save connection settings again':'NAS 家庭网络已变化，请停止服务后重新保存连接设置。',
 'cannot detect the LAN gateway':'无法识别 NAS 的局域网网关。',
 'cannot detect the LAN network':'无法识别 NAS 的局域网地址。',
 'cannot read discovered LAN devices':'无法读取局域网设备记录，请重试。',

 'invalid setup token':'初始化令牌不正确，请重新读取服务器上的令牌文件。','invalid username or password':'用户名或密码不正确。','authentication required':'管理会话已过期，请重新登录。','expired session':'管理会话已过期，请重新打开应用。','invalid CSRF token':'会话验证已失效，请刷新页面后重试。','A fnOS administrator session is required':'仅飞牛 NAS 管理员可访问，请从管理员桌面打开应用。','Local login is disabled in fnOS authentication mode':'请从飞牛 NAS 管理员桌面打开应用。','request origin is not allowed':'请求来源与应用访问地址不匹配，请刷新页面后重试。','Too many authentication attempts; try again later':'登录尝试过于频繁，请稍后再试。','administrator is already initialized':'管理员已初始化，请刷新页面登录。','username must be 1–80 characters and password 12–1024 bytes':'用户名需为 1–80 个字符，密码需至少 12 位。',
 'name must be 1–80 characters':'设备名称需为 1–80 个字符。','name contains control characters':'设备名称不能包含控制字符。','server address must use a private IPv4 /24–/30 subnet':'隧道地址需使用私有 IPv4 地址，掩码范围为 /24 至 /30。','server address cannot be network or broadcast address':'隧道地址不能使用网段地址或广播地址。','configuration fields cannot contain control characters':'设置不能包含换行或控制字符。','listen port must be 1–65535':'监听端口需为 1–65535。','keepalive must be 0–65535':'持续保活需为 0–65535 秒。','endpoint too long':'连接地址过长，请缩短后重试。','endpoint must be hostname:port or [IPv6]:port':'请填写域名或 IP，可附带端口；不要填写 http://、https:// 或网页路径。','invalid endpoint port':'连接地址中的端口无效。','invalid endpoint host':'连接地址中的 IP 或域名无效。','invalid endpoint hostname':'连接地址中的域名无效。','DNS must be comma-separated IP addresses':'DNS 需填写有效 IP 地址，多个地址用英文逗号分隔。','too many DNS or routing entries':'DNS 或路由条目过多，请减少后重试。','allowed IPs must be comma-separated CIDRs':'允许的 IP 需使用有效 CIDR 网段，多个网段用英文逗号分隔。','subnet has no available peer addresses':'当前网段已无可分配地址。','stop the server before changing settings':'请先停止服务，再修改连接设置。','remove all peers before changing the server address':'已有设备时不能修改隧道地址，请先删除所有设备。','save a public endpoint before exporting configurations':'请先在连接设置中保存公网连接地址，再导出配置。','peer not found':'设备不存在，请刷新列表。','invalid device type':'设备类型无效，请重新选择。',
 'Development mode: WireGuard runtime is unavailable':'当前为本地开发预览，VPN 需在飞牛 NAS 上运行。','WireGuard runtime requires Linux':'当前系统无法运行 WireGuard，请在飞牛 NAS 上启动。','Required ip binary is missing':'缺少网络管理工具，请检查 NAS 安装环境。','WireGuard interface is missing':'WireGuard 网络接口不存在，请重新启动服务。','fnwg0 exists without application ownership; refusing to modify it':'系统已存在同名网络接口，请先由管理员检查冲突。'};
 const imports:Record<string,string>={
 'too many pending import previews; wait five minutes':'待处理的配置预览过多，请等待 5 分钟后重试。','invalid import preview token':'配置预览无效，请重新检查配置。','cannot start import transaction':'无法开始导入，请重试或检查服务器日志。','configuration exceeds 32 KiB':'配置内容不能超过 32 KiB。','configuration exceeds 64 KiB':'配置文件过大，请缩短后重试。','server import requires an empty peer list; existing devices will not be overwritten':'导入服务器配置要求设备列表为空，请先删除现有设备。','stop the server before importing a server configuration':'请先停止服务，再导入服务器配置。','runtime state is uncertain; resolve the server error before importing':'服务器状态异常，请先解决服务错误，再导入配置。','client configuration belongs to a different WireGuard server':'此客户端配置属于其他 WireGuard 服务器，不能导入当前 NAS。','client address or preshared key does not match the imported server peer':'客户端地址或预共享密钥与已导入的服务器设备不匹配。','client is already managed and has a private key':'此设备已存在完整配置，无需重复导入。','server or peers changed after preview; preview again':'服务器或设备已发生更改，请重新检查配置。','import preview expired; preview again':'配置预览已过期，请重新检查配置。','This imported peer has no private key; import its client configuration to enable export':'此设备只有公钥，请先导入对应客户端配置，补全私钥后才能导出。','peer must have exactly one IPv4 address':'设备需填写一个 IPv4 隧道地址。','peer must have exactly one IPv4 CIDR address':'设备需填写一个 IPv4 地址及 CIDR 掩码。','server peer AllowedIPs must be one /32 host route; broad or IPv6 routes are unsupported':'服务器中的设备路由需使用单个 IPv4 /32 地址，不支持网段或 IPv6。','peer address must be an unused host inside the NAS tunnel subnet':'设备地址需位于 NAS 隧道网段内，且未被其他设备使用。','server Interface must have one private IPv4 address':'服务器接口需使用单个私有 IPv4 地址。','server Interface requires ListenPort':'服务器配置缺少监听端口 ListenPort。','server Peer Endpoint and PersistentKeepalive are unsupported; import client configuration separately':'服务器设备段不支持 Endpoint 或 PersistentKeepalive，请单独导入客户端配置。','peer public key cannot equal the server public key':'设备公钥不能与服务器公钥相同。','duplicate peer address':'配置中存在重复设备地址。','client Interface ListenPort is unsupported':'客户端接口不支持 ListenPort，请移除后重试。','client configuration must contain exactly one server Peer':'客户端配置必须包含且仅包含一个服务器 Peer 段。','client server Peer requires Endpoint':'客户端配置缺少服务器连接地址 Endpoint。','client key cannot equal the server key':'客户端密钥不能与服务器密钥相同。','client address is already assigned to another peer':'该地址已被其他设备使用。','Interface must precede Peer sections':'Interface 段必须位于 Peer 段之前。','too many peers':'配置中的设备数量过多。','invalid listen port':'监听端口无效。','invalid keepalive':'持续保活值无效。','DNS must contain IP addresses':'DNS 需填写有效 IP 地址。','Interface requires PrivateKey and Address':'Interface 段需包含私钥 PrivateKey 和隧道地址 Address。','each Peer requires PublicKey and AllowedIPs':'每个 Peer 段需包含公钥 PublicKey 和允许路由 AllowedIPs。','duplicate peer public key':'配置中存在重复设备公钥。','invalid server private key':'服务器私钥格式无效。','invalid client private key':'客户端私钥格式无效。'};
 if(imports[raw])return imports[raw];
 const line=raw.match(/^line (\d+): (.+)/);
 if(line){const detail=line[2].includes('unsupported field')?'存在不支持的字段，不能包含脚本或路由命令。':line[2].includes('duplicate')?'存在重复的配置段或字段。':line[2].includes('invalid')?'地址或密钥格式无效。':'配置格式无效，请检查字段与配置段。';return `配置第 ${line[1]} 行：${detail}`}
 if(known[raw])return known[raw];
 if(raw.startsWith('cannot verify LAN firewall table ownership'))return '无法核实防火墙表的归属，本次更改未应用。请稍后重试或检查应用日志。';
 if(raw.startsWith('Runtime update and rollback failed:')||raw.startsWith('Database commit failed and runtime rollback failed:'))return '操作失败，且旧配置未能恢复。请先在概览中停止服务并重新启动，再重试。';
 if(raw.startsWith('LAN firewall operation failed:'))return '应用局域网访问规则失败，请检查应用日志中的防火墙错误后重试。';
 const occupied=raw.match(/^UDP port (\d+) is already in use$/);
 if(occupied)return `UDP ${occupied[1]} 已被占用，请释放该端口或更换服务端口。`;
 if(raw.startsWith('cannot verify WireGuard listening port'))return '无法核实 WireGuard 实际监听端口，请检查服务权限后重试。';
 const mismatch=raw.match(/^WireGuard listening port mismatch: expected (\d+), actual (\d+)$/);
 if(mismatch)return `端口未生效：期望 UDP ${mismatch[1]}，实际 UDP ${mismatch[2]}。请停止后重新启动服务。`;
 if(raw.includes('NET_ADMIN')||raw.includes('kernel WireGuard support'))return '无法管理 VPN 网络，请检查 NAS 的网络管理权限和 WireGuard 内核支持。';
 if(raw.includes('tunnel subnet overlaps'))return '隧道网段与 NAS 现有网络冲突，请选择其他私有网段。';
 if(raw.startsWith('WireGuard configuration failed'))return '应用 WireGuard 配置失败，请检查 NAS 的 WireGuard 支持。';
 if(raw==='Failed to fetch'||raw==='Load failed')return '无法连接服务器，请检查网络后重试。';
 if(raw.startsWith('cannot read'))return '无法读取服务器数据，请刷新页面或检查服务日志。';
 if(raw.startsWith('cannot save'))return '无法保存更改，请重试或检查服务日志。';
 return raw;
}
export const nativeMode=location.pathname.startsWith('/app/fn-wireguard');
