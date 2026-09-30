import {AlertCircle,CheckCircle2} from 'lucide-react';
import {translateError} from './api';

export interface PortCheck {port:number;actualPort:number;state:'active'|'available'|'in-use'|'unknown';detail?:string;checkedAt:string}
export function PortCheckResult({result}:{result:PortCheck}) {
 const ok=result.state==='active'||result.state==='available';
 const title={active:`UDP ${result.port} 已生效`,available:`UDP ${result.port} 当前空闲`,'in-use':`UDP ${result.port} 已被占用`,unknown:`UDP ${result.port} 暂时无法检测`}[result.state];
 let detail={active:'已从 WireGuard 接口读取并核对实际监听端口。',available:'可以使用此端口；保存并启动服务后可核对是否生效。','in-use':'此端口已有其他 UDP 监听，请释放该端口或更换服务端口。',unknown:'未能确认端口状态，请检查服务权限或稍后重试。'}[result.state];
 if(result.state==='unknown'&&result.detail){detail=result.detail.startsWith('cannot check')?'当前权限或网络环境不允许检测此端口。请检查应用权限，或改用大于 1023 的端口。':translateError(result.detail)}
 return <div className={`port-result ${ok?'ok':'warning'}`} role="status">{ok?<CheckCircle2 size={17}/>:<AlertCircle size={17}/>}<div><strong>{title}</strong><p>{detail}</p>{result.actualPort>0&&result.actualPort!==result.port&&<p>WireGuard 目前实际监听 UDP {result.actualPort}，与待检测端口不同。</p>}<small>{new Date(result.checkedAt).toLocaleTimeString('zh-CN',{hour12:false})} 检测 · 仅检查 NAS，不验证公网转发</small></div></div>;
}
