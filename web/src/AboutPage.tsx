import {useEffect,useState} from 'react';
import {ArrowUpRight,CheckCircle2,Download,Github,Info,LoaderCircle,RefreshCw,Shield,AlertCircle} from 'lucide-react';
import {api} from './api';

interface AppInfo {name:string;version:string;author:string;authorURL:string;repositoryURL:string;releasesURL:string;architecture:string;platform:string}
interface UpdateResult {state:'current'|'available'|'ahead'|'unpublished';currentVersion:string;latestVersion?:string;releaseURL:string;notes?:string;publishedAt?:string;checkedAt:string;asset?:{name:string;browser_download_url:string;size:number}}

function formatDate(value:string){const date=new Date(value);return Number.isNaN(date.getTime())?'—':date.toLocaleString('zh-CN',{hour12:false})}

export function AboutPage(){
 const [info,setInfo]=useState<AppInfo|null>(null),[loading,setLoading]=useState(true),[infoError,setInfoError]=useState('');
 const [checking,setChecking]=useState(false),[result,setResult]=useState<UpdateResult|null>(null),[error,setError]=useState('');
 const [attempt,setAttempt]=useState(0);
 useEffect(()=>{let active=true;setLoading(true);setInfoError('');api<AppInfo>('/about').then(value=>{if(active)setInfo(value)}).catch(e=>{if(active)setInfoError(e instanceof Error?e.message:'无法读取应用信息。')}).finally(()=>{if(active)setLoading(false)});return()=>{active=false}},[attempt]);
 const check=async()=>{setChecking(true);setError('');setResult(null);try{setResult(await api<UpdateResult>('/updates/check','POST',{}))}catch(e){setError(e instanceof Error?e.message:'检测更新失败，请重试。')}finally{setChecking(false)}};
 if(loading)return <section className="glass panel loading" role="status"><LoaderCircle className="spin" size={20}/>正在读取应用信息…</section>;
 if(!info)return <section className="glass panel"><div className="notice error" role="alert"><AlertCircle size={20}/><span>{infoError}</span></div><button className="button secondary" onClick={()=>setAttempt(value=>value+1)}><RefreshCw size={18}/>重新加载</button></section>;
 const architecture=info.architecture==='amd64'?'x86_64':info.architecture==='arm64'?'ARM64':info.architecture;
 const stateTitle=result?{current:'已是最新版本',available:`发现新版本 v${result.latestVersion}`,ahead:'当前版本领先于正式发布版',unpublished:'暂未找到公开的正式版本'}[result.state]:'';
 return <div className="about-page">
  <section className="glass panel about-identity" aria-labelledby="about-title">
   <div className="about-brand"><span className="brand-icon"><Shield size={40}/></span><div><span className="eyebrow">关于应用</span><h1 id="about-title">{info.name}</h1><p>让每一台设备，都能安全回家。</p></div><span className="about-version">v{info.version}</span></div>
   <p className="about-description">为飞牛 NAS 打造的 WireGuard 管理工具。轻松连接家庭网络，清晰管理每台设备的访问权限。</p>
   <dl className="about-facts"><div><dt>作者</dt><dd><a href={info.authorURL} target="_blank" rel="noopener noreferrer">{info.author}<ArrowUpRight size={15}/></a></dd></div><div><dt>当前版本</dt><dd>v{info.version}</dd></div><div><dt>运行架构</dt><dd>{architecture}<span>{info.platform==='linux'?'Linux · NAS 运行环境':'本地开发环境'}</span></dd></div></dl>
   <div className="about-links"><a className="button secondary" href={info.repositoryURL} target="_blank" rel="noopener noreferrer"><Github size={18}/>GitHub 项目<ArrowUpRight size={15}/></a><a className="button secondary" href={`${info.repositoryURL}/issues`} target="_blank" rel="noopener noreferrer">反馈问题<ArrowUpRight size={15}/></a><a className="text-button" href={info.releasesURL} target="_blank" rel="noopener noreferrer">历史版本<ArrowUpRight size={15}/></a></div>
  </section>
  <section className="glass panel about-updates" aria-labelledby="updates-title" aria-busy={checking}>
   <div className="section-head"><div><h2 id="updates-title">应用更新</h2><p>从作者的 GitHub 仓库检测最新正式版本。</p></div><button className="button primary" onClick={()=>void check()} disabled={checking}>{checking?<LoaderCircle className="spin" size={18}/>:<RefreshCw size={18}/>} {checking?'正在检测…':'检测更新'}</button></div>
   <div className="update-status" aria-live="polite" aria-atomic="true">
    {checking?<div className="update-message"><LoaderCircle className="spin" size={24}/><div><h3>正在连接 GitHub</h3><p>通常只需几秒钟，请稍候。</p></div></div>:error?<div className="notice error" role="alert"><AlertCircle size={22}/><span>{error}</span></div>:result?<div className={`update-message ${result.state==='available'?'has-update':''}`}>
     {result.state==='current'?<CheckCircle2 size={26}/>:result.state==='available'?<Download size={26}/>:<Info size={26}/>}<div><h3>{stateTitle}</h3><p>{result.state==='unpublished'?'可以前往 GitHub 发布页面查看，稍后再试。':`当前 v${result.currentVersion} · 最新正式版 v${result.latestVersion}`}</p><small>检测时间：{formatDate(result.checkedAt)}</small></div>
    </div>:<div className="update-message"><RefreshCw size={25}/><div><h3>让应用保持最新</h3><p>点击“检测更新”，查看新功能与修复。</p></div></div>}
   </div>
   {result&&result.state!=='unpublished'&&<div className="release-details">
    {result.publishedAt&&<p className="muted">发布时间：{formatDate(result.publishedAt)}</p>}
    {result.notes&&<details className="release-notes" open={result.state==='available'}><summary>更新说明</summary><pre>{result.notes}</pre></details>}
    <div className="about-links">{result.asset&&<a className={`button ${result.state==='available'?'primary':'secondary'}`} href={result.asset.browser_download_url} target="_blank" rel="noopener noreferrer"><Download size={18}/>下载 {architecture} 安装包<span className="download-size">{(result.asset.size/1024/1024).toFixed(1)} MB</span></a>}<a className="button secondary" href={result.releaseURL} target="_blank" rel="noopener noreferrer">查看发布页面<ArrowUpRight size={15}/></a></div>
    {result.state==='available'&&!result.asset&&<p className="form-help">该版本尚无适配当前架构的安装包，请查看发布页面。</p>}
   </div>}
   <div className="update-guidance"><Info size={18}/><p>下载后，在飞牛应用中心选择手动更新，无需卸载。检测仅在点击时进行；5 分钟内复用检测结果，不上传设备配置或密钥。</p></div>
  </section>
  <p className="about-credit">由 {info.author} 开发与维护 · 基于 WireGuard</p>
 </div>;
}
