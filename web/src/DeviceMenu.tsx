import {useEffect,useLayoutEffect,useRef,useState,type ReactNode} from 'react';
import {createPortal} from 'react-dom';
import {Settings2} from 'lucide-react';

export function DeviceMenu({name,children}:{name:string;children:ReactNode}){
 const [open,setOpen]=useState(false),[position,setPosition]=useState({top:0,left:0});
 const trigger=useRef<HTMLButtonElement>(null),menu=useRef<HTMLDivElement>(null);
 useLayoutEffect(()=>{
  if(!open||!trigger.current||!menu.current)return;
  const anchor=trigger.current.getBoundingClientRect(),height=menu.current.offsetHeight,width=menu.current.offsetWidth;
  setPosition({left:Math.max(16,Math.min(anchor.right-width,innerWidth-width-16)),top:Math.max(16,anchor.bottom+height+8>innerHeight?anchor.top-height-8:anchor.bottom+8)});
  menu.current.querySelector<HTMLButtonElement>('button:not(:disabled)')?.focus({preventScroll:true});
 },[open]);
 useEffect(()=>{
  if(!open)return;
  const outside=(event:Event)=>{const target=event.target as Node;if(!trigger.current?.contains(target)&&!menu.current?.contains(target))setOpen(false)};
  const escape=(event:KeyboardEvent)=>{if(event.key==='Escape'){event.preventDefault();setOpen(false);trigger.current?.focus({preventScroll:true})}};
  const dismiss=()=>setOpen(false);
  document.addEventListener('pointerdown',outside,true);document.addEventListener('focusin',outside,true);document.addEventListener('keydown',escape);window.addEventListener('resize',dismiss);window.addEventListener('scroll',dismiss,true);
  return()=>{document.removeEventListener('pointerdown',outside,true);document.removeEventListener('focusin',outside,true);document.removeEventListener('keydown',escape);window.removeEventListener('resize',dismiss);window.removeEventListener('scroll',dismiss,true)};
 },[open]);
 return <div className="row-menu"><button ref={trigger} className="icon-button device-menu-toggle" aria-label={`${name}的更多操作`} aria-expanded={open} onClick={()=>setOpen(value=>!value)}><Settings2 size={17}/></button>{open&&createPortal(<div ref={menu} role="group" aria-label={`${name}的操作`} className="menu-popover" style={position} onClick={event=>{if((event.target as Element).closest('button'))setOpen(false)}}>{children}</div>,document.body)}</div>
}
