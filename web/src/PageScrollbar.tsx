import {useEffect,useRef,useState,type KeyboardEvent,type PointerEvent} from 'react';

// The page keeps native wheel, touch and keyboard scrolling. Only the desktop
// scrollbar is overlaid, so showing a bar or a dialog never shifts the layout.
export function PageScrollbar({hidden=false}:{hidden?:boolean}) {
 const track=useRef<HTMLDivElement>(null);
 const drag=useRef<{pointer:number;offset:number}|null>(null);
 const [metrics,setMetrics]=useState({height:0,thumb:0,top:0,max:0,value:0});
 const [dragging,setDragging]=useState(false);
 useEffect(()=>{
  document.documentElement.classList.add('has-overlay-scrollbar');
  let frame=0;
  const update=()=>{
   frame=0;
   const root=document.documentElement,height=track.current?.clientHeight||0;
   const max=Math.max(0,root.scrollHeight-root.clientHeight);
   const thumb=Math.min(height,Math.max(32,height*root.clientHeight/root.scrollHeight));
   const value=Math.max(0,Math.min(max,window.scrollY));
   setMetrics({height,thumb,top:max ? value/max*(height-thumb) : 0,max,value});
  };
  const schedule=()=>{if(!frame)frame=requestAnimationFrame(update)};
  const observer=new ResizeObserver(schedule);
  observer.observe(document.body);
  if(track.current)observer.observe(track.current);
  window.addEventListener('scroll',schedule,{passive:true});
  window.addEventListener('resize',schedule);
  schedule();
  return()=>{observer.disconnect();cancelAnimationFrame(frame);window.removeEventListener('scroll',schedule);window.removeEventListener('resize',schedule);document.documentElement.classList.remove('has-overlay-scrollbar')};
 },[]);
 const seek=(clientY:number,offset:number)=>{
  const rect=track.current?.getBoundingClientRect();
  if(!rect||metrics.height<=metrics.thumb)return;
  const fraction=(clientY-rect.top-offset)/(metrics.height-metrics.thumb);
  window.scrollTo({top:Math.max(0,Math.min(1,fraction))*metrics.max,behavior:'instant'});
 };
 const start=(event:PointerEvent<HTMLDivElement>)=>{
  if(event.button!==0)return;
  event.preventDefault();event.currentTarget.focus();event.currentTarget.setPointerCapture(event.pointerId);
  const y=event.clientY-event.currentTarget.getBoundingClientRect().top;
  const offset=y>=metrics.top&&y<=metrics.top+metrics.thumb ? y-metrics.top : metrics.thumb/2;
  drag.current={pointer:event.pointerId,offset};setDragging(true);seek(event.clientY,offset);
 };
 const key=(event:KeyboardEvent<HTMLDivElement>)=>{
  const page=window.innerHeight*.9;
  const next:Record<string,number>={ArrowDown:metrics.value+48,ArrowUp:metrics.value-48,PageDown:metrics.value+page,PageUp:metrics.value-page,Home:0,End:metrics.max,' ':metrics.value+(event.shiftKey?-page:page)};
  if(!(event.key in next))return;
  event.preventDefault();window.scrollTo({top:next[event.key],behavior:'instant'});
 };
 const inactive=hidden||metrics.max<=0;
 return <div ref={track} className={`page-scrollbar${dragging?' dragging':''}${inactive?' inactive':''}`} role="scrollbar" aria-label="页面滚动" aria-controls="main" aria-orientation="vertical" aria-valuemin={0} aria-valuemax={Math.round(metrics.max)} aria-valuenow={Math.round(metrics.value)} aria-hidden={inactive||undefined} tabIndex={inactive?-1:0} onKeyDown={key} onPointerDown={start} onPointerMove={event=>{if(drag.current?.pointer===event.pointerId)seek(event.clientY,drag.current.offset)}} onPointerUp={event=>{if(event.currentTarget.hasPointerCapture(event.pointerId))event.currentTarget.releasePointerCapture(event.pointerId);drag.current=null;setDragging(false)}} onLostPointerCapture={()=>{drag.current=null;setDragging(false)}}><span className="page-scrollbar-thumb" style={{height:metrics.thumb,transform:`translateY(${metrics.top}px)`}}/></div>;
}
