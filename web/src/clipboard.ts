/** Copies only after a user action; the fallback also works inside an open modal. */
export async function copyText(value:string):Promise<boolean>{
 if(navigator.clipboard?.writeText){
  try{await navigator.clipboard.writeText(value);return true}catch{/* Try the legacy browser copy command. */}
 }
 const active=document.activeElement instanceof HTMLElement?document.activeElement:null;
 const selection=window.getSelection();
 const ranges=selection?Array.from({length:selection.rangeCount},(_,i)=>selection.getRangeAt(i).cloneRange()):[];
 const input=active instanceof HTMLInputElement||active instanceof HTMLTextAreaElement?active:null;
 const inputSelection=input?{start:input.selectionStart,end:input.selectionEnd,direction:input.selectionDirection}:null;
 const temporary=document.createElement('textarea');
 temporary.value=value;temporary.tabIndex=-1;temporary.readOnly=true;
 temporary.style.cssText='position:fixed;left:0;top:0;width:1px;height:1px;padding:0;border:0;opacity:0;pointer-events:none;';
 const host=active?.closest('dialog[open]')||document.querySelector('dialog[open]')||document.body;
 try{
  host.appendChild(temporary);temporary.focus({preventScroll:true});temporary.select();
  return document.execCommand('copy')===true;
 }catch{return false}
 finally{
  temporary.value='';temporary.remove();
  if(active?.isConnected)active.focus({preventScroll:true});
  if(selection){selection.removeAllRanges();for(const range of ranges){if(range.commonAncestorContainer.isConnected)selection.addRange(range)}}
  if(input?.isConnected&&inputSelection&&inputSelection.start!==null&&inputSelection.end!==null){
   try{input.setSelectionRange(inputSelection.start,inputSelection.end,inputSelection.direction||undefined)}catch{/* Some input types do not support selection. */}
  }
 }
}
