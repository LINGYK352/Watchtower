import { getToken } from './request'

/** Authenticated same-origin file response, kept in the native Save As workflow. */
export async function downloadApiFile(path: string, fallback: string) {
  const url=new URL(path,location.origin)
  if(url.origin!==location.origin || !url.pathname.startsWith('/api/'))throw new Error('Invalid download URL')
  const response=await fetch(url.href,{headers:{Token:getToken()},cache:'no-store',redirect:'error'})
  if(!response.ok){let detail='';try{detail=(await response.json()).message||''}catch{}throw new Error(detail||`Download failed (${response.status})`)}
  const cd=response.headers.get('Content-Disposition')||''
  let filename=fallback
  try{filename=decodeURIComponent(cd.match(/filename\*=UTF-8''([^;]+)/i)?.[1]||'')||cd.match(/filename="?([^";]+)"?/i)?.[1]||fallback}catch{}
  filename=filename.replace(/[<>:"/\\|?*\u0000-\u001f]/g,'_').slice(0,180)||fallback
  const blob=await response.blob(),href=URL.createObjectURL(blob),a=document.createElement('a')
  a.href=href;a.download=filename;document.body.appendChild(a);a.click();a.remove()
  // Native windows defer this release until Save As finishes/cancels.
  setTimeout(()=>URL.revokeObjectURL(href),5000)
}
