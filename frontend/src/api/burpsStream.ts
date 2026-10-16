import { getToken,toQueryString } from './request'

export type TrafficConnection='connecting'|'live'|'reconnecting'|'stopped'
export interface TrafficEvent {items?:unknown[];ids?:string[];snapshot?:boolean;message?:string}

/** Incremental SSE with Token headers, UTF-8 chunk decoding and retained reconnects. */
export function trafficStream(sessionId:string,args:Record<string,unknown>,onEvent:(name:string,event:TrafficEvent)=>void,onStatus:(status:TrafficConnection)=>void,onError:(message:string)=>void){
  const control=new AbortController()
  let retry=0
  async function delay(ms:number){await new Promise<void>(resolve=>{const finish=()=>{clearTimeout(timer);control.signal.removeEventListener('abort',finish);resolve()};const timer=setTimeout(finish,ms);control.signal.addEventListener('abort',finish,{once:true});if(control.signal.aborted)finish()})}
  void (async()=>{
    while(!control.signal.aborted){
      let reader:ReadableStreamDefaultReader<Uint8Array>|undefined
      try{
        onStatus(retry?'reconnecting':'connecting')
        const response=await fetch('/api/pentest/session/'+encodeURIComponent(sessionId)+'/burps/stream'+toQueryString(args),{headers:{Token:getToken()},signal:control.signal,cache:'no-store'})
        if(!response.ok||!response.body||!response.headers.get('content-type')?.includes('text/event-stream')){
          const value=await response.json().catch(()=>({}));onError(value.message||'Traffic stream unavailable')
          if(response.status>=400&&response.status<500){onStatus('stopped');return}
          throw new Error(value.message||'Traffic stream unavailable')
        }
        reader=response.body.getReader();const decoder=new TextDecoder();let buffer='';onStatus('live');retry=0
        while(!control.signal.aborted){
          const result=await reader.read();if(result.done)break
          buffer+=decoder.decode(result.value,{stream:true})
          if(buffer.length>4*1024*1024)throw new Error('Traffic frame exceeds its budget')
          let boundary:RegExpExecArray|null
          while((boundary=/\r?\n\r?\n/.exec(buffer))){
            const frame=buffer.slice(0,boundary.index);buffer=buffer.slice(boundary.index+boundary[0].length)
            let name='message';const data:string[]=[]
            for(const line of frame.split(/\r?\n/)){if(line.startsWith('event:'))name=line.slice(6).trim();else if(line.startsWith('data:'))data.push(line.slice(5).trimStart())}
            if(!data.length)continue
            const event=JSON.parse(data.join('\n')) as TrafficEvent
            if(control.signal.aborted)return
            if(name==='access_revoked'){onError(event.message||'Session access revoked');onStatus('stopped');return}
            if(name==='stream_error')throw new Error(event.message||'Traffic stream interrupted')
            onEvent(name,event)
          }
        }
      }catch(error){if(!control.signal.aborted)onError(String(error instanceof Error?error.message:error))}
      finally{if(reader){await reader.cancel().catch(()=>{});reader.releaseLock()}}
      if(!control.signal.aborted){onStatus('reconnecting');await delay(Math.min(8000,1000*2**Math.min(retry++,3)))}
    }
  })()
  return {close:()=>control.abort()}
}
