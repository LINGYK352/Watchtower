type Entry = { id: string; priority: number; show: () => void }
let active = '', timer: ReturnType<typeof setTimeout> | null = null
const queue: Entry[] = []
function pump() {
 if (active || timer || !queue.length) return
 timer=setTimeout(()=>{timer=null;if(active)return;queue.sort((a,b)=>b.priority-a.priority);const next=queue.shift();if(next){active=next.id;next.show()}},350)
}
export function requestNotice(id:string,priority:number,show:()=>void){if(active===id || queue.some(x=>x.id===id))return;queue.push({id,priority,show});pump()}
export function releaseNotice(id:string){for(let i=queue.length-1;i>=0;i--)if(queue[i].id===id)queue.splice(i,1);if(active===id)active='';pump()}
