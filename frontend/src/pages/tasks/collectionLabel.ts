/** Follow the task's effective collection gates, including legacy defaults. */
export function hasDynamicAssets(task: Record<string, unknown>): boolean {
 const kind=String(task.type||'').toLowerCase()
 if(kind==='fofa')return true
 const options=task.options && typeof task.options==='object' && !Array.isArray(task.options)?task.options as Record<string,unknown>:{}
 const mode=String(options.collect_mode||'multi_brute').toLowerCase()
 if(mode==='single')return false
 if(['domain','unit'].includes(kind))return true // passive/subdomain discovery
 if(options.domain_brute===true && String(options.domain_brute_type||'').toLowerCase()!=='none')return true
 return Array.isArray(options.collect_sources) && options.collect_sources.some(x=>typeof x==='string' && ['fofa','hunter','quake','zoomeye'].includes(x.toLowerCase()))
}
