export function suggestedReachable(addresses:string[]|undefined,port?:number):string{
 const current=location.hostname.replace(/^\[|\]$/g,'')
 const host=current && !['localhost','127.0.0.1','::1'].includes(current)?current:(addresses||[])[0]
 if(!host)return ''
 const value=host.includes(':')?'['+host+']':host
 return port?value+':'+port:value
}
