/** Wire ordering shared with core.update_policy; patch serials stay out of labels. */
export const PATCH_OFFSET=1_000_000
export function versionKey(value:string):number[]{
 const match=/^v?(\d+)\.(\d+)\.(\d+)(?:-(\d+))?$/i.exec(String(value||'').trim())
 if(!match)return [0,0,0,0,0]
 const main=[Number(match[1]),Number(match[2]),Number(match[3])],number=match[4]===undefined?null:Number(match[4])
 if(number===null)return [...main,1,0]
 if(number===PATCH_OFFSET||number>1_999_999)return [0,0,0,0,0]
 return [...main,number>PATCH_OFFSET?2:0,number>PATCH_OFFSET?number-PATCH_OFFSET:number]
}
export function isPatchVersion(value:string):boolean{return versionKey(value)[3]===2}
export function displayVersion(value:string):string{
 if(!isPatchVersion(value))return value
 return 'v'+versionKey(value).slice(0,3).join('.')
}
