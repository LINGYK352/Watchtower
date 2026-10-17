import {reactive} from 'vue'
export const restartState=reactive({until:0,visible:false})
let previousPhase=''
export function updateRestartPhase(phase:string){
 if(['applying','restarting'].includes(phase)&&phase!==previousPhase){restartState.until=Date.now()+120000}
 else if(['done','error'].includes(phase)){restartState.until=0;restartState.visible=false}
 previousPhase=phase
}
export function restartingFailure(status:number){
 if(Date.now()>=restartState.until || ![0,502,503,504].includes(status))return false
 restartState.visible=true;return true
}
