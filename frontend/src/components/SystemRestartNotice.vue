<template><a-modal :open="restartState.visible" :title="t('repair128.restarting')" :footer="null" :closable="false" :mask-closable="false" :keyboard="false" centered><a-spin /><p>{{ t('repair128.restartNote') }}</p></a-modal></template>
<script setup lang="ts">
import {onMounted,onUnmounted} from 'vue'
import {t} from '../i18n'
import {request} from '../api/request'
import {restartState,updateRestartPhase} from '../composables/useRestartState'
let timer:ReturnType<typeof setInterval>,busy=false,stopped=false,healthy=0,active:AbortController|undefined
async function check(){
 if(!restartState.visible||busy||stopped)return
 if(Date.now()>restartState.until){restartState.visible=false;return}
 busy=true;active=new AbortController();const timeout=setTimeout(()=>active?.abort(),2000)
 try{
  const progress=await request<any>('/api/about/progress',{signal:active.signal,silent:true})
  if(!['applying','restarting'].includes(progress.phase)){
   if(++healthy>=2){restartState.visible=false;restartState.until=0;updateRestartPhase(progress.phase)}
  }else healthy=0
 }catch{healthy=0}finally{clearTimeout(timeout);active=undefined;busy=false}
}
onMounted(()=>{timer=setInterval(check,2000)});onUnmounted(()=>{stopped=true;active?.abort();clearInterval(timer)})
</script>
