<template>
  <a-modal :open="!!pendingLink || !!pendingRun" :title="t(pendingLink?'control.pairConfirmTitle':'control.transferConfirmTitle')" :closable="false" :mask-closable="false" :keyboard="false" :footer="null" data-testid="control-sync-confirm">
    <a-alert v-if="pendingRun?.state==='preparing'" type="info" show-icon :message="t('control.preparingSnapshot')" /><a-alert v-else type="warning" show-icon :message="t('repair128.confirmCountdown',{seconds:remaining})" />
    <template v-if="pendingLink"><p>{{ t('control.confirmPeerNote') }}</p><div class="peer-id"><strong>{{ pendingLink.remote?.name }}</strong> · {{ pendingLink.remote?.platform }} {{ pendingLink.remote?.version }}<br />{{ pendingLink.remote?.instance_id }}<br />{{ pendingLink.target }}</div><p>{{ t('control.allowedCategories') }}: {{ pendingLink.categories.map(c=>t('control.categories.'+c)).join(' / ') }}</p></template>
    <template v-else-if="pendingRun"><a-alert :type="pendingRun.mode==='overwrite'?'warning':'info'" show-icon :message="t(pendingRun.mode==='overwrite'?'control.overwriteNote':'control.incrementalNote')" /><p>{{ t('control.direction') }}: {{ t(pendingRun.flow==='push'?'control.receiveFromPeer':'control.sendToPeer') }}</p><p>{{ t('control.contents') }}: {{ pendingRun.categories.map(c=>t('control.categories.'+c)).join(' / ') }}</p><p>{{ t('control.snapshot') }}: {{ pendingRun.summary?.bytes }} bytes · {{ pendingRun.summary?.files }} {{ t('control.files') }}</p></template>
    <a-alert v-if="error" type="error" :message="error" /><a-space style="margin-top:20px"><a-button type="primary" :disabled="pendingRun?.state==='preparing' || remaining<=0" :loading="working" @click="decide(true)" data-testid="sync-confirm-accept">{{ t('control.confirm') }}</a-button><a-button danger :disabled="working" @click="decide(false)" data-testid="sync-confirm-reject">{{ t('control.reject') }}</a-button></a-space>
  </a-modal>
</template>
<script setup lang="ts">
import {computed,onMounted,onUnmounted,ref} from 'vue'
import {t} from '../i18n'
import {getRole} from '../api/request'
import {controlSyncApi,type SyncLink,type SyncRun} from '../api/controlSync'
const links=ref<SyncLink[]>([]),runs=ref<SyncRun[]>([]),error=ref(''),working=ref(false),now=ref(Date.now()/1000)
const pendingLink=computed(()=>links.value.find(l=>l.state==='pending' && !(l.kind==='initiator'?l.source_confirmed:l.receiver_confirmed)))
const pendingRun=computed(()=>pendingLink.value?undefined:runs.value.find(r=>r.kind==='receiver' && ['preparing','pending'].includes(r.state) && links.value.some(l=>l._id===r.link_id && l.state==='paired')))
const remaining=computed(()=>Math.max(0,Math.ceil(((pendingLink.value||pendingRun.value)?.confirm_expires_at||now.value)-now.value)))
let stopped=false,polling=false,pumping=false,generation=0,offset=0,timeOffset=0
let timer:ReturnType<typeof setInterval>,ticks:ReturnType<typeof setInterval>,pumpTimer:ReturnType<typeof setInterval>,controller:AbortController|undefined
async function poll(){
 if(stopped||polling||getRole()!=='admin')return
 polling=true;const serial=generation;controller=new AbortController();const timeout=setTimeout(()=>controller?.abort(),4500)
 try{const data=await controlSyncApi.pending(controller.signal);if(!stopped&&serial===generation){links.value=data.links;runs.value=data.runs;timeOffset=data.server_time-Date.now()/1000;now.value=Date.now()/1000+timeOffset}}
 catch{/* Next poll reads fresh shared state; an unavailable peer cannot block approval UI. */}
 finally{clearTimeout(timeout);polling=false}
}
async function pump(){
 if(stopped||pumping||getRole()!=='admin')return
 pumping=true
 try{
  const jobs=[...links.value.filter(l=>l.kind==='initiator'&&['pending','connecting'].includes(l.state)).map(l=>async()=>{await controlSyncApi.refresh(l._id,true)}),...runs.value.filter(r=>r.kind==='initiator'&&['pending','ready','transferring'].includes(r.state)).map(r=>async()=>{const current=await controlSyncApi.progress(r._id,true);if(['ready','transferring'].includes(current.state))await controlSyncApi.advance(r._id,true)})]
  const batch=Array.from({length:Math.min(2,jobs.length)},(_,i)=>jobs[(offset+i)%jobs.length]);offset+=batch.length
  await Promise.allSettled(batch.map(fn=>fn()));void poll()
 }finally{pumping=false}
}
async function decide(accepted:boolean){
 if(working.value)return
 const link=pendingLink.value,run=pendingRun.value;working.value=true;error.value=''
 try{if(link){if(accepted)await controlSyncApi.confirm(link._id);else await controlSyncApi.revokeLink(link._id)}else if(run)await controlSyncApi.decide(run._id,accepted);await poll()}
 catch(e){error.value=(e as Error).message;void poll()}finally{working.value=false}
}
function deleted(event:Event){const id=(event as CustomEvent).detail?.id;if(typeof id!=='string')return;++generation;links.value=links.value.filter(l=>l._id!==id);runs.value=runs.value.filter(r=>r.link_id!==id)}
function wake(){void poll()}
onMounted(()=>{window.addEventListener('watchtower:sync-link-deleted',deleted);window.addEventListener('watchtower:sync-requested',wake);window.addEventListener('focus',wake);document.addEventListener('visibilitychange',wake);void poll();timer=setInterval(poll,750);pumpTimer=setInterval(pump,3500);ticks=setInterval(()=>{now.value=Date.now()/1000+timeOffset},250)})
onUnmounted(()=>{stopped=true;++generation;controller?.abort();clearInterval(timer);clearInterval(ticks);clearInterval(pumpTimer);window.removeEventListener('watchtower:sync-link-deleted',deleted);window.removeEventListener('watchtower:sync-requested',wake);window.removeEventListener('focus',wake);document.removeEventListener('visibilitychange',wake)})
</script>
<style scoped>.peer-id{margin-top:14px;padding:14px;background:var(--dt-fill);border:1px solid var(--dt-border);border-radius:10px;font-family:monospace;overflow-wrap:anywhere}</style>
