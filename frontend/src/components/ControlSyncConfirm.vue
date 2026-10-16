<template>
  <a-modal :open="!!pendingLink || !!pendingRun" :title="pendingLink ? t('control.pairConfirmTitle') : t('control.transferConfirmTitle')" :closable="false" :mask-closable="false" :keyboard="false" :footer="null" data-testid="control-sync-confirm">
    <template v-if="pendingLink">
      <p>{{ t('control.confirmPeerNote') }}</p><div class="peer-id"><strong>{{ pendingLink.remote?.name }}</strong> · {{ pendingLink.remote?.platform }} {{ pendingLink.remote?.version }}<br />{{ pendingLink.remote?.instance_id }}<br />{{ pendingLink.target }}</div>
      <p>{{ t('control.allowedCategories') }}: {{ pendingLink.categories.map(c => t('control.categories.' + c)).join(' / ') }}</p><p>{{ t('control.expiry') }}: {{ date(pendingLink.pair_expires_at) }}</p>
    </template>
    <template v-else-if="pendingRun">
      <a-alert :type="pendingRun.mode === 'overwrite' ? 'warning' : 'info'" show-icon :message="t(pendingRun.mode === 'overwrite' ? 'control.overwriteNote' : 'control.incrementalNote')" />
      <p>{{ t('control.direction') }}: {{ t(pendingRun.flow === 'push' ? 'control.receiveFromPeer' : 'control.sendToPeer') }}</p><p>{{ t('control.contents') }}: {{ pendingRun.categories.map(c => t('control.categories.' + c)).join(' / ') }}</p><p>{{ t('control.snapshot') }}: {{ pendingRun.summary?.bytes }} bytes · {{ pendingRun.summary?.files }} {{ t('control.files') }}</p>
      <div class="peer-id">{{ JSON.stringify(pendingRun.summary?.counts) }}</div>
    </template>
    <a-alert v-if="error" type="error" :message="error" /><a-space style="margin-top:20px"><a-button type="primary" :loading="working" @click="decide(true)" data-testid="sync-confirm-accept">{{ t('control.confirm') }}</a-button><a-button danger :disabled="working" @click="decide(false)" data-testid="sync-confirm-reject">{{ t('control.reject') }}</a-button></a-space>
  </a-modal>
</template>

<script setup lang="ts">
import { computed, onMounted, onUnmounted, ref } from 'vue'
import { appLocale, t } from '../i18n'
import { getRole } from '../api/request'
import { controlSyncApi, type ControlState } from '../api/controlSync'
const state = ref<ControlState | null>(null), error = ref(''), working = ref(false)
const pendingLink = computed(() => state.value?.links.find(link => link.state === 'pending' && !(link.kind === 'initiator' ? link.source_confirmed : link.receiver_confirmed)))
const pendingRun = computed(() => pendingLink.value ? undefined : state.value?.runs.find(run => run.kind === 'receiver' && run.state === 'pending' && state.value?.links.some(link=>link._id===run.link_id && link.state==='paired')))
const date = (seconds: number) => new Date(seconds * 1000).toLocaleString(appLocale.value)
let timer: ReturnType<typeof setInterval> | undefined, polling = false, stopped = false
let generation=0
function deleted(event:Event){const id=(event as CustomEvent).detail?.id;if(typeof id!=='string')return;++generation;if(state.value){state.value.links=state.value.links.filter(link=>link._id!==id);state.value.runs=state.value.runs.filter(run=>run.link_id!==id)}}
async function poll() {
  if (stopped || polling || getRole() !== 'admin') return
  polling = true
  const currentGeneration=generation
  try {
    const data = await controlSyncApi.state()
    const pendingSources = data.links.filter(l => l.kind === 'initiator' && ['pending','connecting'].includes(l.state)).slice(0, 4)
    await Promise.allSettled(pendingSources.map(l => controlSyncApi.refresh(l._id)))
    const running = data.runs.filter(r => r.kind === 'initiator' && ['pending','ready','transferring'].includes(r.state)).slice(0, 4)
    for (const run of running) { try { const current = await controlSyncApi.progress(run._id); if (['ready','transferring'].includes(current.state)) await controlSyncApi.advance(run._id) } catch { /* state remains persisted; retry next poll */ } }
    const latest=await controlSyncApi.state()
    if (!stopped && currentGeneration===generation) state.value = latest
  } catch { /* No startup popup for unavailable/unconfigured control services. */ }
  finally { polling = false }
}
async function decide(accepted: boolean) {
  if (working.value) return
  working.value = true; error.value = ''
  try {
    if (pendingLink.value) { if (accepted) await controlSyncApi.confirm(pendingLink.value._id); else await controlSyncApi.revokeLink(pendingLink.value._id) }
    else if (pendingRun.value) await controlSyncApi.decide(pendingRun.value._id, accepted)
    state.value = await controlSyncApi.state()
  } catch (e) { error.value = (e as Error).message }
  finally { working.value = false }
}
onMounted(() => { window.addEventListener('watchtower:sync-link-deleted',deleted);poll(); timer = setInterval(poll, 4000) })
onUnmounted(() => { stopped = true;++generation;window.removeEventListener('watchtower:sync-link-deleted',deleted);if (timer) clearInterval(timer) })
</script>
<style scoped>.peer-id{padding:14px;background:var(--dt-fill);border:1px solid var(--dt-border);border-radius:10px;font-family:monospace;overflow-wrap:anywhere}</style>
