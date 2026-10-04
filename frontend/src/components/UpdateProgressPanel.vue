<template>
  <div class="chain-progress" aria-live="polite">
    <div class="chain-heading">{{ translate('ui.update_route') }}: {{ progress.current_version || '-' }} → {{ progress.target_version || progress.target || '-' }}</div>
    <p v-if="progress.hops">{{ translate('ui.update_hop', { current: progress.hop || 1, total: progress.hops, version: progress.hop_version || '-' }) }}</p>
    <a-tag :color="progress.phase === 'error' ? 'error' : 'processing'">{{ phaseLabel }}</a-tag>
    <a-progress :percent="percent" :status="progress.phase === 'error' ? 'exception' : 'active'" size="small" />
    <p class="chain-detail">{{ progress.msg || phaseLabel }}</p>
    <a-alert v-if="networkLost" type="warning" show-icon :message="translate('ui.update_connection_lost')" :description="translate('ui.update_preserved')" />
    <a-alert v-if="progress.resumable && progress.phase === 'error'" type="warning" show-icon :message="translate('ui.update_paused')" :description="translate('ui.update_preserved')" />
    <a-button v-if="progress.resumable && (progress.phase === 'error' || networkLost)" type="primary" @click="$emit('resume')">{{ translate('ui.update_resume') }}</a-button>
  </div>
</template>

<script setup lang="ts">
import { computed } from 'vue'
import { t as translate } from '../i18n'
const props = defineProps<{ progress: any; networkLost?: boolean }>()
defineEmits<{ (event: 'resume'): void }>()
const phaseLabel = computed(() => translate('ui.update_phase_' + (['checking','downloading','validating','applying','restarting','done','error'].includes(props.progress.phase) ? props.progress.phase : 'checking')))
const percent = computed(() => props.progress.phase === 'done' && !props.progress.chain_active ? 100 : Math.min(99, Math.max(0, Math.round((props.progress.done || 0) * 100 / Math.max(1, props.progress.total || 0)))))
</script>

<style scoped>
.chain-progress { padding: 14px; border: 1px solid var(--dt-border); border-radius: 10px; margin: 12px 0; }
.chain-heading { font-weight: 600; overflow-wrap: anywhere; }
.chain-progress p { margin: 8px 0; }
.chain-detail { color: var(--dt-muted); font-size: 12px; overflow-wrap: anywhere; }
.chain-progress .ant-alert, .chain-progress .ant-btn { margin-top: 10px; }
</style>
