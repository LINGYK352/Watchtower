<!--
  同资产重复渗透确认弹窗：发起/重启任务前，若检测到该资产已有活跃渗透会话或历史报告则弹出。
  - 活跃会话：提示"当前有 N 个会话正在渗透该资产，重复发起会导致资源浪费"，列出会话+距上次时间。
  - 历史报告：提示"该资产曾渗透过，可复用上次报告复验/深入"，列出报告+漏洞数+距今时长。
  用户可【确定发起】（继续任务，同资产新任务会在开局注入上次报告供复验深入）或【取消】。
  best_effort 作用域（大域名/单位）会额外提示"检测为尽力范围，可能不覆盖全部子资产"。
  纯展示组件，检测由父组件调 intelApi.checkOverlap 后把结果传入 :data。
-->
<template>
  <a-modal :open="open" @update:open="(v: boolean) => emit('update:open', v)" :footer="null"
    :width="620" :title="translate('ui.m_2b98f4f90db6')" :mask-closable="false">
    <a-alert type="warning" show-icon style="margin-bottom:14px" :message="data?.summary || translate('ui.m_13145bb2fa23')" />

    <div v-if="data?.scope === 'best_effort'" class="ov-scope">
      {{ translate('ui.m_2baa0c0a5b47') }}<b>{{ translate('ui.m_39ddff1a7da9') }}</b>{{ translate('ui.m_12c28c46caf6') }}
    </div>

    <div v-if="data?.active_sessions?.length" class="ov-sec">
      <div class="ov-title">{{ translate('ui.m_c0a7b200ab3d') }}{{ data.active_sessions.length }}{{ translate('ui.m_637d178667df') }}</div>
      <div v-for="s in data.active_sessions" :key="s.session_id" class="ov-row">
        <a-tag :color="statusColor(s.status)">{{ statusText(s.status) }}</a-tag>
        <span class="ov-site">{{ s.site }}</span>
        <span v-if="s.unit" class="ov-unit">{{ s.unit }}</span>
        <span class="ov-ago">{{ translate('ui.m_41f5cada11ed') }} {{ s.ago }}</span>
      </div>
    </div>

    <div v-if="data?.last_reports?.length" class="ov-sec">
      <div class="ov-title">{{ translate('ui.m_b79899bd0b63') }}{{ data.last_reports.length }}{{ translate('ui.m_f58ad124b9bd') }}</div>
      <div v-for="r in data.last_reports" :key="r.report_id" class="ov-row">
        <a-tag :color="sevColor(r.max_severity)">{{ r.max_severity || '—' }}</a-tag>
        <span class="ov-site">{{ r.site }}</span>
        <span class="ov-vuln">{{ r.vuln_count }} {{ translate('ui.m_1f3ef482e067') }}</span>
        <span class="ov-ago">{{ r.ago }}{{ translate('ui.m_37c00a48482d') }}</span>
      </div>
    </div>

    <div class="ov-actions">
      <a-button @click="onCancel">{{ translate('ui.m_537d17f1c531') }}</a-button>
      <a-button type="primary" danger @click="onConfirm">
        {{ translate('ui.m_10d01f1eeddf') }}
      </a-button>
    </div>
  </a-modal>
</template>

<script setup lang="ts">
import { t as translate } from '../i18n'

import type { OverlapResult } from '../api/intel'

defineProps<{ open: boolean; data: OverlapResult | null }>()
const emit = defineEmits<{
  (e: 'update:open', v: boolean): void
  (e: 'confirm'): void
  (e: 'cancel'): void
}>()

const _S: Record<string, [string, string]> = {
  running: ['渗透中', 'processing'], queued: ['排队中', 'default'], waiting: ['等待中', 'default'],
  dispatching: ['派发中', 'processing'], paused_transient: ['暂停(自恢复)', 'orange'],
  paused_resource: ['暂停(资源)', 'orange'], paused_manual: ['暂停(人工)', 'gold'],
}
function statusText(s: string): string { return _S[s]?.[0] || s }
function statusColor(s: string): string { return _S[s]?.[1] || 'default' }
function sevColor(s: string): string {
  return ({ critical: 'red', high: 'volcano', medium: 'orange', low: 'gold', info: 'blue' } as Record<string, string>)[s] || 'default'
}
function onConfirm() { emit('confirm'); emit('update:open', false) }
function onCancel() { emit('cancel'); emit('update:open', false) }
</script>

<style scoped>
.ov-scope { color: #ad6800; background: #fffbe6; border: 1px solid #ffe58f; border-radius: 6px;
  padding: 6px 10px; font-size: 12px; margin-bottom: 12px; }
.ov-sec { margin-bottom: 14px; }
.ov-title { font-weight: 600; color: #333; margin-bottom: 8px; font-size: 13px; }
.ov-row { display: flex; align-items: center; gap: 10px; padding: 5px 0; font-size: 13px;
  border-bottom: 1px dashed #f0f0f0; }
.ov-site { color: #1677ff; word-break: break-all; }
.ov-unit { color: #666; }
.ov-vuln { color: #cf1322; }
.ov-ago { margin-left: auto; color: #999; font-size: 12px; white-space: nowrap; }
.ov-actions { display: flex; justify-content: flex-end; gap: 12px; margin-top: 18px; }
</style>
