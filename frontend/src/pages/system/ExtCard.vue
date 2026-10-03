<template>
  <div class="ext-card">
    <div class="c-head">
      <code class="c-name">{{ ext.name || ext.extension_id }}</code>
      <a-tag :color="ext.available ? 'green' : 'red'" size="small">{{ ext.available ? translate('ui.m_e1ba8151b252') : ext.unavailable_reason || translate('ui.m_460b3574e4bd') }}</a-tag>
    </div>
    <div class="c-cat">
      <a-tag color="blue" size="small">{{ ext.category }}</a-tag>
      <span class="muted">v{{ ext.version }}</span>
      <a-tag :color="ext.source === 'store' ? 'gold' : 'default'" size="small">{{ ext.source === 'store' ? translate('ui.m_61f96c6aac6a') : translate('ui.m_bf4ad761840f') }}</a-tag>
      <a-tag :color="ext.origin === 'third_party' ? 'orange' : 'cyan'" size="small">{{ ext.origin === 'third_party' ? translate('ui.m_376cbd8cfc85') : translate('ui.m_4e88cd310f2c') }}</a-tag>
      <a-tag v-if="ext.ext_type === 'both'" color="purple" size="small">{{ translate('ui.m_4e7009404af9') }}</a-tag>
    </div>
    <div class="c-sum">{{ ext.summary || ext.description }}</div>
    <div v-if="params.length" class="c-params">
      <span class="c-params-label">{{ translate('ui.m_9634fb0832be') }}</span>
      <span v-for="p in params" :key="p.name" class="param">{{ p.name }}<i v-if="p.required">*</i></span>
    </div>
    <div class="c-actions">
      <a-space size="small">
        <a @click="$emit('detail', ext)">{{ translate('ui.m_979a332955c8') }}</a>
        <a @click="$emit('check', ext)">{{ translate('ui.m_071089398bfd') }}</a>
        <a-popconfirm :title="translate('ui.m_ee8441ca0919')" @confirm="$emit('remove', ext)"><a class="danger">{{ translate('ui.m_2f9daa828907') }}</a></a-popconfirm>
      </a-space>
      <span class="c-switch">
        <span class="s-label">{{ ext.enabled ? translate('ui.m_dfb802238b38') : translate('ui.m_a8c3698b5b8c') }}</span>
        <a-switch size="small" :checked="ext.enabled"
          :disabled="!ext.available || ext.side_effect === 'dangerous'"
          @change="(v: boolean) => $emit('toggle', ext, v)" />
      </span>
    </div>
    <div v-if="ext.side_effect === 'dangerous'" class="c-danger">{{ translate('ui.m_5110ffe55072') }}</div>
  </div>
</template>
<script setup lang="ts">
import { t as translate } from '../../i18n'

import { computed } from 'vue'
import type { ExtensionItem, ExtParam } from '../../api/aiExtension'

const props = defineProps<{ ext: ExtensionItem }>()
defineEmits<{ (e: 'toggle', ext: ExtensionItem, v: boolean): void; (e: 'detail', ext: ExtensionItem): void
  (e: 'remove', ext: ExtensionItem): void; (e: 'check', ext: ExtensionItem): void }>()

// params 优先用后端已解析的 params；否则从 parameters schema 现场解析
const params = computed<ExtParam[]>(() => {
  if (props.ext.params && props.ext.params.length) return props.ext.params
  const schema = props.ext.parameters
  if (!schema || !schema.properties) return []
  const req = schema.required || []
  return Object.entries(schema.properties).map(([name, item]) => ({
    name, desc: item?.description || '', required: req.includes(name)
  }))
})
</script>
<style scoped>
.ext-card { border: 1px solid var(--dt-border, #f0f0f0); border-radius: 8px; padding: 12px 14px; display: flex; flex-direction: column; gap: 6px; background: var(--dt-card-bg, #fff); }
.c-head { display: flex; align-items: center; justify-content: space-between; gap: 8px; }
.c-name { font-weight: 600; color: #1677ff; font-size: 13px; word-break: break-all; }
.c-cat { display: flex; align-items: center; gap: 8px; }
.c-sum { font-size: 12px; line-height: 1.6; color: var(--dt-text, #333); min-height: 32px; }
/* BUG-016 + 复发修复(2026-08-20)：参数多(http_request 11参数)或单个参数名过长时，
   旧版 .param{white-space:nowrap}+overflow:hidden 会把长参数名裁切掉(文字看着"溢出/缺字")。
   改 chip 样式 + break-all，长名整齐换行不裁切，与 SystemExtension 内置卡口径统一。 */
.c-params { font-size: 12px; color: var(--dt-muted, #888); display: flex; flex-wrap: wrap; align-items: center; gap: 6px; min-width: 0; }
.c-params-label { flex: 0 0 auto; color: var(--dt-muted, #888); }
.c-params .param { display: inline-flex; align-items: center; max-width: 100%;
  padding: 1px 7px; background: var(--dt-fill, #f0f2f5); border-radius: 4px;
  font-family: ui-monospace, Menlo, Consolas, monospace; font-size: 11px; color: var(--dt-text, #555);
  word-break: break-all; overflow-wrap: anywhere; }
.c-params .param i { color: #ff4d4f; font-style: normal; }
.c-actions { display: flex; align-items: center; justify-content: space-between; margin-top: 4px; padding-top: 8px; border-top: 1px dashed var(--dt-border, #f0f0f0); }
.c-switch { display: flex; align-items: center; gap: 6px; }
.s-label { font-size: 12px; color: var(--dt-muted, #888); }
.danger { color: #ff4d4f; }
.muted { color: var(--dt-muted, #888); font-size: 12px; }
.c-danger { font-size: 11px; color: #ff4d4f; }
</style>
