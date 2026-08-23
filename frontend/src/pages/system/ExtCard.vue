<template>
  <div class="ext-card">
    <div class="c-head">
      <code class="c-name">{{ ext.name || ext.extension_id }}</code>
      <a-tag :color="ext.available ? 'green' : 'red'" size="small">{{ ext.available ? '兼容' : ext.unavailable_reason || '不可用' }}</a-tag>
    </div>
    <div class="c-cat">
      <a-tag color="blue" size="small">{{ ext.category }}</a-tag>
      <span class="muted">v{{ ext.version }}</span>
      <a-tag :color="ext.source === 'store' ? 'gold' : 'default'" size="small">{{ ext.source === 'store' ? '商店' : '本地' }}</a-tag>
    </div>
    <div class="c-sum">{{ ext.summary || ext.description }}</div>
    <div v-if="params.length" class="c-params">
      <span class="c-params-label">参数</span>
      <span v-for="p in params" :key="p.name" class="param">{{ p.name }}<i v-if="p.required">*</i></span>
    </div>
    <div class="c-actions">
      <a-space size="small">
        <a @click="$emit('detail', ext)">详情</a>
        <a @click="$emit('check', ext)">检测</a>
        <a-popconfirm title="删除该扩展所有本地版本？" @confirm="$emit('remove', ext)"><a class="danger">删除</a></a-popconfirm>
      </a-space>
      <span class="c-switch">
        <span class="s-label">{{ ext.enabled ? '已启用' : '已停用' }}</span>
        <a-switch size="small" :checked="ext.enabled"
          :disabled="!ext.available || ext.side_effect === 'dangerous'"
          @change="(v: boolean) => $emit('toggle', ext, v)" />
      </span>
    </div>
    <div v-if="ext.side_effect === 'dangerous'" class="c-danger">高危扩展，不进入自动工具表</div>
  </div>
</template>
<script setup lang="ts">
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
