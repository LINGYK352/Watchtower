<template>
  <a-button size="small" @click="open = true">AI 辅助完善</a-button>
  <a-modal v-model:open="open" title="AI 辅助完善报告" width="980px" :footer="null">
    <a-alert type="info" show-icon message="使用模板学习模型，依据当前报告文字提出建议；不会自动保存，也不改变原始请求、截图和验证状态。" />
    <a-form layout="vertical" style="margin-top:16px">
      <a-form-item label="辅助要求"><a-textarea v-model:value="instruction" :auto-size="{ minRows: 2, maxRows: 5 }" placeholder="例如：用人工报告的表达方式整理原因、影响和修复建议，保留所有证据边界" :maxlength="4000" /></a-form-item>
      <a-space wrap>
        <a-select v-model:value="providerId" :options="providers" allow-clear placeholder="跟随模板学习模型" style="width:260px" />
        <a-checkbox v-model:checked="onlyEmpty">只补充空字段</a-checkbox>
        <a-button type="primary" :loading="loading" @click="generate">生成修改建议</a-button>
      </a-space>
    </a-form>
    <template v-if="result">
      <p>模型：{{ result.provider_name }} · {{ result.changes.length }} 条建议</p>
      <a-alert v-for="(warning, i) in result.warnings" :key="i" type="warning" :message="warning" style="margin-bottom:8px" />
      <a-empty v-if="!result.changes.length" description="暂无可应用的建议；可补充证据，或取消“只补充空字段”后重试" />
      <div class="suggestions">
        <div v-for="(change, i) in result.changes" :key="i" class="suggestion">
          <a-checkbox v-model:checked="selected[i]">{{ fieldLabels[change.field] || change.field }}<span v-if="change.field === 'step_text'"> {{ change.step_index + 1 }}</span></a-checkbox>
          <div class="comparison"><section><b>当前内容</b><pre>{{ change.before || '（空）' }}</pre></section><section><b>建议内容</b><pre>{{ change.after }}</pre></section></div>
          <p class="reason">{{ change.reason }}</p>
          <details><summary>查看原文依据 · {{ change.source_field }}</summary><pre>{{ change.source_quote }}</pre></details>
        </div>
      </div>
      <a-button type="primary" style="margin-top:14px" :disabled="!selected.some(Boolean) || loading" @click="apply">应用所选建议到草稿</a-button>
      <span class="hint">应用后仍需保存报告，才会更新导出文件。</span>
    </template>
  </a-modal>
</template>

<script setup lang="ts">
import { ref } from 'vue'
import { message } from 'ant-design-vue'
import { intelApi, type ReportData, type ReportAiResult } from '../../api/intel'
const props = defineProps<{ reportId: string; data: ReportData; providers: { label: string; value: string }[] }>()
const open = ref(false), loading = ref(false), onlyEmpty = ref(true)
const providerId = ref<string>()
const instruction = ref('依据现有证据，按人工 NCC 报告的写法完善事件背景、原因、影响和修复建议；缺乏证据的内容请指出，不要编造。')
const result = ref<ReportAiResult | null>(null)
const selected = ref<boolean[]>([])
const fieldLabels: Record<string, string> = { discovery_context: '事件发现场景', affected_users: '受影响用户', affected_data: '受影响数据', quantification: '事件量化信息', trigger_path: '触发路径', root_cause: '产生原因', impact: '影响范围', verify_method: '复现条件', remediation: '紧急修复建议', hardening: '长期加固', fix_validation: '修复验证建议', notes: '备注', step_text: '复现步骤' }
async function generate() {
  loading.value = true; result.value = null; selected.value = []
  try {
    result.value = await intelApi.assistPentestReport(props.reportId, { report_data: props.data, instruction: instruction.value, provider_id: providerId.value, only_empty: onlyEmpty.value })
    selected.value = result.value.changes.map(() => true)
  } catch (e) { message.error((e as Error).message || 'AI 辅助失败，草稿未改变') }
  finally { loading.value = false }
}
function apply() {
  let applied = 0, stale = 0
  result.value?.changes.forEach((change, i) => {
    if (!selected.value[i] || !Object.prototype.hasOwnProperty.call(fieldLabels, change.field)) return
    const finding = props.data.findings.find(f => f.finding_id === change.finding_id)
    if (!finding) { stale++; return }
    if (change.field === 'step_text') {
      const step = finding.reproduction_steps[change.step_index]
      if (!step || step.text !== change.before) { stale++; return }
      step.text = change.after
    } else {
      if (String(finding[change.field] ?? '') !== String(change.before ?? '')) { stale++; return }
      finding[change.field] = change.after
    }
    applied++
  })
  if (applied) { message.success(`已应用 ${applied} 条建议，请保存报告`); open.value = false; result.value = null }
  if (stale) message.warning(`${stale} 条建议的原文已变化，未覆盖当前修改`)
}
</script>

<style scoped>
.suggestions { max-height: 48vh; overflow: auto; }
.suggestion { border-bottom: 1px solid #ddd; padding: 12px 0; }
.comparison { display: grid; grid-template-columns: 1fr 1fr; gap: 18px; margin-top: 10px; }
pre { white-space: pre-wrap; overflow-wrap: anywhere; font-family: inherit; margin: 6px 0; }
.reason, .hint { color: #777; font-size: 12px; }
.hint { margin-left: 12px; }
</style>
