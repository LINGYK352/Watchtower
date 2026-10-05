<template>
  <a-button size="small" @click="open = true">{{ translate('ui.m_02dc8b80e753') }}</a-button>
  <a-modal v-model:open="open" :title="translate('ui.m_efb3639418a0')" width="980px" :footer="null">
    <a-alert type="info" show-icon :message="translate('ui.m_965289c8e00f')" />
    <a-form layout="vertical" style="margin-top:16px">
      <a-form-item :label="translate('ui.m_182e0728f528')"><a-textarea v-model:value="instruction" :auto-size="{ minRows: 2, maxRows: 5 }" :placeholder="translate('ui.m_800d5b06cd46')" :maxlength="4000" /></a-form-item>
      <a-space wrap>
        <a-select v-model:value="providerId" :options="providers" allow-clear :placeholder="translate('ui.m_51f68df1bdda')" style="width:260px" />
        <a-checkbox v-model:checked="onlyEmpty">{{ translate('ui.m_d8c03257a6e6') }}</a-checkbox>
        <a-button type="primary" :loading="loading" @click="generate">{{ translate('ui.m_9c662c1ddd41') }}</a-button>
      </a-space>
    </a-form>
    <template v-if="result">
      <p>{{ translate('ui.m_2a845bd8e225') }}{{ result.provider_name }} · {{ result.changes.length }} {{ translate('ui.m_8d846195b013') }}</p>
      <a-alert v-for="(warning, i) in result.warnings" :key="i" type="warning" :message="warning" style="margin-bottom:8px" />
      <a-empty v-if="!result.changes.length" :description="translate('ui.m_b4f6871b4419')" />
      <div class="suggestions">
        <div v-for="(change, i) in result.changes" :key="i" class="suggestion">
          <a-checkbox v-model:checked="selected[i]">{{ fieldLabels[change.field] || change.field }}<span v-if="change.field === 'step_text'"> {{ change.step_index + 1 }}</span></a-checkbox>
          <div class="comparison"><section><b>{{ translate('ui.m_df492b6fdd3b') }}</b><pre>{{ change.before || translate('ui.m_fa8bc5e925f9') }}</pre></section><section><b>{{ translate('ui.m_4b31e4ef691c') }}</b><pre>{{ change.after }}</pre></section></div>
          <p class="reason">{{ change.reason }}</p>
          <details><summary>{{ translate('ui.m_f974b70f64c1') }} {{ change.source_field }}</summary><pre>{{ change.source_quote }}</pre></details>
        </div>
      </div>
      <a-button type="primary" style="margin-top:14px" :disabled="!selected.some(Boolean) || loading" @click="apply">{{ translate('ui.m_52f1d8e0fe3b') }}</a-button>
      <span class="hint">{{ translate('ui.m_8d01b8c721e4') }}</span>
    </template>
  </a-modal>
</template>

<script setup lang="ts">
import { t as translate } from '../../i18n'

import { ref } from 'vue'
import { message } from 'ant-design-vue'
import { intelApi, type ReportData, type ReportAiResult } from '../../api/intel'
const props = defineProps<{ reportId: string; data: ReportData; providers: { label: string; value: string }[] }>()
const open = ref(false), loading = ref(false), onlyEmpty = ref(true)
const providerId = ref<string>()
const instruction = ref('依据现有证据，按人工 NCC 报告的写法完善事件背景、原因、影响和修复建议；缺乏证据的内容请指出，不要编造。')
const result = ref<ReportAiResult | null>(null)
const selected = ref<boolean[]>([])
const fieldLabels: Record<string, string> = { get discovery_context() { return translate('ui.m_b7676e52a40a') }, get affected_users() { return translate('ui.m_dd29813b94a6') }, get affected_data() { return translate('ui.m_9815e76f2ff4') }, get quantification() { return translate('ui.m_289824cdbfc6') }, get trigger_path() { return translate('ui.m_619e3105afdf') }, get root_cause() { return translate('ui.m_ac4e4e6ed3cc') }, get impact() { return translate('ui.m_3a76ebfb6233') }, get verify_method() { return translate('ui.m_dfa9eef9ba28') }, get remediation() { return translate('ui.m_324227697bfc') }, get hardening() { return translate('ui.m_cc52d8fad9fd') }, get fix_validation() { return translate('ui.m_08d08f966d1e') }, get notes() { return translate('ui.m_daede9881787') }, get step_text() { return translate('ui.m_ce3597f37f12') } }
async function generate() {
  loading.value = true; result.value = null; selected.value = []
  try {
    result.value = await intelApi.assistPentestReport(props.reportId, { report_data: props.data, instruction: instruction.value, provider_id: providerId.value, only_empty: onlyEmpty.value })
    selected.value = result.value.changes.map(() => true)
  } catch (e) { message.error((e as Error).message || translate('ui.m_d76881abfe54')) }
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
  if (applied) { message.success(translate('ui.m_750b18c8ef37', { p0: (applied) })); open.value = false; result.value = null }
  if (stale) message.warning(translate('ui.m_9e51871e4ef3', { p0: (stale) }))
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
