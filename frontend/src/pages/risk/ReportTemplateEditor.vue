<template>
  <div class="template-editor">
    <a-alert type="info" show-icon :message="translate('ui.m_52bca129fc8d')" />
    <a-form layout="vertical" class="report-fields">
      <a-row :gutter="16">
        <a-col :span="12" v-for="field in reportFields" :key="field.key">
          <a-form-item :label="field.label"><a-input v-model:value="data.report[field.key]" /></a-form-item>
        </a-col>
      </a-row>
      <a-form-item :label="translate('ui.m_433620cb3b06')"><a-textarea v-model:value="data.report.summary" :auto-size="{ minRows: 2 }" /></a-form-item>
    </a-form>
    <a-collapse :default-active-key="data.findings.map(f => f.finding_id)">
      <a-collapse-panel v-for="(finding, fi) in data.findings" :key="finding.finding_id" :header="`${fi + 1}. ${finding.vuln_type || translate('ui.m_978074e2b1b9')}`">
        <a-form layout="vertical">
          <a-row :gutter="16">
            <a-col :span="12">
              <a-form-item :label="translate('ui.m_58c48802553a')"><a-select :value="String(finding.severity || '')" :options="severityOptions" @change="(value: string) => setSeverity(finding, value)" /></a-form-item>
            </a-col>
            <a-col :span="12" v-for="field in shortFields" :key="field.key">
              <a-form-item :label="field.label"><a-input :value="String(finding[field.key] ?? '')" @update:value="finding[field.key] = $event" /></a-form-item>
            </a-col>
          </a-row>
          <a-form-item v-for="field in longFields" :key="field.key" :label="field.label">
            <a-textarea :value="String(finding[field.key] ?? '')" @update:value="finding[field.key] = $event" :auto-size="{ minRows: 2, maxRows: 16 }" />
          </a-form-item>
        </a-form>
        <h3>{{ translate('ui.m_ce3597f37f12') }}</h3>
        <div v-for="(step, si) in finding.reproduction_steps" :key="si" class="step-editor">
          <div class="step-label">{{ translate('ui.m_4ec7d4554df9') }} {{ si + 1 }} <a-button size="small" type="link" danger @click="removeStep(finding, si)">{{ translate('ui.m_979fcfe25ff4') }}</a-button></div>
          <a-textarea v-model:value="step.text" :auto-size="{ minRows: 2 }" :placeholder="translate('ui.m_f83c4877ecc3')" />
        </div>
        <a-button @click="finding.reproduction_steps.push({ text: '' })">{{ translate('ui.m_f2ee4d080167') }}</a-button>
        <h3>{{ translate('ui.m_ebc711ca0c3c') }}</h3>
        <a-space wrap>
          <a-upload :show-upload-list="false" accept="image/png,image/jpeg,image/webp,image/gif" :before-upload="(file: File) => upload(finding, file)">
            <a-button :loading="uploading === finding.finding_id">{{ translate('ui.m_3495f2cca5ab') }}</a-button>
          </a-upload>
          <a-button @click="importShots(finding)">{{ translate('ui.m_62e293a7bd61') }}</a-button>
          <span class="help">{{ translate('ui.m_617ecd19d49a') }}</span>
        </a-space>
        <div v-if="!finding.screenshots.length" class="help">{{ translate('ui.m_9d8b248f8644') }}</div>
        <div v-for="(shot, index) in finding.screenshots" :key="shot.name" class="shot-editor">
          <a :href="shotUrl(finding, shot)" target="_blank" rel="noopener"><img :src="shotUrl(finding, shot)" alt="证据截图" /></a>
          <div class="shot-controls">
            <a-input v-model:value="shot.caption" :placeholder="translate('ui.m_5306d50c58f8')" />
            <a-space wrap>
              <a-select v-model:value="shot.section" style="width:160px" :options="sections" />
              <a-input-number v-model:value="shot.width_percent" :min="10" :max="100" :placeholder="'100'" :addon-before="translate('ui.m_9d9a54a0e090')" />
              <a-input-number v-if="shot.section === 'steps'" v-model:value="shot.step" :min="1" :max="Math.max(1, finding.reproduction_steps.length)" :addon-before="translate('ui.m_4ec7d4554df9')" />
              <a-button size="small" :disabled="index === 0" @click="move(finding, index, -1)">{{ translate('ui.m_f853a70b1204') }}</a-button>
              <a-button size="small" :disabled="index === finding.screenshots.length - 1" @click="move(finding, index, 1)">{{ translate('ui.m_e75e8b4e5c97') }}</a-button>
              <a-button size="small" @click="annotating = { finding, shot }">{{ translate('ui.m_2d407f17c6df') }}</a-button>
              <a-button size="small" danger @click="finding.screenshots.splice(index, 1)">{{ translate('ui.m_493b5d3e95a6') }}</a-button>
            </a-space>
          </div>
        </div>
      </a-collapse-panel>
    </a-collapse>
    <EvidenceAnnotator v-if="annotating" :src="shotUrl(annotating.finding, annotating.shot)" :saving="annotationSaving"
      @cancel="annotating = null" @save="saveAnnotation" />
  </div>
</template>

<script setup lang="ts">
import { t as translate } from '../../i18n'

import { ref } from 'vue'
import { message } from 'ant-design-vue'
import { findingShotApi, type ReportData, type ReportFindingData, type ReportScreenshot } from '../../api/intel'
import EvidenceAnnotator from './EvidenceAnnotator.vue'
defineProps<{ data: ReportData }>()
const uploading = ref('')
const annotating = ref<{ finding: ReportFindingData; shot: ReportScreenshot } | null>(null)
const annotationSaving = ref(false)
async function saveAnnotation(file: File) {
  const target = annotating.value
  if (!target) return
  annotationSaving.value = true
  try {
    const result = await findingShotApi.upload(target.finding.finding_id, file)
    target.shot.name = String(result.name)
    annotating.value = null
    message.success(translate('ui.m_e5e777160740'))
  } catch (e) { message.error((e as Error).message || translate('ui.m_df8f4028c446')) }
  finally { annotationSaving.value = false }
}
const reportFields = [{ key: 'unit', get label() { return translate('ui.m_59dca28a1dd0') } }, { key: 'system_name', get label() { return translate('ui.m_ba21e862e3bd') } }, { key: 'period', get label() { return translate('ui.m_4b5e3139311d') } }]
const shortFields = [
  { key: 'vuln_type', get label() { return translate('ui.m_5600494fad70') } }, { key: 'cvss_score', get label() { return translate('ui.m_47aead3dfc67') } },
  { key: 'target', get label() { return translate('ui.m_092cb725c713') } }, { key: 'affected_ip', get label() { return translate('ui.m_8f79dae69a8c') } },
  { key: 'discovered_at', get label() { return translate('ui.m_18560650321c') } }, { key: 'version', get label() { return translate('ui.m_2da3906a24ee') } },
  { key: 'test_environment', get label() { return translate('ui.m_d1992adbd980') } }, { key: 'verification_status', get label() { return translate('ui.m_6a2176d9e5d9') } },
]
const longFields = [
  { key: 'discovery_context', get label() { return translate('ui.m_b7676e52a40a') } }, { key: 'affected_users', get label() { return translate('ui.m_e080cda6d39b') } },
  { key: 'affected_data', get label() { return translate('ui.m_d7b320eed35a') } }, { key: 'quantification', get label() { return translate('ui.m_289824cdbfc6') } },
  { key: 'trigger_path', get label() { return translate('ui.m_eb5f3abe2fb3') } }, { key: 'root_cause', get label() { return translate('ui.m_1efd16c515ee') } },
  { key: 'impact', get label() { return translate('ui.m_637254217d9a') } }, { key: 'verify_method', get label() { return translate('ui.m_13e2802d34d2') } },
  { key: 'poc', get label() { return translate('ui.m_4c796c4a154b') } }, { key: 'evidence', get label() { return translate('ui.m_090001170311') } },
  { key: 'remediation', get label() { return translate('ui.m_324227697bfc') } }, { key: 'hardening', get label() { return translate('ui.m_431c0c30a4e6') } },
  { key: 'fix_validation', get label() { return translate('ui.m_08d08f966d1e') } }, { key: 'notes', get label() { return translate('ui.m_daede9881787') } },
]
const sections = [{ value: 'icp', get label() { return translate('ui.m_946c53b99f1e') } }, { value: 'steps', get label() { return translate('ui.m_82555f649ba4') } }, { value: 'evidence', get label() { return translate('ui.m_63bc7bcf0453') } }]
const severityOptions = [{ value: 'critical', get label() { return translate('ui.m_73eb0e14e307') } }, { value: 'high', get label() { return translate('ui.m_4aa71c570566') } }, { value: 'medium', get label() { return translate('ui.m_36a7c77b623b') } }, { value: 'low', get label() { return translate('ui.m_27a7f42a0afb') } }, { value: 'info', get label() { return translate('ui.m_e7028601e7da') } }]
function setSeverity(f: ReportFindingData, value: string) { f.severity = value; f.severity_cn = severityOptions.find(o => o.value === value)?.label || value }
function shotUrl(f: ReportFindingData, shot: ReportScreenshot) { return `/api/image/finding_${encodeURIComponent(f.finding_id)}/${encodeURIComponent(shot.name)}` }
function append(f: ReportFindingData, name: string) {
  if (!f.screenshots.some(s => s.name === name)) f.screenshots.push({ name, caption: '', section: 'evidence', step: 1 })
}
function upload(f: ReportFindingData, file: File) {
  uploading.value = f.finding_id
  findingShotApi.upload(f.finding_id, file).then(result => { append(f, String(result.name)); message.success(translate('ui.m_39c43dd507e3')) })
    .catch(e => message.error(e.message || translate('ui.m_8417fca8bc09'))).finally(() => { uploading.value = '' })
  return false
}
async function importShots(f: ReportFindingData) {
  try { const result = await findingShotApi.list(f.finding_id); result.shots.forEach(s => append(f, s.name)) }
  catch (e) { message.error((e as Error).message || translate('ui.m_d8e74014939a')) }
}
function move(f: ReportFindingData, i: number, delta: number) { const [shot] = f.screenshots.splice(i, 1); f.screenshots.splice(i + delta, 0, shot) }
function removeStep(f: ReportFindingData, i: number) {
  f.reproduction_steps.splice(i, 1)
  for (const shot of f.screenshots) {
    if (shot.section !== 'steps') continue
    if (shot.step === i + 1) { shot.section = 'evidence'; shot.step = 1 }
    else if (shot.step > i + 1) shot.step--
  }
}
</script>

<style scoped>
.report-fields { margin-top: 16px; }
.step-editor { margin: 12px 0; }
.step-label { margin-bottom: 6px; }
.shot-editor { display: flex; gap: 16px; padding: 14px 0; border-bottom: 1px solid var(--dt-border, #ddd); }
.shot-editor img { width: 180px; height: 120px; object-fit: contain; background: #fff; }
.shot-controls { display: flex; flex: 1; min-width: 0; flex-direction: column; gap: 10px; }
.help { color: #888; padding: 8px 0; font-size: 12px; }
h3 { margin-top: 24px; }
</style>
