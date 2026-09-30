<template>
  <div class="template-editor">
    <a-alert type="info" show-icon message="按原模板保存字段、复现步骤和截图；保存后重新生成 Word。截图移除只影响本报告。" />
    <a-form layout="vertical" class="report-fields">
      <a-row :gutter="16">
        <a-col :span="12" v-for="field in reportFields" :key="field.key">
          <a-form-item :label="field.label"><a-input v-model:value="data.report[field.key]" /></a-form-item>
        </a-col>
      </a-row>
      <a-form-item label="报告概述"><a-textarea v-model:value="data.report.summary" :auto-size="{ minRows: 2 }" /></a-form-item>
    </a-form>
    <a-collapse :default-active-key="data.findings.map(f => f.finding_id)">
      <a-collapse-panel v-for="(finding, fi) in data.findings" :key="finding.finding_id" :header="`${fi + 1}. ${finding.vuln_type || '漏洞详情'}`">
        <a-form layout="vertical">
          <a-row :gutter="16">
            <a-col :span="12">
              <a-form-item label="漏洞等级"><a-select :value="String(finding.severity || '')" :options="severityOptions" @change="(value: string) => setSeverity(finding, value)" /></a-form-item>
            </a-col>
            <a-col :span="12" v-for="field in shortFields" :key="field.key">
              <a-form-item :label="field.label"><a-input :value="String(finding[field.key] ?? '')" @update:value="finding[field.key] = $event" /></a-form-item>
            </a-col>
          </a-row>
          <a-form-item v-for="field in longFields" :key="field.key" :label="field.label">
            <a-textarea :value="String(finding[field.key] ?? '')" @update:value="finding[field.key] = $event" :auto-size="{ minRows: 2, maxRows: 16 }" />
          </a-form-item>
        </a-form>
        <h3>复现步骤</h3>
        <div v-for="(step, si) in finding.reproduction_steps" :key="si" class="step-editor">
          <div class="step-label">步骤 {{ si + 1 }} <a-button size="small" type="link" danger @click="removeStep(finding, si)">移除步骤</a-button></div>
          <a-textarea v-model:value="step.text" :auto-size="{ minRows: 2 }" placeholder="填写该步骤的操作与观察结果" />
        </div>
        <a-button @click="finding.reproduction_steps.push({ text: '' })">添加步骤</a-button>
        <h3>截图编排</h3>
        <a-space wrap>
          <a-upload :show-upload-list="false" accept="image/png,image/jpeg,image/webp,image/gif" :before-upload="(file: File) => upload(finding, file)">
            <a-button :loading="uploading === finding.finding_id">上传截图</a-button>
          </a-upload>
          <a-button @click="importShots(finding)">添加已有漏洞截图</a-button>
          <span class="help">长截图导出时自动分段；按当前位置和列表顺序插入。</span>
        </a-space>
        <div v-if="!finding.screenshots.length" class="help">暂无截图，导出不会生成虚假证据。</div>
        <div v-for="(shot, index) in finding.screenshots" :key="shot.name" class="shot-editor">
          <a :href="shotUrl(finding, shot)" target="_blank" rel="noopener"><img :src="shotUrl(finding, shot)" alt="证据截图" /></a>
          <div class="shot-controls">
            <a-input v-model:value="shot.caption" placeholder="截图说明，例如响应返回了哪项关键数据" />
            <a-space wrap>
              <a-select v-model:value="shot.section" style="width:160px" :options="sections" />
              <a-input-number v-model:value="shot.width_percent" :min="10" :max="100" :placeholder="'100'" addon-before="宽度 %" />
              <a-input-number v-if="shot.section === 'steps'" v-model:value="shot.step" :min="1" :max="Math.max(1, finding.reproduction_steps.length)" addon-before="步骤" />
              <a-button size="small" :disabled="index === 0" @click="move(finding, index, -1)">上移</a-button>
              <a-button size="small" :disabled="index === finding.screenshots.length - 1" @click="move(finding, index, 1)">下移</a-button>
              <a-button size="small" @click="annotating = { finding, shot }">标注 / 脱敏</a-button>
              <a-button size="small" danger @click="finding.screenshots.splice(index, 1)">从报告移除</a-button>
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
    message.success('标注副本已生成，保存报告后生效；原图保留')
  } catch (e) { message.error((e as Error).message || '标注保存失败') }
  finally { annotationSaving.value = false }
}
const reportFields = [{ key: 'unit', label: '涉及单位全称' }, { key: 'system_name', label: '平台 / 系统名称' }, { key: 'period', label: '报告日期' }]
const shortFields = [
  { key: 'vuln_type', label: '漏洞类型' }, { key: 'cvss_score', label: 'CVSS 评分' },
  { key: 'target', label: '访问地址' }, { key: 'affected_ip', label: '受影响 IP' },
  { key: 'discovered_at', label: '漏洞发现时间' }, { key: 'version', label: '版本信息' },
  { key: 'test_environment', label: '测试环境' }, { key: 'verification_status', label: '验证状态' },
]
const longFields = [
  { key: 'discovery_context', label: '事件发现场景' }, { key: 'affected_users', label: '受影响用户类型' },
  { key: 'affected_data', label: '受影响数据类型' }, { key: 'quantification', label: '事件量化信息' },
  { key: 'trigger_path', label: '漏洞触发路径' }, { key: 'root_cause', label: '漏洞产生原因' },
  { key: 'impact', label: '事件影响范围' }, { key: 'verify_method', label: '复现条件与说明' },
  { key: 'poc', label: '请求 / POC 原文' }, { key: 'evidence', label: '关键响应与证据原文' },
  { key: 'remediation', label: '紧急修复建议' }, { key: 'hardening', label: '长期加固方案' },
  { key: 'fix_validation', label: '修复验证建议' }, { key: 'notes', label: '备注' },
]
const sections = [{ value: 'icp', label: '单位 / ICP 归属证明' }, { value: 'steps', label: '对应复现步骤' }, { value: 'evidence', label: '证据材料' }]
const severityOptions = [{ value: 'critical', label: '严重' }, { value: 'high', label: '高危' }, { value: 'medium', label: '中危' }, { value: 'low', label: '低危' }, { value: 'info', label: '信息' }]
function setSeverity(f: ReportFindingData, value: string) { f.severity = value; f.severity_cn = severityOptions.find(o => o.value === value)?.label || value }
function shotUrl(f: ReportFindingData, shot: ReportScreenshot) { return `/api/image/finding_${encodeURIComponent(f.finding_id)}/${encodeURIComponent(shot.name)}` }
function append(f: ReportFindingData, name: string) {
  if (!f.screenshots.some(s => s.name === name)) f.screenshots.push({ name, caption: '', section: 'evidence', step: 1 })
}
function upload(f: ReportFindingData, file: File) {
  uploading.value = f.finding_id
  findingShotApi.upload(f.finding_id, file).then(result => { append(f, String(result.name)); message.success('截图已添加，保存报告后生效') })
    .catch(e => message.error(e.message || '截图上传失败')).finally(() => { uploading.value = '' })
  return false
}
async function importShots(f: ReportFindingData) {
  try { const result = await findingShotApi.list(f.finding_id); result.shots.forEach(s => append(f, s.name)) }
  catch (e) { message.error((e as Error).message || '读取截图失败') }
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
