<template>
 <div v-if="data" class="shared-preview"><div class="preview-heading"><a-tag>{{ t('team.kinds.'+data.item.kind) }}</a-tag><a-tag v-if="record.severity" :color="severityColor">{{ t('repair128.severities.'+severityKey) }}</a-tag><h3>{{ record.title || record.vuln_type || record.task_name || record.system_name || data.item.title }}</h3></div>
 <a-descriptions bordered :column="1" size="small"><a-descriptions-item v-for="field in fields" :key="field.name" :label="t('repair128.fields.'+field.name)">{{ field.value }}</a-descriptions-item></a-descriptions>
 <section v-for="section in sections" :key="section.name"><h4>{{ t('repair128.fields.'+section.name) }}</h4><pre>{{ section.value }}</pre></section>
 <a-collapse><a-collapse-panel key="complete" :header="t('repair128.completeData')"><pre>{{ JSON.stringify(data.preview,null,2) }}</pre></a-collapse-panel></a-collapse>
 </div>
</template>
<script setup lang="ts">
import {computed} from 'vue'
import {t} from '../i18n'
const props=defineProps<{data:any}>()
const record=computed(()=>props.data?.preview?.session||props.data?.preview||{})
const severityKey=computed(()=>{const key=String(record.value.severity||'').toLowerCase();return ['critical','high','medium','low','info','none'].includes(key)?key:'unknown'})
const severityColor=computed(()=>({critical:'magenta',high:'red',medium:'orange',low:'gold',info:'blue'} as Record<string,string>)[severityKey.value]||'blue')
const fields=computed(()=>['target','url','site','component','vuln_type','status','save_date','session_id','source_session'].filter(name=>record.value[name]).map(name=>({name,value:String(record.value[name])})))
const sections=computed(()=>['description','impact','evidence','request','response','poc','content','summary','reproduce','reproduce_steps'].filter(name=>record.value[name]).map(name=>({name,value:typeof record.value[name]==='string'?record.value[name]:JSON.stringify(record.value[name],null,2)})))
</script>
<style scoped>.shared-preview{max-height:65vh;overflow:auto;padding:2px 8px 8px}.preview-heading{padding:16px;background:var(--dt-fill);border:1px solid var(--dt-border);border-radius:12px;margin-bottom:16px}.preview-heading h3{margin:10px 0 0;overflow-wrap:anywhere}.shared-preview section{margin-top:18px}.shared-preview pre{white-space:pre-wrap;overflow-wrap:anywhere;padding:14px;background:var(--dt-fill);border:1px solid var(--dt-border);border-radius:10px;color:var(--dt-text);max-height:320px;overflow:auto}.shared-preview :deep(.ant-descriptions-item-content){overflow-wrap:anywhere}</style>
