<template>
  <a-modal :open="true" :width="980" :title="translate('reportGenerate.title')" :footer="null" :mask-closable="false" @cancel="!saving && emit('close')">
    <div data-testid="report-source-picker">
      <a-steps :current="step" size="small" class="picker-gap"><a-step :title="translate('reportGenerate.sourceStep')" /><a-step :title="translate('reportGenerate.optionsStep')" /></a-steps>
      <a-alert v-if="error" type="error" show-icon :message="error" class="picker-gap" />
      <template v-if="step === 0">
        <a-radio-group v-if="allowKind" :value="kind" @change="changeKind($event.target.value)" class="picker-gap">
          <a-radio-button v-for="value in kinds" :key="value" :value="value">{{ translate('reportGenerate.' + value) }}</a-radio-button>
        </a-radio-group>
        <a-input-search v-model:value="keyword" :placeholder="translate('reportGenerate.search')" :enter-button="translate('reportGenerate.searchButton')" @search="search" data-testid="report-source-search" />
        <a-spin :spinning="loading">
          <div class="source-list" data-testid="report-source-list">
            <a-empty v-if="!loading && !rows.length" :description="translate('reportGenerate.empty')" />
            <button v-for="row in rows" :key="row.key" type="button" class="source-choice" :class="{ chosen: selected?.key === row.key }" :aria-pressed="selected?.key === row.key" :data-source-id="row.id" :data-source-kind="row.source" @click="selected=row">
              <div class="source-choice-title"><span>{{ row.title }}</span><a-tag v-if="kind === 'finding'">{{ severityLabel(row.severity) }}</a-tag></div>
              <div v-if="row.target" class="source-target">{{ row.target }}</div>
              <div class="source-meta"><span>{{ row.sourceLabel }}</span><span>{{ row.status }}</span><span>{{ row.id }}</span></div>
            </button>
          </div>
        </a-spin>
        <a-pagination :current="page" :page-size="10" :total="total" :show-size-changer="false" size="small" class="source-pagination" @change="load($event)" />
      </template>
      <template v-else>
        <div class="selected-source" data-testid="report-selected-source"><strong>{{ selected?.title }}</strong><p>{{ selected?.target }}</p><span>{{ selected?.sourceLabel }} · {{ selected?.id }}</span></div>
        <a-form layout="vertical" class="picker-options">
          <a-form-item :label="translate('reportGenerate.template')" required><a-select v-model:value="template" :options="templateOptions" :loading="templatesLoading" show-search option-filter-prop="label" data-testid="report-source-template" /></a-form-item>
          <a-form-item :label="translate('reportGenerate.reportTitle')"><a-input v-model:value="title" :maxlength="200" :placeholder="translate('reportGenerate.automatic')" /></a-form-item>
          <a-form-item><a-checkbox v-model:checked="assist">{{ translate('reportGenerate.assist') }}</a-checkbox><p class="source-note">{{ translate('reportGenerate.assistHelp') }}</p></a-form-item>
        </a-form>
      </template>
      <div v-if="step === 0 && selected" class="source-note picker-gap">{{ translate('reportGenerate.selected') }}：{{ selected.title }}</div>
      <div class="picker-actions"><a-space><a-button :disabled="saving" @click="step ? step=0 : emit('close')">{{ translate(step ? 'reportGenerate.back' : 'reportGenerate.cancel') }}</a-button><a-button v-if="step === 0" type="primary" :disabled="!selected || loading" @click="next" data-testid="report-source-next">{{ translate('reportGenerate.next') }}</a-button><a-button v-else type="primary" :loading="saving" :disabled="!template || templatesLoading" @click="generate" data-testid="report-source-generate">{{ translate('reportGenerate.generate') }}</a-button></a-space></div>
    </div>
  </a-modal>
</template>

<script setup lang="ts">
import { computed, onBeforeUnmount, onMounted, ref } from 'vue'
import { message } from 'ant-design-vue'
import { t as translate } from '../../i18n'
import { taskApi } from '../../api/task'
import { pentestApi } from '../../api/pentest'
import { reportTemplateApi } from '../../api/intel'
import { severityLabel } from '../../utils/severity'
import type { RowRecord } from '../../api/types'

type Kind='task'|'session'|'finding'
interface Choice {key:string;id:string;title:string;target:string;source:'ai'|'poc'|'nuclei';sourceLabel:string;status:string;severity:string}
const props=defineProps<{initialKind:Kind;presetTemplate?:string;allowKind?:boolean}>()
const emit=defineEmits<{close:[];generated:[kind:Kind,reportId:string]}>()
const kinds:Kind[]=['task','session','finding'],kind=ref<Kind>(props.initialKind),step=ref(0),keyword=ref(''),page=ref(1),total=ref(0),rows=ref<Choice[]>([]),selected=ref<Choice>()
const loading=ref(false),saving=ref(false),error=ref(''),templatesLoading=ref(false),template=ref(''),title=ref(''),assist=ref(false)
const templates=ref<RowRecord[]>([]),templateOptions=computed(()=>templates.value.map(row=>({value:String(row._id),label:String(row.name || row._id)})))
let epoch=0,disposed=false
onMounted(()=>load(1));onBeforeUnmount(()=>{disposed=true;++epoch})
async function load(number:number){
  const generation=++epoch;page.value=number;loading.value=true;error.value=''
  try{
    let records:RowRecord[],count:number
    if(kind.value==='task'){
      const result=await taskApi.list({name:keyword.value.trim() || undefined,page:number,size:10});records=result.items;count=result.total
    }else if(kind.value==='session'){
      const result=await pentestApi.list({keyword:keyword.value.trim(),page:number,size:10});records=result.items as unknown as RowRecord[];count=result.total
    }else{
      const result=await pentestApi.unifiedList({keyword:keyword.value.trim(),page:number,size:10,min_severity:'info',dedup:'0'});records=result.items as unknown as RowRecord[];count=result.total
    }
    if(disposed || generation!==epoch)return
    rows.value=(records || []).map(row=>{
      const source=row.source==='poc' || row.source==='nuclei'?row.source:'ai'
      return {key:source+':'+String(row._id),id:String(row._id),title:String(kind.value==='finding'?row.name || row.vuln_type || row._id:row.task_name || row.name || row.site || row._id),target:String(row.target || row.site || ''),source,sourceLabel:kind.value==='finding'?translate('reportGenerate.'+(row.origin_category==='group'?'group':source==='ai'?'ai':'kernel')):translate('reportGenerate.'+kind.value),status:String(row.display_status || row.status || ''),severity:String(row.severity || '')}
    });total.value=count || 0
  }catch(cause){if(generation===epoch)error.value=(cause as Error).message}
  finally{if(generation===epoch)loading.value=false}
}
function search(){void load(1)}
function changeKind(value:Kind){kind.value=value;selected.value=undefined;keyword.value='';rows.value=[];void load(1)}
async function next(){
  if(!selected.value)return
  step.value=1;templatesLoading.value=true;error.value=''
  try{
    const result=await reportTemplateApi.list({page:1,size:500,scope:kind.value})
    if(disposed)return
    templates.value=result.items.filter(row=>row.status==='ready')
    const preset=templates.value.find(row=>String(row._id)===props.presetTemplate)
    const builtin=templates.value.find(row=>row.builtin && row.scope===kind.value)
    template.value=String((preset || builtin || templates.value[0])?._id || '')
    if(!template.value)error.value=translate('reportGenerate.noTemplate')
  }catch(cause){error.value=(cause as Error).message}
  finally{templatesLoading.value=false}
}
async function generate(){
  if(!selected.value || !template.value || saving.value)return
  saving.value=true;error.value=''
  try{
    const common={template_id:template.value,options:{ai_assist:assist.value,...(title.value.trim()?{title:title.value.trim()}:{})}}
    const result=await reportTemplateApi.generate(kind.value==='task'?{...common,type:'task',task_id:selected.value.id}:kind.value==='session'?{...common,type:'session',session_id:selected.value.id}:{...common,type:'finding',finding_id:selected.value.id,finding_source:selected.value.source})
    if(result.generation_warnings?.length)message.warning(translate('reportGenerate.withWarnings'))
    else message.success(translate('reportGenerate.success'))
    emit('generated',kind.value,result.report_id);emit('close')
  }catch(cause){error.value=(cause as Error).message}
  finally{saving.value=false}
}
</script>

<style scoped>
.picker-gap{margin-bottom:16px}.source-list{max-height:390px;min-height:180px;overflow:auto;display:flex;flex-direction:column;gap:10px;margin:14px 0}.source-choice{width:100%;text-align:left;background:var(--dt-fill);color:var(--dt-text);border:1px solid var(--dt-border);padding:12px 14px;border-radius:9px;cursor:pointer;transition:background .15s,border-color .15s;flex-shrink:0}.source-choice:hover,.source-choice.chosen{border-color:var(--dt-primary);background:var(--dt-accent-soft)}.source-choice:focus-visible{outline:2px solid var(--dt-primary);outline-offset:-2px}.source-choice-title{display:flex;justify-content:space-between;align-items:start;gap:10px;font-weight:600}.source-choice-title>span{min-width:0;overflow-wrap:anywhere}.source-target{font-size:12px;margin-top:6px;overflow-wrap:anywhere;color:var(--dt-muted)}.source-meta{display:flex;flex-wrap:wrap;gap:12px;font-size:11px;color:var(--dt-muted);margin-top:7px}.source-pagination{text-align:right;margin-bottom:16px}.source-note{font-size:12px;color:var(--dt-muted);overflow-wrap:anywhere}.picker-actions{text-align:right;margin-top:18px}.selected-source{padding:14px;background:var(--dt-fill);border:1px solid var(--dt-border);border-radius:9px;overflow-wrap:anywhere}.selected-source p{margin:8px 0}.selected-source>span{font-size:12px;color:var(--dt-muted)}.picker-options{margin-top:20px}@media(max-width:600px){.source-list{max-height:46vh}.source-choice{padding:10px}.source-meta{gap:7px}.source-choice-title{flex-wrap:wrap}}
</style>
