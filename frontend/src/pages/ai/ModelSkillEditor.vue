<template>
 <a-modal :open="open" :title="t('modelSkill.edit')" :width="900" :footer="null" :mask-closable="!busy" :keyboard="!busy" @cancel="close">
  <a-alert v-if="error" type="error" :message="error" show-icon style="margin-bottom:16px" />
  <a-alert type="info" :message="t('modelSkill.scope')" show-icon style="margin-bottom:16px" />
  <a-spin :spinning="loading"><div class="skill-editor" data-testid="model-skill-editor">
   <a-form layout="vertical">
    <a-form-item :label="t('modelSkill.modelName')" required><a-select v-model:value="selectedId" :options="modelOptions" :disabled="busy||!!provider" show-search option-filter-prop="label" :placeholder="t('revision17.chooseModel')" data-testid="skill-model-select" /></a-form-item>
    <a-form-item :label="t('revision17.stages')" required><a-select v-model:value="boundStages" mode="multiple" :options="stages" :disabled="busy||!selectedId" :placeholder="t('revision17.chooseStages')" data-testid="skill-stages-select" /></a-form-item>
    <a-upload :before-upload="upload" :show-upload-list="false" accept=".zip,.md,.txt"><a-button :loading="uploading" :disabled="busy||loading||!selectedId" data-testid="model-skill-upload">{{ t('modelSkill.upload') }}</a-button></a-upload>
    <p class="skill-note">{{ t('modelSkill.uploadNote') }}</p>
    <a-form-item :label="t('modelSkill.entry')" required><a-select v-model:value="entry" :disabled="!files.length||busy" :options="entries" show-search option-filter-prop="label" data-testid="model-skill-entry" /></a-form-item>
   </a-form>
   <div class="skill-files"><div v-for="file in files" :key="file.path"><code>{{ file.path }}</code><span>{{ (file.bytes/1024).toFixed(1) }} KiB · {{ file.text?t('modelSkill.text'):t('modelSkill.asset') }}</span></div></div>
   <pre v-if="preview" class="skill-preview" data-testid="model-skill-preview">{{ preview }}</pre>
   <div class="skill-actions"><a-button :disabled="busy" @click="close">{{ t('ui.m_120e7cea1231') }}</a-button><a-button type="primary" :loading="saving" :disabled="!selectedId||!entry||!boundStages.length||uploading||loading" @click="requestSave" data-testid="model-skill-save">{{ t('ui.m_bcc5da2cf6c1') }}</a-button></div>
  </div></a-spin>
 </a-modal>
 <a-modal :open="guardWarning" :title="t('revision17.guardTitle')" centered :width="520" :confirm-loading="saving" :ok-text="t('revision17.confirmGuard')" :ok-button-props="{danger:true}" @cancel="guardWarning=false" @ok="save(true)" data-testid="guard-skill-warning"><a-alert type="warning" show-icon :message="t('revision17.guardWarning')" /></a-modal>
</template>
<script setup lang="ts">
import {ref,computed,watch} from 'vue'
import {message} from 'ant-design-vue'
import {t} from '../../i18n'
import {aiConfigApi,type AIProvider,type ModelSkillView} from '../../api/aiConfig'
const props=defineProps<{open:boolean;provider:AIProvider|null;providers:AIProvider[];stages:{value:string;label:string}[]}>(),emit=defineEmits(['close','saved'])
const selectedId=ref(''),boundStages=ref<string[]>([]),guardWarning=ref(false),loading=ref(false),uploading=ref(false),saving=ref(false),error=ref(''),draftId=ref(''),entry=ref(''),revision=ref(0),files=ref<ModelSkillView['files']>([]),preview=ref('')
const busy=computed(()=>uploading.value||saving.value),entries=computed(()=>files.value.filter(f=>f.text).map(f=>({value:f.path,label:f.path})))
const modelOptions=computed(()=>props.providers.filter(p=>!p.exclusive_skill||p._id===props.provider?._id).map(p=>({value:p._id,label:p.name})))
let generation=0
function close(){if(!busy.value){generation++;guardWarning.value=false;emit('close')}}
watch(()=>[props.open,props.provider?._id],()=>{selectedId.value=props.open?(props.provider?._id||''):'';guardWarning.value=false;void load()}, {immediate:true})
watch(selectedId,load)
async function load(){
 const g=++generation;error.value='';draftId.value='';entry.value='';boundStages.value=[];files.value=[];preview.value='';revision.value=0;loading.value=false
 if(!props.open||!selectedId.value)return
 loading.value=true
 try{const data=await aiConfigApi.modelSkill(selectedId.value);if(g!==generation)return;files.value=data.files||[];entry.value=data.entry||'';boundStages.value=data.stages||[];revision.value=data.revision;preview.value=data.entry_preview?.content||''}catch(e){if(g===generation)error.value=(e as Error).message}finally{if(g===generation)loading.value=false}
}
function upload(file:File){
 if(!selectedId.value||busy.value)return false
 if(file.size>20*1024*1024-65536){error.value=t('modelSkill.tooLarge');return false}
 const g=generation,id=selectedId.value;uploading.value=true;error.value=''
 aiConfigApi.uploadModelSkill(id,file).then(data=>{if(g!==generation)return;draftId.value=data.draft_id||'';revision.value=data.revision;files.value=data.files||[];preview.value='';entry.value=data.files.find(f=>f.text&&f.path==='SKILL.md')?.path||(data.files.filter(f=>f.text).length===1?data.files.find(f=>f.text)!.path:'')}).catch(e=>{if(g===generation)error.value=(e as Error).message}).finally(()=>{uploading.value=false})
 return false
}
function requestSave(){if(boundStages.value.some(stage=>stage.startsWith('guard')))guardWarning.value=true;else void save(false)}
async function save(confirmed:boolean){if(!selectedId.value||!entry.value||!boundStages.value.length||busy.value)return;saving.value=true;error.value='';try{await aiConfigApi.saveModelSkill(selectedId.value,{draft_id:draftId.value||undefined,entry:entry.value,revision:revision.value,stages:boundStages.value,guard_confirmed:confirmed});guardWarning.value=false;message.success(t('ui.m_514df589127f'));emit('saved');emit('close')}catch(e){guardWarning.value=false;error.value=(e as Error).message}finally{saving.value=false}}
</script>
<style scoped>
.skill-note{color:var(--dt-muted);font-size:12px;line-height:1.8}.skill-files{max-height:220px;overflow:auto;border:1px solid var(--dt-border);border-radius:8px;padding:10px 14px}.skill-files>div{display:flex;flex-wrap:wrap;justify-content:space-between;gap:6px 16px;padding:6px 0}.skill-files code{overflow-wrap:anywhere;color:var(--dt-text)}.skill-files span{font-size:12px;color:var(--dt-muted)}.skill-preview{white-space:pre-wrap;overflow-wrap:anywhere;max-height:240px;overflow:auto;background:var(--dt-fill);color:var(--dt-text);padding:14px;border-radius:8px;margin-top:16px}.skill-actions{display:flex;justify-content:flex-end;gap:10px;margin-top:20px}
</style>
