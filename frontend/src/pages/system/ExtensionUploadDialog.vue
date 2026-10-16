<template>
  <a-modal :open="open" :title="t('extensions.uploadTitle')" :width="820" :footer="null" centered :body-style="{maxHeight:'calc(100dvh - 160px)',overflowY:'auto',paddingRight:'8px'}" :mask-closable="!busy && !codeBusy" :keyboard="!busy && !codeBusy" :closable="!busy && !codeBusy" :destroy-on-close="true" @cancel="close" data-testid="extension-upload-dialog">
    <a-alert v-if="error" type="error" :message="error" show-icon class="page-alert" data-testid="extension-upload-error" />
    <template v-if="!prepared">
      <a-form layout="vertical"><a-form-item :label="t('extensions.uploadTarget')"><a-radio-group v-model:value="target" :disabled="busy" data-testid="extension-upload-target"><a-radio value="local">{{ t('extensions.localTarget') }}</a-radio><a-radio value="cloud">{{ t('extensions.cloudTarget') }}</a-radio></a-radio-group></a-form-item>
        <a-form-item v-if="target==='cloud'" :label="t('extensions.platform')" required><a-select v-model:value="platform" :options="platformOptions" :disabled="busy" data-testid="extension-upload-platform" /></a-form-item>
        <a-alert type="info" :message="t(target==='local'?'extensions.localNote':'extensions.cloudNote')" show-icon />
        <p class="upload-note">{{ t('extensions.zipNote') }}</p><input ref="picker" type="file" accept=".zip" :disabled="busy || target==='cloud' && !platform" @change="chooseFile" data-testid="extension-upload-file" class="file-picker" />
        <a-button :disabled="busy || target==='cloud' && !platform" @click="picker?.click()">{{ t('extensions.chooseZip') }}</a-button><span class="file-name">{{ file?.name }}</span>
        <a-button type="primary" :loading="busy" :disabled="!file || target==='cloud' && !platform" @click="prepare" class="prepare-button" data-testid="extension-prepare">{{ t('extensions.inspectZip') }}</a-button>
        <div v-if="busy" class="upload-progress"><a-progress :percent="percent" :status="percent>=100?'active':'normal'" /><p>{{ t(percent>=100?'extensions.unpacking':'extensions.uploading') }}</p></div>
      </a-form>
    </template>
    <a-form v-else layout="vertical" @submit.prevent="finish" data-testid="extension-settings-form">
      <a-alert type="info" :message="t('extensions.prepareReady',{count:prepared.entries.length,minutes:Math.floor(prepared.expires_in/60)})" show-icon class="page-alert" />
      <div class="upload-grid"><a-form-item :label="t('extensions.entry')" required><a-select v-model:value="settings.entry_path" :options="prepared.entries.map((value:string)=>({value,label:value}))" :disabled="busy" data-testid="extension-entry" @change="inferType" /></a-form-item><a-form-item :label="t('extensions.entryType')"><a-select v-model:value="settings.entry_type" :options="[{value:'python',label:'Python'},{value:'binary',label:t('extensions.binary')},{value:'launcher',label:t('extensions.launcher')}]" :disabled="busy" /></a-form-item></div>
      <div class="upload-grid"><a-form-item :label="t('control.name')" required><a-input v-model:value="settings.name" :maxlength="80" :disabled="busy" data-testid="extension-name" /></a-form-item><a-form-item :label="t('extensions.category')" required><a-input v-model:value="settings.category" :maxlength="80" :disabled="busy" data-testid="extension-category" /></a-form-item></div>
      <div class="upload-grid"><a-form-item :label="t('extensions.usage')"><a-select v-model:value="settings.ext_type" :options="[{value:'ai',label:t('extensions.aiTab')},{value:'feature',label:t('extensions.kernelTab')},{value:'both',label:t('extensions.both')}]" :disabled="busy" /></a-form-item><a-form-item :label="t('extensions.version')"><a-input v-model:value="settings.version" :disabled="busy" :maxlength="64" /></a-form-item></div>
      <a-form-item :label="t('extensions.summary')" required><a-input v-model:value="settings.summary" :maxlength="300" :disabled="busy" data-testid="extension-summary" /></a-form-item>
      <a-form-item :label="t('extensions.aiDocument')" required><a-textarea v-model:value="settings.ai_instruction" :rows="4" :maxlength="12000" :disabled="busy" :placeholder="t('extensions.documentHint')" data-testid="extension-ai-doc" /></a-form-item>
      <a-collapse><a-collapse-panel key="parameters" :header="t('extensions.parameterContract')"><p class="upload-note">{{ t('extensions.parameterHint') }}</p><a-form-item :label="t('extensions.schema')" required><a-textarea v-model:value="schema" :rows="7" :maxlength="16000" :disabled="busy" class="code-input" data-testid="extension-schema" /></a-form-item><a-form-item :label="t('extensions.argv')" required><a-textarea v-model:value="argv" :rows="3" :maxlength="12000" :disabled="busy" class="code-input" data-testid="extension-argv" /></a-form-item></a-collapse-panel>
        <a-collapse-panel key="origin" :header="t('extensions.originInfo')"><a-form-item :label="t('extensions.origin')"><a-select v-model:value="settings.origin" :options="[{value:'self',label:t('extensions.self')},{value:'third_party',label:t('extensions.thirdParty')}]" :disabled="busy" /></a-form-item><template v-if="settings.origin==='third_party'"><a-form-item v-for="field in ['vendor','license','upstream_version']" :key="field" :label="t('extensions.'+field)" required><a-input v-model:value="settings[field]" :disabled="busy" :maxlength="160" /></a-form-item></template></a-collapse-panel></a-collapse>
      <section v-if="target==='cloud'" class="cloud-verification" data-testid="cloud-verification">
        <a-alert type="info" :message="t('extensions.cloudLimits')" show-icon class="page-alert" />
        <a-form-item :label="t('extensions.registeredEmail')" required><a-input v-model:value="email" type="email" :maxlength="254" :disabled="busy || codeBusy" autocomplete="email" data-testid="cloud-email" /></a-form-item>
        <a-form-item :label="t('extensions.emailCode')" required><a-space><a-input v-model:value="emailCode" :maxlength="6" :disabled="busy || codeBusy" inputmode="numeric" autocomplete="one-time-code" data-testid="cloud-code" /><a-button :loading="codeBusy" :disabled="busy || countdown>0 || !email.trim()" @click="requestCode" data-testid="cloud-request-code">{{ countdown>0?t('extensions.resendCode',{seconds:countdown}):t('extensions.sendCode') }}</a-button></a-space></a-form-item>
        <p v-if="challenge" class="upload-note">{{ t('extensions.codeSent',{remaining}) }}</p>
        <a-alert v-if="busy" type="info" :message="t('extensions.cloudSubmitting')" show-icon />
      </section>
      <p class="upload-note">{{ t('extensions.installNote') }}</p><a-space><a-button :disabled="busy" @click="back">{{ t('extensions.back') }}</a-button><a-button type="primary" html-type="submit" :loading="busy" data-testid="extension-finish">{{ t(target==='local'?'extensions.installLocal':'extensions.submitCloud') }}</a-button></a-space>
    </a-form>
  </a-modal>
</template>
<script setup lang="ts">
import {ref,reactive,computed,watch,onUnmounted} from 'vue'
import {t,appLocale} from '../../i18n'
import {getToken,request} from '../../api/request'
const props=defineProps<{open:boolean;defaultKind:string}>(),emit=defineEmits(['update:open','complete'])
const target=ref('local'),platform=ref(''),file=ref<File|null>(null),picker=ref<HTMLInputElement|null>(null),prepared=ref<any>(null),busy=ref(false),error=ref(''),percent=ref(0)
const settings=reactive<any>({name:'',category:'',summary:'',ai_instruction:'',entry_path:'',entry_type:'python',ext_type:'ai',version:'1.0.0',origin:'self',vendor:'',license:'',upstream_version:''}),schema=ref(''),argv=ref('')
const platformOptions=computed(()=>[{value:'linux',label:'Linux'},{value:'windows',label:'Windows'},{value:'common',label:t('extensions.commonPlatform')}])
const bodyId=ref('')
const email=ref(''),emailCode=ref(''),challenge=ref(''),codeBusy=ref(false),countdown=ref(0),remaining=ref(5)
let xhr:XMLHttpRequest|undefined,disposed=false,codeTimer:ReturnType<typeof setInterval>|undefined
watch(email,()=>{challenge.value='';emailCode.value=''})
async function requestCode(){if(busy.value || codeBusy.value || countdown.value)return;codeBusy.value=true;error.value='';try{const value=await request<any>('/api/pentest/extensions/cloud-code',{method:'POST',body:JSON.stringify({email:email.value.trim(),locale:appLocale.value})});if(disposed)return;challenge.value=value.challenge_id;remaining.value=value.remaining;countdown.value=value.retry_after || 60;emailCode.value='';if(codeTimer)clearInterval(codeTimer);codeTimer=setInterval(()=>{if(countdown.value>0)countdown.value--;else if(codeTimer)clearInterval(codeTimer)},1000)}catch(e){if(!disposed)error.value=(e as Error).message}finally{codeBusy.value=false}}
watch(()=>props.open,value=>{if(value){error.value='';email.value='';emailCode.value='';challenge.value='';file.value=null;prepared.value=null;target.value='local';platform.value='';settings.ext_type=props.defaultKind==='feature'?'feature':'ai'}})
function chooseFile(event:Event){if(bodyId.value)void discard().catch(()=>{});file.value=(event.target as HTMLInputElement).files?.[0] || null;error.value=''}
function inferType(){settings.entry_type=settings.entry_path.toLowerCase().endsWith('.py')?'python':'binary'}
async function discard(){if(bodyId.value){const id=bodyId.value;bodyId.value='';await request('/api/pentest/extensions/prepared/'+id+'/discard',{method:'POST',body:'{}'})}if(prepared.value){const id=prepared.value.upload_id;prepared.value=null;await request('/api/pentest/extensions/prepared/'+id+'/discard',{method:'POST',body:'{}'})}}
async function close(){if(busy.value || codeBusy.value)return;try{await discard();emit('update:open',false)}catch(exc){error.value=(exc as Error).message}}
async function back(){if(busy.value)return;try{await discard();error.value=''}catch(exc){error.value=(exc as Error).message}}
async function prepare(){
 if(busy.value || !file.value)return
 if(!file.value.name.toLowerCase().endsWith('.zip') || file.value.size>300*1024*1024){error.value=t('extensions.zipBudget');return}
 busy.value=true;error.value='';percent.value=0
 const form=new FormData();form.append('file',file.value);form.append('target',target.value);if(target.value==='cloud')form.append('platform',platform.value)
 try{
  const value=file.value.size>8*1024*1024?await prepareLarge(file.value):await new Promise<any>((resolve,reject)=>{xhr=new XMLHttpRequest();xhr.open('POST','/api/pentest/extensions/prepare');xhr.setRequestHeader('Token',getToken());xhr.timeout=180000;xhr.upload.onprogress=e=>{if(e.lengthComputable)percent.value=Math.round(e.loaded/e.total*100)};xhr.onerror=()=>reject(new Error(t('extensions.networkError')));xhr.ontimeout=()=>reject(new Error(t('extensions.networkError')));xhr.onabort=()=>reject(new Error(t('extensions.cancelled')));xhr.onload=()=>{try{const response=JSON.parse(xhr!.responseText);if(xhr!.status>=400 || response.code!==200)reject(new Error(response.message || t('extensions.uploadFailed')));else resolve(response.data)}catch(exc){reject(exc)}};xhr.send(form)})
  if(disposed)return
  prepared.value=value;const m=value.defaults || {};Object.assign(settings,{name:m.name || '',category:m.category || '',summary:m.summary || '',ai_instruction:m.ai_instruction || '',ext_type:m.ext_type || settings.ext_type,version:m.version || '1.0.0',origin:m.origin || 'self',vendor:m.vendor || '',license:m.license || '',upstream_version:m.upstream_version || '',entry_path:value.entries.includes(m.entry?.path)?m.entry.path:value.entries.length===1?value.entries[0]:''});inferType()
  schema.value=JSON.stringify(m.parameters || {type:'object',properties:{target:{type:'string',description:t('extensions.targetParam'),'x-sentinel-scope':'target'}},required:['target']},null,2);argv.value=JSON.stringify(m.entry?.argv || ['{target}'],null,2)
 }catch(exc){if(!disposed)error.value=(exc as Error).message}finally{busy.value=false;xhr=undefined}
}
async function prepareLarge(selected:File){
 const chunkSize=8*1024*1024
 if(!bodyId.value){const result=await request<any>('/api/pentest/extensions/body/start',{method:'POST',body:JSON.stringify({size:selected.size,target:target.value,platform:target.value==='cloud'?platform.value:''})});bodyId.value=result.upload_id}
 for(let offset=0;offset<selected.size;offset+=chunkSize){
  const part=selected.slice(offset,offset+chunkSize)
  await new Promise<void>((resolve,reject)=>{xhr=new XMLHttpRequest();xhr.open('POST','/api/pentest/extensions/body/'+bodyId.value+'/chunk');xhr.setRequestHeader('Token',getToken());xhr.setRequestHeader('Content-Type','application/octet-stream');xhr.setRequestHeader('X-Upload-Offset',String(offset));xhr.timeout=180000;xhr.upload.onprogress=e=>{percent.value=Math.round((offset+e.loaded)/selected.size*100)};xhr.onerror=xhr.ontimeout=()=>reject(new Error(t('extensions.networkError')));xhr.onabort=()=>reject(new Error(t('extensions.cancelled')));xhr.onload=()=>{try{const result=JSON.parse(xhr!.responseText);if(xhr!.status>=400 || result.code!==200)reject(new Error(result.message || t('extensions.uploadFailed')));else resolve()}catch(e){reject(e)}};xhr.send(part)})
 }
 const result=await request<any>('/api/pentest/extensions/body/'+bodyId.value+'/prepare',{method:'POST',body:'{}'});bodyId.value='';return result
}
async function finish(){
 if(busy.value || !prepared.value)return
 busy.value=true;error.value=''
 try{if(target.value==='cloud' && (!challenge.value || !/^[0-9]{6}$/.test(emailCode.value)))throw new Error(t('extensions.codeRequired'));if(!settings.entry_path || !settings.name.trim() || !settings.category.trim() || !settings.summary.trim() || !settings.ai_instruction.trim())throw new Error(t('extensions.fieldsRequired'));const parameters=JSON.parse(schema.value),args=JSON.parse(argv.value);if(!parameters || parameters.type!=='object' || !Array.isArray(args))throw new Error(t('extensions.invalidContract'));const result=await request('/api/pentest/extensions/prepared/'+prepared.value.upload_id+'/finish',{method:'POST',body:JSON.stringify({...settings,description:settings.ai_instruction,parameters,argv:args,...(target.value==='cloud'?{cloud_verification:{email:email.value.trim(),challenge_id:challenge.value,code:emailCode.value}}:{})})});await discard();emit('complete',result);emit('update:open',false)}catch(exc){if(!disposed)error.value=(exc as Error).message}finally{busy.value=false}
}
onUnmounted(()=>{disposed=true;if(codeTimer)clearInterval(codeTimer);emailCode.value='';challenge.value='';xhr?.abort();void discard().catch(()=>{})})
</script>
<style scoped>.upload-grid{display:grid;grid-template-columns:1fr 1fr;gap:16px}.upload-note{color:var(--dt-muted);font-size:12px;line-height:1.8;margin:14px 0}.file-picker{position:absolute;width:1px;height:1px;opacity:0}.file-name{margin-left:12px;overflow-wrap:anywhere}.prepare-button{display:block;margin-top:20px}.upload-progress{margin-top:20px}.code-input{font-family:ui-monospace,Consolas,monospace}@media(max-width:650px){.upload-grid{grid-template-columns:1fr;gap:0}}</style>
