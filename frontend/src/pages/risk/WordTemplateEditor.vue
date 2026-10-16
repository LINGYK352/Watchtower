<template>
  <a-modal :open="true" :width="1200" :title="translate(templateId ? 'wordTemplate.edit' : 'wordTemplate.create')" :mask-closable="false" :keyboard="false" :footer="null" @cancel="close">
    <div data-testid="word-template-editor">
      <a-alert v-if="error" type="error" show-icon :message="error" class="word-gap" />
      <a-form layout="vertical">
        <a-form-item :label="translate('wordTemplate.name')" required><a-input v-model:value="name" :maxlength="120" data-testid="word-template-name" /></a-form-item>
        <a-form-item v-if="!templateId" :label="translate('wordTemplate.method')">
          <a-radio-group v-model:value="mode" :disabled="busy || !!document" data-testid="word-template-method" @change="file=undefined;sourceName=''"> <a-radio-button value="manual">{{ translate('wordTemplate.manual') }}</a-radio-button><a-radio-button value="ai">{{ translate('wordTemplate.ai') }}</a-radio-button></a-radio-group>
        </a-form-item>
        <a-form-item v-if="mode === 'ai'" :label="translate('wordTemplate.model')"><a-select v-model:value="providerId" :options="providers" allow-clear :placeholder="translate('wordTemplate.defaultModel')" /></a-form-item>
      </a-form>
      <div class="word-gap word-source">
        <a-upload v-if="!templateId" accept=".docx" :show-upload-list="false" :before-upload="upload"><a-button :loading="uploading" :disabled="busy" data-testid="word-template-upload">{{ translate('wordTemplate.upload') }}</a-button></a-upload>
        <span v-if="sourceName" class="word-note">{{ sourceName }}</span>
        <span class="word-note">{{ translate('wordTemplate.reviewRequired') }}</span>
      </div>
      <template v-if="document">
        <a-alert class="word-gap" type="info" show-icon :message="translate('wordTemplate.annotationHelp')" />
        <a-space wrap class="word-toolbar">
          <a-select v-model:value="tag" show-search :options="tagOptions" class="word-tag-select" :placeholder="translate('wordTemplate.tag')" data-testid="word-template-tags" />
          <a-button :disabled="!selection || !tag" @mousedown.prevent @click="insert('{{' + tag + '}}')" data-testid="word-template-insert">{{ translate('wordTemplate.insert') }}</a-button>
          <a-button :disabled="!selection" @mousedown.prevent @click="insert('{{#findings}}')">{{ translate('wordTemplate.loopStart') }}</a-button>
          <a-button :disabled="!selection" @mousedown.prevent @click="insert('{{/findings}}')">{{ translate('wordTemplate.loopEnd') }}</a-button>
          <span class="word-note">{{ selection ? translate('wordTemplate.selected', { id: selection }) : translate('wordTemplate.selectText') }}</span>
        </a-space>
        <div ref="canvas" class="word-canvas" data-testid="word-template-canvas" @mouseup="capture" @keyup="capture" @input="changed" @paste="paste" @keydown.enter.prevent="insert('\n')">
          <section v-for="section in document.sections" :key="section.part" class="word-sheet">
            <div class="word-part" contenteditable="false">{{ section.part }}</div>
            <div class="word-content" v-html="safeHtml(section.html)"></div>
          </section>
        </div>
      </template>
      <p v-else class="word-empty">{{ translate('wordTemplate.uploadFirst') }}</p>
      <div class="word-actions"><a-space><a-button :disabled="busy" @click="close">{{ translate('wordTemplate.cancel') }}</a-button><a-button type="primary" :disabled="mode === 'manual' ? !document : !file" :loading="saving" @click="save" data-testid="word-template-save">{{ translate(mode === 'manual' ? 'wordTemplate.save' : 'wordTemplate.learn') }}</a-button></a-space></div>
    </div>
  </a-modal>
</template>

<script setup lang="ts">
import { computed, nextTick, onBeforeUnmount, onMounted, ref } from 'vue'
import { Modal, message } from 'ant-design-vue'
import { t as translate } from '../../i18n'
import { reportTemplateApi, type WordTemplateView } from '../../api/intel'
import { useUnsavedGuard } from '../../composables/useUnsavedGuard'

const props = defineProps<{ templateId?: string; providers: {label:string;value:string}[] }>()
const emit = defineEmits<{ close: []; saved: [] }>()
const name = ref(''), mode = ref<'manual'|'ai'>('manual'), providerId = ref<string>(), sourceName = ref(''), error = ref('')
const document = ref<WordTemplateView>(), file = ref<File>(), edits = ref<Record<string,string>>({}), canvas = ref<HTMLElement>(), selection = ref(''), tag = ref('')
const uploading = ref(false), saving = ref(false), busy = computed(() => uploading.value || saving.value)
const tagOptions = computed(() => (document.value?.tags || []).map(value => ({value,label:'{{'+value+'}}'})))
let disposed = false, range: Range | undefined
const { dirty, markSaved } = useUnsavedGuard(() => JSON.stringify([name.value,mode.value,sourceName.value,edits.value]))
// The server generates this small Word preview vocabulary. Keep the same
// vocabulary here; never accept links, scripts, arbitrary CSS or remote images.
function safeHtml(html:string){
  const template=window.document.createElement('template');template.innerHTML=html
  const allowed=new Set(['P','SPAN','TABLE','TBODY','THEAD','TR','TD','TH','BR','IMG'])
  template.content.querySelectorAll<HTMLElement>('*').forEach(element=>{
    if(!allowed.has(element.tagName)){element.replaceWith(window.document.createTextNode(element.textContent || ''));return}
    for(const attribute of Array.from(element.attributes)){
      const name=attribute.name,value=attribute.value
      const keep=name==='style' && /^(?:(?:font-weight:700|font-style:italic|color:#[a-f0-9]{6}|font-size:[0-9.]+pt);?)*$/i.test(value)
        || name==='data-word-paragraph' && element.tagName==='P' && /^word\/[a-z0-9]+\.xml#\d+$/i.test(value)
        || name==='contenteditable' && ['true','false'].includes(value)
        || name==='spellcheck' && value==='false'
        || name==='src' && element.tagName==='IMG' && /^data:image\/(?:png|jpeg|gif);base64,[a-z0-9+/=]+$/i.test(value)
        || name==='alt' && element.tagName==='IMG'
      if(!keep)element.removeAttribute(name)
    }
  })
  return template.innerHTML
}

onMounted(async () => {
  if (props.templateId) {
    uploading.value = true
    try { document.value = await reportTemplateApi.viewWord(props.templateId); name.value = document.value.name || ''; sourceName.value = document.value.source_filename; tag.value = document.value.tags[0] || '';edits.value=document.value.edits || {} }
    catch (cause) { error.value = (cause as Error).message }
    finally { uploading.value = false }
  }
  await nextTick(); markSaved()
})
onBeforeUnmount(() => { disposed = true; const id=document.value?.draft_id; if(id)void reportTemplateApi.discardWord(id).catch(() => {}) })
async function upload(selected:File) {
  if (!selected.name.toLowerCase().endsWith('.docx') || selected.size > 20*1024*1024-65536) { error.value=translate('wordTemplate.fileLimit'); return false }
  error.value=''; file.value=selected;sourceName.value=selected.name
  if (!name.value)name.value=selected.name.replace(/\.docx$/i,'')
  if(mode.value==='ai')return false
  uploading.value=true
  try {
    const previous=document.value?.draft_id
    const result=await reportTemplateApi.uploadWord(selected)
    if(disposed){if(result.draft_id)await reportTemplateApi.discardWord(result.draft_id);return false}
    document.value=result;edits.value={};selection.value='';range=undefined;tag.value=result.tags[0]||''
    if(previous)await reportTemplateApi.discardWord(previous)
  } catch(cause){error.value=(cause as Error).message}
  finally{uploading.value=false}
  return false
}
function capture(){
  const current=window.getSelection()
  if(!current?.rangeCount || !canvas.value)return
  const selected=current.getRangeAt(0);const node=selected.commonAncestorContainer;const element=node.nodeType===Node.ELEMENT_NODE?node as Element:node.parentElement
  const paragraph=element?.closest<HTMLElement>('[data-word-paragraph]')
  if(!paragraph || !canvas.value.contains(paragraph))return
  range=selected.cloneRange();selection.value=paragraph.dataset.wordParagraph || ''
}
function changed(event:Event){
  const element=(event.target as HTMLElement).closest<HTMLElement>('[data-word-paragraph]')
  if(!element?.dataset.wordParagraph)return
  const key=element.dataset.wordParagraph;edits.value={...edits.value,[key]:element.textContent || ''};capture()
}
function insert(value:string){
  if(!range || !canvas.value?.contains(range.commonAncestorContainer))return
  range.deleteContents();const node=window.document.createTextNode(value);range.insertNode(node);range.setStartAfter(node);range.collapse(true)
  const current=window.getSelection();current?.removeAllRanges();current?.addRange(range)
  const paragraph=node.parentElement?.closest<HTMLElement>('[data-word-paragraph]')
  if(paragraph){const key=paragraph.dataset.wordParagraph!;edits.value={...edits.value,[key]:paragraph.textContent || ''}}
  capture()
}
function paste(event:ClipboardEvent){event.preventDefault();range=undefined;selection.value='';capture();insert(event.clipboardData?.getData('text/plain') || '')}
async function close(){
  if(busy.value)return
  const leave=()=>{markSaved();emit('close')}
  if(dirty.value)Modal.confirm({title:translate('wordTemplate.unsaved'),onOk:leave});else leave()
}
async function save(){
  if(busy.value)return
  if(!name.value.trim()){error.value=translate('wordTemplate.requiredName');return}
  saving.value=true;error.value=''
  try{
    if(mode.value==='ai'){
      if(!file.value)return
      await reportTemplateApi.upload(file.value,name.value.trim(),{provider_id:providerId.value,need_review:true})
    }else{
      if(!document.value)return
      await reportTemplateApi.saveWord({name:name.value.trim(),edits:edits.value,...(props.templateId?{template_id:props.templateId,revision:document.value.revision}:{}),...(document.value.draft_id?{draft_id:document.value.draft_id}:{})})
    }
    markSaved();message.success(translate(mode.value==='ai'?'wordTemplate.learning':'wordTemplate.saved'));emit('saved');emit('close')
  }catch(cause){error.value=(cause as Error).message}
  finally{saving.value=false}
}
</script>

<style scoped>
.word-gap{margin-bottom:14px}.word-note{font-size:12px;color:var(--dt-muted);overflow-wrap:anywhere}.word-source{display:flex;flex-wrap:wrap;align-items:center;gap:10px;max-width:100%;margin-bottom:18px}.word-source>span{display:block;flex-basis:100%;min-width:0;line-height:1.55;overflow-wrap:anywhere}.word-toolbar{padding:10px;background:var(--dt-fill);border:1px solid var(--dt-border);border-radius:8px;margin-bottom:12px;position:sticky;top:0;z-index:2}.word-tag-select{width:270px;max-width:100%}.word-canvas{max-height:56vh;overflow:auto;padding:20px;background:var(--dt-fill);border:1px solid var(--dt-border);border-radius:8px}.word-sheet{max-width:850px;min-height:200px;margin:0 auto 18px;background:#fff;color:#222;padding:28px 40px;box-shadow:0 3px 18px #10204014}.word-part{font:11px monospace;color:#7a8597;padding-bottom:14px;border-bottom:1px solid #e6eaf0;margin-bottom:14px}.word-content:deep(p){min-height:1.5em;white-space:pre-wrap;overflow-wrap:anywhere;line-height:1.65;outline:0;padding:3px;margin:5px 0;border-radius:3px}.word-content:deep(p:focus){box-shadow:0 0 0 2px #1677ff66;background:#edf5ff}.word-content:deep(table){width:100%;border-collapse:collapse}.word-content:deep(td){border:1px solid #bdc7d5;padding:6px;vertical-align:top}.word-content:deep(img){max-width:100%;max-height:320px;object-fit:contain}.word-actions{text-align:right;margin-top:18px}.word-empty{padding:32px;text-align:center;color:var(--dt-muted);border:1px dashed var(--dt-border);border-radius:8px}@media(max-width:650px){.word-canvas{padding:8px}.word-sheet{padding:12px}.word-toolbar{position:static}.word-tag-select{width:220px}}
</style>
