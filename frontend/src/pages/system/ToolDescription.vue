<template>
  <a-modal v-if="!longDocument" :open="open" :title="title" :width="520" centered :footer="null" @cancel="$emit('close')">
    <div class="tool-document tool-document-modal" data-testid="tool-description"><ToolBody /></div>
  </a-modal>
  <a-drawer v-else :open="open" :title="title" width="min(760px, calc(100vw - 16px))" placement="right" @close="$emit('close')" :body-style="{padding:'20px'}">
    <div class="tool-document" data-testid="tool-description-long"><ToolBody /></div>
  </a-drawer>
</template>
<script setup lang="ts">
import { computed, defineComponent, h } from 'vue'
import { t } from '../../i18n'
const props=defineProps<{open:boolean;tool:Record<string,any>|null}>()
defineEmits<{(e:'close'):void}>()
const title=computed(()=>String(props.tool?.name||props.tool?.extension_id||''))
const documentation=computed(()=>[props.tool?.description,props.tool?.ai_instruction].filter((value,index,all)=>typeof value==='string' && value.trim() && all.indexOf(value)===index).join('\n\n') || String(props.tool?.summary||''))
const longDocument=computed(()=>documentation.value.length>1400 || documentation.value.split('\n').length>18)
const ToolBody=defineComponent({setup:()=>()=>h('div',{},[
  h('p',{class:'tool-description-text'},documentation.value||t('extensions.noDescription')),
  ...(props.tool?.params?.length?[h('h4',t('ui.m_9634fb0832be')),h('dl',{},props.tool.params.flatMap((param:any)=>[h('dt',{},String(param.name)+(param.required?' *':'')),h('dd',{},String(param.desc||param.description||''))]))]:[]),
  ...(props.tool?.ai_instruction?[h('p',{class:'tool-source-note'},t('extensions.standardDescription'))]:[])
])})
</script>
<style scoped>
.tool-document{color:var(--dt-text);font-size:14px;line-height:1.8;overflow-wrap:anywhere}.tool-document-modal{max-height:65vh;overflow:auto;padding-right:8px}.tool-document :deep(.tool-description-text){white-space:pre-wrap;margin:0}.tool-document :deep(dt){font-family:monospace;font-weight:600;margin-top:12px}.tool-document :deep(dd){color:var(--dt-muted);margin-left:0}.tool-document :deep(h4){color:var(--dt-text);margin:20px 0 8px}.tool-document :deep(.tool-source-note){color:var(--dt-muted);font-size:12px;border-top:1px solid var(--dt-border);padding-top:14px;margin-top:18px}
</style>
