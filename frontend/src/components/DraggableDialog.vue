<template>
  <a-modal :open="open" :width="width" :footer="null" centered destroy-on-close :mask-closable="false"
    :body-style="{padding:'0'}" class="draggable-dialog" @cancel="emit('update:open',false)">
    <template #title>
      <div class="dialog-grip" tabindex="0" @pointerdown="begin" @keydown="keyboard" data-testid="dialog-drag-handle"
        :aria-label="t('chainView.moveWindow')">
        <DragOutlined /><span>{{ title }}</span>
        <button type="button" class="dialog-reset" @pointerdown.stop @click="reset" :title="t('chainView.resetWindow')">↺</button>
      </div>
    </template>
    <template #modalRender="{originVNode}">
      <div ref="box" :style="{transform:`translate(${offset.x}px, ${offset.y}px)`}" data-testid="draggable-dialog-body">
        <component :is="originVNode" />
      </div>
    </template>
    <slot />
  </a-modal>
</template>
<script setup lang="ts">
import { ref,reactive,computed,watch,onMounted,onUnmounted,nextTick } from 'vue'
import { DragOutlined } from '@ant-design/icons-vue'
import { t } from '../i18n'
const props=withDefaults(defineProps<{open:boolean;title:string;preferredWidth?:number}>(),{preferredWidth:1160})
const emit=defineEmits<{ 'update:open':[boolean] }>()
const box=ref<HTMLElement|null>(null),offset=reactive({x:0,y:0}),viewport=ref(window.innerWidth)
const width=computed(()=>Math.min(props.preferredWidth,Math.max(1,viewport.value-24)))
let drag:{id:number;x:number;y:number;left:number;top:number}|undefined
function clamp(x:number,y:number) {
  const rect=box.value?.getBoundingClientRect();if(!rect)return
  const left=rect.left-offset.x,top=rect.top-offset.y
  offset.x=Math.max(12-left,Math.min(window.innerWidth-12-left-rect.width,x))
  offset.y=Math.max(12-top,Math.min(window.innerHeight-12-top-rect.height,y))
}
function reset(){offset.x=0;offset.y=0;void nextTick().then(()=>clamp(0,0))}
function begin(event:PointerEvent){
  if(event.button!==0 || (event.target as Element).closest('button,a,input'))return
  event.preventDefault();drag={id:event.pointerId,x:event.clientX,y:event.clientY,left:offset.x,top:offset.y}
  window.addEventListener('pointermove',move);window.addEventListener('pointerup',end);window.addEventListener('pointercancel',end)
}
function move(event:PointerEvent){if(drag && event.pointerId===drag.id)clamp(drag.left+event.clientX-drag.x,drag.top+event.clientY-drag.y)}
function end(){drag=undefined;window.removeEventListener('pointermove',move);window.removeEventListener('pointerup',end);window.removeEventListener('pointercancel',end)}
function keyboard(event:KeyboardEvent){
  const delta:Record<string,number[]>={ArrowLeft:[-20,0],ArrowRight:[20,0],ArrowUp:[0,-20],ArrowDown:[0,20]}
  if(delta[event.key]){event.preventDefault();clamp(offset.x+delta[event.key][0],offset.y+delta[event.key][1])}
}
function resize(){viewport.value=window.innerWidth;if(props.open)void nextTick().then(()=>clamp(offset.x,offset.y))}
watch(()=>props.open,value=>{end();if(value)reset()})
onMounted(()=>window.addEventListener('resize',resize));onUnmounted(()=>{end();window.removeEventListener('resize',resize)})
</script>
<style scoped>
.dialog-grip{display:flex;align-items:center;gap:10px;min-width:0;padding-right:32px;cursor:move;touch-action:none;user-select:none;color:var(--dt-text)}
.dialog-grip>span{flex:1;min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}.dialog-reset{border:0;background:var(--dt-fill);color:var(--dt-muted);border-radius:6px;width:28px;height:28px;cursor:pointer}.dialog-grip:focus-visible{outline:2px solid var(--dt-primary);outline-offset:4px}
</style>
