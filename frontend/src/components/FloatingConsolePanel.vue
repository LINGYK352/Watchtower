<template>
  <section v-if="open" ref="panel" class="console-float" :style="style" :aria-label="title" @pointerdown="raise" data-testid="console-floating-panel">
    <header class="float-handle" @pointerdown="begin($event, 'move')" data-testid="floating-panel-handle">
      <strong>{{ title }}</strong><div class="float-actions" @pointerdown.stop><slot name="actions" /><button type="button" @click="reset" :title="t('burps.resetPosition')" :aria-label="t('burps.resetPosition')">↺</button><button type="button" @click="emit('update:open',false)" :title="t('burps.close')" :aria-label="t('burps.close')">×</button></div>
    </header>
    <div class="float-content"><slot /></div>
    <button class="float-resize" type="button" @pointerdown="begin($event, 'resize')" :aria-label="t('burps.resize')">◢</button>
  </section>
</template>
<script lang="ts">
let floatLayer=50;
</script>
<script setup lang="ts">
import { ref, reactive, computed, onMounted, onUnmounted, nextTick, watch } from 'vue'
import { t } from '../i18n'
const props=withDefaults(defineProps<{open:boolean;title:string;width?:number;height?:number}>(),{width:960,height:620})
const emit=defineEmits<{ 'update:open':[boolean] }>()
const panel=ref<HTMLElement|null>(null),box=reactive({x:24,y:56,w:960,h:620,z:++floatLayer})
const style=computed(()=>({left:box.x+'px',top:box.y+'px',width:box.w+'px',height:box.h+'px',zIndex:box.z}))
let observer:ResizeObserver|undefined,drag:{id:number;x:number;y:number;left:number;top:number;width:number;height:number;mode:'move'|'resize'}|undefined
function bounds(){const parent=panel.value?.parentElement;return {w:parent?.clientWidth||window.innerWidth,h:parent?.clientHeight||window.innerHeight}}
function clamp(){const b=bounds();box.w=Math.min(Math.max(300,box.w),Math.max(1,b.w-8));box.h=Math.min(Math.max(180,box.h),Math.max(1,b.h-8));box.x=Math.max(0,Math.min(box.x,b.w-box.w));box.y=Math.max(0,Math.min(box.y,b.h-box.h))}
function reset(){box.w=props.width;box.h=props.height;box.x=24;box.y=56;clamp()}
function raise(){box.z=++floatLayer}
function begin(event:PointerEvent,mode:'move'|'resize'){
  if(event.button!==0)return
  event.preventDefault();raise();drag={id:event.pointerId,x:event.clientX,y:event.clientY,left:box.x,top:box.y,width:box.w,height:box.h,mode}
  window.addEventListener('pointermove',move);window.addEventListener('pointerup',end);window.addEventListener('pointercancel',end)
}
function move(event:PointerEvent){if(!drag||event.pointerId!==drag.id)return;const dx=event.clientX-drag.x,dy=event.clientY-drag.y;if(drag.mode==='move'){box.x=drag.left+dx;box.y=drag.top+dy}else{box.w=drag.width+dx;box.h=drag.height+dy}clamp()}
function end(){drag=undefined;window.removeEventListener('pointermove',move);window.removeEventListener('pointerup',end);window.removeEventListener('pointercancel',end)}
async function observe(){await nextTick();observer?.disconnect();if(panel.value?.parentElement){observer=new ResizeObserver(clamp);observer.observe(panel.value.parentElement);reset()}}
watch(()=>props.open,open=>{if(open)observe();else{end();observer?.disconnect()}});onMounted(()=>{if(props.open)observe()});onUnmounted(()=>{end();observer?.disconnect()})
</script>
<style scoped>
.console-float{position:absolute;display:flex;flex-direction:column;min-width:0;min-height:0;border:1px solid var(--line2,#39465a);border-radius:12px;background:var(--panel,#101826);color:var(--txt,#dce5ed);box-shadow:0 12px 48px #0005;overflow:hidden}
.float-handle{display:flex;align-items:center;gap:12px;flex-shrink:0;height:46px;padding:0 12px;background:var(--card2,#172334);border-bottom:1px solid var(--line2,#39465a);cursor:move;touch-action:none;user-select:none}
.float-handle strong{font-size:13px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}.float-actions{display:flex;align-items:center;gap:8px;margin-left:auto}.float-actions button{color:inherit;background:transparent;border:0;cursor:pointer;font-size:19px;padding:2px 6px;min-width:32px;min-height:32px;border-radius:6px}.float-content{flex:1;min-height:0;overflow:hidden}.float-resize{position:absolute;right:0;bottom:0;border:0;background:transparent;color:var(--dim,#8194aa);cursor:nwse-resize;touch-action:none}
</style>
