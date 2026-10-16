<template>
  <Teleport v-if="anchor" :to="anchor">
    <button ref="launcher" class="page-help-button" type="button" :title="t('guides.open')" :aria-label="t('guides.open')" @click="start" data-testid="page-help">
      <QuestionCircleOutlined />
    </button>
  </Teleport>
  <Teleport to="body">
    <div v-if="open && current" class="page-guide" role="dialog" aria-modal="true" :aria-label="t('guides.title')" @keydown="keyboard" data-testid="page-guide">
      <svg class="guide-shade" :viewBox="`0 0 ${viewport.width} ${viewport.height}`" preserveAspectRatio="none" aria-hidden="true">
        <defs><mask id="watchtower-guide-cutout"><rect width="100%" height="100%" fill="white" /><rect v-if="targetBox" :x="targetBox.left" :y="targetBox.top" :width="targetBox.width" :height="targetBox.height" rx="10" fill="black" /></mask><marker id="watchtower-guide-arrow" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse"><path d="M 0 0 L 10 5 L 0 10 z" fill="var(--dt-primary)" /></marker></defs>
        <rect width="100%" height="100%" fill="rgba(9,17,27,.67)" mask="url(#watchtower-guide-cutout)" />
        <rect v-if="targetBox" :x="targetBox.left" :y="targetBox.top" :width="targetBox.width" :height="targetBox.height" rx="14" fill="none" stroke="var(--dt-primary)" stroke-width="2" stroke-dasharray="7 5" data-testid="guide-dashed-ring" />
        <path v-if="arrow" :d="arrow" fill="none" stroke="var(--dt-primary)" stroke-width="2.5" stroke-dasharray="7 5" stroke-linecap="round" marker-end="url(#watchtower-guide-arrow)" data-testid="guide-arrow" />
      </svg>
      <section ref="bubble" class="guide-bubble" :style="position" tabindex="-1" data-testid="guide-bubble">
        <div class="guide-heading"><span>{{ t('guides.title') }} · {{ index + 1 }} / {{ steps.length }}</span><button type="button" @click="close" :aria-label="t('guides.close')" data-testid="guide-close">×</button></div>
        <img class="guide-mascot" :class="{'face-right':mascotDirection==='right'}" :src="mascotDirection==='up'?'/mascot/guide-up.png':'/mascot/guide-left.png'" :alt="t('guides.mascot')" @error="fallbackMascot" data-testid="guide-mascot" />
        <h2>{{ t('guides.' + current.key + '.title') }}</h2>
        <p class="guide-description">{{ t('guides.' + current.key + '.body') }}</p>
        <p v-if="!targetBox" class="guide-unavailable" data-testid="guide-unavailable">{{ t('guides.unavailable') }}</p>
        <details class="guide-contents"><summary>{{ t('guides.contents') }}</summary><button v-for="(step, n) in steps" :key="step.key" type="button" :class="{active:n===index}" @click="go(n)">{{ n + 1 }}. {{ t('guides.' + step.key + '.title') }}</button></details>
        <div class="guide-actions"><button type="button" :disabled="!index" @click="go(index - 1)" data-testid="guide-prev">{{ t('guides.previous') }}</button><span>{{ t('guides.keyboard') }}</span><button type="button" class="primary" @click="index + 1 === steps.length ? close() : go(index + 1)" data-testid="guide-next">{{ t(index + 1 === steps.length ? 'guides.finish' : 'guides.next') }}</button></div>
      </section>
    </div>
  </Teleport>
</template>

<script setup lang="ts">
import { computed, nextTick, onBeforeUnmount, onMounted, ref, watch } from 'vue'
import { useRoute } from 'vue-router'
import { QuestionCircleOutlined } from '@ant-design/icons-vue'
import { t, appLocale } from '../i18n'
import { pageGuides } from '../help/pageGuides'
const route=useRoute(),launcher=ref<HTMLElement|null>(null),bubble=ref<HTMLElement|null>(null),open=ref(false),index=ref(0)
const anchor=ref<HTMLElement|null>(null),mascotDirection=ref('left')
const workspaceGuide=ref(false)
const steps=computed(()=>(workspaceGuide.value?pageGuides.collaborationWorkspace:undefined) || pageGuides[String(route.name)] || pageGuides.dashboard)
const current=computed(()=>steps.value[index.value])
const viewport=ref({width:window.innerWidth,height:window.innerHeight})
const targetBox=ref<{left:number;top:number;width:number;height:number}|null>(null)
const position=ref<Record<string,string>>({}),arrow=ref('')
let frame=0, observer:MutationObserver|undefined, resize:ResizeObserver|undefined, generation=0,restoreFocus:HTMLElement|null=null,anchorObserver:MutationObserver|undefined,anchorFrame=0
function findAnchor(){
  anchorFrame=0
  if(route.name==='pentestConsole' && document.querySelector('.app-content .cc-body')){if(open.value)close();anchor.value=null;return}
  const workspaceTitle=route.name==='collaboration'?document.querySelector<HTMLElement>('.app-content [data-testid="group-workspace"] .workspace-caption'):null
  if(workspaceGuide.value!==!!workspaceTitle){if(open.value)close();workspaceGuide.value=!!workspaceTitle}
  const title=document.querySelector<HTMLElement>('.app-content .page-heading h1')
  const next=workspaceTitle || title || document.querySelector<HTMLElement>('.app-content .cc-listhead .lh-brand') || document.querySelector<HTMLElement>('.app-content .lh-actions') || document.querySelector<HTMLElement>('.app-content .cc-telemetry') || document.querySelector<HTMLElement>('.app-header .page-title')
  if(anchor.value!==next)anchor.value=next
}
function scheduleAnchor(){if(!anchorFrame)anchorFrame=requestAnimationFrame(findAnchor)}
function fallbackMascot(event:Event){const image=event.target as HTMLImageElement;if(!image.src.endsWith('/normal.png'))image.src='/mascot/normal.png'}
function target():HTMLElement|null {
  const selectors=(current.value?.selector || '').split('|')
  for(const selector of selectors){
    if(!selector.trim())continue
    const candidates=document.querySelectorAll<HTMLElement>('.app-content '+selector.trim())
    for(const element of candidates){const r=element.getBoundingClientRect();if(r.width>0 && r.height>0 && getComputedStyle(element).visibility!=='hidden')return element}
  }
  return null
}
function measure(){
  frame=0;if(!open.value || !bubble.value)return
  const width=window.innerWidth,height=window.innerHeight;viewport.value={width,height}
  const element=target(),bounds=element?.getBoundingClientRect(),margin=12
  let box=null
  if(bounds && bounds.right>0 && bounds.bottom>0 && bounds.left<width && bounds.top<height){
    const left=Math.max(4,bounds.left-6),top=Math.max(4,bounds.top-6),right=Math.min(width-4,bounds.right+6),bottom=Math.min(height-4,bounds.bottom+6)
    box={left,top,width:Math.max(0,right-left),height:Math.max(0,bottom-top)}
  }
  targetBox.value=box
  const b=bubble.value.getBoundingClientRect(),bw=Math.min(400,width-margin*2),bh=Math.min(b.height,height-margin*2)
  let x=(width-bw)/2,y=(height-bh)/2,d=''
  if(box){
    const right=box.left+box.width,bottom=box.top+box.height
    if(right+24+bw<width){x=right+24;y=box.top;d=`M ${x-2} ${Math.min(height-22,Math.max(22,box.top+box.height/2))} L ${right+9} ${box.top+box.height/2}`}
    else if(box.left>bw+24){x=box.left-bw-24;y=box.top;d=`M ${x+bw+2} ${Math.min(height-22,Math.max(22,box.top+box.height/2))} L ${box.left-9} ${box.top+box.height/2}`}
    else if(bottom+24+bh<height){x=box.left+(box.width-bw)/2;y=bottom+24;d=`M ${Math.max(margin+bw/2,Math.min(width-margin-bw/2,x+bw/2))} ${y-2} L ${box.left+box.width/2} ${bottom+9}`}
    else{ x=box.left+(box.width-bw)/2;y=box.top-bh-24;d=`M ${Math.max(margin+bw/2,Math.min(width-margin-bw/2,x+bw/2))} ${Math.max(margin,y)+bh+2} L ${box.left+box.width/2} ${box.top-9}` }
  }
  x=Math.max(margin,Math.min(width-bw-margin,x));y=Math.max(margin,Math.min(height-bh-margin,y))
  position.value={left:x+'px',top:y+'px',width:bw+'px',maxHeight:Math.max(80,height-margin*2)+'px'}
  // A large target can overlap the bubble after viewport clamping. Choose an
  // exposed point and begin outside the bubble so the arrow cannot hide behind it.
  if(box){
    const right=box.left+box.width,bottom=box.top+box.height,pad=Math.min(10,box.width/4,box.height/4)
    const targets=[[box.left+pad,box.top+pad],[right-pad,box.top+pad],[box.left+pad,bottom-pad],[right-pad,bottom-pad],[(box.left+right)/2,box.top+pad],[(box.left+right)/2,bottom-pad],[box.left+pad,(box.top+bottom)/2],[right-pad,(box.top+bottom)/2]]
    let best=Infinity,chosen:number[]|null=null
    for(const [tx,ty] of targets){
      if(tx>=x-5 && tx<=x+bw+5 && ty>=y-5 && ty<=y+bh+5)continue
      let ax=Math.max(x+16,Math.min(x+bw-16,tx)),ay=Math.max(y+16,Math.min(y+bh-16,ty))
      if(tx<x)ax=x-4;else if(tx>x+bw)ax=x+bw+4;else if(ty<y)ay=y-4;else ay=y+bh+4
      const distance=Math.hypot(tx-ax,ty-ay)
      if(distance<best){best=distance;chosen=[ax,ay,tx,ty]}
    }
    if(chosen){d=`M ${chosen[0]} ${chosen[1]} L ${chosen[2]} ${chosen[3]}`;mascotDirection.value=chosen[3]<y ? 'up' : chosen[2]>x+bw/2 ? 'right' : 'left'}
  }
  arrow.value=d
}
function schedule(){if(open.value && !frame)frame=requestAnimationFrame(measure)}
async function go(value:number){
  const revision=++generation;index.value=Math.max(0,Math.min(steps.value.length-1,value));targetBox.value=null;arrow.value=''
  await nextTick();if(!open.value || revision!==generation)return
  target()?.scrollIntoView({block:'nearest',inline:'nearest',behavior:'instant'})
  measure();await nextTick();if(open.value && revision===generation){measure();bubble.value?.focus({preventScroll:true})}
}
async function start(){
  if(open.value)return
  restoreFocus=document.activeElement as HTMLElement;open.value=true
  window.addEventListener('resize',schedule);window.addEventListener('scroll',schedule,true)
  observer=new MutationObserver(schedule);const root=document.querySelector('.app-content');if(root)observer.observe(root,{childList:true,subtree:true})
  resize=new ResizeObserver(schedule);await go(0);if(bubble.value)resize.observe(bubble.value)
}
function close(){
  open.value=false;++generation;observer?.disconnect();resize?.disconnect();window.removeEventListener('resize',schedule);window.removeEventListener('scroll',schedule,true)
  if(frame)cancelAnimationFrame(frame);frame=0;targetBox.value=null;arrow.value=''
  const focus=restoreFocus?.isConnected?restoreFocus:launcher.value;focus?.focus({preventScroll:true})
}
function keyboard(event:KeyboardEvent){
  if(event.key==='Escape'){event.preventDefault();close()}
  if(event.key==='ArrowRight'){event.preventDefault();if(index.value+1<steps.value.length)void go(index.value+1)}
  if(event.key==='ArrowLeft'){event.preventDefault();void go(index.value-1)}
  if(event.key==='Tab'){
    const controls=Array.from(bubble.value?.querySelectorAll<HTMLElement>('button:not(:disabled),summary') || []).filter(e=>e.getClientRects().length)
    const first=controls[0],last=controls[controls.length-1]
    if(event.shiftKey && (document.activeElement===first || document.activeElement===bubble.value)){event.preventDefault();last?.focus()}
    else if(!event.shiftKey && (document.activeElement===last || document.activeElement===bubble.value)){event.preventDefault();first?.focus()}
  }
}
watch(()=>route.fullPath,()=>{if(open.value)close()})
onMounted(()=>{findAnchor();anchorObserver=new MutationObserver(scheduleAnchor);const root=document.querySelector('.app-content');if(root)anchorObserver.observe(root,{childList:true,subtree:true})})
watch(appLocale,async()=>{if(open.value){await nextTick();schedule()}})
onBeforeUnmount(()=>{close();anchorObserver?.disconnect();if(anchorFrame)cancelAnimationFrame(anchorFrame)})
</script>

<style scoped>
.page-help-button{position:relative;width:20px;height:20px;padding:0;display:inline-flex;align-items:center;justify-content:center;vertical-align:middle;flex-shrink:0;margin-left:12px;border:1px solid var(--dt-control-border);border-radius:50%;background:var(--dt-card);color:var(--dt-muted);font-size:12.5px;cursor:pointer}.page-help-button::after{content:"";position:absolute;inset:-6px;border-radius:50%}.page-help-button:hover{color:var(--dt-primary);background:var(--dt-hover)}.page-help-button:focus-visible,.guide-bubble button:focus-visible,.guide-contents summary:focus-visible{outline:3px solid var(--dt-primary);outline-offset:3px}.page-guide{position:fixed;inset:0;z-index:2100;isolation:isolate;touch-action:none}.guide-shade{position:absolute;inset:0;width:100%;height:100%;pointer-events:none}.guide-bubble{position:fixed;box-sizing:border-box;background:var(--dt-card,#fff);color:var(--dt-text);border:1px solid var(--dt-border);border-radius:16px;box-shadow:0 16px 64px #0005;padding:18px 20px;overflow-y:auto;overscroll-behavior:contain;touch-action:pan-y;outline:none}.guide-heading{display:flex;align-items:center;justify-content:space-between;gap:12px;color:var(--dt-muted);font-size:12px}.guide-heading button{width:32px;height:32px;background:transparent;border:0;border-radius:8px;font-size:24px;color:var(--dt-muted);cursor:pointer}.guide-bubble h2{font-size:18px;line-height:1.5;color:var(--dt-text);margin:10px 0}.guide-description{font-size:14px;line-height:1.8;white-space:pre-line;overflow-wrap:anywhere;margin:0 0 16px}.guide-unavailable{font-size:12px;line-height:1.6;background:var(--dt-fill);color:var(--dt-muted);padding:9px 12px;border-radius:8px}.guide-mascot{float:right;width:110px;height:135px;object-fit:contain;margin:4px 0 10px 14px;pointer-events:none}.guide-mascot.face-right{transform:scaleX(-1)}.guide-contents{clear:both;border-top:1px solid var(--dt-border);padding-top:12px;margin-bottom:14px;color:var(--dt-muted);font-size:12px}.guide-contents summary{cursor:pointer;padding:4px 0}.guide-contents button{display:block;width:100%;text-align:left;background:none;border:0;color:var(--dt-muted);padding:7px;border-radius:6px;cursor:pointer}.guide-contents button.active{background:var(--dt-fill);color:var(--dt-text)}.guide-actions{display:flex;align-items:center;gap:8px}.guide-actions span{flex:1;font-size:10px;color:var(--dt-muted);text-align:center}.guide-actions button{border:1px solid var(--dt-control-border);background:var(--dt-card);border-radius:8px;padding:7px 12px;min-height:36px;color:var(--dt-text);cursor:pointer}.guide-actions button.primary{background:var(--dt-action);color:#fff;border-color:var(--dt-action)}.guide-actions button:disabled{opacity:.45;cursor:default}@media(prefers-reduced-motion:reduce){.page-guide *{scroll-behavior:auto!important}}
</style>
