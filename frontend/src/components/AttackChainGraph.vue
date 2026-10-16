<template>
  <div class="chain-explorer" data-testid="chain-explorer">
    <div class="graph-toolbar">
      <span class="graph-caption"><NodeIndexOutlined /> {{ t('chainView.recordedFlow') }} <b>{{ layout.stepCount }}</b></span>
      <span class="graph-tools"><button @click="zoom(.8)" :aria-label="t('chainView.zoomOut')">−</button><output>{{ Math.round(scale*100) }}%</output>
        <button @click="zoom(1.25)" :aria-label="t('chainView.zoomIn')">+</button><button @click="fit" data-testid="chain-fit">{{ t('chainView.fit') }}</button></span>
    </div>
    <div class="graph-layout">
      <div ref="canvas" class="graph-viewport" tabindex="0" :aria-label="t('chainView.canvasHelp')" data-testid="chain-canvas"
        @pointerdown="begin" @pointermove="move" @pointerup="end" @pointercancel="end" @lostpointercapture="end" @wheel.prevent="wheel" @keydown="key">
        <svg v-if="layout.nodes.length" width="100%" height="100%" data-testid="chain-svg">
          <defs><pattern :id="gridId" width="20" height="20" patternUnits="userSpaceOnUse"><circle cx="1" cy="1" r=".7" fill="var(--dt-border-strong)" opacity=".4" /></pattern>
            <marker :id="arrowId" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse"><path d="M 0 0 L 10 5 L 0 10 z" fill="var(--dt-muted)" /></marker></defs>
          <rect width="100%" height="100%" :fill="`url(#${gridId})`" />
          <g :transform="`translate(${pan.x},${pan.y}) scale(${scale})`" data-testid="chain-transform">
            <path v-for="edge in layout.edges" :key="edge.id" :d="edge.path" class="flow-edge" :class="{'cross-session':edge.crossSession}"
              :marker-end="`url(#${arrowId})`" data-testid="chain-edge"><title>{{ t(edge.crossSession?'chainView.crossSessionOrder':'chainView.recordOrder') }}</title></path>
            <g v-for="node in layout.nodes" :key="node.id" :transform="`translate(${node.x},${node.y})`" class="chain-node"
              :class="['node-'+node.severity,{selected:selectedId===node.id}]" role="button" tabindex="0" :aria-label="nodeTitle(node)"
              :data-node-id="node.id" @click.stop="select(node)" @keydown.enter.stop="select(node)" @keydown.space.prevent.stop="select(node)">
              <rect :width="NODE_WIDTH" :height="NODE_HEIGHT" rx="12" />
              <foreignObject x="12" y="10" :width="NODE_WIDTH-24" :height="NODE_HEIGHT-20">
                <div class="node-content" xmlns="http://www.w3.org/1999/xhtml">
                  <div class="node-meta"><span>{{ node.kind==='step'?t('chainView.step',{n:node.seq}):t('chainView.'+node.kind) }}</span>
                    <span class="node-level">{{ node.kind==='step'?node.severity.toUpperCase():node.kind==='end'?t('chainView.closedRecord'):t('chainView.scope') }}</span></div>
                  <span v-if="node.step?.intranet_breakthrough" class="intranet-entry">{{ t('revision17.intranetEntry') }}</span><strong class="node-title" :title="nodeTitle(node)">{{ nodeTitle(node) }}</strong>
                  <div v-if="node.step?.action && node.step.action!==nodeTitle(node)" class="node-summary">{{ node.step.action }}</div>
                  <div class="node-target" :title="node.step?.target || chain?.unit">{{ node.step?.target || node.target || chain?.unit || '—' }}</div>
                  <div class="node-footer"><span v-if="node.step?.session_id" :title="node.step.session_id"><BranchesOutlined /> {{ t('chainView.sourceSession',{n:sourceNumber(node.step.session_id)}) }}</span>
                    <span v-if="node.step?.finding_ref || node.step?.clue_ref"><FileSearchOutlined /> {{ t('chainView.reference') }}</span></div>
                </div>
              </foreignObject>
            </g>
          </g>
        </svg>
        <a-empty v-else :description="t('chainView.empty')" />
        <span class="canvas-hint">{{ t('chainView.canvasHelp') }}</span>
      </div>
      <aside class="node-details" data-testid="chain-node-details">
        <div class="detail-kicker">{{ t('chainView.details') }}</div>
        <nav class="step-selector" :aria-label="t('chainView.steps')"><button v-for="node in layout.nodes" :key="node.id"
          :class="{active:selectedId===node.id}" @click="focus(node)" :data-step-picker="node.id">{{ node.kind==='step'?t('chainView.step',{n:node.seq}):t('chainView.'+node.kind) }}</button></nav>
        <template v-if="selected">
          <h3>{{ nodeTitle(selected) }}</h3>
          <dl><template v-for="field in fields" :key="field.label"><dt>{{ t('chainView.'+field.label) }}</dt><dd><CopyText v-if="field.copy" :text="field.value" /><span v-else>{{ field.value }}</span></dd></template></dl>
        </template>
        <a-empty v-else :description="t('chainView.empty')" />
        <p class="relation-note">{{ t('chainView.orderNotice') }}</p>
      </aside>
    </div>
  </div>
</template>
<script setup lang="ts">
import { computed,ref,reactive,watch,onMounted,onUnmounted,nextTick,getCurrentInstance } from 'vue'
import { NodeIndexOutlined,BranchesOutlined,FileSearchOutlined } from '@ant-design/icons-vue'
import { t } from '../i18n'
import CopyText from './CopyText.vue'
import type { AttackChain } from '../api/intel'
import { buildChainLayout,NODE_WIDTH,NODE_HEIGHT,type ChainNode } from '../utils/chainGraph'
const props=defineProps<{chain:AttackChain|null}>()
const uid=getCurrentInstance()?.uid ?? 0,gridId=`chain-grid-${uid}`,arrowId=`chain-arrow-${uid}`
const canvas=ref<HTMLElement|null>(null),pan=reactive({x:18,y:18}),scale=ref(1),selectedId=ref('')
const canvasWidth=ref(0),columns=computed(()=>canvasWidth.value>=1044?3:canvasWidth.value>=708?2:1)
const layout=computed(()=>buildChainLayout(props.chain,columns.value)),selected=computed(()=>layout.value.nodes.find(n=>n.id===selectedId.value))
let observer:ResizeObserver|undefined,autoFit=true,drag:{id:number;x:number;y:number;px:number;py:number}|undefined
function sourceNumber(id:string){return [...new Set(layout.value.nodes.map(n=>n.step?.session_id).filter(Boolean))].indexOf(id)+1}
function nodeTitle(node:ChainNode){return node.kind==='step'?String(node.step?.vuln_type || node.step?.action || t('chainView.unnamed')):node.kind==='entry'?node.label || props.chain?.unit || t('chainView.entry'):t('chainView.closedRecord')}
const fields=computed(()=>{
  const node=selected.value,s=node?.step
  if(!node)return []
  const values=[{label:'action',value:s?.action},{label:'target',value:s?.target||node.target,copy:true},{label:'result',value:s?.result},
    {label:'session',value:s?.session_id,copy:true},{label:'finding',value:s?.finding_ref,copy:true},{label:'clue',value:s?.clue_ref,copy:true},{label:'time',value:s?.at}]
  return values.filter(v=>v.value!=null && v.value!=='').map(v=>({...v,value:String(v.value)}))
})
function fit(){const el=canvas.value;if(!el)return;autoFit=true;scale.value=Math.max(.45,Math.min(1,(el.clientWidth-36)/layout.value.width));pan.x=18;pan.y=18}
function zoom(factor:number,x?:number,y?:number){const el=canvas.value;if(!el)return;autoFit=false;const a=x??el.clientWidth/2,b=y??el.clientHeight/2,next=Math.max(.08,Math.min(2.5,scale.value*factor));pan.x=a-(a-pan.x)*next/scale.value;pan.y=b-(b-pan.y)*next/scale.value;scale.value=next}
function select(node:ChainNode){selectedId.value=node.id}
function focus(node:ChainNode){select(node);autoFit=false;const el=canvas.value;if(!el)return;scale.value=Math.min(1.1,Math.max(.45,(el.clientWidth-48)/NODE_WIDTH));pan.x=(el.clientWidth-NODE_WIDTH*scale.value)/2-node.x*scale.value;pan.y=24-node.y*scale.value}
function begin(event:PointerEvent){if(event.button!==0 || (event.target as Element).closest('.chain-node'))return;event.preventDefault();autoFit=false;drag={id:event.pointerId,x:event.clientX,y:event.clientY,px:pan.x,py:pan.y};canvas.value?.setPointerCapture(event.pointerId)}
function move(event:PointerEvent){if(drag && drag.id===event.pointerId){pan.x=drag.px+event.clientX-drag.x;pan.y=drag.py+event.clientY-drag.y}}
function end(){if(drag && canvas.value?.hasPointerCapture(drag.id))canvas.value.releasePointerCapture(drag.id);drag=undefined}
function wheel(event:WheelEvent){if(event.ctrlKey || event.metaKey){const r=canvas.value!.getBoundingClientRect();zoom(Math.exp(-Math.max(-100,Math.min(100,event.deltaY))*.002),event.clientX-r.left,event.clientY-r.top)}else{autoFit=false;pan.x-=event.deltaX;pan.y-=event.deltaY}}
function key(event:KeyboardEvent){if(event.target!==canvas.value)return;const d:Record<string,number[]>={ArrowLeft:[32,0],ArrowRight:[-32,0],ArrowUp:[0,32],ArrowDown:[0,-32]};if(d[event.key]){event.preventDefault();autoFit=false;pan.x+=d[event.key][0];pan.y+=d[event.key][1]}else if(event.key==='+'||event.key==='='){event.preventDefault();zoom(1.2)}else if(event.key==='-'){event.preventDefault();zoom(.8)}}
watch(()=>props.chain,()=>{selectedId.value=layout.value.nodes.find(n=>n.kind==='step')?.id || '';void nextTick().then(fit)})
onMounted(()=>{
  observer=new ResizeObserver(()=>{
    const previous=columns.value;canvasWidth.value=canvas.value?.clientWidth || 0
    void nextTick().then(()=>{if(autoFit)fit();else if(previous!==columns.value&&selected.value)focus(selected.value)})
  })
  if(canvas.value){canvasWidth.value=canvas.value.clientWidth;observer.observe(canvas.value)}
  selectedId.value=layout.value.nodes.find(n=>n.kind==='step')?.id || '';void nextTick().then(fit)
})
onUnmounted(()=>{end();observer?.disconnect()})
</script>
<style scoped>
.intranet-entry{display:block;color:var(--dt-primary);font-size:11px;font-weight:700;line-height:16px}.node-content:has(.intranet-entry) .node-summary{display:none}
.chain-explorer{height:min(68vh,680px);min-height:320px;display:flex;flex-direction:column;background:var(--dt-card);color:var(--dt-text)}
.graph-toolbar{display:flex;align-items:center;justify-content:space-between;gap:12px;padding:12px 16px;border-bottom:1px solid var(--dt-border);flex-wrap:wrap}.graph-caption{display:flex;align-items:center;gap:8px;font-weight:600}.graph-caption>b{font-size:12px;color:var(--dt-muted);background:var(--dt-fill);padding:2px 8px;border-radius:12px}.graph-tools{display:flex;align-items:center;gap:6px}.graph-tools button{border:1px solid var(--dt-control-border);background:var(--dt-card);color:var(--dt-text);border-radius:6px;padding:4px 9px;min-height:30px;cursor:pointer}.graph-tools output{min-width:48px;text-align:center;font-size:12px;color:var(--dt-muted)}
.graph-layout{display:grid;grid-template-columns:minmax(0,1fr) 280px;flex:1;min-height:0}.graph-viewport{position:relative;min-width:0;min-height:0;overflow:hidden;background:var(--dt-bg);touch-action:none;cursor:grab}.graph-viewport:active{cursor:grabbing}.graph-viewport:focus-visible{outline:2px solid var(--dt-primary);outline-offset:-2px}.graph-viewport>.ant-empty{position:absolute;inset:30% 0}.canvas-hint{position:absolute;bottom:10px;left:12px;font-size:11px;pointer-events:none;color:var(--dt-muted);background:var(--dt-card);padding:4px 7px;border-radius:5px;max-width:calc(100% - 24px)}
.flow-edge{fill:none;stroke:var(--dt-muted);stroke-width:2;stroke-opacity:.75}.flow-edge.cross-session{stroke-dasharray:6 4}.chain-node{cursor:pointer;outline:none}.chain-node>rect{fill:var(--dt-card);stroke:var(--dt-border-strong);stroke-width:1.4}.chain-node.selected>rect,.chain-node:focus-visible>rect{stroke:var(--dt-primary);stroke-width:3}.chain-node.node-critical>rect,.chain-node.node-high>rect{stroke:var(--dt-danger)}.chain-node.node-medium>rect{stroke:var(--dt-warning)}.chain-node.node-end>rect{stroke:var(--dt-success)}
.node-content{display:flex;flex-direction:column;height:100%;color:var(--dt-text);font-family:var(--dt-font)}.node-meta{display:flex;justify-content:space-between;gap:6px;font-size:11px;color:var(--dt-muted);margin-bottom:8px}.node-level{font-size:10px;border-radius:4px;padding:1px 5px;background:var(--dt-fill)}.node-high .node-level,.node-critical .node-level{background:var(--dt-danger-soft);color:var(--dt-danger)}.node-title{font-size:14px;line-height:1.5;display:-webkit-box;-webkit-line-clamp:2;-webkit-box-orient:vertical;overflow:hidden;overflow-wrap:anywhere}.node-summary{font-size:11px;line-height:1.4;display:-webkit-box;-webkit-line-clamp:1;-webkit-box-orient:vertical;overflow:hidden;overflow-wrap:anywhere;color:var(--dt-muted);margin-top:4px;flex-shrink:0}.node-target{font-family:var(--dt-mono);font-size:10px;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;color:var(--dt-muted);margin-top:7px}.node-footer{margin-top:auto;display:flex;gap:10px;justify-content:space-between;font-size:10px;color:var(--dt-muted)}.node-footer>span{display:flex;align-items:center;gap:4px}
.node-details{border-left:1px solid var(--dt-border);padding:14px;min-height:0;overflow:auto;background:var(--dt-card)}.detail-kicker{font-size:11px;color:var(--dt-cyan);letter-spacing:.08em;text-transform:uppercase;font-weight:600}.step-selector{display:flex;gap:5px;flex-wrap:wrap;padding:10px 0;max-height:126px;overflow:auto}.step-selector button{padding:3px 7px;border:1px solid var(--dt-border);border-radius:5px;background:var(--dt-fill);color:var(--dt-muted);font-size:11px;cursor:pointer}.step-selector button.active{border-color:var(--dt-primary);color:var(--dt-primary)}.node-details h3{font-size:15px;margin:6px 0 14px;overflow-wrap:anywhere}.node-details dl{margin:0}.node-details dt{color:var(--dt-muted);font-size:11px;margin-top:12px}.node-details dd{margin:4px 0 0;font-size:12px;line-height:1.7;white-space:pre-wrap;overflow-wrap:anywhere}.relation-note{font-size:11px;line-height:1.7;color:var(--dt-muted);border-top:1px solid var(--dt-border);padding-top:12px;margin-top:16px}
@media(max-width:780px){.chain-explorer{height:75vh;min-height:280px}.graph-layout{grid-template-columns:minmax(0,1fr);grid-template-rows:minmax(180px,1fr) minmax(120px,.55fr)}.node-details{border-left:0;border-top:1px solid var(--dt-border);padding:10px 12px}.step-selector{max-height:66px}.canvas-hint{font-size:10px}.graph-toolbar{padding:9px 12px;gap:8px}}
</style>
