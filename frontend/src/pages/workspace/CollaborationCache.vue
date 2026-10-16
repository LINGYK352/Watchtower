<template>
  <a-modal :open="open" :title="t(nodesView?'teamCache.nodes':'teamCache.title')" :width="820" :footer="null" :destroy-on-close="true" @cancel="close" data-testid="cache-settings">
    <a-alert v-if="error" :message="error" type="error" show-icon class="cache-alert" />
    <a-spin :spinning="loading">
      <section v-if="groupId && !nodesView" class="cache-section">
        <h3>{{ t('teamCache.mode') }}</h3>
        <a-radio-group v-model:value="policy.mode" :disabled="!host || busy || loading || !loaded" class="mode-options" data-testid="cache-mode">
          <a-radio value="realtime"><strong>{{ t('teamCache.realtime') }}</strong><span>{{ t('teamCache.realtimeNote') }}</span></a-radio>
          <a-radio value="hosted"><strong>{{ t('teamCache.hosted') }}</strong><span>{{ t('teamCache.hostedNote') }}</span></a-radio>
        </a-radio-group>
        <a-form layout="vertical" @submit.prevent="save" class="cache-form">
          <a-form-item :label="t('teamCache.node')"><a-select v-model:value="policy.node_id" :disabled="!host || busy || loading || !loaded" data-testid="cache-node"><a-select-option value="">{{ t('teamCache.noNode') }}</a-select-option><a-select-option v-for="node in nodes" :key="node._id" :value="node._id">{{ node.name }} · {{ node.mode==='cache'?t('teamCache.hostingReady'):t('teamCache.relayOnly') }}</a-select-option></a-select></a-form-item>
          <div class="cache-fields"><a-form-item :label="t('teamCache.pendingDays')"><a-input-number v-model:value="policy.pending_days" :min="1" :max="90" :precision="0" :disabled="!host || busy || loading || !loaded" /></a-form-item><a-form-item :label="t('teamCache.receivedHours')"><a-input-number v-model:value="policy.received_hours" :min="1" :max="168" :precision="0" :disabled="!host || busy || loading || !loaded" /></a-form-item><a-form-item :label="t('teamCache.sharedDays')"><a-input-number v-model:value="policy.shared_days" :min="1" :max="90" :precision="0" :disabled="!host || busy || loading || !loaded" /></a-form-item><a-form-item :label="t('teamCache.groupQuota')"><a-input-number v-model:value="groupMiB" :min="64" :max="65536" :precision="0" :disabled="!host || busy || loading || !loaded" /></a-form-item><a-form-item :label="t('teamCache.senderQuota')"><a-input-number v-model:value="senderMiB" :min="64" :max="groupMiB || 64" :precision="0" :disabled="!host || busy || loading || !loaded" /></a-form-item></div>
          <a-alert :message="t('teamCache.limits')" :description="t('teamCache.receiptsNote')" type="info" show-icon class="cache-alert" />
          <p class="cache-muted">{{ t('teamCache.changeNote') }}</p><a-button v-if="host" type="primary" :disabled="!loaded" :loading="busy" html-type="submit" data-testid="save-cache-policy">{{ t('common.save') }}</a-button>
        </a-form>
      </section>
      <section v-if="nodesView && host && groupId" class="cache-section">
        <div class="cache-title"><h3>{{ t('teamCache.nodes') }}</h3><a-space wrap><a-button :loading="downloading" @click="download" data-testid="download-node-tool">{{ t('teamCache.download') }}</a-button><a-button :disabled="busy || loading || !loaded" @click="adding=!adding" data-testid="add-node">{{ t('teamCache.addNode') }}</a-button></a-space></div>
        <a-alert :message="t('teamCache.nodeNote')" type="info" show-icon class="cache-alert" />
        <p class="cache-muted">{{ t('nodeHealth.liveNote') }}</p><a-empty v-if="!nodes.length && !adding" :description="t('teamCache.emptyNodes')" />
        <div v-for="node in nodes" :key="node._id" class="node-row"><div><strong>{{ node.name }}</strong><p>{{ node.url }}</p><span>{{ node.mode==='cache'?t('teamCache.hostingReady'):t('teamCache.relayOnly') }}</span><div class="node-health" data-testid="node-health" :data-node-id="node._id"><a-tag :color="node.health?.state==='healthy'?'green':node.health?.state==='unhealthy'?'red':node.health?.state==='checking'?'blue':'default'">{{ t('nodeHealth.states.'+(node.health?.state||'unknown')) }}</a-tag><span v-if="node.health?.latency_ms!==null && node.health?.latency_ms!==undefined">{{ node.health.latency_ms }} ms</span><span>{{ t('nodeHealth.checked') }} {{ date(node.health?.checked_at) }}</span><p v-if="node.health?.reason">{{ t('nodeHealth.reasons.'+node.health.reason) }}</p></div></div><a-popconfirm :title="t('teamCache.deleteConfirm')" @confirm="remove(node._id)"><a-button danger :disabled="busy || loading || !loaded" data-testid="delete-node">{{ t('control.delete') }}</a-button></a-popconfirm></div>
        <a-form v-if="adding" layout="vertical" @submit.prevent="add" class="cache-form" data-testid="node-form"><a-form-item :label="t('control.name')" required><a-input v-model:value="nodeDraft.name" :maxlength="80" :disabled="busy || loading || !loaded" /></a-form-item><a-form-item :label="t('teamCache.nodeAddress')" required><a-input v-model:value="nodeDraft.url" placeholder="https://node.example.com:7443" :disabled="busy || loading || !loaded" data-testid="node-url" /></a-form-item><a-form-item :label="t('teamCache.tlsFingerprint')"><a-input v-model:value="nodeDraft.tls_fingerprint" :maxlength="64" :disabled="busy || loading || !loaded" /></a-form-item><a-form-item :label="t('teamCache.nodeCredential')" required><a-input-password v-model:value="nodeDraft.admin_key" autocomplete="off" :disabled="busy || loading || !loaded" data-testid="node-admin-key" /></a-form-item><p class="cache-muted">{{ t('teamCache.deployNote') }}</p><a-button type="primary" html-type="submit" :loading="busy" data-testid="connect-node">{{ t('teamCache.connect') }}</a-button></a-form>
      </section>
      <section v-if="groupId && !nodesView" class="cache-section"><h3>{{ t('teamCache.deliveries') }}</h3><a-empty v-if="!tasks.length" :description="t('teamCache.emptyTasks')" /><div v-for="task in tasks" :key="task.item_id" class="delivery-row"><div><strong>{{ t('team.kinds.'+task.kind) }} · {{ (task.bytes/1048576).toFixed(2) }} MiB</strong><p>{{ task.item_id }}</p><a-tag :color="['queued','paused'].includes(task.state)?'gold':undefined">{{ t('teamCache.states.'+task.state) }}</a-tag><span v-if="task.recipient_count">{{ task.received_count || 0 }}/{{ task.recipient_count }} {{ t('teamCache.received') }}</span><p v-if="task.error" role="status">{{ task.error }}</p><span>{{ t('teamCache.expires') }} {{ date(task.expires_at) }}</span></div><a-space wrap v-if="!['delivered','cancelled','expired'].includes(task.state)"><a-button @click="taskAction(task,'retry')" :disabled="busy || loading || !loaded">{{ t('teamCache.retry') }}</a-button><a-button @click="taskAction(task,'pause')" :disabled="busy || task.state==='paused'">{{ t('teamCache.pause') }}</a-button><a-button @click="taskAction(task,'reroute')" :disabled="busy || loading || !loaded">{{ t('teamCache.reroute') }}</a-button><a-popconfirm :title="t('teamCache.cancelConfirm')" @confirm="taskAction(task,'cancel')"><a-button danger :disabled="busy || loading || !loaded">{{ t('common.cancel') }}</a-button></a-popconfirm></a-space></div></section>
    </a-spin>
  </a-modal>
</template>
<script setup lang="ts">
import {ref,reactive,watch,onUnmounted,computed,onMounted} from 'vue'
import {message} from 'ant-design-vue'
import {request} from '../../api/request'
import {downloadMaintenanceNode} from '../../api/nodeTool'
import {t,appLocale} from '../../i18n'
const props=defineProps<{open:boolean;groupId?:string;host:boolean;view?:'cache'|'nodes'}>(),emit=defineEmits(['close','saved'])
const root='/api/collaboration'
const nodesView=computed(()=>props.view==='nodes'),loaded=ref(false)
let polling=false
const loading=ref(false),busy=ref(false),error=ref(''),nodes=ref<any[]>([]),tasks=ref<any[]>([]),adding=ref(false),downloading=ref(false)
const policy=reactive({mode:'realtime',node_id:'',pending_days:7,received_hours:24,shared_days:30}),groupMiB=ref<number|null>(512),senderMiB=ref<number|null>(128)
const nodeDraft=reactive({name:'',url:'',tls_fingerprint:'',admin_key:''})
let serial=0,timer:ReturnType<typeof setInterval>|undefined,disposed=false
const post=(path:string,data:unknown={})=>request<any>(root+path,{method:'POST',body:JSON.stringify(data)})
const date=(v?:number)=>v?new Date(v*1000).toLocaleString(appLocale.value):'—'
async function load(){const n=++serial;loading.value=true;loaded.value=false;try{const list=(props.host && props.groupId)?await request<any>(root+'/nodes?group_id='+encodeURIComponent(props.groupId)+(nodesView.value?'&health=1':'')):{items:[]};const detail=props.groupId?await request<any>(root+'/groups/'+props.groupId+'/cache'):null;if(disposed || n!==serial || !props.open)return;nodes.value=list.items || [];if(detail){Object.assign(policy,detail.policy);groupMiB.value=detail.policy.group_quota/1048576;senderMiB.value=detail.policy.sender_quota/1048576;tasks.value=detail.delivery.items || [];loaded.value=true}}catch(e){if(n===serial)error.value=(e as Error).message}finally{if(n===serial)loading.value=false}}
async function action(fn:()=>Promise<unknown>){if(busy.value || loading.value || !loaded.value)return;busy.value=true;error.value='';try{await fn()}catch(e){error.value=(e as Error).message}finally{busy.value=false}}
const save=()=>action(async()=>{await post('/groups/'+props.groupId+'/cache',{...policy,group_quota:(groupMiB.value || 0)*1048576,sender_quota:(senderMiB.value || 0)*1048576});message.success(t('teamCache.saved'));emit('saved');await load()})
const add=()=>action(async()=>{await post('/nodes',{...nodeDraft,group_id:props.groupId});nodeDraft.admin_key='';adding.value=false;await load()})
const remove=(id:string)=>action(async()=>{await post('/nodes/'+id+'/delete',{confirmed:true});await load()})
const taskAction=(task:any,name:string)=>action(async()=>{await post('/groups/'+props.groupId+'/deliveries/'+task.item_id+'/'+name);await load();emit('saved')})
async function download(){if(downloading.value)return;downloading.value=true;error.value='';try{await downloadMaintenanceNode()}catch(e){error.value=(e as Error).message}finally{downloading.value=false}}
function close(){if(busy.value)return;serial++;nodeDraft.admin_key='';adding.value=false;emit('close')}
async function poll(){
 if(polling || !props.open || !props.groupId || busy.value || document.hidden || !loaded.value)return
 const n=serial,gid=props.groupId;polling=true
 try{if(nodesView.value){const result=await request<any>(root+'/nodes?group_id='+encodeURIComponent(gid)+'&health=1');if(!disposed && props.open && n===serial && props.groupId===gid){nodes.value=result.items||[];error.value=''}}else{const result=await request<any>(root+'/groups/'+gid+'/deliveries');if(!disposed && props.open && n===serial && props.groupId===gid)tasks.value=result.items||[]}}
 catch(e){if(n===serial && props.open)error.value=(e as Error).message}finally{polling=false}
}
function resume(){if(!document.hidden)void poll()}
watch(()=>[props.open,props.groupId,props.view] as const,([value])=>{serial++;loaded.value=false;nodes.value=[];tasks.value=[];nodeDraft.admin_key='';adding.value=false;if(timer)clearInterval(timer);if(value){error.value='';void load();timer=setInterval(()=>void poll(),nodesView.value?5000:3000)}else nodeDraft.admin_key=''},{immediate:true})
onMounted(()=>document.addEventListener('visibilitychange',resume))
onUnmounted(()=>{document.removeEventListener('visibilitychange',resume);disposed=true;serial++;nodeDraft.admin_key='';if(timer)clearInterval(timer)})
</script>
<style scoped>
.cache-section{padding:10px 0 22px;border-bottom:1px solid var(--dt-border)}.cache-section:last-child{border-bottom:0}.cache-section h3{color:var(--dt-text);font-size:16px;margin:5px 0 14px}.cache-title{display:flex;justify-content:space-between;align-items:center;gap:12px;flex-wrap:wrap}.mode-options{display:grid;grid-template-columns:1fr 1fr;gap:12px;width:100%;margin-bottom:18px}.mode-options :deep(.ant-radio-wrapper){border:1px solid var(--dt-border);border-radius:10px;padding:14px;margin:0;align-items:flex-start}.mode-options strong,.mode-options span span{display:block}.mode-options :deep(.ant-radio-wrapper>span:last-child>span){display:block;color:var(--dt-muted);font-size:12px;line-height:1.7;margin-top:7px}.cache-fields{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:0 14px}.cache-form :deep(.ant-input-number){width:100%}.cache-form{margin-top:14px}.cache-muted,.node-row p,.node-row span,.delivery-row p,.delivery-row span{color:var(--dt-muted);font-size:12px;overflow-wrap:anywhere}.node-health{display:flex;flex-wrap:wrap;gap:6px 12px;align-items:center;margin-top:8px}.node-health p{width:100%;margin:0}.cache-alert{margin-bottom:14px}.node-row,.delivery-row{display:flex;justify-content:space-between;align-items:center;gap:16px;padding:14px 0;border-bottom:1px solid var(--dt-border)}.node-row p,.delivery-row p{margin:6px 0}.delivery-row{align-items:flex-start}.delivery-row>div{min-width:0}.delivery-row :deep(.ant-space){flex-shrink:0;max-width:45%}@media(max-width:640px){.mode-options,.cache-fields{grid-template-columns:1fr}.delivery-row{flex-direction:column}.delivery-row :deep(.ant-space){max-width:100%}}
</style>

