<template>
  <div class="page-container control-sync" data-testid="control-sync-page">
    <div class="page-heading"><div><div class="page-kicker">WATCHTOWER CONNECT</div><h1>{{ t('control.title') }}</h1><p :title="t('control.subtitle')" class="page-description">{{ t('control.subtitle') }}</p></div><a-button :loading="loading" @click="load()">{{ t('control.refresh') }}</a-button></div>
    <a-alert v-if="error" type="error" :message="error" show-icon closable @close="error = ''" class="page-alert" />
    <a-tabs v-model:activeKey="tab">
      <a-tab-pane key="control" :tab="t('control.controlTab')">
        <a-card class="page-card" :title="t('control.keyList')" data-testid="control-keys-card">
          <template #extra><a-button type="primary" :disabled="working" @click="openControlCreate" data-testid="open-control-key-create">{{ t('control.createControl') }}</a-button></template>
          <a-table :data-source="state.keys" :columns="keyColumns" row-key="_id" :scroll="{ x: 780 }" :pagination="{ pageSize: 10 }"><template #bodyCell="{ column, record }">
          <template v-if="column.key === 'expiry'">{{ date(record.expires_at) }}</template>
          <template v-else-if="column.key === 'state'"><a-tag :color="keyStatus(record) === 'active' ? 'green' : 'default'">{{ t('control.states.' + keyStatus(record)) }}</a-tag></template>
          <template v-else-if="column.key === 'actions'"><a-space><a-popconfirm :title="t('control.revokeConfirm')" @confirm="revokeKey(record._id)"><a-button danger size="small" :disabled="record.revoked">{{ t('control.revoke') }}</a-button></a-popconfirm><a-popconfirm :title="t('control.deleteConfirm')" @confirm="deleteKey(record._id)"><a-button danger size="small" data-testid="delete-control-key">{{ t('control.delete') }}</a-button></a-popconfirm></a-space></template>
        </template></a-table></a-card>
        <a-card class="page-card" :title="t('control.manual')" data-testid="control-operation-guide">
          <p>{{ t('control.controlNote') }}</p>
          <div class="connect-grid operation-guide-grid">
            <section data-testid="control-http-guide"><h3>{{ t('control.httpAccess') }}</h3>
              <div class="connect-endpoint">{{ endpoint }}</div><p>{{ t('control.manualNote') }}</p>
              <a-alert type="info" :message="t('control.reachableAddressNote')" show-icon /><pre class="connect-code">{{ httpExample }}</pre>
              <a-typography-paragraph :copyable="{ text: endpoint }">{{ t('control.copyEndpoint') }}</a-typography-paragraph>
            </section>
            <section data-testid="control-mcp-guide"><h3>{{ t('control.mcpAccess') }}</h3>
              <p>{{ t('control.mcpClientNote') }}</p><div class="connect-endpoint">{{ mcpEndpoint }}</div><pre class="connect-code">{{ clientConfig }}</pre>
              <p>{{ t('control.protocolNote') }}</p>
            </section>
          </div>
        </a-card>
      </a-tab-pane>
      <a-tab-pane key="sync" :tab="t('control.syncTab')">
        <a-alert type="info" show-icon :message="t('control.syncNote')" class="page-alert" />
        <a-alert v-if="mode==='overwrite' && state.admission?.blocked" type="warning" show-icon class="page-alert" data-testid="sync-admission-blocked" :message="syncBlockerTitle"><template #description><p>{{ syncBlockerText }}</p><a-space wrap><a-button v-for="item in syncBlockerLinks" :key="item.kind" size="small" @click="router.push(item.path)" :data-testid="'sync-blocker-'+item.kind">{{ t(item.label) }}</a-button></a-space></template></a-alert>
        <a-card v-if="state.listener?.available" class="page-card" :title="t('control.listenerTitle')">
          <p>{{ t('control.listenerNote') }}</p><a-alert v-if="state.listener.firewall?.state==='blocked'" type="warning" show-icon :message="t('repair128.firewallBlocked')" :description="t('repair128.firewallNote')" data-testid="receiver-firewall-blocked" style="margin-bottom:14px" /><a-space wrap><a-input-number v-model:value="listenerPort" :min="1" :max="65535" data-testid="peer-listener-port" /><a-button :loading="working" @click="setListener(!state.listener?.enabled)" data-testid="peer-listener-toggle">{{ t(state.listener?.enabled ? 'control.disableListener' : 'control.enableListener') }}</a-button><a-tag :color="state.listener.running ? 'green' : 'default'">{{ t(state.listener.running ? 'control.listenerActive' : 'control.listenerInactive') }}</a-tag></a-space>
          <div v-if="state.listener.running" class="target-history"><a-typography-paragraph v-for="address in state.listener.targets" :key="address" :copyable="{ text: address }">{{ address }}</a-typography-paragraph></div><a-alert v-if="state.listener.error" type="error" :message="state.listener.error" />
        </a-card>
        <div class="connect-grid">
          <a-card class="page-card" :title="t('control.receiveTitle')">
            <a-form layout="vertical" @submit.prevent="createPair">
              <a-form-item :label="t('control.routeMode')"><a-radio-group v-model:value="routeMode" :disabled="working" data-testid="sync-route-mode"><a-radio-button value="direct">{{ t('control.routeDirect') }}</a-radio-button><a-radio-button value="node">{{ t('control.routeNode') }}</a-radio-button></a-radio-group></a-form-item>
              <a-form-item v-if="routeMode==='direct'" :label="t('invitationLink.reachableAddress')" required><a-input v-model:value="publicTarget" :disabled="working" :placeholder="state.listener?.available?'192.168.1.10':'192.168.1.10:5555'" data-testid="sync-public-target" /><p class="connect-muted">{{ t(state.listener?.available?'revision17.receiverAddressNote':'invitationLink.reachableNote') }}</p></a-form-item>
              <section v-else data-testid="sync-node-settings"><a-button type="link" :loading="nodeDownloading" @click="downloadNode" data-testid="sync-download-node">{{ t('teamCache.download') }}</a-button><a-alert type="info" show-icon :message="t('control.nodeNote')" class="page-alert" />
                <a-form-item :label="t('control.nodeUrl')" required><a-input v-model:value="nodeUrl" :disabled="working" placeholder="https://node.example:7443" data-testid="sync-node-url" /></a-form-item>
                <a-form-item :label="t('control.nodeFingerprint')"><a-input v-model:value="nodeFingerprint" :disabled="working" :maxlength="64" autocomplete="off" data-testid="sync-node-fingerprint" /></a-form-item>
                <a-form-item :label="t('control.nodeKey')" required><a-input-password v-model:value="nodeKey" :disabled="working" :maxlength="128" autocomplete="off" data-testid="sync-node-key" /></a-form-item>
              </section>
              <a-form-item :label="t('control.name')" required><a-input v-model:value="pairName" :maxlength="80" /></a-form-item>
              <div class="connect-grid compact"><a-form-item :label="t('control.pairMinutes')" required><a-input-number v-model:value="pairMinutes" :min="1" :max="60" class="full" data-testid="pair-key-expiry" /></a-form-item><a-form-item :label="t('control.linkMinutes')" required><a-input-number v-model:value="linkMinutes" :min="5" :max="129600" class="full" /></a-form-item></div>
              <a-form-item :label="t('control.allowedCategories')" required><a-checkbox-group v-model:value="pairCategories" :options="categoryOptions" class="permission-list" /></a-form-item>
              <a-button type="primary" :loading="working" html-type="submit" data-testid="create-pair-key">{{ t('control.createPair') }}</a-button>
            </a-form>
          </a-card>
          <a-card class="page-card" :title="t('control.connectTitle')">
            <a-form layout="vertical" @submit.prevent="connect"><a-form-item :label="t('invitationLink.pasteLink')"><a-input-password v-model:value="invitationInput" :disabled="working" :maxlength="4096" autocomplete="off" @change="fillInvitation" data-testid="sync-invitation-link" /><p class="connect-muted">{{ t('invitationLink.pasteNote') }}</p></a-form-item>
              <a-tag v-if="nodeDescriptor" color="blue" data-testid="sync-invitation-node">{{ t('control.routeNode') }}</a-tag>
              <a-form-item :label="t('control.target')" required><a-auto-complete v-model:value="target" :options="state.history.map(h => ({ value: h.target, label: h.name + ' · ' + h.target }))" class="full" @select="nodeDescriptor=null"><a-input placeholder="192.168.1.10:5555" data-testid="sync-target" @input="nodeDescriptor=null" /></a-auto-complete></a-form-item>
              <a-form-item :label="t('control.peerKey')" required><a-input-password v-model:value="peerKey" autocomplete="off" data-testid="peer-pair-key" @input="nodeDescriptor=null" /></a-form-item>
              <a-button type="primary" :loading="working" html-type="submit" data-testid="connect-sync-target">{{ t('control.connect') }}</a-button>
            </a-form>
            <div v-if="state.history.length" class="target-history"><div class="connect-muted">{{ t('control.history') }}</div><a-button v-for="h in state.history" :key="h.target" type="link" @click="target = h.target">{{ h.target }}</a-button></div>
          </a-card>
        </div>
        <a-card class="page-card" :title="t('control.links')"><a-table :data-source="state.links" :columns="linkColumns" row-key="_id" :scroll="{ x: 860 }" :pagination="{ pageSize: 8 }"><template #bodyCell="{ column, record }">
          <template v-if="column.key === 'peer'">{{ record.target || record.remote?.name || t('control.waitingPeer') }}<div class="connect-muted">{{ record.remote?.platform }} {{ record.remote?.version }} · {{ t(record.route_mode==='node'?'control.routeNode':'control.routeDirect') }}</div><div v-if="record.node_error" class="connect-muted">{{ record.node_error }}</div><div v-if="record.peer_error" class="connect-muted" data-testid="sync-peer-offline"><a-tag color="gold">{{ t('invitationLink.peerUnavailable') }}</a-tag>{{ record.peer_error }} · {{ t('invitationLink.retryAfter') }} {{ date(record.peer_retry_at) }}</div></template>
          <template v-else-if="column.key === 'state'"><a-tag :color="record.state === 'paired' ? 'green' : ['pending','connecting'].includes(record.state) ? 'gold' : 'default'" data-testid="sync-link-state">{{ t('control.states.' + (['pending','connecting'].includes(record.state)?'pending':record.state)) }}</a-tag></template>
          <template v-else-if="column.key === 'expiry'">{{ date(record.connection_expires_at || record.pair_expires_at) }}</template>
          <template v-else-if="column.key === 'actions'"><a-space><a-button size="small" :disabled="record.state !== 'paired'" @click="selectLink(record)" data-testid="sync-direction">{{ t(record.kind==='receiver'?'syncReadiness.receiverHelp':'control.chooseSync') }}</a-button><a-button size="small" danger :disabled="['revoked','rejected','expired'].includes(record.state)" @click="revokeLink(record._id)">{{ t('control.revoke') }}</a-button><a-button danger size="small" :disabled="working" @click="deleteTarget=record;deleteError=''" data-testid="delete-pair-link">{{ t('control.delete') }}</a-button></a-space></template>
        </template></a-table></a-card>
        <a-card v-if="chosenLink" class="page-card" :title="t('control.newTransfer')" data-testid="sync-plan">
          <a-form layout="vertical" @submit.prevent="startTransfer">
            <div class="connect-grid compact"><a-form-item :label="t('control.direction')" required><a-select v-model:value="flow" :options="[{ value: 'push', label: t('control.push') }, { value: 'pull', label: t('control.pull') }]" /></a-form-item><a-form-item :label="t('control.mode')" required><a-select v-model:value="mode" :options="[{ value: 'incremental', label: t('control.incremental') }, { value: 'overwrite', label: t('control.overwrite') }]" /></a-form-item></div>
            <a-form-item :label="t('control.contents')" required><a-checkbox-group v-model:value="syncCategories" :options="chosenLink.categories.map(c => ({ value: c, label: t('control.categories.' + c) }))" class="permission-list" /></a-form-item>
            <p class="connect-muted" data-testid="sync-mode-note">{{ t(mode === 'overwrite' ? 'control.overwriteNote' : 'control.incrementalNote') }}</p>
            <a-button type="primary" :loading="working" html-type="submit" data-testid="request-sync">{{ t('control.requestSync') }}</a-button>
          </a-form>
        </a-card>
        <a-card class="page-card" :title="t('control.transfers')">
          <a-empty v-if="!state.runs.length" :description="t('control.noTransfers')" />
          <div v-for="run in state.runs" :key="run._id" class="sync-history-row" data-testid="sync-run">
            <button class="sync-record-open" @click="selectedRunId=run._id" data-testid="sync-record-open"><span><a-tag :color="run.state==='complete'?'green':run.state==='failed'?'red':'blue'">{{ t('control.states.'+run.state) }}</a-tag><b>{{ runDirection(run) }} · {{ t('control.'+run.mode) }}</b></span><span class="connect-muted">{{ date(run.created_at||0) }} · {{ run._id.slice(0,8) }}</span><span class="connect-muted">{{ run.categories.map(c=>t('control.categories.'+c)).join(' / ') }}</span></button>
            <a-popconfirm :title="t('revision17.deleteSyncNote')" :disabled="!deletable(run)" @confirm="deleteRun(run._id)"><a-button danger size="small" :disabled="working||!deletable(run)" data-testid="delete-sync-record">{{ t('control.delete') }}</a-button></a-popconfirm>
          </div>
        </a-card>
      </a-tab-pane>
    </a-tabs>
    <a-drawer :open="!!selectedRun" :title="t('revision17.syncRecord')" width="min(680px,calc(100vw - 24px))" @close="selectedRunId=''" data-testid="sync-record-detail"><template v-if="selectedRun"><div class="transfer-row" v-for="run in [selectedRun]" :key="run._id"><p class="connect-muted">{{ run._id }} · {{ date(run.created_at||0) }}</p>          <div><a-tag :color="run.state === 'complete' ? 'green' : run.state === 'failed' ? 'red' : 'blue'">{{ t('control.states.' + run.state) }}</a-tag><strong>{{ runDirection(run) }}</strong> · {{ t('control.' + run.mode) }}</div>
          <div class="connect-muted">{{ run.categories.map(c => t('control.categories.' + c)).join(' / ') }} · {{ run.summary?.bytes ? (run.summary.bytes / 1024).toFixed(1) + ' KiB' : '' }}</div>
          <a-progress :percent="run.state === 'complete' ? 100 : run.summary?.bytes ? Math.round((run.transferred_bytes || 0) / run.summary.bytes * 100) : 0" :status="run.state === 'failed' ? 'exception' : run.state === 'complete' ? 'success' : 'active'" />
          <div>{{ run.error || t('control.stages.' + (run.stage || 'ready')) }}</div><div v-if="run.result" class="connect-muted">{{ t('control.result') }} {{ JSON.stringify(run.result) }}</div>
          <a-button v-if="run.kind === 'initiator' && run.state === 'failed'" size="small" @click="retry(run._id)">{{ t('control.retry') }}</a-button>
</div></template></a-drawer>
    <a-modal :open="controlCreateOpen" :title="t('control.createControl')" :footer="null" :width="760" centered :destroy-on-close="true"
      :mask-closable="!working" :keyboard="!working" :closable="!working" :body-style="{ maxHeight: 'calc(100vh - 180px)', overflowY: 'auto' }"
      @cancel="closeControlCreate" data-testid="control-key-create-dialog">
      <a-alert v-if="keyCreateError" type="error" :message="keyCreateError" show-icon class="page-alert" data-testid="control-key-create-error" />
      <a-form class="control-key-create-form" layout="vertical" @submit.prevent="createControl">
        <a-form-item :label="t('control.name')" required><a-input v-model:value="keyName" :maxlength="80" :disabled="working" data-testid="control-key-name" /></a-form-item>
        <a-form-item :label="t('control.validMinutes')" required><a-input-number v-model:value="keyMinutes" :min="1" :max="129600" :disabled="working" class="full" data-testid="control-key-expiry" /></a-form-item>
        <a-form-item :label="t('control.permissions')" required><a-checkbox-group v-model:value="keyScopes" :options="scopeOptions" :disabled="working" class="permission-list" /></a-form-item>
        <a-button type="primary" :loading="working" html-type="submit" data-testid="create-control-key">{{ t('control.create') }}</a-button>
      </a-form>
    </a-modal>
    <a-modal :open="!!revealedKey" :title="t('control.keyCreated')" :destroy-on-close="true" :footer="null" @cancel="revealedKey = ''" data-testid="created-key-dialog">
      <a-alert type="warning" show-icon :message="t('control.showOnce')" /><p>{{ t('control.expiry') }} {{ date(revealedExpiry) }}</p><template v-if="pairLink"><a-textarea :value="pairLink" readonly :rows="3" data-testid="sync-generated-link" /><a-typography-paragraph :copyable="{text:pairLink}">{{ t('invitationLink.copyLink') }}</a-typography-paragraph><a-alert type="info" :message="t('invitationLink.linkSecret')" show-icon /></template><a-input v-if="!pairLink" :value="revealedKey" readonly data-testid="created-key-value" /><a-space style="margin-top:16px"><a-button v-if="!pairLink" type="primary" @click="copyKey">{{ t('control.copy') }}</a-button><a-button @click="revealedKey = ''">{{ t('control.close') }}</a-button></a-space>
    </a-modal>
    <a-modal :open="!!deleteTarget" :title="t('control.deleteLink')" :confirm-loading="working" :mask-closable="!working" :keyboard="!working" :closable="!working" :ok-text="t('control.delete')" :ok-button-props="{danger:true}" @cancel="!working && (deleteTarget=null)" @ok="deleteLink">
      <a-alert v-if="deleteError" :message="deleteError" type="error" show-icon /><p data-testid="delete-pair-confirm">{{ deleteTarget?.name }}</p><p>{{ t('control.deleteLinkNote') }}</p>
    </a-modal>
  </div>
</template>

<script setup lang="ts">
import {suggestedReachable} from '../../utils/networkHint'
import {downloadMaintenanceNode} from '../../api/nodeTool'
import { computed, onMounted, onUnmounted, ref } from 'vue'
import { message, Modal } from 'ant-design-vue'
import {useRouter} from 'vue-router'
import {invitationTarget,syncReceiverTarget,makeInvitationLink,parseInvitationLink,pendingInvitation,clearPendingInvitation} from '../../utils/invitationLink'
import { appLocale, t, localizedError } from '../../i18n'
import { controlSyncApi, type ControlState, type ControlKey, type SyncLink, type SyncRun } from '../../api/controlSync'
const state = ref<ControlState>({ identity: {}, keys: [], links: [], history: [], runs: [], scopes: [], categories: [] })
const selectedRunId=ref(''),selectedRun=computed(()=>state.value.runs.find(run=>run._id===selectedRunId.value)||null)
function runDirection(run:SyncRun){const outgoing=(run.flow==='push')!==(run.kind==='receiver');return t(outgoing?'control.push':'control.pull')}
function deletable(run:SyncRun){return ['complete','rejected','failed','expired'].includes(run.state)}
async function deleteRun(id:string){await action(async()=>{await controlSyncApi.deleteRun(id);if(selectedRunId.value===id)selectedRunId.value=''})}
const nodeDownloading=ref(false)
async function downloadNode(){if(nodeDownloading.value)return;nodeDownloading.value=true;try{await downloadMaintenanceNode()}catch(e){error.value=(e as Error).message}finally{nodeDownloading.value=false}}
const router=useRouter(),publicTarget=ref(''),invitationInput=ref(''),pairLink=ref('')
const routeMode=ref<'direct'|'node'>('direct'),nodeUrl=ref(''),nodeFingerprint=ref(''),nodeKey=ref(''),nodeDescriptor=ref<Record<string,unknown>|null>(null)
const tab = ref('control'), loading = ref(false), working = ref(false), error = ref('')
const deleteTarget=ref<SyncLink|null>(null),deleteError=ref('')
const controlCreateOpen = ref(false), keyCreateError = ref('')
const keyName = ref('MCP'), keyMinutes = ref<number | null>(1440), keyScopes = ref(['system:read', 'assets:read', 'tasks:read', 'findings:read', 'reports:read', 'policies:read'])
const pairName = ref('Watchtower'), pairMinutes = ref<number | null>(10), linkMinutes = ref<number | null>(1440), pairCategories = ref(['assets', 'findings', 'reports', 'policies', 'configuration'])
const target = ref(''), peerKey = ref(''), chosenLink = ref<SyncLink | null>(null), flow = ref('push'), mode = ref('incremental'), syncCategories = ref<string[]>([])
const revealedKey = ref(''), revealedExpiry = ref(0), now = ref(Date.now() / 1000)
const listenerPort = ref<number | null>(5588)
let initialListenerLoaded = false,initialAddressLoaded=false
const endpoint = location.origin + '/api/control_sync/watchtower_operations'
const mcpEndpoint = location.origin + '/api/control_sync/mcp'
const clientConfig = JSON.stringify({ mcpServers: { watchtower: { type: 'http', url: mcpEndpoint, headers: { Authorization: 'Bearer <CONTROL_KEY>' } } } }, null, 2)
const httpExample = 'GET ' + endpoint + '\nAuthorization: Bearer <CONTROL_KEY>\n\nPOST ' + location.origin + '/api/control_sync/watchtower_request\nAuthorization: Bearer <CONTROL_KEY>\nContent-Type: application/json\n\n' + JSON.stringify({ method: 'GET', path: '/api/console/info' }, null, 2)
const scopeOptions = computed(() => state.value.scopes.map(s => ({ value: s, label: t('control.domains.' + s.split(':')[0]) + ' · ' + t('control.' + s.split(':')[1]) })))
const categoryOptions = computed(() => state.value.categories.map(c => ({ value: c, label: t('control.categories.' + c) })))
const keyColumns = computed(() => [{ title: t('control.name'), dataIndex: 'name' }, { title: 'Key', dataIndex: 'prefix' }, { title: t('control.expiry'), key: 'expiry' }, { title: t('control.status'), key: 'state' }, { title: t('control.actions'), key: 'actions' }])
const linkColumns = computed(() => [{ title: t('control.name'), dataIndex: 'name' }, { title: t('control.peer'), key: 'peer' }, { title: t('control.status'), key: 'state' }, { title: t('control.expiry'), key: 'expiry' }, { title: t('control.actions'), key: 'actions' }])
function date(value: number) { return value ? new Date(value * 1000).toLocaleString(appLocale.value) : '—' }
function keyStatus(key: ControlKey) { return key.revoked ? 'revoked' : key.expires_at <= now.value ? 'expired' : 'active' }
let stateSerial=0,disposed=false
async function load(force=false) { if (loading.value && !force) return;const serial=++stateSerial; loading.value = true; try { const result=await controlSyncApi.state();if(disposed || serial!==stateSerial)return;state.value=result; if(chosenLink.value)chosenLink.value=result.links.find(link=>link._id===chosenLink.value?._id && link.state==='paired')||null; if(!initialAddressLoaded){publicTarget.value=result.preferences?.sync_target || suggestedReachable(result.preferences?.local_addresses,result.listener?.available?undefined:Number(location.port|| (location.protocol==='https:'?443:80)));initialAddressLoaded=true} if (!initialListenerLoaded && state.value.listener) { listenerPort.value = state.value.listener.port; initialListenerLoaded = true } } catch (e) { if(!disposed && serial===stateSerial)error.value = (e as Error).message } finally { if(serial===stateSerial)loading.value = false } }
async function action(fn: () => Promise<unknown>) { if (working.value) return; working.value = true; error.value = ''; try { await fn(); await load(true) } catch (e) { error.value = localizedError(e) } finally { working.value = false } }
async function deleteLink(){
 if(working.value || !deleteTarget.value)return
 working.value=true;deleteError.value='';const id=deleteTarget.value._id
 try{const result=await controlSyncApi.deleteLink(id);++stateSerial;state.value.links=state.value.links.filter(link=>link._id!==id);window.dispatchEvent(new CustomEvent('watchtower:sync-link-deleted',{detail:{id}}));if(chosenLink.value?._id===id){chosenLink.value=null;syncCategories.value=[]}revealedKey.value='';deleteTarget.value=null;if(result.peer_notified===false)message.warning(t('control.deleteLinkOffline'));await load(true)}catch(e){if(!disposed)deleteError.value=(e as Error).message}finally{working.value=false}
}
function minutes(value: number | null) { if (value === null || !Number.isInteger(value)) throw new Error(t('control.expiryRequired')); return value * 60 }
function openControlCreate() { if (!working.value) { keyCreateError.value = ''; controlCreateOpen.value = true } }
function closeControlCreate() { if (!working.value) { controlCreateOpen.value = false; keyCreateError.value = '' } }
async function createControl() {
  if (working.value) return
  working.value = true; keyCreateError.value = ''
  try {
    const result = await controlSyncApi.createKey({ name: keyName.value, expires_in: minutes(keyMinutes.value), scopes: keyScopes.value })
    controlCreateOpen.value = false; pairLink.value=''; revealedKey.value = result.key; revealedExpiry.value = result.expires_at
    await load()
  } catch (e) { keyCreateError.value = (e as Error).message }
  finally { working.value = false }
}
const blockerKinds = computed(()=>new Set(state.value.admission?.reasons.map(row=>row.kind)||[]))
const syncBlockerTitle=computed(()=>t('syncReadiness.blocked',{types:[['sessions','sessionBlock'],['tasks','taskBlock'],['schedules','scheduleBlock']].filter(([kind])=>blockerKinds.value.has(kind)).map(([,key])=>t('syncReadiness.'+key)).join(appLocale.value==='en-US'?', ':'、')||t('syncReadiness.unknownBlock')}))
const syncBlockerLinks=computed(()=>[{kind:'sessions',path:'/pentest',label:'syncReadiness.openSessions'},{kind:'tasks',path:'/tasks',label:'syncReadiness.openTasks'},{kind:'schedules',path:'/task-schedule',label:'syncReadiness.openSchedules'}].filter(item=>blockerKinds.value.has(item.kind)))
const syncBlockerText=computed(()=>state.value.admission?.reasons.map(row=>t('syncReadiness.'+row.kind,{count:row.count})+(row.paused?t('syncReadiness.paused',{count:row.paused}):'')).join('；')+' '+t('syncReadiness.keepWork'))
const createPair=()=>action(async()=>{
 if(routeMode.value==='direct' && state.value.listener?.available && !state.value.listener.running){Modal.warning({title:t('syncReadiness.receiverStopped'),content:t('syncReadiness.receiverStoppedNote')});return}
 let address='',node:Record<string,unknown>|undefined
 try{
  if(!pairName.value.trim()||!pairCategories.value.length||!pairMinutes.value||!linkMinutes.value)throw new Error('missing')
  minutes(pairMinutes.value);minutes(linkMinutes.value)
  if(routeMode.value==='node'){
   if(!/^[a-fA-F0-9]{64}$/.test(nodeFingerprint.value.trim())||nodeKey.value.length<32)throw new Error('missing')
   node={url:invitationTarget(nodeUrl.value),tls_fingerprint:nodeFingerprint.value.trim().toLowerCase(),admin_key:nodeKey.value}
  }else address=state.value.listener?.available?syncReceiverTarget(publicTarget.value,listenerPort.value):invitationTarget(publicTarget.value)
 }catch{Modal.warning({title:t('revision17.inputRequired'),content:t('revision17.invalidReceiver')});return}
 const result=await controlSyncApi.createPairKey({name:pairName.value,expires_in:minutes(pairMinutes.value),connection_expires_in:minutes(linkMinutes.value),categories:pairCategories.value,public_target:address,...(node?{node}:{})})
 revealedKey.value=result.key;revealedExpiry.value=result.pair_expires_at;pairLink.value=makeInvitationLink('sync',address,result.key,result.node_descriptor);nodeKey.value=''
})
const connect = () => action(async () => { await controlSyncApi.connect({ target: target.value, key: peerKey.value, name: target.value,...(nodeDescriptor.value?{node_descriptor:nodeDescriptor.value}:{}) }); peerKey.value = '';invitationInput.value='';nodeDescriptor.value=null;message.info(t('invitationLink.syncWaiting')) })
const revokeKey = (id: string) => action(() => controlSyncApi.revokeKey(id))
const deleteKey = (id: string) => action(() => controlSyncApi.deleteKey(id))
const revokeLink = (id: string) => action(async()=>{await controlSyncApi.revokeLink(id);if(chosenLink.value?._id===id){chosenLink.value=null;syncCategories.value=[]}})
const setListener = (enabled: boolean) => action(() => controlSyncApi.listener({ enabled, port: listenerPort.value }))
function selectLink(link: SyncLink) { if(link.kind==='receiver'){Modal.info({title:t('syncReadiness.receiverHelp'),content:t('syncReadiness.receiverNote')});return} chosenLink.value = link; syncCategories.value = link.categories.filter(c => c !== 'credentials') }
let syncAttempt:{fingerprint:string;id:string}|undefined
const startTransfer = () => action(async()=>{
 const notice=message.loading(t('control.requestPreparing'),0)
 try {
 await load(true)
 if(!chosenLink.value || chosenLink.value.state!=='paired')throw new Error(t('control.states.pending'))
 if(mode.value==='overwrite' && state.value.admission?.blocked){Modal.warning({title:syncBlockerTitle.value,content:syncBlockerText.value});return}
 const body={link_id:chosenLink.value?._id,flow:flow.value,mode:mode.value,categories:[...syncCategories.value].sort()}
 const fingerprint=JSON.stringify(body)
 if(!syncAttempt||syncAttempt.fingerprint!==fingerprint)syncAttempt={fingerprint,id:Array.from(crypto.getRandomValues(new Uint8Array(16)),v=>v.toString(16).padStart(2,'0')).join('')}
 const result=await controlSyncApi.start({...body,request_id:syncAttempt.id})
 if(['failed','rejected','expired'].includes(result.state))throw new Error(result.error||t('control.states.'+result.state))
 syncAttempt=undefined;window.dispatchEvent(new Event('watchtower:sync-requested'));message.info(t('repair128.requestSent'))
 } finally {notice()}
})
const retry = (id: string) => action(() => controlSyncApi.advance(id))
async function copyKey() { try { if (navigator.clipboard?.writeText) await navigator.clipboard.writeText(revealedKey.value); else { const input = document.querySelector<HTMLInputElement>('[data-testid="created-key-value"]'); input?.select(); if (!document.execCommand('copy')) throw new Error('copy') }; message.success(t('control.copied')) } catch { message.error(t('control.copyManual')) } }
function fillInvitation(){if(!invitationInput.value.trim()){nodeDescriptor.value=null;return}try{const parsed=parseInvitationLink(invitationInput.value,'sync');target.value=parsed.target;peerKey.value=parsed.key;nodeDescriptor.value=parsed.node_descriptor || null;error.value=''}catch(e){nodeDescriptor.value=null;error.value=localizedError(e)}}
let timer: ReturnType<typeof setInterval> | undefined
let polling=false,pollOffset=0
onMounted(() => {const saved=pendingInvitation('sync');if(saved){invitationInput.value=saved;tab.value='sync';fillInvitation();clearPendingInvitation();if(location.hash)void router.replace({path:router.currentRoute.value.path,query:router.currentRoute.value.query,hash:''})}void load();timer=setInterval(async()=>{now.value=Date.now()/1000;if(polling || disposed || working.value || document.hidden)return;polling=true;try{await load();const pending=state.value.links.filter(l=>l.kind==='initiator' && ['pending','connecting'].includes(l.state));const batch=Array.from({length:Math.min(3,pending.length)},(_,i)=>pending[(pollOffset+i)%pending.length]);pollOffset+=batch.length;for(const link of batch){try{const fresh=await controlSyncApi.refresh(link._id,true);const at=state.value.links.findIndex(l=>l._id===fresh._id);if(at>=0)state.value.links[at]=fresh}catch{/* retry on the next poll */}}}finally{polling=false}},5000)})
onUnmounted(() => { disposed=true;++stateSerial;if (timer) clearInterval(timer); controlCreateOpen.value = false; keyCreateError.value = ''; revealedKey.value = ''; peerKey.value = '';pairLink.value='';invitationInput.value='';nodeKey.value='';nodeDescriptor.value=null })
</script>

<style scoped>
.sync-history-row{display:flex;align-items:center;gap:12px;padding:12px 0;border-bottom:1px solid var(--dt-border)}.sync-record-open{display:flex;flex:1;min-width:0;flex-direction:column;gap:7px;text-align:left;border:0;background:transparent;color:var(--dt-text);cursor:pointer;padding:8px;border-radius:8px}.sync-record-open:hover{background:var(--dt-fill)}.sync-record-open:focus-visible{outline:2px solid var(--dt-primary)}
.connect-grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:18px}.compact{gap:14px}.permission-list{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:10px}.connect-endpoint,.connect-code{background:var(--dt-fill);border:1px solid var(--dt-border);padding:14px;border-radius:10px;overflow:auto;overflow-wrap:anywhere}.connect-code{font-size:12px;line-height:1.6}.connect-muted{color:var(--dt-muted);font-size:12px;overflow-wrap:anywhere}.target-history{margin-top:18px}.transfer-row{padding:16px 0;border-bottom:1px solid var(--dt-border)}.transfer-row:last-child{border-bottom:0}.control-sync :deep(.ant-checkbox-wrapper){margin-inline-start:0;align-items:flex-start}@media(max-width:1050px){.connect-grid{grid-template-columns:1fr}}@media(max-width:560px){.permission-list{grid-template-columns:1fr}}
.operation-guide-grid > section{min-width:0}.operation-guide-grid h3{font-size:15px;font-weight:600;color:var(--dt-text);margin:0 0 14px}.operation-guide-grid p{margin:14px 0;color:var(--dt-muted)}.control-key-create-form :deep(.ant-checkbox-wrapper){margin-inline-start:0;align-items:flex-start}.control-key-create-form .permission-list{width:100%}
</style>
