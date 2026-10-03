<template>
  <div class="probe-manage">
    <a-tabs v-model:activeKey="activeTab">
      <!-- Tab 1: 探针管理 -->
      <a-tab-pane key="probe" tab="探针管理">
        <p class="tab-desc">{{ translate('ui.m_3c3d8683a6a4') }}</p>
        <div class="toolbar">
          <a-button type="primary" @click="showProbeCreate = true">{{ translate('ui.m_532a2d3aaa53') }}</a-button>
          <a-button @click="loadProbes" style="margin-left: 8px">{{ translate('ui.m_aee887434131') }}</a-button>
        </div>
        <a-table :dataSource="probes" :columns="probeColumns" rowKey="probe_id" :loading="probeLoading" :pagination="false" size="small" style="margin-top: 12px">
          <template #bodyCell="{ column, record }">
            <template v-if="column.key === 'status'">
              <a-tag :color="record.status === 'online' ? 'green' : record.status === 'built' ? 'blue' : 'default'">{{ probeStatusLabel(record.status) }}</a-tag>
            </template>
            <template v-if="column.key === 'created_at'">{{ fmtTime(record.created_at) }}</template>
            <template v-if="column.key === 'action'">
              <a-space>
                <a-button size="small" @click="handleProbeBuild(record)" :loading="probeBuildingId === record.probe_id">{{ translate('ui.m_a9a49c817394') }}</a-button>
                <a-button size="small" type="primary" @click="handleProbeDownload(record)" :disabled="!record.build_path">{{ translate('ui.m_4673a2306165') }}</a-button>
                <a-button size="small" @click="handleProbeStatus(record)">{{ translate('ui.m_071089398bfd') }}</a-button>
                <a-popconfirm :title="translate('ui.m_7e18d0731e35')" @confirm="handleProbeDelete(record)"><a-button size="small" danger>{{ translate('ui.m_2f9daa828907') }}</a-button></a-popconfirm>
              </a-space>
            </template>
          </template>
        </a-table>
      </a-tab-pane>

      <!-- Tab 2: 木马管理 -->
      <a-tab-pane key="agent" tab="木马管理">
        <p class="tab-desc">{{ translate('ui.m_3a71443f57a5') }}</p>
        <div class="toolbar">
          <a-button type="primary" @click="showAgentCreate = true">{{ translate('ui.m_2721f8549e2d') }}</a-button>
          <a-button @click="loadAgents" style="margin-left: 8px">{{ translate('ui.m_aee887434131') }}</a-button>
        </div>
        <a-table :dataSource="agents" :columns="agentColumns" rowKey="agent_id" :loading="agentLoading" :pagination="false" size="small" style="margin-top: 12px">
          <template #bodyCell="{ column, record }">
            <template v-if="column.key === 'status'">
              <a-tag :color="record.status === 'online' ? 'green' : record.status === 'built' ? 'blue' : 'default'">{{ agentStatusLabel(record.status) }}</a-tag>
            </template>
            <template v-if="column.key === 'probe_ids'">{{ (record.probe_ids || [record.probe_id]).map((id: string) => probeName(id)).join(', ') }}</template>
            <template v-if="column.key === 'created_at'">{{ fmtTime(record.created_at) }}</template>
            <template v-if="column.key === 'action'">
              <a-space>
                <a-button size="small" @click="handleAgentBuild(record)" :loading="agentBuildingId === record.agent_id">{{ translate('ui.m_1ad1463fe16f') }}</a-button>
                <a-button size="small" type="primary" @click="handleAgentDownload(record)" :disabled="!record.build_path">{{ translate('ui.m_4673a2306165') }}</a-button>
                <a-button size="small" @click="handleAgentStatus(record)">{{ translate('ui.m_6320b4a8722a') }}</a-button>
                <a-popconfirm :title="translate('ui.m_7e18d0731e35')" @confirm="handleAgentDelete(record)"><a-button size="small" danger>{{ translate('ui.m_2f9daa828907') }}</a-button></a-popconfirm>
              </a-space>
            </template>
          </template>
        </a-table>
      </a-tab-pane>

      <!-- Tab 3: 蓝队探针 -->
      <a-tab-pane key="blue" tab="蓝队探针">
        <a-empty :description="translate('ui.m_a1e44ee5df01')" />
      </a-tab-pane>
    </a-tabs>

    <!-- Probe Create Modal -->
    <a-modal v-model:open="showProbeCreate" :title="translate('ui.m_532a2d3aaa53')" @ok="handleProbeCreate" :confirmLoading="probeCreating">
      <a-form :labelCol="{ span: 6 }">
        <a-form-item :label="translate('ui.m_1f0fb02b335e')" required><a-input v-model:value="probeForm.name" :placeholder="translate('ui.m_067ef6a83281')" /></a-form-item>
        <a-form-item label="VPS IP" required><a-input v-model:value="probeForm.vps_ip" :placeholder="translate('ui.m_946d1e4eb022')" /></a-form-item>
        <a-form-item :label="translate('ui.m_eaf541af55cd')"><a-input-number v-model:value="probeForm.port" :min="1" :max="65535" style="width:100%" /></a-form-item>
        <a-form-item :label="translate('ui.m_7588ac20b54b')"><a-input v-model:value="probeForm.auth_key" readonly><template #addonAfter><a-button size="small" type="link" @click="genProbeKey">{{ translate('ui.m_3221a042ea36') }}</a-button></template></a-input></a-form-item>
      </a-form>
    </a-modal>

    <!-- Agent Create Modal -->
    <a-modal v-model:open="showAgentCreate" :title="translate('ui.m_2721f8549e2d')" @ok="handleAgentCreate" :confirmLoading="agentCreating" width="560px">
      <a-form :labelCol="{ span: 6 }">
        <a-form-item :label="translate('ui.m_51c17eb5d67d')" required><a-input v-model:value="agentForm.name" :placeholder="translate('ui.m_50e6f938829e')" /></a-form-item>
        <a-form-item :label="translate('ui.m_4296ae3ebaf3')" required>
          <a-select v-model:value="agentForm.probe_ids" mode="multiple" :placeholder="translate('ui.m_9b863b89b184')">
            <a-select-option v-for="p in probes" :key="p.probe_id" :value="p.probe_id">{{ p.name }} ({{ p.vps_ip }})</a-select-option>
          </a-select>
        </a-form-item>
        <a-form-item :label="translate('ui.m_9120b47dbe8b')">
          <a-select v-model:value="agentForm.platform">
            <a-select-option value="linux_x64">Linux x86_64</a-select-option>
            <a-select-option value="linux_arm">Linux ARM</a-select-option>
            <a-select-option value="win_x64">Windows x86_64</a-select-option>
          </a-select>
        </a-form-item>
        <a-form-item :label="translate('ui.m_a1b4f5f0b883')"><a-input-number v-model:value="agentForm.beacon_interval" :min="1" style="width:100%" /></a-form-item>
        <a-form-item :label="translate('ui.m_2aac189812cd')"><a-input-number v-model:value="agentForm.beacon_jitter" :min="0" :max="100" style="width:100%" /></a-form-item>
      </a-form>
    </a-modal>
  </div>
</template>

<script setup lang="ts">
import { t as translate } from '../../i18n'

import { ref, onMounted } from 'vue'
import { message } from 'ant-design-vue'
import { probeApi, type ProbeConfig, type AgentConfig } from '../../api/probe'

const activeTab = ref('probe')

// ── Probe state ──
const probes = ref<ProbeConfig[]>([])
const probeLoading = ref(false)
const showProbeCreate = ref(false)
const probeCreating = ref(false)
const probeBuildingId = ref('')
const probeForm = ref({ name: '', vps_ip: '', port: 8443, auth_key: _genHex(32) })

const probeColumns = [
  { get title() { return translate('ui.m_d44e9b3d3b31') }, dataIndex: 'name', key: 'name' },
  { title: 'VPS IP', dataIndex: 'vps_ip', key: 'vps_ip' },
  { get title() { return translate('ui.m_e71ac32b544b') }, dataIndex: 'port', key: 'port', width: 80 },
  { get title() { return translate('ui.m_6320b4a8722a') }, key: 'status', width: 80 },
  { get title() { return translate('ui.m_07ec86e0f1d4') }, key: 'created_at', width: 160 },
  { get title() { return translate('ui.m_ed31fbb483ee') }, key: 'action', width: 260 },
]

// ── Agent state ──
const agents = ref<AgentConfig[]>([])
const agentLoading = ref(false)
const showAgentCreate = ref(false)
const agentCreating = ref(false)
const agentBuildingId = ref('')
const agentForm = ref({ name: '', probe_ids: [] as string[], platform: 'linux_x64', beacon_interval: 5, beacon_jitter: 30 })

const agentColumns = [
  { get title() { return translate('ui.m_d44e9b3d3b31') }, dataIndex: 'name', key: 'name' },
  { get title() { return translate('ui.m_4296ae3ebaf3') }, key: 'probe_ids' },
  { get title() { return translate('ui.m_910887705c7a') }, dataIndex: 'platform', key: 'platform', width: 100 },
  { get title() { return translate('ui.m_6320b4a8722a') }, key: 'status', width: 80 },
  { get title() { return translate('ui.m_07ec86e0f1d4') }, key: 'created_at', width: 160 },
  { get title() { return translate('ui.m_ed31fbb483ee') }, key: 'action', width: 260 },
]

// ── Helpers ──
// ── Helpers ──
function _genHex(bytes: number) { const a = new Uint8Array(bytes); crypto.getRandomValues(a); return Array.from(a, b => b.toString(16).padStart(2, '0')).join('') }
function genProbeKey() { probeForm.value.auth_key = _genHex(32) }
function fmtTime(ts: number) { return ts ? new Date(ts * 1000).toLocaleString() : '-' }
function probeStatusLabel(s: string) { return ({ get created() { return translate('ui.m_80bfa30db209') }, get built() { return translate('ui.m_097fb3bf3fd3') }, get online() { return translate('ui.m_b9086662b1df') }, get offline() { return translate('ui.m_be1b4f3c6c1c') } } as Record<string,string>)[s] || s }
function agentStatusLabel(s: string) { return ({ get created() { return translate('ui.m_80bfa30db209') }, get built() { return translate('ui.m_11448fff91a4') }, get online() { return translate('ui.m_b9086662b1df') }, get offline() { return translate('ui.m_be1b4f3c6c1c') } } as Record<string,string>)[s] || s }
function probeName(pid: string) { return probes.value.find(p => p.probe_id === pid)?.name || pid.slice(0, 8) }

// ── Probe CRUD ──
async function loadProbes() { probeLoading.value = true; try { probes.value = await probeApi.list('red') } catch (e: any) { message.error(e.message) } finally { probeLoading.value = false } }
async function handleProbeCreate() { if (!probeForm.value.name.trim()) { message.warning(translate('ui.m_8955cce7f172')); return } if (!probeForm.value.vps_ip.trim()) { message.warning(translate('ui.m_8c33d994fd27')); return } probeCreating.value = true; try { await probeApi.create({ ...probeForm.value, type: 'red', protocol: 'https' }); message.success(translate('ui.m_1ab62884f4ee')); showProbeCreate.value = false; probeForm.value = { name: '', vps_ip: '', port: 8443, auth_key: _genHex(32) }; loadProbes() } catch (e: any) { message.error(e.message) } finally { probeCreating.value = false } }
async function handleProbeBuild(r: ProbeConfig) { probeBuildingId.value = r.probe_id; try { await probeApi.build(r.probe_id); message.success(translate('ui.m_6a619612255b')); loadProbes() } catch (e: any) { message.error(e.message) } finally { probeBuildingId.value = '' } }
async function handleProbeDownload(r: ProbeConfig) { try { await probeApi.downloadWithAuth(r.probe_id) } catch (e: any) { message.error(e.message) } }
async function handleProbeDelete(r: ProbeConfig) { try { await probeApi.delete(r.probe_id); message.success(translate('ui.m_077a6d37719a')); loadProbes() } catch (e: any) { message.error(e.message) } }
async function handleProbeStatus(r: ProbeConfig) { try { const d = await probeApi.status(r.probe_id); (d as any).version ? message.success(translate('ui.m_b9086662b1df')) : message.warning(translate('ui.m_be1b4f3c6c1c')); loadProbes() } catch { message.warning(translate('ui.m_8d7c03019f1d')) } }

// ── Agent CRUD ──
async function loadAgents() { agentLoading.value = true; try { agents.value = await probeApi.agentList() } catch (e: any) { message.error(e.message) } finally { agentLoading.value = false } }
async function handleAgentCreate() { if (!agentForm.value.name.trim()) { message.warning(translate('ui.m_0c5cf2aa43a9')); return } if (!agentForm.value.probe_ids.length) { message.warning(translate('ui.m_572db596b596')); return } agentCreating.value = true; try { await probeApi.agentCreate({ name: agentForm.value.name, probe_id: agentForm.value.probe_ids[0], probe_ids: agentForm.value.probe_ids, platform: agentForm.value.platform, beacon_interval: agentForm.value.beacon_interval, beacon_jitter: agentForm.value.beacon_jitter }); message.success(translate('ui.m_3c07a995bbd4')); showAgentCreate.value = false; agentForm.value = { name: '', probe_ids: [], platform: 'linux_x64', beacon_interval: 5, beacon_jitter: 30 }; loadAgents() } catch (e: any) { message.error(e.message) } finally { agentCreating.value = false } }
async function handleAgentBuild(r: AgentConfig) { agentBuildingId.value = r.agent_id; try { await probeApi.agentBuild(r.agent_id); message.success(translate('ui.m_57c99e7e15e4')); loadAgents() } catch (e: any) { message.error(e.message) } finally { agentBuildingId.value = '' } }
async function handleAgentDownload(r: AgentConfig) { try { await probeApi.agentDownload(r.agent_id) } catch (e: any) { message.error(e.message) } }
async function handleAgentDelete(r: AgentConfig) { try { await probeApi.agentDelete(r.agent_id); message.success(translate('ui.m_077a6d37719a')); loadAgents() } catch (e: any) { message.error(e.message) } }
async function handleAgentStatus(r: AgentConfig) { try { const d = await probeApi.agentStatus(r.agent_id); (d as any).online ? message.success(translate('ui.m_d5cf8ef5da09')) : message.warning(translate('ui.m_5c8d5f76317f')); loadAgents() } catch { message.warning(translate('ui.m_bf4cedf76a4e')) } }

onMounted(() => { loadProbes(); loadAgents() })
</script>

<style scoped>
.probe-manage { padding: 16px; }
.toolbar { display: flex; align-items: center; }
.form-hint { font-size: 12px; color: #999; margin-top: 4px; }
.tab-desc { color: #666; font-size: 13px; margin-bottom: 12px; }
</style>