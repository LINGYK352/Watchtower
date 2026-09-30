<template>
  <PageContainer title="攻击告警" kicker="Attack Alert" description="实时监控和溯源针对平台的攻击行为，包括 Web 攻击（SQL 注入、XSS 等）和后渗透攻击（Webshell、反弹 Shell 等）">
    <template #extra>
      <a-space>
        <a-button @click="loadData">刷新</a-button>
      </a-space>
    </template>

    <!-- 统计卡片 -->
    <a-row :gutter="16" style="margin-bottom: 16px">
      <a-col :span="6">
        <a-card :bordered="false">
          <a-statistic title="累计攻击" :value="stats.total_attacks" :value-style="{ color: '#cf1322' }" />
        </a-card>
      </a-col>
      <a-col :span="6">
        <a-card :bordered="false">
          <a-statistic title="今日攻击" :value="stats.today_attacks" :value-style="{ color: '#d46b08' }" />
        </a-card>
      </a-col>
      <a-col :span="6">
        <a-card :bordered="false">
          <a-statistic title="高危攻击" :value="stats.by_severity?.high || 0" :value-style="{ color: '#a8071a' }" />
        </a-card>
      </a-col>
      <a-col :span="6">
        <a-card :bordered="false">
          <a-statistic title="活跃攻击者" :value="stats.top_attackers?.length || 0" :value-style="{ color: '#096dd9' }" />
        </a-card>
      </a-col>
    </a-row>

    <!-- 攻击类型分布 -->
    <a-row :gutter="16" style="margin-bottom: 16px">
      <a-col :span="12">
        <a-card title="攻击类型分布" :bordered="false">
          <div v-if="Object.keys(stats.by_type || {}).length > 0">
            <div v-for="(count, type) in stats.by_type" :key="type" style="margin-bottom: 8px">
              <span style="display: inline-block; width: 150px">{{ type }}</span>
              <a-progress :percent="(count / stats.total_attacks * 100)" :show-info="true" :format="() => count" />
            </div>
          </div>
          <a-empty v-else description="暂无数据" />
        </a-card>
      </a-col>
      <a-col :span="12">
        <a-card title="Top 攻击者" :bordered="false">
          <a-list v-if="stats.top_attackers && stats.top_attackers.length > 0" size="small" :data-source="stats.top_attackers">
            <template #renderItem="{ item }">
              <a-list-item>
                <a-list-item-meta>
                  <template #title>
                    <a @click="traceAttacker(item.ip)">{{ item.ip }}</a>
                  </template>
                  <template #description>攻击 {{ item.count }} 次</template>
                </a-list-item-meta>
                <template #actions>
                  <a-tag :color="item.count >= 10 ? 'red' : item.count >= 3 ? 'orange' : 'default'">
                    {{ item.count >= 10 ? '高危' : item.count >= 3 ? '中危' : '低危' }}
                  </a-tag>
                </template>
              </a-list-item>
            </template>
          </a-list>
          <a-empty v-else description="暂无数据" />
        </a-card>
      </a-col>
    </a-row>

    <!-- 筛选条件 -->
    <a-card :bordered="false" style="margin-bottom: 16px">
      <a-form layout="inline">
        <a-form-item label="攻击类型">
          <a-select v-model:value="query.attack_type" allow-clear placeholder="全部" style="width: 170px" @change="onSearch">
            <a-select-option value="Sensitive Path Access">敏感路径访问</a-select-option>
            <a-select-option value="Directory Brute-force">目录爆破</a-select-option>
            <a-select-option value="SQL Injection">SQL 注入</a-select-option>
            <a-select-option value="XSS">XSS</a-select-option>
            <a-select-option value="Path Traversal">目录遍历</a-select-option>
            <a-select-option value="Command Injection">命令注入</a-select-option>
            <a-select-option value="Scanner">扫描器</a-select-option>
            <a-select-option value="Webshell Upload">Webshell 上传</a-select-option>
          </a-select>
        </a-form-item>
        <a-form-item label="严重程度">
          <a-select v-model:value="query.severity" allow-clear placeholder="全部" style="width: 120px" @change="onSearch">
            <a-select-option value="high">高危</a-select-option>
            <a-select-option value="medium">中危</a-select-option>
            <a-select-option value="low">低危</a-select-option>
          </a-select>
        </a-form-item>
        <a-form-item label="攻击者 IP">
          <a-input v-model:value="query.source_ip" placeholder="输入 IP" style="width: 200px" @pressEnter="onSearch" allow-clear />
        </a-form-item>
        <a-form-item>
          <a-button type="primary" @click="onSearch">查询</a-button>
        </a-form-item>
      </a-form>
    </a-card>

    <!-- 攻击记录列表：loading 作用于表格本身（非整卡），避免查询时整块重渲染闪屏残影（问题2） -->
    <a-card :bordered="false">
      <a-table
        :columns="columns"
        :data-source="list"
        :loading="loading"
        :scroll="{ x: 'max-content' }"
        :pagination="{ current: query.page, pageSize: query.size, total, showSizeChanger: true, showTotal: (t: number) => `共 ${t} 条` }"
        @change="onTableChange"
        row-key="_id"
      >
        <template #bodyCell="{ column, record }">
          <template v-if="column.key === 'source_ip'">
            <a @click="traceAttacker(record.source_ip)">{{ record.source_ip }}</a>
          </template>
          <template v-if="column.key === 'attack_type'">
            <a-tag :color="getAttackTypeColor(record.attack_type)">{{ record.attack_type }}</a-tag>
          </template>
          <template v-if="column.key === 'severity'">
            <a-tag :color="getSeverityColor(record.severity)">{{ getSeverityLabel(record.severity) }}</a-tag>
          </template>
          <template v-if="column.key === 'hit_count'">
            <a-tag :color="(record.hit_count || 1) >= 50 ? 'red' : (record.hit_count || 1) >= 10 ? 'orange' : 'default'">
              {{ record.hit_count || 1 }} 次
            </a-tag>
          </template>
          <template v-if="column.key === 'confidence'">
            <a-progress :percent="record.confidence * 100" :show-info="false" :stroke-width="6" />
            <span style="margin-left: 8px">{{ (record.confidence * 100).toFixed(0) }}%</span>
          </template>
          <template v-if="column.key === 'timestamp'">
            {{ formatTime(record.timestamp) }}
          </template>
          <template v-if="column.key === 'actions'">
            <a-space>
              <a @click="viewDetail(record)">详情</a>
              <a @click="traceAttacker(record.source_ip)">溯源</a>
              <a-popconfirm :title="`确认封禁 ${record.source_ip}？`" @confirm="doBan(record.source_ip)">
                <a style="color:#cf1322">封禁</a>
              </a-popconfirm>
              <a-popconfirm :title="`将 ${record.source_ip} 加入白名单？（同时解除其封禁）`" @confirm="doAddWhitelist(record.source_ip)">
                <a style="color:#52c41a">加白</a>
              </a-popconfirm>
            </a-space>
          </template>
        </template>
      </a-table>
    </a-card>

    <!-- 封禁管理 + 白名单管理 -->
    <a-row :gutter="16" style="margin-top:16px">
      <a-col :span="12">
        <a-card title="封禁名单" :bordered="false">
          <template #extra><a-button size="small" @click="loadBans">刷新</a-button></template>
          <a-table :columns="banColumns" :data-source="bans" :loading="banLoading" size="small"
            :pagination="false" row-key="_id" :scroll="{ y: 260 }">
            <template #bodyCell="{ column, record }">
              <template v-if="column.key === 'ban_type'">
                <a-tag :color="record.ban_type === 'auto' ? 'orange' : 'red'">{{ record.ban_type === 'auto' ? '自动' : '手动' }}</a-tag>
              </template>
              <template v-if="column.key === 'expire_at'">
                <span>{{ record.expire_at ? formatTime(record.expire_at) : '永久' }}</span>
              </template>
              <template v-if="column.key === 'ban_action'">
                <a-space>
                  <a-popconfirm :title="`解封 ${record._id}？`" @confirm="doUnban(record._id)"><a>解封</a></a-popconfirm>
                  <a-popconfirm :title="`将 ${record._id} 加白名单？`" @confirm="doAddWhitelist(record._id)"><a style="color:#52c41a">加白</a></a-popconfirm>
                </a-space>
              </template>
            </template>
          </a-table>
          <a-empty v-if="!bans.length && !banLoading" description="暂无封禁" />
        </a-card>
      </a-col>
      <a-col :span="12">
        <a-card title="白名单" :bordered="false">
          <template #extra>
            <a-space>
              <a-input v-model:value="wlInput" placeholder="输入 IP 加白名单" size="small" style="width:160px" @pressEnter="doAddWhitelistInput" />
              <a-button type="primary" size="small" @click="doAddWhitelistInput">添加</a-button>
              <a-button size="small" @click="loadWhitelist">刷新</a-button>
            </a-space>
          </template>
          <a-table :columns="wlColumns" :data-source="whitelist" :loading="wlLoading" size="small"
            :pagination="false" row-key="_id" :scroll="{ y: 260 }">
            <template #bodyCell="{ column, record }">
              <template v-if="column.key === 'added_at'">{{ formatTime(record.added_at) }}</template>
              <template v-if="column.key === 'wl_action'">
                <a-popconfirm :title="`移出白名单 ${record._id}？`" @confirm="doDelWhitelist(record._id)"><a style="color:#cf1322">移除</a></a-popconfirm>
              </template>
            </template>
          </a-table>
          <a-empty v-if="!whitelist.length && !wlLoading" description="暂无白名单" />
        </a-card>
      </a-col>
    </a-row>

    <!-- 攻击详情弹窗 -->
    <a-modal v-model:open="detailVisible" title="攻击详情" width="800px" :footer="null" wrap-class-name="aa-detail">
      <a-descriptions v-if="currentAttack" class="aa-detail" :column="2" bordered>
        <a-descriptions-item label="攻击类型">
          <a-tag :color="getAttackTypeColor(currentAttack.attack_type)">{{ currentAttack.attack_type }}</a-tag>
        </a-descriptions-item>
        <a-descriptions-item label="严重程度">
          <a-tag :color="getSeverityColor(currentAttack.severity)">{{ getSeverityLabel(currentAttack.severity) }}</a-tag>
        </a-descriptions-item>
        <a-descriptions-item label="攻击者 IP" :span="2">
          <a @click="traceAttacker(currentAttack.source_ip)">{{ currentAttack.source_ip }}</a>
        </a-descriptions-item>
        <a-descriptions-item label="置信度" :span="2">
          <a-progress :percent="currentAttack.confidence * 100" />
        </a-descriptions-item>
        <a-descriptions-item label="描述" :span="2">{{ currentAttack.description }}</a-descriptions-item>
        <a-descriptions-item label="攻击时间" :span="2">{{ formatTime(currentAttack.timestamp) }}</a-descriptions-item>
        <a-descriptions-item label="请求方法">{{ currentAttack.request?.method }}</a-descriptions-item>
        <a-descriptions-item label="请求路径">{{ currentAttack.request?.path }}</a-descriptions-item>
        <a-descriptions-item label="查询参数" :span="2">
          <pre style="margin: 0; max-height: 100px; overflow: auto">{{ currentAttack.request?.query || '-' }}</pre>
        </a-descriptions-item>
        <a-descriptions-item label="攻击证据" :span="2">
          <pre style="margin: 0; background: #f5f5f5; padding: 8px; border-radius: 4px; max-height: 200px; overflow: auto">{{ currentAttack.evidence }}</pre>
        </a-descriptions-item>
        <a-descriptions-item label="请求头" :span="2">
          <pre style="margin: 0; max-height: 150px; overflow: auto">{{ JSON.stringify(currentAttack.request?.headers, null, 2) }}</pre>
        </a-descriptions-item>
        <a-descriptions-item label="请求体" :span="2">
          <pre style="margin: 0; max-height: 150px; overflow: auto">{{ currentAttack.request?.body || '-' }}</pre>
        </a-descriptions-item>
      </a-descriptions>
    </a-modal>

    <!-- 攻击者溯源弹窗 -->
    <a-modal v-model:open="traceVisible" title="攻击者溯源" width="700px" :footer="null" wrap-class-name="aa-detail">
      <a-descriptions v-if="attackerProfile" class="aa-detail" :column="2" bordered>
        <a-descriptions-item label="IP 地址" :span="2">{{ attackerProfile.ip }}</a-descriptions-item>
        <a-descriptions-item label="威胁等级" :span="2">
          <a-tag :color="attackerProfile.threat_level === 'high' ? 'red' : attackerProfile.threat_level === 'medium' ? 'orange' : 'default'">
            {{ attackerProfile.threat_level === 'high' ? '高危' : attackerProfile.threat_level === 'medium' ? '中危' : '低危' }}
          </a-tag>
        </a-descriptions-item>
        <a-descriptions-item label="国家">{{ attackerProfile.country }}</a-descriptions-item>
        <a-descriptions-item label="城市">{{ attackerProfile.city }}</a-descriptions-item>
        <a-descriptions-item label="ISP">{{ attackerProfile.isp }}</a-descriptions-item>
        <a-descriptions-item label="ASN">{{ attackerProfile.asn }}</a-descriptions-item>
        <a-descriptions-item label="时区">{{ attackerProfile.timezone }}</a-descriptions-item>
        <a-descriptions-item label="代理/VPN">
          {{ attackerProfile.is_proxy ? 'Proxy' : '' }} {{ attackerProfile.is_vpn ? 'VPN' : '' }} {{ !attackerProfile.is_proxy && !attackerProfile.is_vpn ? '否' : '' }}
        </a-descriptions-item>
        <a-descriptions-item label="历史攻击次数">{{ attackerProfile.attack_history }}</a-descriptions-item>
        <a-descriptions-item label="攻击手法" :span="2">
          <template v-if="attackerProfile.attack_types && attackerProfile.attack_types.length">
            <a-tag v-for="t in attackerProfile.attack_types" :key="t" :color="getAttackTypeColor(t)" style="margin-bottom:4px">{{ t }}</a-tag>
          </template>
          <span v-else>-</span>
        </a-descriptions-item>
        <a-descriptions-item label="首次出现">{{ formatTime(attackerProfile.first_seen) }}</a-descriptions-item>
        <a-descriptions-item label="最近活动">{{ formatTime(attackerProfile.last_seen) }}</a-descriptions-item>
      </a-descriptions>
    </a-modal>
  </PageContainer>
</template>

<script setup lang="ts">
import { onMounted, reactive, ref } from 'vue'
import { message } from 'ant-design-vue'
import PageContainer from '../../layouts/PageContainer.vue'
import { attackAlertApi, type AttackAlert, type AttackStats, type AttackerProfile, type BanItem, type WhitelistItem } from '../../api/attackAlert'

const loading = ref(false)
const list = ref<AttackAlert[]>([])
const total = ref(0)
const stats = ref<AttackStats>({
  total_attacks: 0,
  today_attacks: 0,
  by_type: {},
  by_severity: {},
  top_attackers: [],
  recent_attacks: []
})

const query = reactive({
  page: 1,
  size: 20,
  attack_type: undefined as string | undefined,
  severity: undefined as string | undefined,
  source_ip: undefined as string | undefined,
  sort_order: 'desc' as 'asc' | 'desc'   // 最近时间排序方向（点击列头切换）
})

const detailVisible = ref(false)
const currentAttack = ref<AttackAlert | null>(null)

const traceVisible = ref(false)
const attackerProfile = ref<AttackerProfile | null>(null)

const columns = [
  { title: '攻击者 IP', dataIndex: 'source_ip', key: 'source_ip', width: 150 },
  { title: '攻击类型', dataIndex: 'attack_type', key: 'attack_type', width: 160 },
  { title: '严重程度', dataIndex: 'severity', key: 'severity', width: 100 },
  { title: '命中次数', dataIndex: 'hit_count', key: 'hit_count', width: 100 },
  { title: '置信度', dataIndex: 'confidence', key: 'confidence', width: 140 },
  { title: '描述', dataIndex: 'description', key: 'description', ellipsis: true, width: 260 },
  { title: '最近时间', dataIndex: 'timestamp', key: 'timestamp', width: 170, sorter: true, sortDirections: ['descend', 'ascend'], defaultSortOrder: 'descend' },
  { title: '操作', key: 'actions', width: 120, fixed: 'right' }
]

function getAttackTypeColor(type: string) {
  const colors: Record<string, string> = {
    'SQL Injection': 'red',
    'XSS': 'orange',
    'Path Traversal': 'volcano',
    'Command Injection': 'red',
    'Trap Access': 'magenta',
    'Scanner': 'blue',
    'Webshell Upload': 'red'
  }
  return colors[type] || 'default'
}

function getSeverityColor(severity: string) {
  return severity === 'high' ? 'red' : severity === 'medium' ? 'orange' : 'default'
}

function getSeverityLabel(severity: string) {
  return severity === 'high' ? '高危' : severity === 'medium' ? '中危' : '低危'
}

function formatTime(timestamp: number) {
  if (!timestamp) return '-'
  return new Date(timestamp * 1000).toLocaleString('zh-CN')
}

async function loadStats() {
  try {
    stats.value = await attackAlertApi.getStats()
  } catch (error) {
    message.error('加载统计失败：' + (error instanceof Error ? error.message : String(error)))
  }
}

async function loadList() {
  loading.value = true
  try {
    const result = await attackAlertApi.list({
      page: query.page,
      size: query.size,
      attack_type: query.attack_type,
      severity: query.severity,
      source_ip: query.source_ip,
      sort_order: query.sort_order
    })
    list.value = result.items
    total.value = result.total
  } catch (error) {
    message.error('加载列表失败：' + (error instanceof Error ? error.message : String(error)))
  } finally {
    loading.value = false
  }
}

function loadData() {
  loadStats()
  loadList()
  loadBans()
  loadWhitelist()
}

// 查询/筛选：重置到第 1 页再查（避免停在空页闪回，问题2）
function onSearch() {
  query.page = 1
  loadList()
}

// ── 封禁 / 白名单 ──
const bans = ref<BanItem[]>([])
const banLoading = ref(false)
const whitelist = ref<WhitelistItem[]>([])
const wlLoading = ref(false)
const wlInput = ref('')

const banColumns = [
  { title: 'IP', dataIndex: '_id', key: '_id' },
  { title: '类型', dataIndex: 'ban_type', key: 'ban_type', width: 70 },
  { title: '原因', dataIndex: 'reason', key: 'reason', ellipsis: true },
  { title: '到期', dataIndex: 'expire_at', key: 'expire_at', width: 160 },
  { title: '操作', key: 'ban_action', width: 110 }
]
const wlColumns = [
  { title: 'IP', dataIndex: '_id', key: '_id' },
  { title: '操作人', dataIndex: 'operator', key: 'operator', width: 90 },
  { title: '添加时间', dataIndex: 'added_at', key: 'added_at', width: 160 },
  { title: '操作', key: 'wl_action', width: 70 }
]

async function loadBans() {
  banLoading.value = true
  try { bans.value = (await attackAlertApi.banList()).items }
  catch (e) { message.error('加载封禁名单失败：' + (e instanceof Error ? e.message : String(e))) }
  finally { banLoading.value = false }
}
async function loadWhitelist() {
  wlLoading.value = true
  try { whitelist.value = (await attackAlertApi.whitelist()).items }
  catch (e) { message.error('加载白名单失败：' + (e instanceof Error ? e.message : String(e))) }
  finally { wlLoading.value = false }
}
async function doBan(ip: string) {
  try { await attackAlertApi.banIp(ip); message.success(`已封禁 ${ip}`); loadBans() }
  catch (e) { message.error('封禁失败：' + (e instanceof Error ? e.message : String(e))) }
}
async function doUnban(ip: string) {
  try { await attackAlertApi.unbanIp(ip); message.success(`已解封 ${ip}`); loadBans() }
  catch (e) { message.error('解封失败：' + (e instanceof Error ? e.message : String(e))) }
}
async function doAddWhitelist(ip: string) {
  try { await attackAlertApi.addWhitelist(ip); message.success(`${ip} 已加入白名单`); loadWhitelist(); loadBans() }
  catch (e) { message.error('加白失败：' + (e instanceof Error ? e.message : String(e))) }
}
function doAddWhitelistInput() {
  const ip = wlInput.value.trim()
  if (!ip) { message.warning('请输入 IP'); return }
  doAddWhitelist(ip); wlInput.value = ''
}
async function doDelWhitelist(ip: string) {
  try { await attackAlertApi.delWhitelist(ip); message.success(`${ip} 已移出白名单`); loadWhitelist() }
  catch (e) { message.error('移除失败：' + (e instanceof Error ? e.message : String(e))) }
}

function onTableChange(pagination: any, _filters: any, sorter: any) {
  query.page = pagination.current
  query.size = pagination.pageSize
  // 点击"最近时间"列头切换排序方向（服务端排序，跨页有效）；取消排序回退默认 desc
  if (sorter && sorter.field === 'timestamp' && sorter.order) {
    query.sort_order = sorter.order === 'ascend' ? 'asc' : 'desc'
  } else if (sorter && sorter.field === 'timestamp' && !sorter.order) {
    query.sort_order = 'desc'
  }
  loadList()
}

function viewDetail(record: AttackAlert) {
  currentAttack.value = record
  detailVisible.value = true
}

async function traceAttacker(ip: string) {
  try {
    attackerProfile.value = await attackAlertApi.traceAttacker(ip)
    traceVisible.value = true
  } catch (error) {
    message.error('溯源失败：' + (error instanceof Error ? error.message : String(error)))
  }
}

onMounted(() => {
  loadData()
})
</script>

<!-- 全局样式（弹窗 teleport 到 body，scoped 命中不到，用 wrap-class-name=aa-detail 定位） -->
<style>
/* 详情弹窗代码块：强制换行 + 断词，防长 evidence/headers/body 横向溢出撑破弹窗（问题1脱框） */
.aa-detail pre {
  font-family: 'Consolas', 'Monaco', monospace;
  font-size: 12px;
  white-space: pre-wrap;
  word-break: break-all;
  overflow-wrap: anywhere;
  margin: 0;
}
/* 描述列表值区允许收缩换行，防长 IP/路径/UA 撑破弹窗 */
.aa-detail .ant-descriptions-item-content {
  word-break: break-all;
  overflow-wrap: anywhere;
}
</style>
