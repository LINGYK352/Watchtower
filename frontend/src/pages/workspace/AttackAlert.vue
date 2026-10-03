<template>
  <PageContainer :title="translate('ui.m_22d1a41590ad')" kicker="Attack Alert" :description="translate('ui.m_e0315ade42af')">
    <template #extra>
      <a-space>
        <a-button @click="loadData">{{ translate('ui.m_aee887434131') }}</a-button>
      </a-space>
    </template>

    <!-- 统计卡片 -->
    <a-row :gutter="16" style="margin-bottom: 16px">
      <a-col :span="6">
        <a-card :bordered="false">
          <a-statistic :title="translate('ui.m_d435554f6d52')" :value="stats.total_attacks" :value-style="{ color: '#cf1322' }" />
        </a-card>
      </a-col>
      <a-col :span="6">
        <a-card :bordered="false">
          <a-statistic :title="translate('ui.m_70c07a5a1c79')" :value="stats.today_attacks" :value-style="{ color: '#d46b08' }" />
        </a-card>
      </a-col>
      <a-col :span="6">
        <a-card :bordered="false">
          <a-statistic :title="translate('ui.m_0d6fbc5813b6')" :value="stats.by_severity?.high || 0" :value-style="{ color: '#a8071a' }" />
        </a-card>
      </a-col>
      <a-col :span="6">
        <a-card :bordered="false">
          <a-statistic :title="translate('ui.m_b31427d6e3a2')" :value="stats.top_attackers?.length || 0" :value-style="{ color: '#096dd9' }" />
        </a-card>
      </a-col>
    </a-row>

    <!-- 攻击类型分布 -->
    <a-row :gutter="16" style="margin-bottom: 16px">
      <a-col :span="12">
        <a-card :title="translate('ui.m_934ef3c99ade')" :bordered="false">
          <div v-if="Object.keys(stats.by_type || {}).length > 0">
            <div v-for="(count, type) in stats.by_type" :key="type" style="margin-bottom: 8px">
              <span style="display: inline-block; width: 150px">{{ type }}</span>
              <a-progress :percent="(count / stats.total_attacks * 100)" :show-info="true" :format="() => count" />
            </div>
          </div>
          <a-empty v-else :description="translate('ui.m_497c85690c4c')" />
        </a-card>
      </a-col>
      <a-col :span="12">
        <a-card :title="translate('ui.m_8a7741921641')" :bordered="false">
          <a-list v-if="stats.top_attackers && stats.top_attackers.length > 0" size="small" :data-source="stats.top_attackers">
            <template #renderItem="{ item }">
              <a-list-item>
                <a-list-item-meta>
                  <template #title>
                    <a @click="traceAttacker(item.ip)">{{ item.ip }}</a>
                  </template>
                  <template #description>{{ translate('ui.m_8226ca02ff36') }} {{ item.count }} {{ translate('ui.m_172fb7e67b9b') }}</template>
                </a-list-item-meta>
                <template #actions>
                  <a-tag :color="item.count >= 10 ? 'red' : item.count >= 3 ? 'orange' : 'default'">
                    {{ item.count >= 10 ? translate('ui.m_4aa71c570566') : item.count >= 3 ? translate('ui.m_36a7c77b623b') : translate('ui.m_27a7f42a0afb') }}
                  </a-tag>
                </template>
              </a-list-item>
            </template>
          </a-list>
          <a-empty v-else :description="translate('ui.m_497c85690c4c')" />
        </a-card>
      </a-col>
    </a-row>

    <!-- 筛选条件 -->
    <a-card :bordered="false" style="margin-bottom: 16px">
      <a-form layout="inline">
        <a-form-item :label="translate('ui.m_713eb94e2557')">
          <a-select v-model:value="query.attack_type" allow-clear :placeholder="translate('ui.m_5c55a67935af')" style="width: 170px" @change="onSearch">
            <a-select-option value="Sensitive Path Access">{{ translate('ui.m_8297d2f3c76f') }}</a-select-option>
            <a-select-option value="Directory Brute-force">{{ translate('ui.m_ebead1a64959') }}</a-select-option>
            <a-select-option value="SQL Injection">{{ translate('ui.m_9d382cab8959') }}</a-select-option>
            <a-select-option value="XSS">XSS</a-select-option>
            <a-select-option value="Path Traversal">{{ translate('ui.m_edb2823251e9') }}</a-select-option>
            <a-select-option value="Command Injection">{{ translate('ui.m_3f66eba0fa1a') }}</a-select-option>
            <a-select-option value="Scanner">{{ translate('ui.m_c80d55f78467') }}</a-select-option>
            <a-select-option value="Webshell Upload">{{ translate('ui.m_8457ca99d8a1') }}</a-select-option>
          </a-select>
        </a-form-item>
        <a-form-item :label="translate('ui.m_55b4fd17d6ed')">
          <a-select v-model:value="query.severity" allow-clear :placeholder="translate('ui.m_5c55a67935af')" style="width: 120px" @change="onSearch">
            <a-select-option value="high">{{ translate('ui.m_4aa71c570566') }}</a-select-option>
            <a-select-option value="medium">{{ translate('ui.m_36a7c77b623b') }}</a-select-option>
            <a-select-option value="low">{{ translate('ui.m_27a7f42a0afb') }}</a-select-option>
          </a-select>
        </a-form-item>
        <a-form-item :label="translate('ui.m_fc04ec7e0993')">
          <a-input v-model:value="query.source_ip" :placeholder="translate('ui.m_61453d3a12d6')" style="width: 200px" @pressEnter="onSearch" allow-clear />
        </a-form-item>
        <a-form-item>
          <a-button type="primary" @click="onSearch">{{ translate('ui.m_bcd6771e08ec') }}</a-button>
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
        :pagination="{ current: query.page, pageSize: query.size, total, showSizeChanger: true, showTotal: (t: number) => translate('ui.m_f292bcb94fe6', { p0: (t) }) }"
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
              {{ record.hit_count || 1 }} {{ translate('ui.m_172fb7e67b9b') }}
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
              <a @click="viewDetail(record)">{{ translate('ui.m_979a332955c8') }}</a>
              <a @click="traceAttacker(record.source_ip)">{{ translate('ui.m_f1c618bd6e48') }}</a>
              <a-popconfirm :title="translate('ui.m_3c114045b255', { p0: (record.source_ip) })" @confirm="doBan(record.source_ip)">
                <a style="color:#cf1322">{{ translate('ui.m_6f93ba4c79f8') }}</a>
              </a-popconfirm>
              <a-popconfirm :title="translate('ui.m_2695ac4dc494', { p0: (record.source_ip) })" @confirm="doAddWhitelist(record.source_ip)">
                <a style="color:#52c41a">{{ translate('ui.m_bad6a27d86fa') }}</a>
              </a-popconfirm>
            </a-space>
          </template>
        </template>
      </a-table>
    </a-card>

    <!-- 封禁管理 + 白名单管理 -->
    <a-row :gutter="16" style="margin-top:16px">
      <a-col :span="12">
        <a-card :title="translate('ui.m_af1bbbadeda1')" :bordered="false">
          <template #extra><a-button size="small" @click="loadBans">{{ translate('ui.m_aee887434131') }}</a-button></template>
          <a-table :columns="banColumns" :data-source="bans" :loading="banLoading" size="small"
            :pagination="false" row-key="_id" :scroll="{ y: 260 }">
            <template #bodyCell="{ column, record }">
              <template v-if="column.key === 'ban_type'">
                <a-tag :color="record.ban_type === 'auto' ? 'orange' : 'red'">{{ record.ban_type === 'auto' ? translate('ui.m_7eb336e42cb5') : translate('ui.m_962f41ef825b') }}</a-tag>
              </template>
              <template v-if="column.key === 'expire_at'">
                <span>{{ record.expire_at ? formatTime(record.expire_at) : translate('ui.m_3e71ccc89a43') }}</span>
              </template>
              <template v-if="column.key === 'ban_action'">
                <a-space>
                  <a-popconfirm :title="translate('ui.m_a8f5577d18b3', { p0: (record._id) })" @confirm="doUnban(record._id)"><a>{{ translate('ui.m_f375a0009c57') }}</a></a-popconfirm>
                  <a-popconfirm :title="translate('ui.m_71a6ffd527ad', { p0: (record._id) })" @confirm="doAddWhitelist(record._id)"><a style="color:#52c41a">{{ translate('ui.m_bad6a27d86fa') }}</a></a-popconfirm>
                </a-space>
              </template>
            </template>
          </a-table>
          <a-empty v-if="!bans.length && !banLoading" :description="translate('ui.m_2a2707600e42')" />
        </a-card>
      </a-col>
      <a-col :span="12">
        <a-card :title="translate('ui.m_27e2d9e2d924')" :bordered="false">
          <template #extra>
            <a-space>
              <a-input v-model:value="wlInput" :placeholder="translate('ui.m_c9b7121a6dcc')" size="small" style="width:160px" @pressEnter="doAddWhitelistInput" />
              <a-button type="primary" size="small" @click="doAddWhitelistInput">{{ translate('ui.m_7a8a11ead507') }}</a-button>
              <a-button size="small" @click="loadWhitelist">{{ translate('ui.m_aee887434131') }}</a-button>
            </a-space>
          </template>
          <a-table :columns="wlColumns" :data-source="whitelist" :loading="wlLoading" size="small"
            :pagination="false" row-key="_id" :scroll="{ y: 260 }">
            <template #bodyCell="{ column, record }">
              <template v-if="column.key === 'added_at'">{{ formatTime(record.added_at) }}</template>
              <template v-if="column.key === 'wl_action'">
                <a-popconfirm :title="translate('ui.m_94ae52fd671b', { p0: (record._id) })" @confirm="doDelWhitelist(record._id)"><a style="color:#cf1322">{{ translate('ui.m_6135d4159e89') }}</a></a-popconfirm>
              </template>
            </template>
          </a-table>
          <a-empty v-if="!whitelist.length && !wlLoading" :description="translate('ui.m_198f3d4aaa7e')" />
        </a-card>
      </a-col>
    </a-row>

    <!-- 攻击详情弹窗 -->
    <a-modal v-model:open="detailVisible" :title="translate('ui.m_9e1ed951ade3')" width="800px" :footer="null" wrap-class-name="aa-detail">
      <a-descriptions v-if="currentAttack" class="aa-detail" :column="2" bordered>
        <a-descriptions-item :label="translate('ui.m_713eb94e2557')">
          <a-tag :color="getAttackTypeColor(currentAttack.attack_type)">{{ currentAttack.attack_type }}</a-tag>
        </a-descriptions-item>
        <a-descriptions-item :label="translate('ui.m_55b4fd17d6ed')">
          <a-tag :color="getSeverityColor(currentAttack.severity)">{{ getSeverityLabel(currentAttack.severity) }}</a-tag>
        </a-descriptions-item>
        <a-descriptions-item :label="translate('ui.m_fc04ec7e0993')" :span="2">
          <a @click="traceAttacker(currentAttack.source_ip)">{{ currentAttack.source_ip }}</a>
        </a-descriptions-item>
        <a-descriptions-item :label="translate('ui.m_b4f01cf8324d')" :span="2">
          <a-progress :percent="currentAttack.confidence * 100" />
        </a-descriptions-item>
        <a-descriptions-item :label="translate('ui.m_dc2ba467fc7a')" :span="2">{{ currentAttack.description }}</a-descriptions-item>
        <a-descriptions-item :label="translate('ui.m_ae8aee0dbbdc')" :span="2">{{ formatTime(currentAttack.timestamp) }}</a-descriptions-item>
        <a-descriptions-item :label="translate('ui.m_cf206666a6a5')">{{ currentAttack.request?.method }}</a-descriptions-item>
        <a-descriptions-item :label="translate('ui.m_f92b5d1f891e')">{{ currentAttack.request?.path }}</a-descriptions-item>
        <a-descriptions-item :label="translate('ui.m_1904a09fab00')" :span="2">
          <pre style="margin: 0; max-height: 100px; overflow: auto">{{ currentAttack.request?.query || '-' }}</pre>
        </a-descriptions-item>
        <a-descriptions-item :label="translate('ui.m_072acedc0af8')" :span="2">
          <pre style="margin: 0; background: #f5f5f5; padding: 8px; border-radius: 4px; max-height: 200px; overflow: auto">{{ currentAttack.evidence }}</pre>
        </a-descriptions-item>
        <a-descriptions-item :label="translate('ui.m_cea1aafe9416')" :span="2">
          <pre style="margin: 0; max-height: 150px; overflow: auto">{{ JSON.stringify(currentAttack.request?.headers, null, 2) }}</pre>
        </a-descriptions-item>
        <a-descriptions-item :label="translate('ui.m_c3760858cdb6')" :span="2">
          <pre style="margin: 0; max-height: 150px; overflow: auto">{{ currentAttack.request?.body || '-' }}</pre>
        </a-descriptions-item>
      </a-descriptions>
    </a-modal>

    <!-- 攻击者溯源弹窗 -->
    <a-modal v-model:open="traceVisible" :title="translate('ui.m_32c5ea5c8be4')" width="700px" :footer="null" wrap-class-name="aa-detail">
      <a-descriptions v-if="attackerProfile" class="aa-detail" :column="2" bordered>
        <a-descriptions-item :label="translate('ui.m_572c01ee2bf2')" :span="2">{{ attackerProfile.ip }}</a-descriptions-item>
        <a-descriptions-item :label="translate('ui.m_483abe2b9c80')" :span="2">
          <a-tag :color="attackerProfile.threat_level === 'high' ? 'red' : attackerProfile.threat_level === 'medium' ? 'orange' : 'default'">
            {{ attackerProfile.threat_level === 'high' ? translate('ui.m_4aa71c570566') : attackerProfile.threat_level === 'medium' ? translate('ui.m_36a7c77b623b') : translate('ui.m_27a7f42a0afb') }}
          </a-tag>
        </a-descriptions-item>
        <a-descriptions-item :label="translate('ui.m_0cc659a9f57c')">{{ attackerProfile.country }}</a-descriptions-item>
        <a-descriptions-item :label="translate('ui.m_ed84a1665f79')">{{ attackerProfile.city }}</a-descriptions-item>
        <a-descriptions-item label="ISP">{{ attackerProfile.isp }}</a-descriptions-item>
        <a-descriptions-item label="ASN">{{ attackerProfile.asn }}</a-descriptions-item>
        <a-descriptions-item :label="translate('ui.m_b5d72c5c00f2')">{{ attackerProfile.timezone }}</a-descriptions-item>
        <a-descriptions-item :label="translate('ui.m_cedb6cf006c0')">
          {{ attackerProfile.is_proxy ? 'Proxy' : '' }} {{ attackerProfile.is_vpn ? 'VPN' : '' }} {{ !attackerProfile.is_proxy && !attackerProfile.is_vpn ? translate('ui.m_0c70665b6eb6') : '' }}
        </a-descriptions-item>
        <a-descriptions-item :label="translate('ui.m_20265dc6b1be')">{{ attackerProfile.attack_history }}</a-descriptions-item>
        <a-descriptions-item :label="translate('ui.m_307cd3e0f270')" :span="2">
          <template v-if="attackerProfile.attack_types && attackerProfile.attack_types.length">
            <a-tag v-for="t in attackerProfile.attack_types" :key="t" :color="getAttackTypeColor(t)" style="margin-bottom:4px">{{ t }}</a-tag>
          </template>
          <span v-else>-</span>
        </a-descriptions-item>
        <a-descriptions-item :label="translate('ui.m_f28362666fee')">{{ formatTime(attackerProfile.first_seen) }}</a-descriptions-item>
        <a-descriptions-item :label="translate('ui.m_41f5cada11ed')">{{ formatTime(attackerProfile.last_seen) }}</a-descriptions-item>
      </a-descriptions>
    </a-modal>
  </PageContainer>
</template>

<script setup lang="ts">
import { t as translate } from '../../i18n'

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
  { get title() { return translate('ui.m_fc04ec7e0993') }, dataIndex: 'source_ip', key: 'source_ip', width: 150 },
  { get title() { return translate('ui.m_713eb94e2557') }, dataIndex: 'attack_type', key: 'attack_type', width: 160 },
  { get title() { return translate('ui.m_55b4fd17d6ed') }, dataIndex: 'severity', key: 'severity', width: 100 },
  { get title() { return translate('ui.m_c133427ba6d0') }, dataIndex: 'hit_count', key: 'hit_count', width: 100 },
  { get title() { return translate('ui.m_b4f01cf8324d') }, dataIndex: 'confidence', key: 'confidence', width: 140 },
  { get title() { return translate('ui.m_dc2ba467fc7a') }, dataIndex: 'description', key: 'description', ellipsis: true, width: 260 },
  { get title() { return translate('ui.m_58542839a693') }, dataIndex: 'timestamp', key: 'timestamp', width: 170, sorter: true, sortDirections: ['descend', 'ascend'], defaultSortOrder: 'descend' },
  { get title() { return translate('ui.m_ed31fbb483ee') }, key: 'actions', width: 120, fixed: 'right' }
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
  return severity === 'high' ? translate('ui.m_4aa71c570566') : severity === 'medium' ? translate('ui.m_36a7c77b623b') : translate('ui.m_27a7f42a0afb')
}

function formatTime(timestamp: number) {
  if (!timestamp) return '-'
  return new Date(timestamp * 1000).toLocaleString('zh-CN')
}

async function loadStats() {
  try {
    stats.value = await attackAlertApi.getStats()
  } catch (error) {
    message.error(translate('ui.m_a45f0f924582') + (error instanceof Error ? error.message : String(error)))
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
    message.error(translate('ui.m_dbe37fce81cb') + (error instanceof Error ? error.message : String(error)))
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
  { get title() { return translate('ui.m_ba40014ff496') }, dataIndex: 'ban_type', key: 'ban_type', width: 70 },
  { get title() { return translate('ui.m_f029d9cb4a76') }, dataIndex: 'reason', key: 'reason', ellipsis: true },
  { get title() { return translate('ui.m_1f29b74ad60c') }, dataIndex: 'expire_at', key: 'expire_at', width: 160 },
  { get title() { return translate('ui.m_ed31fbb483ee') }, key: 'ban_action', width: 110 }
]
const wlColumns = [
  { title: 'IP', dataIndex: '_id', key: '_id' },
  { get title() { return translate('ui.m_9689906e74a1') }, dataIndex: 'operator', key: 'operator', width: 90 },
  { get title() { return translate('ui.m_526fed29561d') }, dataIndex: 'added_at', key: 'added_at', width: 160 },
  { get title() { return translate('ui.m_ed31fbb483ee') }, key: 'wl_action', width: 70 }
]

async function loadBans() {
  banLoading.value = true
  try { bans.value = (await attackAlertApi.banList()).items }
  catch (e) { message.error(translate('ui.m_08d7e7c9e3db') + (e instanceof Error ? e.message : String(e))) }
  finally { banLoading.value = false }
}
async function loadWhitelist() {
  wlLoading.value = true
  try { whitelist.value = (await attackAlertApi.whitelist()).items }
  catch (e) { message.error(translate('ui.m_0572878980c9') + (e instanceof Error ? e.message : String(e))) }
  finally { wlLoading.value = false }
}
async function doBan(ip: string) {
  try { await attackAlertApi.banIp(ip); message.success(translate('ui.m_882cf60ee113', { p0: (ip) })); loadBans() }
  catch (e) { message.error(translate('ui.m_0d918c5a4188') + (e instanceof Error ? e.message : String(e))) }
}
async function doUnban(ip: string) {
  try { await attackAlertApi.unbanIp(ip); message.success(translate('ui.m_157651819da7', { p0: (ip) })); loadBans() }
  catch (e) { message.error(translate('ui.m_7fc3bf9e3c92') + (e instanceof Error ? e.message : String(e))) }
}
async function doAddWhitelist(ip: string) {
  try { await attackAlertApi.addWhitelist(ip); message.success(translate('ui.m_f95c112a1adb', { p0: (ip) })); loadWhitelist(); loadBans() }
  catch (e) { message.error(translate('ui.m_60ab7338f16b') + (e instanceof Error ? e.message : String(e))) }
}
function doAddWhitelistInput() {
  const ip = wlInput.value.trim()
  if (!ip) { message.warning(translate('ui.m_295bd10db17e')); return }
  doAddWhitelist(ip); wlInput.value = ''
}
async function doDelWhitelist(ip: string) {
  try { await attackAlertApi.delWhitelist(ip); message.success(translate('ui.m_6df48e790144', { p0: (ip) })); loadWhitelist() }
  catch (e) { message.error(translate('ui.m_6fad9a6a6179') + (e instanceof Error ? e.message : String(e))) }
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
    message.error(translate('ui.m_166ba6240fac') + (error instanceof Error ? error.message : String(error)))
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
