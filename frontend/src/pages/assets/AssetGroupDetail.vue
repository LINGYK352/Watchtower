<template>
  <PageContainer title="分组资产" kicker="Asset Group Detail" description="查看资产组内的域名 / IP / 站点 / WIH。">
    <template #extra>
      <a-space>
        <a-button v-if="tab === 'domain' || tab === 'site'" type="primary" @click="openAdd">添加{{ tab === 'domain' ? '域名' : '站点' }}</a-button>
        <a-button @click="exportCurrent">导出当前</a-button>
        <a-button @click="router.push('/asset-groups')">返回分组</a-button>
      </a-space>
    </template>
    <a-tabs v-model:activeKey="tab" @change="onTabChange">
      <a-tab-pane key="domain" tab="域名" />
      <a-tab-pane key="ip" tab="IP" />
      <a-tab-pane key="site" tab="站点" />
      <a-tab-pane key="wih" tab="WIH" />
    </a-tabs>

    <SearchBar :model="query" @search="load" @reset="reset">
      <a-form-item label="关键字"><a-input v-model:value="keyword" allow-clear :placeholder="keywordPlaceholder" /></a-form-item>
    </SearchBar>
    <a-card :bordered="false">
      <a-space style="margin-bottom: 12px" v-if="selectedRowKeys.length">
        <ConfirmAction danger type="primary" title="确认删除选中资产？" @confirm="removeSelected">删除选中 ({{ selectedRowKeys.length }})</ConfirmAction>
      </a-space>
      <a-table :columns="columns" :data-source="items" :loading="loading" row-key="_id" :pagination="pagination" size="middle" bordered
        :row-selection="{ selectedRowKeys, onChange: onSelectChange }" @change="onChange">
        <template #bodyCell="{ column, record }">
          <template v-if="column.key === 'copy'"><CopyText :text="String(record[primaryField] || '')" /></template>
          <template v-else-if="column.key === 'ports'">
            <a-space wrap size="small"><a-tag v-for="p in ports(record)" :key="p">{{ p }}</a-tag></a-space>
          </template>
        </template>
      </a-table>
    </a-card>
  </PageContainer>

  <a-modal v-model:open="addOpen" :title="`添加${tab === 'domain' ? '域名' : '站点'}到分组`" @ok="submitAdd" :confirm-loading="adding">
    <a-form-item :label="tab === 'domain' ? '域名' : '站点 URL'">
      <a-textarea v-model:value="addValue" :rows="3" :placeholder="tab === 'domain' ? '域名，多个换行' : '站点 URL，多个换行'" />
    </a-form-item>
    <a-alert type="info" show-icon message="提交后会对新增目标下发扫描任务并归入本资产组。" />
  </a-modal>
</template>

<script setup lang="ts">
import { computed, onMounted, reactive, ref } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { message } from 'ant-design-vue'
import PageContainer from '../../layouts/PageContainer.vue'
import SearchBar from '../../components/SearchBar.vue'
import CopyText from '../../components/CopyText.vue'
import ConfirmAction from '../../components/ConfirmAction.vue'
import { assetDomainApi, assetIpApi, assetSiteApi, assetWihApi } from '../../api/scope'
import type { RowRecord, PortInfo } from '../../api/types'

const route = useRoute()
const router = useRouter()
const scopeId = computed(() => String(route.params.id || ''))
const tab = ref<'domain' | 'ip' | 'site' | 'wih'>('domain')
const loading = ref(false)
const items = ref<RowRecord[]>([])
const total = ref(0)
const keyword = ref('')
const selectedRowKeys = ref<string[]>([])
const query = reactive({ page: 1, size: 10, order: '-_id' })

const apiMap = { domain: assetDomainApi, ip: assetIpApi, site: assetSiteApi, wih: assetWihApi }
const primaryField = computed(() => ({ domain: 'domain', ip: 'ip', site: 'site', wih: 'content' } as const)[tab.value])
const keywordField = computed(() => ({ domain: 'domain', ip: 'ip', site: 'site', wih: 'content' } as const)[tab.value])
const keywordPlaceholder = computed(() => ({ domain: '域名', ip: 'IP', site: '站点 URL', wih: '内容' } as Record<string, string>)[tab.value])

const columnsMap: Record<string, Record<string, unknown>[]> = {
  domain: [
    { title: '域名', key: 'copy', width: 240, ellipsis: true },
    { title: '类型', dataIndex: 'type', key: 'type', width: 80 },
    { title: '解析值', dataIndex: 'record', key: 'record', ellipsis: true },
    { title: '来源', dataIndex: 'source', key: 'source', width: 120 }
  ],
  ip: [
    { title: 'IP', key: 'copy', width: 160 },
    { title: '端口', key: 'ports', ellipsis: true },
    { title: '任务ID', dataIndex: 'task_id', key: 'task_id', width: 130, ellipsis: true }
  ],
  site: [
    { title: '站点', key: 'copy', ellipsis: true },
    { title: '标题', dataIndex: 'title', key: 'title', ellipsis: true },
    { title: '状态', dataIndex: 'status', key: 'status', width: 80 }
  ],
  wih: [
    { title: '内容', key: 'copy', ellipsis: true },
    { title: '类型', dataIndex: 'record_type', key: 'record_type', width: 120 },
    { title: '站点', dataIndex: 'site', key: 'site', ellipsis: true }
  ]
}
const columns = computed(() => columnsMap[tab.value])
const pagination = computed(() => ({ current: query.page, pageSize: query.size, total: total.value, showSizeChanger: true, showTotal: (t: number) => `共 ${t} 条` }))

function ports(record: RowRecord) {
  return ((record.port_info as PortInfo[]) || []).map(p => p.port_id).filter(Boolean)
}
function buildQuery() {
  return { ...query, scope_id: scopeId.value, ...(keyword.value ? { [keywordField.value]: keyword.value } : {}) }
}
async function load() {
  loading.value = true
  selectedRowKeys.value = []
  try {
    const data = await apiMap[tab.value].list(buildQuery())
    items.value = data.items || []
    total.value = data.total || 0
  } catch (error) {
    message.error(error instanceof Error ? error.message : String(error))
  } finally {
    loading.value = false
  }
}
function reset() { keyword.value = ''; query.page = 1; load() }
function onTabChange() { keyword.value = ''; query.page = 1; load() }
function onChange(p: { current?: number; pageSize?: number }) { query.page = p.current || 1; query.size = p.pageSize || 10; load() }
function onSelectChange(keys: (string | number)[]) { selectedRowKeys.value = keys.map(String) }
async function removeSelected() {
  try { await apiMap[tab.value].delete(selectedRowKeys.value); message.success('已删除'); load() }
  catch (error) { message.error(error instanceof Error ? error.message : String(error)) }
}
function exportCurrent() { window.open(apiMap[tab.value].exportUrl(buildQuery()), '_blank') }

/* 添加域名 / 站点到分组 */
const addOpen = ref(false)
const adding = ref(false)
const addValue = ref('')
function openAdd() { addValue.value = ''; addOpen.value = true }
async function submitAdd() {
  const targets = addValue.value.split(/[\n,]/).map(s => s.trim()).filter(Boolean)
  if (!targets.length) return message.warning('请输入内容')
  adding.value = true
  try {
    for (const t of targets) {
      if (tab.value === 'domain') await assetDomainApi.add({ domain: t, scope_id: scopeId.value })
      else await assetSiteApi.add({ site: t, scope_id: scopeId.value })
    }
    message.success(`已添加 ${targets.length} 个`); addOpen.value = false; load()
  } catch (error) { message.error(error instanceof Error ? error.message : String(error)) }
  finally { adding.value = false }
}
onMounted(load)
</script>
