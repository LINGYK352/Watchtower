<template>
  <PageContainer :title="translate('ui.m_0f0de6f7ec4f')" kicker="Asset Group Detail" :description="translate('ui.m_ea1b8da7f947')">
    <template #extra>
      <a-space>
        <a-button v-if="tab === 'domain' || tab === 'site'" type="primary" @click="openAdd">{{ translate('ui.m_7a8a11ead507') }}{{ tab === 'domain' ? translate('ui.m_222952431147') : translate('ui.m_a59fe62777ff') }}</a-button>
        <a-button @click="exportCurrent">{{ translate('ui.m_929e5852cc18') }}</a-button>
        <a-button @click="router.push('/asset-groups')">{{ translate('ui.m_26712eb0693b') }}</a-button>
      </a-space>
    </template>
    <a-tabs v-model:activeKey="tab" @change="onTabChange">
      <a-tab-pane key="domain" tab="域名" />
      <a-tab-pane key="ip" tab="IP" />
      <a-tab-pane key="site" tab="站点" />
      <a-tab-pane key="wih" tab="WIH" />
    </a-tabs>

    <SearchBar :model="query" @search="load" @reset="reset">
      <a-form-item :label="translate('ui.m_884e461647a3')"><a-input v-model:value="keyword" allow-clear :placeholder="keywordPlaceholder" /></a-form-item>
    </SearchBar>
    <a-card :bordered="false">
      <a-space style="margin-bottom: 12px" v-if="selectedRowKeys.length">
        <ConfirmAction danger type="primary" :title="translate('ui.m_af96f361fe7b')" @confirm="removeSelected">{{ translate('ui.m_b2a2890c8d6e') }}{{ selectedRowKeys.length }})</ConfirmAction>
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

  <a-modal v-model:open="addOpen" :title="translate('ui.m_917d669b11c3', { p0: (tab === 'domain' ? '域名' : '站点') })" @ok="submitAdd" :confirm-loading="adding">
    <a-form-item :label="tab === 'domain' ? translate('ui.m_222952431147') : translate('ui.m_fb952476c712')">
      <a-textarea v-model:value="addValue" :rows="3" :placeholder="tab === 'domain' ? translate('ui.m_6ad7d19386c0') : translate('ui.m_0dbc0220d10b')" />
    </a-form-item>
    <a-alert type="info" show-icon :message="translate('ui.m_610854583b0a')" />
  </a-modal>
</template>

<script setup lang="ts">
import { t as translate } from '../../i18n'

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
const keywordPlaceholder = computed(() => ({ get domain() { return translate('ui.m_222952431147') }, ip: 'IP', get site() { return translate('ui.m_fb952476c712') }, get wih() { return translate('ui.m_7a688306423b') } } as Record<string, string>)[tab.value])

const columnsMap: Record<string, Record<string, unknown>[]> = {
  domain: [
    { get title() { return translate('ui.m_222952431147') }, key: 'copy', width: 240, ellipsis: true },
    { get title() { return translate('ui.m_ba40014ff496') }, dataIndex: 'type', key: 'type', width: 80 },
    { get title() { return translate('ui.m_5632a6a4e542') }, dataIndex: 'record', key: 'record', ellipsis: true },
    { get title() { return translate('ui.m_a488e93d69cc') }, dataIndex: 'source', key: 'source', width: 120 }
  ],
  ip: [
    { title: 'IP', key: 'copy', width: 160 },
    { get title() { return translate('ui.m_e71ac32b544b') }, key: 'ports', ellipsis: true },
    { get title() { return translate('ui.m_aa2353039024') }, dataIndex: 'task_id', key: 'task_id', width: 130, ellipsis: true }
  ],
  site: [
    { get title() { return translate('ui.m_a59fe62777ff') }, key: 'copy', ellipsis: true },
    { get title() { return translate('ui.m_c3405f8c7d9d') }, dataIndex: 'title', key: 'title', ellipsis: true },
    { get title() { return translate('ui.m_6320b4a8722a') }, dataIndex: 'status', key: 'status', width: 80 }
  ],
  wih: [
    { get title() { return translate('ui.m_7a688306423b') }, key: 'copy', ellipsis: true },
    { get title() { return translate('ui.m_ba40014ff496') }, dataIndex: 'record_type', key: 'record_type', width: 120 },
    { get title() { return translate('ui.m_a59fe62777ff') }, dataIndex: 'site', key: 'site', ellipsis: true }
  ]
}
const columns = computed(() => columnsMap[tab.value])
const pagination = computed(() => ({ current: query.page, pageSize: query.size, total: total.value, showSizeChanger: true, showTotal: (t: number) => translate('ui.m_f292bcb94fe6', { p0: (t) }) }))

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
  try { await apiMap[tab.value].delete(selectedRowKeys.value); message.success(translate('ui.m_077a6d37719a')); load() }
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
  if (!targets.length) return message.warning(translate('ui.m_606ae522e681'))
  adding.value = true
  try {
    for (const t of targets) {
      if (tab.value === 'domain') await assetDomainApi.add({ domain: t, scope_id: scopeId.value })
      else await assetSiteApi.add({ site: t, scope_id: scopeId.value })
    }
    message.success(translate('ui.m_30da848e0737', { p0: (targets.length) })); addOpen.value = false; load()
  } catch (error) { message.error(error instanceof Error ? error.message : String(error)) }
  finally { adding.value = false }
}
onMounted(load)
</script>
