<template>
  <PageContainer title="PoC 信息" kicker="PoC" description="PoC 插件库，可从源同步或清空。">
    <template #extra>
      <a-space>
        <a-upload :before-upload="beforeImport" :show-upload-list="false" accept=".py">
          <a-button type="primary" :loading="importing">导入 POC</a-button>
        </a-upload>
        <a-upload :before-upload="beforeBatch" :show-upload-list="false" accept=".zip">
          <a-button :loading="batching">批量导入(zip)</a-button>
        </a-upload>
        <a-button @click="downloadTemplate">下载模板</a-button>
        <ConfirmAction type="default" title="确认从源同步内置 PoC？" @confirm="sync">同步 PoC</ConfirmAction>
        <ConfirmAction danger type="default" title="确认清空全部 PoC？" @confirm="clearAll">清空</ConfirmAction>
      </a-space>
    </template>
    <a-alert type="warning" show-icon style="margin-bottom: 12px"
      message="导入的 POC 为 .py 脚本：npoc 结构(class Plugin(BasePlugin))自动进内核扫描执行，其他脚本供 AI 渗透 query_poc 检索/read_poc 读取。POC 会被真实执行，仅导入可信来源。" />
    <a-space style="margin-bottom: 12px" v-if="selectedRowKeys.length">
      <ConfirmAction danger type="primary" title="确认删除选中的导入 POC(含物理文件)？" @confirm="removeSelected">删除选中 ({{ selectedRowKeys.length }})</ConfirmAction>
    </a-space>
    <SearchBar :model="query" @search="load" @reset="reset">
      <a-form-item label="插件名"><a-input v-model:value="query.plugin_name" allow-clear placeholder="plugin id" /></a-form-item>
      <a-form-item label="应用名"><a-input v-model:value="query.app_name" allow-clear placeholder="应用名" /></a-form-item>
      <a-form-item label="漏洞名"><a-input v-model:value="query.vul_name" allow-clear placeholder="漏洞名称" /></a-form-item>
      <a-form-item label="类别"><a-select v-model:value="query.plugin_type" allow-clear style="width: 120px" :options="typeOptions" /></a-form-item>
    </SearchBar>
    <a-card :bordered="false">
      <AppTable :columns="columns" :data="items" :loading="loading" :page="query.page" :size="query.size" :total="total" @change="changePage"
        :row-selection="{ selectedRowKeys, onChange: onSelectChange }" row-key="_id">
        <template #bodyCell="{ column, record }">
          <template v-if="column.key === 'plugin_name'"><CopyText :text="String(record.plugin_name || '')" /></template>
          <template v-else-if="column.key === 'plugin_type'"><a-tag :color="record.plugin_type === 'brute' ? 'orange' : 'blue'">{{ record.plugin_type || '-' }}</a-tag></template>
          <template v-else-if="column.key === 'source'">
            <a-tag :color="record.source === 'imported' ? 'green' : 'default'">{{ record.source === 'imported' ? '导入' : '内置' }}</a-tag>
            <a-tag v-if="record.poc_format" :color="record.poc_format === 'npoc' ? 'blue' : 'purple'" style="margin-left:4px">{{ record.poc_format }}</a-tag>
          </template>
          <template v-else-if="column.key === 'action'"><a-button type="link" size="small" @click="showDetail(record)">详情</a-button></template>
        </template>
      </AppTable>
    </a-card>
    <JsonPreview v-model:open="detailOpen" :data="current" />
  </PageContainer>
</template>

<script setup lang="ts">
import { onMounted, reactive, ref } from 'vue'
import { message } from 'ant-design-vue'
import PageContainer from '../../layouts/PageContainer.vue'
import SearchBar from '../../components/SearchBar.vue'
import AppTable from '../../components/AppTable.vue'
import CopyText from '../../components/CopyText.vue'
import ConfirmAction from '../../components/ConfirmAction.vue'
import JsonPreview from '../../components/JsonPreview.vue'
import { pocApi } from '../../api/poc'
import type { RowRecord } from '../../api/types'

const loading = ref(false)
const items = ref<RowRecord[]>([])
const total = ref(0)
const detailOpen = ref(false)
const current = ref<RowRecord>({})
const importing = ref(false)
const batching = ref(false)
const selectedRowKeys = ref<string[]>([])
const query = reactive({ page: 1, size: 10, order: '-_id', plugin_name: '', app_name: '', vul_name: '', plugin_type: undefined as string | undefined })

const typeOptions = [
  { label: 'PoC', value: 'poc' },
  { label: '爆破', value: 'brute' }
]
const columns = [
  { title: '插件名', key: 'plugin_name', ellipsis: true },
  { title: '应用名', dataIndex: 'app_name', key: 'app_name', width: 150, ellipsis: true },
  { title: '协议', dataIndex: 'scheme', key: 'scheme', width: 120 },
  { title: '漏洞名', dataIndex: 'vul_name', key: 'vul_name', ellipsis: true },
  { title: '类别', key: 'plugin_type', width: 90 },
  { title: '来源', key: 'source', width: 130 },
  { title: '更新时间', dataIndex: 'update_date', key: 'update_date', width: 170 },
  { title: '操作', key: 'action', width: 80 }
]

async function load() {
  loading.value = true
  try {
    const data = await pocApi.list(query)
    items.value = data.items || []
    total.value = data.total || 0
  } catch (error) {
    message.error(error instanceof Error ? error.message : String(error))
  } finally {
    loading.value = false
  }
}
function reset() { query.plugin_name = ''; query.app_name = ''; query.vul_name = ''; query.plugin_type = undefined; query.page = 1; load() }
function changePage(page: number, size: number) { query.page = page; query.size = size; load() }
function showDetail(record: RowRecord) { current.value = record; detailOpen.value = true }
async function sync() {
  try { const r = await pocApi.sync(); message.success(`同步完成，共 ${r.plugin_cnt} 个插件`); load() }
  catch (error) { message.error(error instanceof Error ? error.message : String(error)) }
}
async function clearAll() {
  try { const r = await pocApi.clear(); message.success(`已清空 ${r.delete_cnt} 个插件`); load() }
  catch (error) { message.error(error instanceof Error ? error.message : String(error)) }
}
function onSelectChange(keys: (string | number)[]) { selectedRowKeys.value = keys.map(String) }
function beforeImport(file: File) {
  importing.value = true
  pocApi.importFile(file)
    .then((r: any) => {
      if (r.code === 200) message.success(`已导入 ${r.data?.plugin_name}（${r.data?.poc_format === 'npoc' ? 'npoc 结构，进内核扫描' : '脚本，供 AI 检索'}）`)
      else message.error(r.message || '导入失败')
      load()
    })
    .catch(e => message.error(String(e)))
    .finally(() => { importing.value = false })
  return false
}
function beforeBatch(file: File) {
  batching.value = true
  pocApi.batchImport(file)
    .then((r: any) => {
      if (r.code === 200) message.success(`批量导入完成：成功 ${r.data?.success}，跳过 ${r.data?.skipped}，失败 ${r.data?.failed}`)
      else message.error(r.message || '批量导入失败')
      load()
    })
    .catch(e => message.error(String(e)))
    .finally(() => { batching.value = false })
  return false
}
function downloadTemplate() { window.open(pocApi.templateUrl(), '_blank') }
async function removeSelected() {
  try { const r = await pocApi.remove(selectedRowKeys.value); message.success(`已删除 ${r.deleted} 个`); selectedRowKeys.value = []; load() }
  catch (error) { message.error(error instanceof Error ? error.message : String(error)) }
}
onMounted(load)
</script>
