<template>
  <PageContainer title="GitHub 监控" kicker="GitHub Monitor" description="GitHub 关键字周期监控任务。">
    <template #extra><a-button type="primary" @click="openAdd">新建监控</a-button></template>
    <SearchBar :model="query" @search="load" @reset="reset">
      <a-form-item label="任务名"><a-input v-model:value="query.name" allow-clear placeholder="任务名" /></a-form-item>
      <a-form-item label="关键字"><a-input v-model:value="query.keyword" allow-clear placeholder="关键字" /></a-form-item>
    </SearchBar>
    <a-card :bordered="false">
      <a-table :columns="columns" :data-source="items" :loading="loading" row-key="_id" :pagination="pagination" size="middle" bordered @change="onChange">
        <template #bodyCell="{ column, record }">
          <template v-if="column.key === 'status'"><StatusTag :value="String(record.status || '')" /></template>
          <template v-else-if="column.key === 'keyword'"><CopyText :text="String(record.keyword || '')" /></template>
          <template v-else-if="column.key === 'action'">
            <a-space size="small">
              <a-button type="link" size="small" @click="viewResult(record)">结果</a-button>
              <a-button type="link" size="small" @click="openEdit(record)">编辑</a-button>
              <ConfirmAction v-if="record.status === 'running'" title="确认停止监控？" @confirm="stop(String(record._id))">停止</ConfirmAction>
              <ConfirmAction v-else title="确认恢复监控？" @confirm="recover(String(record._id))">恢复</ConfirmAction>
              <ConfirmAction danger title="确认删除监控？" @confirm="remove(String(record._id))">删除</ConfirmAction>
            </a-space>
          </template>
        </template>
      </a-table>
    </a-card>

    <a-modal v-model:open="editOpen" :title="editId ? '编辑监控' : '新建监控'" @ok="submit" :confirm-loading="saving">
      <a-form layout="vertical">
        <a-form-item label="任务名" required><a-input v-model:value="form.name" placeholder="任务名" /></a-form-item>
        <a-form-item label="关键字" required><a-input v-model:value="form.keyword" placeholder="搜索关键字" /></a-form-item>
        <a-form-item label="Cron 表达式" required><a-input v-model:value="form.cron" placeholder="如 0 0 * * *" /></a-form-item>
      </a-form>
    </a-modal>

    <a-drawer v-model:open="resultOpen" title="监控结果" width="60%">
      <a-table :columns="resultColumns" :data-source="results" :loading="resultLoading" row-key="_id" :pagination="resultPagination" size="small" bordered @change="onResultChange">
        <template #bodyCell="{ column, record }">
          <template v-if="column.key === 'repo'"><CopyText :text="String(record.repo_full_name || '')" /></template>
          <template v-else-if="column.key === 'path'"><CopyText :text="String(record.path || '')" /></template>
        </template>
      </a-table>
    </a-drawer>
  </PageContainer>
</template>

<script setup lang="ts">
import { computed, onMounted, reactive, ref } from 'vue'
import { message } from 'ant-design-vue'
import PageContainer from '../../layouts/PageContainer.vue'
import SearchBar from '../../components/SearchBar.vue'
import StatusTag from '../../components/StatusTag.vue'
import CopyText from '../../components/CopyText.vue'
import ConfirmAction from '../../components/ConfirmAction.vue'
import { githubSchedulerApi, githubMonitorResultApi } from '../../api/github'
import type { RowRecord } from '../../api/types'

const loading = ref(false)
const items = ref<RowRecord[]>([])
const total = ref(0)
const query = reactive({ page: 1, size: 10, order: '-_id', name: '', keyword: '' })

const columns = [
  { title: '任务名', dataIndex: 'name', key: 'name', ellipsis: true },
  { title: '关键字', key: 'keyword', ellipsis: true },
  { title: 'Cron', dataIndex: 'cron', key: 'cron', width: 130 },
  { title: '状态', key: 'status', width: 90 },
  { title: '运行次数', dataIndex: 'run_number', key: 'run_number', width: 90 },
  { title: '下次运行', dataIndex: 'next_run_date', key: 'next_run_date', width: 170 },
  { title: '操作', key: 'action', width: 240 }
]
const pagination = computed(() => ({ current: query.page, pageSize: query.size, total: total.value, showSizeChanger: true, showTotal: (t: number) => `共 ${t} 条` }))

async function load() {
  loading.value = true
  try {
    const data = await githubSchedulerApi.list(query)
    items.value = data.items || []
    total.value = data.total || 0
  } catch (error) {
    message.error(error instanceof Error ? error.message : String(error))
  } finally {
    loading.value = false
  }
}
function reset() { query.name = ''; query.keyword = ''; query.page = 1; load() }
function onChange(p: { current?: number; pageSize?: number }) { query.page = p.current || 1; query.size = p.pageSize || 10; load() }

/* 新建 / 编辑 */
const editOpen = ref(false)
const saving = ref(false)
const editId = ref('')
const form = reactive({ name: '', keyword: '', cron: '' })
function openAdd() { editId.value = ''; form.name = ''; form.keyword = ''; form.cron = '0 0 * * *'; editOpen.value = true }
function openEdit(record: RowRecord) {
  editId.value = String(record._id)
  form.name = String(record.name || ''); form.keyword = String(record.keyword || ''); form.cron = String(record.cron || '')
  editOpen.value = true
}
async function submit() {
  if (!form.name || !form.keyword || !form.cron) return message.warning('请填写任务名、关键字和 Cron')
  saving.value = true
  try {
    if (editId.value) await githubSchedulerApi.update({ _id: editId.value, ...form })
    else await githubSchedulerApi.add({ ...form })
    message.success('已保存'); editOpen.value = false; load()
  } catch (error) { message.error(error instanceof Error ? error.message : String(error)) }
  finally { saving.value = false }
}
async function stop(id: string) { try { await githubSchedulerApi.stop([id]); message.success('已停止'); load() } catch (e) { message.error(String(e)) } }
async function recover(id: string) { try { await githubSchedulerApi.recover([id]); message.success('已恢复'); load() } catch (e) { message.error(String(e)) } }
async function remove(id: string) { try { await githubSchedulerApi.delete([id]); message.success('已删除'); load() } catch (e) { message.error(String(e)) } }

/* 结果抽屉 */
const resultOpen = ref(false)
const resultLoading = ref(false)
const results = ref<RowRecord[]>([])
const resultTotal = ref(0)
const resultQuery = reactive({ page: 1, size: 10, order: '-_id', github_scheduler_id: '' })
const resultColumns = [
  { title: '仓库', key: 'repo', ellipsis: true },
  { title: '路径', key: 'path', ellipsis: true },
  { title: '内容', dataIndex: 'human_content', key: 'human_content', ellipsis: true }
]
const resultPagination = computed(() => ({ current: resultQuery.page, pageSize: resultQuery.size, total: resultTotal.value, showSizeChanger: true }))
function viewResult(record: RowRecord) { resultQuery.github_scheduler_id = String(record._id); resultQuery.page = 1; resultOpen.value = true; loadResult() }
async function loadResult() {
  resultLoading.value = true
  try {
    const data = await githubMonitorResultApi.list(resultQuery)
    results.value = data.items || []
    resultTotal.value = data.total || 0
  } catch (error) {
    message.error(error instanceof Error ? error.message : String(error))
  } finally {
    resultLoading.value = false
  }
}
function onResultChange(p: { current?: number; pageSize?: number }) { resultQuery.page = p.current || 1; resultQuery.size = p.pageSize || 10; loadResult() }
onMounted(load)
</script>
