<template>
  <PageContainer title="GitHub 任务" kicker="GitHub" description="GitHub 关键字一次性搜索任务。">
    <template #extra><a-button type="primary" @click="openAdd">新建任务</a-button></template>
    <SearchBar :model="query" @search="load" @reset="reset">
      <a-form-item label="任务名"><a-input v-model:value="query.name" allow-clear placeholder="任务名" /></a-form-item>
      <a-form-item label="关键字"><a-input v-model:value="query.keyword" allow-clear placeholder="关键字" /></a-form-item>
      <a-form-item label="状态"><a-input v-model:value="query.status" allow-clear placeholder="状态" /></a-form-item>
    </SearchBar>
    <a-card :bordered="false">
      <a-table :columns="columns" :data-source="items" :loading="loading" row-key="_id" :pagination="pagination" size="middle" bordered @change="onChange">
        <template #bodyCell="{ column, record }">
          <template v-if="column.key === 'status'"><StatusTag :value="String(record.status || '')" /></template>
          <template v-else-if="column.key === 'keyword'"><CopyText :text="String(record.keyword || '')" /></template>
          <template v-else-if="column.key === 'action'">
            <a-space size="small">
              <a-button type="link" size="small" @click="viewResult(record)">结果</a-button>
              <ConfirmAction title="确认停止该任务？" @confirm="stop(String(record._id))">停止</ConfirmAction>
              <ConfirmAction danger title="确认删除该任务？" @confirm="remove(String(record._id))">删除</ConfirmAction>
            </a-space>
          </template>
        </template>
      </a-table>
    </a-card>

    <a-modal v-model:open="addOpen" title="新建 GitHub 任务" @ok="submitAdd" :confirm-loading="adding">
      <a-form layout="vertical">
        <a-form-item label="任务名" required><a-input v-model:value="addForm.name" placeholder="任务名" /></a-form-item>
        <a-form-item label="关键字" required><a-input v-model:value="addForm.keyword" placeholder="搜索关键字" /></a-form-item>
      </a-form>
    </a-modal>

    <a-drawer v-model:open="resultOpen" title="任务结果" width="60%">
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
import { githubTaskApi, githubResultApi } from '../../api/github'
import type { RowRecord } from '../../api/types'

const loading = ref(false)
const items = ref<RowRecord[]>([])
const total = ref(0)
const query = reactive({ page: 1, size: 10, order: '-_id', name: '', keyword: '', status: '' })
const addOpen = ref(false)
const adding = ref(false)
const addForm = reactive({ name: '', keyword: '' })

const columns = [
  { title: '任务名', dataIndex: 'name', key: 'name', ellipsis: true },
  { title: '关键字', key: 'keyword', ellipsis: true },
  { title: '状态', key: 'status', width: 100 },
  { title: '开始时间', dataIndex: 'start_time', key: 'start_time', width: 170 },
  { title: '结束时间', dataIndex: 'end_time', key: 'end_time', width: 170 },
  { title: '操作', key: 'action', width: 180 }
]
const pagination = computed(() => ({ current: query.page, pageSize: query.size, total: total.value, showSizeChanger: true, showTotal: (t: number) => `共 ${t} 条` }))

async function load() {
  loading.value = true
  try {
    const data = await githubTaskApi.list(query)
    items.value = data.items || []
    total.value = data.total || 0
  } catch (error) {
    message.error(error instanceof Error ? error.message : String(error))
  } finally {
    loading.value = false
  }
}
function reset() { query.name = ''; query.keyword = ''; query.status = ''; query.page = 1; load() }
function onChange(p: { current?: number; pageSize?: number }) { query.page = p.current || 1; query.size = p.pageSize || 10; load() }
function openAdd() { addForm.name = ''; addForm.keyword = ''; addOpen.value = true }
async function submitAdd() {
  if (!addForm.name || !addForm.keyword) return message.warning('请填写任务名和关键字')
  adding.value = true
  try { await githubTaskApi.add({ ...addForm }); message.success('已创建'); addOpen.value = false; load() }
  catch (error) { message.error(error instanceof Error ? error.message : String(error)) }
  finally { adding.value = false }
}
async function stop(id: string) { try { await githubTaskApi.stop([id]); message.success('已发送停止'); load() } catch (e) { message.error(String(e)) } }
async function remove(id: string) { try { await githubTaskApi.delete([id]); message.success('已删除'); load() } catch (e) { message.error(String(e)) } }

/* 结果抽屉 */
const resultOpen = ref(false)
const resultLoading = ref(false)
const results = ref<RowRecord[]>([])
const resultTotal = ref(0)
const resultQuery = reactive({ page: 1, size: 10, order: '-_id', github_task_id: '' })
const resultColumns = [
  { title: '仓库', key: 'repo', ellipsis: true },
  { title: '路径', key: 'path', ellipsis: true },
  { title: '内容', dataIndex: 'human_content', key: 'human_content', ellipsis: true }
]
const resultPagination = computed(() => ({ current: resultQuery.page, pageSize: resultQuery.size, total: resultTotal.value, showSizeChanger: true }))
function viewResult(record: RowRecord) { resultQuery.github_task_id = String(record._id); resultQuery.page = 1; resultOpen.value = true; loadResult() }
async function loadResult() {
  resultLoading.value = true
  try {
    const data = await githubResultApi.list(resultQuery)
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
