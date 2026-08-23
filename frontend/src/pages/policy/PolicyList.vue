<template>
  <PageContainer title="策略配置" kicker="Policy" description="扫描策略库。策略用于任务下发与计划任务。">
    <template #extra><a-button type="primary" @click="router.push('/policy/new')">新建策略</a-button></template>
    <SearchBar :model="query" @search="load" @reset="reset">
      <a-form-item label="策略名"><a-input v-model:value="query.name" allow-clear placeholder="策略名称" /></a-form-item>
    </SearchBar>
    <a-card :bordered="false">
      <a-table :columns="columns" :data-source="items" :loading="loading" row-key="_id" :pagination="pagination" size="middle" bordered @change="onChange">
        <template #bodyCell="{ column, record }">
          <template v-if="column.key === 'action'">
            <a-space size="small">
              <a-button type="link" size="small" @click="router.push(`/policy/${record._id}`)">编辑</a-button>
              <ConfirmAction danger title="确认删除该策略？" @confirm="remove(String(record._id))">删除</ConfirmAction>
            </a-space>
          </template>
        </template>
      </a-table>
    </a-card>
  </PageContainer>
</template>

<script setup lang="ts">
import { computed, onMounted, reactive, ref } from 'vue'
import { useRouter } from 'vue-router'
import { message } from 'ant-design-vue'
import PageContainer from '../../layouts/PageContainer.vue'
import SearchBar from '../../components/SearchBar.vue'
import ConfirmAction from '../../components/ConfirmAction.vue'
import { policyApi } from '../../api/policy'
import type { RowRecord } from '../../api/types'

const router = useRouter()
const loading = ref(false)
const items = ref<RowRecord[]>([])
const total = ref(0)
const query = reactive({ page: 1, size: 10, order: '-_id', name: '' })

const columns = [
  { title: '策略名', dataIndex: 'name', key: 'name', width: 220, ellipsis: true },
  { title: '描述', dataIndex: 'desc', key: 'desc', ellipsis: true },
  { title: '更新时间', dataIndex: 'update_date', key: 'update_date', width: 170 },
  { title: '操作', key: 'action', width: 130 }
]
const pagination = computed(() => ({ current: query.page, pageSize: query.size, total: total.value, showSizeChanger: true, showTotal: (t: number) => `共 ${t} 条` }))

async function load() {
  loading.value = true
  try {
    const data = await policyApi.list(query)
    items.value = data.items || []
    total.value = data.total || 0
  } catch (error) {
    message.error(error instanceof Error ? error.message : String(error))
  } finally {
    loading.value = false
  }
}
function reset() { query.name = ''; query.page = 1; load() }
function onChange(p: { current?: number; pageSize?: number }) { query.page = p.current || 1; query.size = p.pageSize || 10; load() }
async function remove(id: string) { try { await policyApi.delete([id]); message.success('已删除'); load() } catch (e) { message.error(String(e)) } }
onMounted(load)
</script>
