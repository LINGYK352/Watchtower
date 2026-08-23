<template>
  <PageContainer title="资产分组" kicker="Asset Group" description="资产组管理，用于持续监控与资产沉淀。">
    <template #extra><a-button type="primary" @click="openAdd">新建分组</a-button></template>
    <SearchBar :model="query" @search="load" @reset="reset">
      <a-form-item label="分组名"><a-input v-model:value="query.name" allow-clear placeholder="分组名称" /></a-form-item>
      <a-form-item label="范围"><a-input v-model:value="query.scope" allow-clear placeholder="资产范围" /></a-form-item>
    </SearchBar>
    <a-card :bordered="false">
      <a-table :columns="columns" :data-source="items" :loading="loading" row-key="_id" :pagination="pagination" size="middle" bordered @change="onChange">
        <template #bodyCell="{ column, record }">
          <template v-if="column.key === 'scope_type'"><a-tag>{{ record.scope_type || 'DOMAIN' }}</a-tag></template>
          <template v-else-if="column.key === 'scope'"><CopyText :text="String(record.scope || '')" /></template>
          <template v-else-if="column.key === 'action'">
            <a-space size="small">
              <a-button type="link" size="small" @click="router.push(`/asset-groups/${record._id}`)">进入</a-button>
              <ConfirmAction danger title="确认删除该分组及组内资产？" @confirm="remove(String(record._id))">删除</ConfirmAction>
            </a-space>
          </template>
        </template>
      </a-table>
    </a-card>

    <a-modal v-model:open="addOpen" title="新建资产分组" @ok="submitAdd" :confirm-loading="adding" width="560px">
      <a-form layout="vertical">
        <a-form-item label="分组名称" required><a-input v-model:value="form.name" placeholder="分组名称" /></a-form-item>
        <a-form-item label="资产范围" required><a-textarea v-model:value="form.scope" :rows="3" placeholder="域名 / IP，多个用逗号或空格分隔" /></a-form-item>
        <a-form-item label="黑名单范围"><a-textarea v-model:value="form.black_scope" :rows="2" placeholder="可选，排除的范围" /></a-form-item>
        <a-form-item label="范围类别">
          <a-radio-group v-model:value="form.scope_type">
            <a-radio value="DOMAIN">域名</a-radio>
            <a-radio value="IP">IP</a-radio>
          </a-radio-group>
        </a-form-item>
      </a-form>
    </a-modal>
  </PageContainer>
</template>

<script setup lang="ts">
import { computed, onMounted, reactive, ref } from 'vue'
import { useRouter } from 'vue-router'
import { message } from 'ant-design-vue'
import PageContainer from '../../layouts/PageContainer.vue'
import SearchBar from '../../components/SearchBar.vue'
import CopyText from '../../components/CopyText.vue'
import ConfirmAction from '../../components/ConfirmAction.vue'
import { assetScopeApi } from '../../api/scope'
import type { RowRecord } from '../../api/types'

const router = useRouter()
const loading = ref(false)
const items = ref<RowRecord[]>([])
const total = ref(0)
const query = reactive({ page: 1, size: 10, order: '-_id', name: '', scope: '' })

const columns = [
  { title: '分组名', dataIndex: 'name', key: 'name', width: 200, ellipsis: true },
  { title: '类别', key: 'scope_type', width: 90 },
  { title: '范围', key: 'scope', ellipsis: true },
  { title: '黑名单', dataIndex: 'black_scope', key: 'black_scope', ellipsis: true },
  { title: '操作', key: 'action', width: 130 }
]
const pagination = computed(() => ({ current: query.page, pageSize: query.size, total: total.value, showSizeChanger: true, showTotal: (t: number) => `共 ${t} 条` }))

async function load() {
  loading.value = true
  try {
    const data = await assetScopeApi.list(query)
    items.value = data.items || []
    total.value = data.total || 0
  } catch (error) {
    message.error(error instanceof Error ? error.message : String(error))
  } finally {
    loading.value = false
  }
}
function reset() { query.name = ''; query.scope = ''; query.page = 1; load() }
function onChange(p: { current?: number; pageSize?: number }) { query.page = p.current || 1; query.size = p.pageSize || 10; load() }

const addOpen = ref(false)
const adding = ref(false)
const form = reactive({ name: '', scope: '', black_scope: '', scope_type: 'DOMAIN' })
function openAdd() { form.name = ''; form.scope = ''; form.black_scope = ''; form.scope_type = 'DOMAIN'; addOpen.value = true }
async function submitAdd() {
  if (!form.name || !form.scope) return message.warning('请填写分组名称和范围')
  adding.value = true
  try { await assetScopeApi.add({ ...form }); message.success('已创建'); addOpen.value = false; load() }
  catch (error) { message.error(error instanceof Error ? error.message : String(error)) }
  finally { adding.value = false }
}
async function remove(id: string) { try { await assetScopeApi.delete([id]); message.success('已删除'); load() } catch (e) { message.error(String(e)) } }
onMounted(load)
</script>
