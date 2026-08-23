<template>
  <PageContainer title="资产监控" kicker="Monitor" description="资产组周期监控，支持域名 / 站点 / WIH 监控。">
    <template #extra>
      <a-space>
        <a-button type="primary" @click="openAdd('domain')">域名监控</a-button>
        <a-button @click="openAdd('site')">站点监控</a-button>
        <a-button @click="openAdd('wih')">WIH监控</a-button>
      </a-space>
    </template>
    <SearchBar :model="query" @search="load" @reset="reset">
      <a-form-item label="名称"><a-input v-model:value="query.name" allow-clear placeholder="监控名称" /></a-form-item>
      <a-form-item label="域名"><a-input v-model:value="query.domain" allow-clear placeholder="监控域名" /></a-form-item>
    </SearchBar>
    <a-card :bordered="false">
      <a-table :columns="columns" :data-source="items" :loading="loading" row-key="_id" :pagination="pagination" size="middle" bordered @change="onChange">
        <template #bodyCell="{ column, record }">
          <template v-if="column.key === 'status'"><StatusTag :value="String(record.status || '')" /></template>
          <template v-else-if="column.key === 'interval'">{{ humanInterval(Number(record.interval)) }}</template>
          <template v-else-if="column.key === 'action'">
            <a-space size="small">
              <ConfirmAction v-if="record.status === 'running'" title="确认停止监控？" @confirm="stop(String(record._id))">停止</ConfirmAction>
              <ConfirmAction v-else title="确认恢复监控？" @confirm="recover(String(record._id))">恢复</ConfirmAction>
              <ConfirmAction danger title="确认删除监控？" @confirm="remove(String(record._id))">删除</ConfirmAction>
            </a-space>
          </template>
        </template>
      </a-table>
    </a-card>

    <a-modal v-model:open="addOpen" :title="addTitle" @ok="submitAdd" :confirm-loading="adding" width="520px">
      <a-form layout="vertical">
        <a-form-item label="监控名称"><a-input v-model:value="form.name" placeholder="留空自动生成" /></a-form-item>
        <a-form-item label="资产组" required>
          <a-select v-model:value="form.scope_id" :options="scopeOptions" placeholder="选择资产组" show-search :filter-option="filterScope" />
        </a-form-item>
        <a-form-item v-if="addType === 'domain'" label="监控域名" required>
          <a-textarea v-model:value="form.domain" :rows="2" placeholder="多个域名用逗号分隔" />
        </a-form-item>
        <a-form-item label="间隔(小时)"><a-input-number v-model:value="intervalHours" :min="6" style="width: 100%" /></a-form-item>
      </a-form>
    </a-modal>
  </PageContainer>
</template>

<script setup lang="ts">
import { computed, onMounted, reactive, ref } from 'vue'
import { message } from 'ant-design-vue'
import PageContainer from '../../layouts/PageContainer.vue'
import SearchBar from '../../components/SearchBar.vue'
import StatusTag from '../../components/StatusTag.vue'
import ConfirmAction from '../../components/ConfirmAction.vue'
import { schedulerApi } from '../../api/scheduler'
import { assetScopeApi } from '../../api/scope'
import type { RowRecord, SelectOption } from '../../api/types'

const loading = ref(false)
const items = ref<RowRecord[]>([])
const total = ref(0)
const query = reactive({ page: 1, size: 10, order: '-_id', name: '', domain: '' })

const columns = [
  { title: '名称', dataIndex: 'name', key: 'name', ellipsis: true },
  { title: '域名', dataIndex: 'domain', key: 'domain', ellipsis: true },
  { title: '资产组', dataIndex: 'scope_id', key: 'scope_id', width: 130, ellipsis: true },
  { title: '间隔', key: 'interval', width: 100 },
  { title: '状态', key: 'status', width: 90 },
  { title: '运行次数', dataIndex: 'run_number', key: 'run_number', width: 90 },
  { title: '下次运行', dataIndex: 'next_run_date', key: 'next_run_date', width: 170 },
  { title: '操作', key: 'action', width: 170 }
]
const pagination = computed(() => ({ current: query.page, pageSize: query.size, total: total.value, showSizeChanger: true, showTotal: (t: number) => `共 ${t} 条` }))

function humanInterval(sec: number) { return sec ? `${Math.round(sec / 3600)}h` : '-' }
async function load() {
  loading.value = true
  try {
    const data = await schedulerApi.list(query)
    items.value = data.items || []
    total.value = data.total || 0
  } catch (error) {
    message.error(error instanceof Error ? error.message : String(error))
  } finally {
    loading.value = false
  }
}
function reset() { query.name = ''; query.domain = ''; query.page = 1; load() }
function onChange(p: { current?: number; pageSize?: number }) { query.page = p.current || 1; query.size = p.pageSize || 10; load() }
async function stop(id: string) { try { await schedulerApi.stop(id); message.success('已停止'); load() } catch (e) { message.error(String(e)) } }
async function recover(id: string) { try { await schedulerApi.recover(id); message.success('已恢复'); load() } catch (e) { message.error(String(e)) } }
async function remove(id: string) { try { await schedulerApi.delete([id]); message.success('已删除'); load() } catch (e) { message.error(String(e)) } }

/* 新建监控 */
const addOpen = ref(false)
const adding = ref(false)
const addType = ref<'domain' | 'site' | 'wih'>('domain')
const intervalHours = ref(24)
const scopeOptions = ref<SelectOption[]>([])
const form = reactive({ name: '', scope_id: undefined as string | undefined, domain: '' })
const addTitle = computed(() => ({ domain: '新建域名监控', site: '新建站点监控', wih: '新建 WIH 监控' } as Record<string, string>)[addType.value])
function filterScope(input: string, option: SelectOption) { return String(option.label).toLowerCase().includes(input.toLowerCase()) }
async function loadScopes() {
  try {
    const data = await assetScopeApi.list({ page: 1, size: 1000 })
    scopeOptions.value = (data.items || []).map(s => ({ label: String(s.name), value: String(s._id) }))
  } catch { /* 忽略 */ }
}
function openAdd(type: 'domain' | 'site' | 'wih') {
  addType.value = type; form.name = ''; form.scope_id = undefined; form.domain = ''; intervalHours.value = 24
  addOpen.value = true
  if (!scopeOptions.value.length) loadScopes()
}
async function submitAdd() {
  if (!form.scope_id) return message.warning('请选择资产组')
  if (addType.value === 'domain' && !form.domain) return message.warning('请填写监控域名')
  adding.value = true
  const interval = intervalHours.value * 3600
  try {
    if (addType.value === 'domain') await schedulerApi.add({ scope_id: form.scope_id, domain: form.domain, interval, name: form.name || undefined })
    else if (addType.value === 'site') await schedulerApi.addSiteMonitor({ scope_id: form.scope_id, interval, name: form.name || undefined })
    else await schedulerApi.addWihMonitor({ scope_id: form.scope_id, interval, name: form.name || undefined })
    message.success('已创建'); addOpen.value = false; load()
  } catch (error) { message.error(error instanceof Error ? error.message : String(error)) }
  finally { adding.value = false }
}
onMounted(load)
</script>
