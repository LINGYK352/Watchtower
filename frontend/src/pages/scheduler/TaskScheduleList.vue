<template>
  <PageContainer title="计划任务" kicker="Task Schedule" description="定时与周期扫描计划。">
    <template #extra><a-button type="primary" @click="openAdd">新建计划</a-button></template>
    <SearchBar :model="query" @search="load" @reset="reset">
      <a-form-item label="名称"><a-input v-model:value="query.name" allow-clear placeholder="计划名称" /></a-form-item>
      <a-form-item label="目标"><a-input v-model:value="query.target" allow-clear placeholder="目标" /></a-form-item>
      <a-form-item label="类型"><a-select v-model:value="query.schedule_type" allow-clear style="width: 140px" :options="typeOptions" /></a-form-item>
    </SearchBar>
    <a-card :bordered="false">
      <a-table :columns="columns" :data-source="items" :loading="loading" row-key="_id" :pagination="pagination" size="middle" bordered @change="onChange">
        <template #bodyCell="{ column, record }">
          <template v-if="column.key === 'target'"><CopyText :text="String(record.target || '')" /></template>
          <template v-else-if="column.key === 'schedule_type'">
            <a-tag :color="record.schedule_type === 'recurrent_scan' ? 'purple' : 'cyan'">{{ record.schedule_type === 'recurrent_scan' ? '周期' : '定时' }}</a-tag>
          </template>
          <template v-else-if="column.key === 'schedule_status'"><StatusTag :value="String(record.schedule_status || '')" /></template>
          <template v-else-if="column.key === 'action'">
            <a-space size="small">
              <ConfirmAction v-if="record.schedule_status === 'scheduled'" title="确认停止计划？" @confirm="stop(String(record._id))">停止</ConfirmAction>
              <ConfirmAction v-else title="确认恢复计划？" @confirm="recover(String(record._id))">恢复</ConfirmAction>
              <ConfirmAction danger title="确认删除计划？" @confirm="remove(String(record._id))">删除</ConfirmAction>
            </a-space>
          </template>
        </template>
      </a-table>
    </a-card>

    <a-modal v-model:open="addOpen" title="新建计划任务" @ok="submitAdd" :confirm-loading="adding" width="560px">
      <a-form layout="vertical">
        <a-form-item label="名称" required><a-input v-model:value="form.name" placeholder="计划名称" /></a-form-item>
        <a-form-item label="目标" required><a-textarea v-model:value="form.target" :rows="2" placeholder="域名 / IP / URL" /></a-form-item>
        <a-form-item label="任务类别" required>
          <a-radio-group v-model:value="form.task_tag">
            <a-radio value="task">资产侦察</a-radio>
            <a-radio value="risk_cruising">风险巡航</a-radio>
          </a-radio-group>
        </a-form-item>
        <a-form-item label="策略" required>
          <a-select v-model:value="form.policy_id" :options="policyOptions" placeholder="选择策略" show-search :filter-option="filterPolicy" />
        </a-form-item>
        <a-form-item label="计划类型" required>
          <a-radio-group v-model:value="form.schedule_type">
            <a-radio value="future_scan">定时</a-radio>
            <a-radio value="recurrent_scan">周期</a-radio>
          </a-radio-group>
        </a-form-item>
        <a-form-item v-if="form.schedule_type === 'future_scan'" label="开始时间" required>
          <a-input v-model:value="form.start_date" placeholder="YYYY-MM-DD HH:MM:SS" />
        </a-form-item>
        <a-form-item v-else label="Cron 表达式" required>
          <a-input v-model:value="form.cron" placeholder="如 0 2 * * *" />
        </a-form-item>
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
import CopyText from '../../components/CopyText.vue'
import ConfirmAction from '../../components/ConfirmAction.vue'
import { taskScheduleApi } from '../../api/taskSchedule'
import { policyApi } from '../../api/policy'
import type { RowRecord, SelectOption } from '../../api/types'

const loading = ref(false)
const items = ref<RowRecord[]>([])
const total = ref(0)
const query = reactive({ page: 1, size: 10, order: '-_id', name: '', target: '', schedule_type: undefined as string | undefined })

const typeOptions = [
  { label: '定时单次', value: 'future_scan' },
  { label: '周期 Cron', value: 'recurrent_scan' }
]
const columns = [
  { title: '名称', dataIndex: 'name', key: 'name', ellipsis: true },
  { title: '目标', key: 'target', ellipsis: true },
  { title: '策略', dataIndex: 'policy_name', key: 'policy_name', width: 130, ellipsis: true },
  { title: '类型', key: 'schedule_type', width: 80 },
  { title: '状态', key: 'schedule_status', width: 90 },
  { title: 'Cron', dataIndex: 'cron', key: 'cron', width: 120 },
  { title: '下次运行', dataIndex: 'next_run_date', key: 'next_run_date', width: 170 },
  { title: '操作', key: 'action', width: 170 }
]
const pagination = computed(() => ({ current: query.page, pageSize: query.size, total: total.value, showSizeChanger: true, showTotal: (t: number) => `共 ${t} 条` }))

async function load() {
  loading.value = true
  try {
    const data = await taskScheduleApi.list(query)
    items.value = data.items || []
    total.value = data.total || 0
  } catch (error) {
    message.error(error instanceof Error ? error.message : String(error))
  } finally {
    loading.value = false
  }
}
function reset() { query.name = ''; query.target = ''; query.schedule_type = undefined; query.page = 1; load() }
function onChange(p: { current?: number; pageSize?: number }) { query.page = p.current || 1; query.size = p.pageSize || 10; load() }

/* 新建 */
const addOpen = ref(false)
const adding = ref(false)
const policyOptions = ref<SelectOption[]>([])
const form = reactive({ name: '', target: '', task_tag: 'task' as 'task' | 'risk_cruising', policy_id: undefined as string | undefined, schedule_type: 'future_scan' as 'future_scan' | 'recurrent_scan', start_date: '', cron: '' })
function filterPolicy(input: string, option: SelectOption) { return String(option.label).toLowerCase().includes(input.toLowerCase()) }
async function loadPolicies() {
  try {
    const data = await policyApi.list({ page: 1, size: 1000 })
    policyOptions.value = (data.items || []).map(p => ({ label: String(p.name), value: String(p._id) }))
  } catch { /* 忽略策略加载失败 */ }
}
function openAdd() {
  form.name = ''; form.target = ''; form.task_tag = 'task'; form.policy_id = undefined
  form.schedule_type = 'future_scan'; form.start_date = ''; form.cron = ''
  addOpen.value = true
  if (!policyOptions.value.length) loadPolicies()
}
async function submitAdd() {
  if (!form.name || !form.target || !form.policy_id) return message.warning('请填写名称、目标和策略')
  if (form.schedule_type === 'future_scan' && !form.start_date) return message.warning('请填写开始时间')
  if (form.schedule_type === 'recurrent_scan' && !form.cron) return message.warning('请填写 Cron 表达式')
  adding.value = true
  try {
    await taskScheduleApi.add({
      name: form.name, target: form.target, task_tag: form.task_tag, policy_id: form.policy_id,
      schedule_type: form.schedule_type,
      ...(form.schedule_type === 'future_scan' ? { start_date: form.start_date } : { cron: form.cron })
    })
    message.success('已创建'); addOpen.value = false; load()
  } catch (error) { message.error(error instanceof Error ? error.message : String(error)) }
  finally { adding.value = false }
}
async function stop(id: string) { try { await taskScheduleApi.stop([id]); message.success('已停止'); load() } catch (e) { message.error(String(e)) } }
async function recover(id: string) { try { await taskScheduleApi.recover([id]); message.success('已恢复'); load() } catch (e) { message.error(String(e)) } }
async function remove(id: string) { try { await taskScheduleApi.delete([id]); message.success('已删除'); load() } catch (e) { message.error(String(e)) } }
onMounted(load)
</script>
