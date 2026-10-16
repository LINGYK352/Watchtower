<template>
  <PageContainer :title="translate('ui.m_b61129b1fbb2')" kicker="Task Schedule" :description="translate('ui.m_91be2cb0d1ea')">
    <template #extra><a-button type="primary" @click="openAdd">{{ translate('ui.m_87bb612bfa59') }}</a-button></template>
    <SearchBar :model="query" @search="load" @reset="reset">
      <a-form-item :label="translate('ui.m_d44e9b3d3b31')"><a-input v-model:value="query.name" allow-clear :placeholder="translate('ui.m_95ce00d503eb')" /></a-form-item>
      <a-form-item :label="translate('ui.m_57060c88a36b')"><a-input v-model:value="query.target" allow-clear :placeholder="translate('ui.m_57060c88a36b')" /></a-form-item>
      <a-form-item :label="translate('ui.m_ba40014ff496')"><a-select v-model:value="query.schedule_type" allow-clear style="width: 140px" :options="typeOptions" /></a-form-item>
    </SearchBar>
    <a-card :bordered="false">
      <a-table :columns="columns" :data-source="items" :loading="loading" row-key="_id" :pagination="pagination" size="middle" bordered @change="onChange">
        <template #bodyCell="{ column, record }">
          <template v-if="column.key === 'target'"><CopyText :text="String(record.target || '')" /></template>
          <template v-else-if="column.key === 'schedule_type'">
            <a-tag :color="record.schedule_type === 'recurrent_scan' ? 'purple' : 'cyan'">{{ record.schedule_type === 'recurrent_scan' ? translate('ui.m_e9bf2c2feae4') : translate('ui.m_6a2b5eb8d433') }}</a-tag>
          </template>
          <template v-else-if="column.key === 'schedule_status'"><StatusTag :value="String(record.schedule_status || '')" /></template>
          <template v-else-if="column.key === 'action'">
            <a-space size="small">
              <ConfirmAction v-if="record.schedule_status === 'scheduled'" :title="translate('ui.m_280deeda555e')" @confirm="stop(String(record._id))">{{ translate('ui.m_ca4d973c0b00') }}</ConfirmAction>
              <ConfirmAction v-else :title="translate('ui.m_398c8f70de1d')" @confirm="recover(String(record._id))">{{ translate('ui.m_e0534b8a4e46') }}</ConfirmAction>
              <ConfirmAction danger :title="translate('ui.m_efcd55721c5e')" @confirm="remove(String(record._id))">{{ translate('ui.m_2f9daa828907') }}</ConfirmAction>
            </a-space>
          </template>
        </template>
      </a-table>
    </a-card>

    <a-modal  :open="addOpen" :title="translate('ui.m_4bf0c42c2d65')" :footer="null" @cancel="cancelAdd" :mask-closable="!adding" :keyboard="!adding" width="640px">
      <a-steps :current="addStep" size="small" :items="[{title:translate('revision24.scheduleBasics')},{title:translate('revision24.scheduleTargets')}]" style="margin-bottom:22px" /><a-form layout="vertical"><section v-show="addStep===0" data-testid="schedule-step-basics">
        <a-form-item :label="translate('ui.m_d44e9b3d3b31')" required><a-input v-model:value="form.name" :placeholder="translate('ui.m_95ce00d503eb')" /></a-form-item>
        <a-form-item :label="translate('scheduleAI.preferred')"><a-select v-model:value="form.pentest_provider_id" :loading="modelsLoading" data-testid="schedule-preferred-model"><a-select-option value="">{{ translate('scheduleAI.defaultModel') }}</a-select-option><a-select-option v-for="p in providers" :key="p._id" :value="p._id">{{ p.name }} · {{ p.model }}</a-select-option></a-select></a-form-item>
        <a-form-item :label="translate('scheduleAI.backup')"><a-select v-model:value="form.pentest_backup_provider_id" :loading="modelsLoading"  data-testid="schedule-backup-model"><a-select-option value="">{{ translate('scheduleAI.noBackup') }}</a-select-option><a-select-option v-for="p in backupModels" :key="p._id" :value="p._id">{{ p.name }} · {{ p.model }}</a-select-option></a-select></a-form-item>
        <a-form-item><a-checkbox v-model:checked="form.observer_enabled" data-testid="schedule-observer-enabled">{{ translate('scheduleAI.observer') }}</a-checkbox><p class="schedule-ai-note">{{ translate('scheduleAI.policyNote') }}</p></a-form-item>
        <a-form-item v-if="form.observer_enabled" :label="translate('scheduleAI.observerModel')"><a-select v-model:value="form.observer_provider_id" data-testid="schedule-observer-model"><a-select-option value="">{{ translate('scheduleAI.defaultModel') }}</a-select-option><a-select-option v-for="p in providers" :key="p._id" :value="p._id">{{ p.name }} · {{ p.model }}</a-select-option></a-select></a-form-item>
        <a-form-item :label="translate('ui.m_9c8eb75c7e58')" required>
          <a-select v-model:value="form.policy_id" :options="policyOptions" :placeholder="translate('ui.m_62ca1e390e3a')" show-search :filter-option="filterPolicy" />
        </a-form-item>
        <a-form-item :label="translate('ui.m_c5b2429337a3')" required>
          <a-radio-group v-model:value="form.schedule_type">
            <a-radio value="future_scan">{{ translate('ui.m_6a2b5eb8d433') }}</a-radio>
            <a-radio value="recurrent_scan">{{ translate('ui.m_e9bf2c2feae4') }}</a-radio>
          </a-radio-group>
        </a-form-item>
        <a-form-item v-if="form.schedule_type === 'future_scan'" :label="translate('ui.m_6a9906c79f26')" required>
          <a-input v-model:value="form.start_date" placeholder="YYYY-MM-DD HH:MM:SS" />
        </a-form-item>
        <a-form-item v-else :label="translate('ui.m_c9657db58a07')" required>
          <a-input v-model:value="form.cron" :placeholder="translate('ui.m_5eee6fea4c91')" />
        </a-form-item>
      </section><section v-show="addStep===1" data-testid="schedule-step-targets">        <a-form-item :label="translate('scheduleAI.assetGroup')">
          <a-select v-model:value="form.target_scope_id" :options="groupOptions" :loading="groupsLoading" show-search allow-clear option-filter-prop="label" @change="selectGroup" data-testid="schedule-asset-group" />
          <p class="schedule-ai-note">{{ translate('revision24.groupFillNote') }}</p><a-alert v-if="groupError" type="warning" :message="groupError" />
        </a-form-item>
        <a-form-item :label="translate('ui.m_57060c88a36b')" required><a-textarea v-model:value="form.target" :rows="5" :placeholder="translate('ui.m_64c5e550a0f8')" data-testid="schedule-target-preview" /></a-form-item>
</section></a-form><div class="schedule-steps-actions"><a-button v-if="addStep" :disabled="adding" @click="addStep=0">{{ translate('revision24.previous') }}</a-button><a-button v-else @click="cancelAdd">{{ translate('ui.m_120e7cea1231') }}</a-button><a-button v-if="!addStep" type="primary" @click="nextStep" data-testid="schedule-next">{{ translate('revision24.next') }}</a-button><a-button v-else type="primary" :loading="adding" @click="submitAdd" data-testid="schedule-submit">{{ translate('ui.m_bcc5da2cf6c1') }}</a-button></div>
    </a-modal>
  </PageContainer>
</template>

<script setup lang="ts">
import { t as translate } from '../../i18n'

import { computed, onMounted, reactive, ref, watch } from 'vue'
import { message } from 'ant-design-vue'
import PageContainer from '../../layouts/PageContainer.vue'
import SearchBar from '../../components/SearchBar.vue'
import StatusTag from '../../components/StatusTag.vue'
import CopyText from '../../components/CopyText.vue'
import ConfirmAction from '../../components/ConfirmAction.vue'
import { taskScheduleApi } from '../../api/taskSchedule'
import { policyApi } from '../../api/policy'
import { assetScopeApi } from '../../api/scope'
import { aiConfigApi, type AIProviderOption } from '../../api/aiConfig'
import type { RowRecord, SelectOption } from '../../api/types'

const loading = ref(false)
const items = ref<RowRecord[]>([])
const total = ref(0)
const query = reactive({ page: 1, size: 10, order: '-_id', name: '', target: '', schedule_type: undefined as string | undefined })

const typeOptions = [
  { get label() { return translate('ui.m_f276e9ab1e72') }, value: 'future_scan' },
  { get label() { return translate('ui.m_2bd74a2350e3') }, value: 'recurrent_scan' }
]
const columns = [
  { get title() { return translate('ui.m_d44e9b3d3b31') }, dataIndex: 'name', key: 'name', ellipsis: true },
  { get title() { return translate('ui.m_57060c88a36b') }, key: 'target', ellipsis: true },
  { get title() { return translate('ui.m_9c8eb75c7e58') }, dataIndex: 'policy_name', key: 'policy_name', width: 130, ellipsis: true },
  { get title() { return translate('ui.m_ba40014ff496') }, key: 'schedule_type', width: 80 },
  { get title() { return translate('ui.m_6320b4a8722a') }, key: 'schedule_status', width: 90 },
  { title: 'Cron', dataIndex: 'cron', key: 'cron', width: 120 },
  { get title() { return translate('ui.m_bdedfc1bb069') }, dataIndex: 'next_run_date', key: 'next_run_date', width: 170 },
  { get title() { return translate('ui.m_ed31fbb483ee') }, key: 'action', width: 170 }
]
const pagination = computed(() => ({ current: query.page, pageSize: query.size, total: total.value, showSizeChanger: true, showTotal: (t: number) => translate('ui.m_f292bcb94fe6', { p0: (t) }) }))

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
const form = reactive({ name: '', target: '', target_scope_id:undefined as string|undefined, pentest_provider_id:'',pentest_backup_provider_id:'',observer_enabled:false,observer_provider_id:'',task_tag: 'task' as 'task' | 'risk_cruising', policy_id: undefined as string | undefined, schedule_type: 'future_scan' as 'future_scan' | 'recurrent_scan', start_date: '', cron: '' })
const addStep=ref(0),groupOptions=ref<SelectOption[]>([]),groupsLoading=ref(false),groupError=ref('')
const providers=ref<AIProviderOption[]>([]),modelsLoading=ref(false),defaultModelId=ref('')
const primaryModel=computed(()=>providers.value.find(p=>p._id===(form.pentest_provider_id || defaultModelId.value)))
const backupModels=computed(()=>primaryModel.value?providers.value.filter(p=>p._id!==primaryModel.value?._id && (p.protocol||'openai')===(primaryModel.value?.protocol||'openai')):providers.value)
watch(backupModels,options=>{if(form.pentest_backup_provider_id && !options.some(p=>p._id===form.pentest_backup_provider_id))form.pentest_backup_provider_id=''})
watch(()=>form.observer_enabled,enabled=>{if(!enabled)form.observer_provider_id=''})
let groupSerial=0
async function selectGroup(value?:string){
 const serial=++groupSerial;const previous=form.target;groupError.value='';if(!value)return
 try{const data=await assetScopeApi.taskSource(value);if(serial!==groupSerial || !addOpen.value || form.target_scope_id!==value)return;if(form.target===previous)form.target=data.scope;else groupError.value=translate('revision24.targetChanged')}
 catch(error){if(serial===groupSerial)groupError.value=(error as Error).message}
}
async function loadGroups(){
 groupsLoading.value=true
 try{
  const all:SelectOption[]=[];const seen=new Set<string>();let page=1
  for(;;){const data=await assetScopeApi.list({page,size:200});const incoming=(data.items||[]).filter(g=>!seen.has(String(g._id)));for(const g of incoming){seen.add(String(g._id));all.push({value:String(g._id),label:String(g.name)})}if(!incoming.length || all.length>=data.total)break;page++}
  groupOptions.value=all
 }catch(error){groupError.value=(error as Error).message}finally{groupsLoading.value=false}
}
async function loadModels(){modelsLoading.value=true;try{const [options,config]=await Promise.all([aiConfigApi.providerOptions(),aiConfigApi.runtimeConfig()]);providers.value=options.items.filter(p=>p.enabled!==false);defaultModelId.value=config.active_provider_id||''}catch{providers.value=[]}finally{modelsLoading.value=false}}
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
  addStep.value=0;form.target_scope_id=undefined;form.pentest_provider_id='';form.pentest_backup_provider_id='';form.observer_enabled=false;form.observer_provider_id='';groupError.value='';groupSerial++
  addOpen.value = true
  if (!policyOptions.value.length) loadPolicies()
  void loadGroups();void loadModels()
}
function cancelAdd(){if(adding.value)return;groupSerial++;addOpen.value=false}
function validBasics(){
 if(!form.name.trim()||!form.policy_id){message.warning(translate('ui.m_7f3ba0c6767e'));return false}
 if(form.schedule_type==='future_scan'&&!form.start_date){message.warning(translate('ui.m_aefc0bf8b8a4'));return false}
 if(form.schedule_type==='recurrent_scan'&&!form.cron){message.warning(translate('ui.m_bbc067b4eb88'));return false}
 if(form.pentest_backup_provider_id&&!primaryModel.value){message.warning(translate('revision24.selectPreferred'));return false}
 return true
}
function nextStep(){if(validBasics())addStep.value=1}
async function submitAdd() {
  if(!validBasics()){addStep.value=0;return}
  if(!form.target.trim())return message.warning(translate('ui.m_7f3ba0c6767e'))
  if (form.schedule_type === 'future_scan' && !form.start_date) return message.warning(translate('ui.m_aefc0bf8b8a4'))
  if (form.schedule_type === 'recurrent_scan' && !form.cron) return message.warning(translate('ui.m_bbc067b4eb88'))
  adding.value = true
  try {
    await taskScheduleApi.add({
      name: form.name, target: form.target, task_tag: form.task_tag, policy_id: form.policy_id!,
      ...(form.target_scope_id?{target_scope_id:form.target_scope_id}:{}),editable_target:true,
      pentest_provider_id:form.pentest_provider_id,pentest_backup_provider_id:form.pentest_backup_provider_id,
      observer_enabled:form.observer_enabled,observer_provider_id:form.observer_enabled?form.observer_provider_id:'',
      schedule_type: form.schedule_type,
      ...(form.schedule_type === 'future_scan' ? { start_date: form.start_date } : { cron: form.cron })
    })
    message.success(translate('ui.m_80bfa30db209')); addOpen.value = false; load()
  } catch (error) { message.error(error instanceof Error ? error.message : String(error)) }
  finally { adding.value = false }
}
async function stop(id: string) { try { await taskScheduleApi.stop([id]); message.success(translate('ui.m_f006455e3baf')); load() } catch (e) { message.error(String(e)) } }
async function recover(id: string) { try { await taskScheduleApi.recover([id]); message.success(translate('ui.m_3617f737f437')); load() } catch (e) { message.error(String(e)) } }
async function remove(id: string) { try { await taskScheduleApi.delete([id]); message.success(translate('ui.m_077a6d37719a')); load() } catch (e) { message.error(String(e)) } }
onMounted(load)
</script>

<style scoped>
.schedule-steps-actions{display:flex;justify-content:space-between;gap:12px;margin-top:20px}.schedule-ai-note{color:var(--dt-muted);font-size:12px;line-height:1.6;margin:8px 0 0}
</style>
