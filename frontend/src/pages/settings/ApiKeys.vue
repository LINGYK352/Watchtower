<template>
  <PageContainer :title="translate('ui.m_5f600b307b4e')" kicker="API Keys" :description="translate('ui.m_bf185f5af032')">
    <template #extra>
      <a-space>
        <span v-if="dirty" class="dirty-flag">{{ translate('ui.m_e08bdc3722e2') }}</span>
        <a-button @click="load">{{ translate('ui.m_aee887434131') }}</a-button>
        <a-button type="primary" :loading="loading" @click="saveAll">{{ translate('ui.m_10f830160cfd') }}</a-button>
      </a-space>
    </template>

    <a-alert type="info" show-icon style="margin-bottom:16px"
      :message="translate('ui.m_ae494fbdb102')" />

    <a-card v-for="grp in groups" :key="grp" class="page-card" :title="grp" size="small">
      <a-form layout="vertical">
        <a-row :gutter="20">
          <a-col :span="12" v-for="item in itemsByGroup(grp)" :key="item.id">
            <div class="key-item">
              <div class="key-head">
                <span class="key-label">{{ item.label }}</span>
                <a-switch v-model:checked="(forms[item.id].enabled as boolean)" size="small" checked-children="启用" un-checked-children="停用" />
                <a v-if="item.site" :href="item.site" target="_blank" rel="noreferrer" class="key-site">{{ translate('ui.m_a6ba15ce6e34') }}</a>
              </div>
              <a-input v-if="item.fields.includes('email')" v-model:value="(forms[item.id].email as string)"
                :placeholder="translate('ui.m_1f00ddd207e9')" style="margin-bottom:8px" />
              <a-input-password v-if="item.fields.includes('key')" v-model:value="(forms[item.id].key as string)"
                :placeholder="secretPlaceholder(item, 'key')" autocomplete="new-password" style="margin-bottom:8px" />
              <a-input-password v-if="item.fields.includes('token')" v-model:value="(forms[item.id].token as string)"
                :placeholder="secretPlaceholder(item, 'token')" autocomplete="new-password" style="margin-bottom:8px" />
              <a-input-password v-if="item.fields.includes('webhook')" v-model:value="(forms[item.id].webhook as string)"
                :placeholder="secretPlaceholder(item, 'webhook')" autocomplete="new-password" style="margin-bottom:8px" />
              <a-input-password v-if="item.fields.includes('secret')" v-model:value="(forms[item.id].secret as string)"
                :placeholder="secretPlaceholder(item, 'secret')" autocomplete="new-password" style="margin-bottom:8px" />
              <div v-if="item.select && item.select['min_severity']" style="margin-top:8px">
                <span style="margin-right:8px;color:#888;font-size:12px">{{ translate('ui.m_a29dc96e5060') }}</span>
                <a-select v-model:value="(forms[item.id].min_severity as string)" size="small" style="width:160px"
                  :options="item.select['min_severity']" />
              </div>
              <div v-if="item.fields.includes('vuln_feed_notify')" style="margin-top:8px;display:flex;align-items:center;gap:8px">
                <span style="color:#888;font-size:12px">{{ translate('ui.m_8c17fa75cd55') }}</span>
                <a-switch v-model:checked="(forms[item.id].vuln_feed_notify as boolean)" size="small" checked-children="开" un-checked-children="关" />
                <span style="color:#aaa;font-size:11px">{{ translate('ui.m_31fc29a6fdaa') }}</span>
              </div>
              <div v-if="item.fields.includes('proxy_down_notify')" style="margin-top:8px;display:flex;align-items:center;gap:8px">
                <span style="color:#888;font-size:12px">{{ translate('ui.m_61bebff69a94') }}</span>
                <a-switch v-model:checked="(forms[item.id].proxy_down_notify as boolean)" size="small" checked-children="开" un-checked-children="关" />
                <span style="color:#aaa;font-size:11px">{{ translate('ui.m_782cf030d6cb') }}</span>
              </div>
              <div v-if="item.fields.includes('attack_alert_notify')" style="margin-top:8px;display:flex;align-items:center;gap:8px">
                <span style="color:#888;font-size:12px">{{ translate('ui.m_c20a3b53b329') }}</span>
                <a-switch v-model:checked="(forms[item.id].attack_alert_notify as boolean)" size="small" checked-children="开" un-checked-children="关" />
                <span style="color:#aaa;font-size:11px">{{ translate('ui.m_b2ef33f59b8f') }}</span>
              </div>
            </div>
          </a-col>
        </a-row>
      </a-form>
    </a-card>

    <p class="updated" v-if="updatedAt">{{ translate('ui.m_a43321c13e4c') }}{{ updatedAt }}</p>
  </PageContainer>
</template>

<script setup lang="ts">
import { t as translate } from '../../i18n'

import { onMounted, reactive, ref, computed } from 'vue'
import { message } from 'ant-design-vue'
import PageContainer from '../../layouts/PageContainer.vue'
import { apiKeysApi, type ApiKeyItem } from '../../api/apiKeys'
import { useUnsavedGuard } from '../../composables/useUnsavedGuard'

const loading = ref(false)
const items = ref<ApiKeyItem[]>([])
const updatedAt = ref('')
const forms = reactive<Record<string, Record<string, unknown>>>({})

// 未保存提示（问题4）：编辑后未点「保存全部」就切走会静默丢失设置。
const { dirty, markSaved } = useUnsavedGuard(() => JSON.stringify(forms),
  { get content() { return translate('ui.m_dd05da5d1811') } })

const groups = computed(() => {
  const seen: string[] = []
  for (const it of items.value) if (!seen.includes(it.group)) seen.push(it.group)
  return seen
})
function itemsByGroup(grp: string) {
  return items.value.filter(it => it.group === grp)
}
function secretPlaceholder(item: ApiKeyItem, field: string) {
  return item[field + '_set'] ? translate('ui.m_aeba9e39c36b') : translate('ui.m_80a57e03f071')
}

function syncForms(list: ApiKeyItem[]) {
  for (const it of list) {
    const f: Record<string, unknown> = { enabled: it.enabled }
    for (const fld of it.fields) {
      if (fld === 'vuln_feed_notify' || fld === 'proxy_down_notify' || fld === 'attack_alert_notify') {
        f[fld] = it[fld] !== false && it[fld] !== 'false'  // 默认 true
      } else {
        f[fld] = (it[fld] as string) || ''
      }
    }
    forms[it.id] = f
  }
}

async function load() {
  loading.value = true
  try {
    const res = await apiKeysApi.list()
    items.value = res.items
    updatedAt.value = res.updated_at
    syncForms(res.items)
    markSaved()                           // 载入即为已保存基线
  } catch (e) { message.error((e as Error).message) } finally { loading.value = false }
}

async function saveAll() {
  loading.value = true
  try {
    const payload: Record<string, Record<string, unknown>> = {}
    for (const it of items.value) payload[it.id] = { ...forms[it.id] }
    const res = await apiKeysApi.save(payload)
    items.value = res.items
    updatedAt.value = res.updated_at
    syncForms(res.items)
    markSaved()                           // 保存成功后更新基线，脏标记归零
    message.success(translate('ui.m_514df589127f'))
  } catch (e) { message.error((e as Error).message) } finally { loading.value = false }
}

onMounted(load)
</script>

<style scoped>
.page-card { margin-bottom: 16px; }
.key-item { margin-bottom: 16px; }
.key-head { display: flex; align-items: center; gap: 10px; margin-bottom: 6px; }
.key-label { font-weight: 600; }
.key-site { font-size: 12px; color: #1677ff; margin-left: auto; }
.updated { color: #999; font-size: 12px; }
.dirty-flag { color: #d48806; font-size: 12px; font-weight: 600; }
</style>
