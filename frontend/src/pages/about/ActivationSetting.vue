<template>
  <PageContainer :title="translate('ui.m_116636064123')" kicker="Activation" :description="translate('ui.m_6969e3a5b16d')">
    <a-card class="page-card">
      <div class="act-hero">
        <div class="act-badge" :class="info.activated ? 'act-badge--ok' : 'act-badge--off'">
          <KeyOutlined />
        </div>
        <div>
          <div class="act-label">{{ translate('ui.m_83de9a9a3443') }}</div>
          <a-tag :color="info.activated ? 'green' : 'red'" class="act-tag">
            {{ getStatusText(info) }}
          </a-tag>
        </div>
      </div>

      <a-divider style="margin:18px 0" />

      <a-descriptions :column="1" bordered size="middle" class="act-desc" v-if="loaded">
        <a-descriptions-item :label="translate('ui.m_d2b869681367')">{{ info.activated_at || '-' }}</a-descriptions-item>
        <a-descriptions-item :label="translate('ui.m_6bc17d5127bc')">{{ info.expires_at || '-' }}</a-descriptions-item>
        <a-descriptions-item :label="translate('ui.m_80591ea87b74')">{{ info.auth_days || '-' }}</a-descriptions-item>
        <a-descriptions-item :label="translate('ui.m_6684a9225162')">
          <span :class="info.remaining_days <= 7 ? 'danger-text' : ''">{{ info.remaining_days }}</span>
        </a-descriptions-item>
        <a-descriptions-item :label="translate('ui.m_e46b5523ff3c')">{{ info.username || '-' }}</a-descriptions-item>
        <a-descriptions-item :label="translate('ui.m_058f672b8779')">
          <code class="key-masked">{{ info.key_masked || '-' }}</code>
        </a-descriptions-item>
      </a-descriptions>

      <a-divider style="margin:18px 0" />

      <a-button type="primary" @click="showModal = true">
        <template #icon><KeyOutlined /></template>
        {{ info.activated ? translate('ui.m_4dc540cb0369') : translate('ui.m_2036369fe36f') }}
      </a-button>

      <a-divider style="margin:18px 0" />

      <!-- 免责声明签署状态（服务端持久化，重启/换浏览器保留） -->
      <div class="disc-status">
        <span class="disc-label">{{ translate('ui.m_280af617c87f') }}</span>
        <a-tag v-if="disc.accepted" color="green" class="disc-signed">
          <CheckCircleOutlined /> {{ translate('ui.m_51ae950c5f10') }}
        </a-tag>
        <a-tag v-else color="default">{{ translate('ui.m_31b625bbada1') }}</a-tag>
        <span v-if="disc.accepted && disc.accepted_at" class="disc-at">{{ translate('ui.m_ec46c055ab6b') }} {{ disc.accepted_at }} {{ translate('ui.m_8bc94c0cb57c') }}</span>
      </div>
    </a-card>

    <a-modal v-model:open="showModal" :title="translate('ui.m_208a01c79ebb')" @ok="doActivate" :confirm-loading="submitting" :ok-text="translate('ui.m_1fa2b8b2043a')">
      <a-form layout="vertical">
        <a-form-item :label="translate('ui.m_80d0504305aa')" required>
          <a-textarea v-model:value="newKey" :rows="4" :placeholder="translate('ui.m_b846e6d09a49')" />
        </a-form-item>
      </a-form>
    </a-modal>
  </PageContainer>
</template>

<script setup lang="ts">
import { t as translate } from '../../i18n'

import { onMounted, reactive, ref } from 'vue'
import { message } from 'ant-design-vue'
import { KeyOutlined, CheckCircleOutlined } from '@ant-design/icons-vue'
import PageContainer from '../../layouts/PageContainer.vue'
import { getActivationInfo, submitActivation, getDisclaimerStatus } from '../../api/meta'

const loaded = ref(false)
const disc = reactive({ accepted: false, accepted_version: '', accepted_at: '' })
const info = reactive({
  activated: false,
  expired: false,
  revoked: false,
  key_masked: '',
  activated_at: '',
  expires_at: '',
  remaining_days: 0,
  auth_days: 0,
  username: '',
})

const showModal = ref(false)
const newKey = ref('')
const submitting = ref(false)

function getStatusText(i: typeof info) {
  if (i.activated) return translate('ui.m_8f3c822f08ad')
  if (i.revoked) return translate('ui.m_b0bff6e7c453')
  if (i.expired) return translate('ui.m_2fe0e3339ac4')
  return translate('ui.m_fdc1183b6810')
}

async function fetchInfo() {
  try {
    const r = await getActivationInfo()
    Object.assign(info, r)
  } catch { /* ignore */ }
  try {
    const d = await getDisclaimerStatus()
    Object.assign(disc, d)
  } catch { /* ignore */ }
  loaded.value = true
}

async function doActivate() {
  if (!newKey.value.trim()) return message.warning(translate('ui.m_f7f055a82def'))
  submitting.value = true
  try {
    await submitActivation(newKey.value.trim())
    message.success(translate('ui.m_66dcb20e4a76'))
    showModal.value = false
    newKey.value = ''
    await fetchInfo()
  } catch (e) {
    message.error(e instanceof Error ? e.message : String(e))
  } finally {
    submitting.value = false
  }
}

onMounted(fetchInfo)
</script>

<style scoped>
.act-hero { display: flex; align-items: center; gap: 18px; }
.act-badge { width: 60px; height: 60px; border-radius: 16px; font-size: 28px; display: flex; align-items: center; justify-content: center; flex: none; }
.act-badge--ok { background: var(--dt-success-soft); color: var(--dt-success); }
.act-badge--off { background: var(--dt-danger-soft); color: var(--dt-danger); }
.act-label { color: var(--dt-muted); font-size: 13px; margin-bottom: 4px; }
.act-tag { font-size: 14px; }
.act-desc { max-width: 560px; }
.key-masked { font-family: monospace; font-size: 12px; word-break: break-all; color: var(--dt-muted); }
.danger-text { color: var(--dt-danger); font-weight: 600; }
.disc-status { display: flex; align-items: center; gap: 10px; flex-wrap: wrap; }
.disc-label { font-size: 13px; color: var(--dt-muted); }
.disc-signed { background: var(--dt-success-soft) !important; color: var(--dt-success) !important; border-color: var(--dt-success-border) !important; }
.disc-at { font-size: 12px; color: var(--dt-muted); }
</style>
