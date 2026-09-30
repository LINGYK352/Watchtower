<template>
  <PageContainer title="激活设置" kicker="Activation" description="查看当前系统激活状态与授权信息。">
    <a-card class="page-card">
      <div class="act-hero">
        <div class="act-badge" :class="info.activated ? 'act-badge--ok' : 'act-badge--off'">
          <KeyOutlined />
        </div>
        <div>
          <div class="act-label">激活状态</div>
          <a-tag :color="info.activated ? 'green' : 'red'" class="act-tag">
            {{ getStatusText(info) }}
          </a-tag>
        </div>
      </div>

      <a-divider style="margin:18px 0" />

      <a-descriptions :column="1" bordered size="middle" class="act-desc" v-if="loaded">
        <a-descriptions-item label="激活时间">{{ info.activated_at || '-' }}</a-descriptions-item>
        <a-descriptions-item label="失效时间">{{ info.expires_at || '-' }}</a-descriptions-item>
        <a-descriptions-item label="有效期(天)">{{ info.auth_days || '-' }}</a-descriptions-item>
        <a-descriptions-item label="剩余天数">
          <span :class="info.remaining_days <= 7 ? 'danger-text' : ''">{{ info.remaining_days }}</span>
        </a-descriptions-item>
        <a-descriptions-item label="授权用户">{{ info.username || '-' }}</a-descriptions-item>
        <a-descriptions-item label="凭证">
          <code class="key-masked">{{ info.key_masked || '-' }}</code>
        </a-descriptions-item>
      </a-descriptions>

      <a-divider style="margin:18px 0" />

      <a-button type="primary" @click="showModal = true">
        <template #icon><KeyOutlined /></template>
        {{ info.activated ? '更换 Key' : '重新激活' }}
      </a-button>

      <a-divider style="margin:18px 0" />

      <!-- 免责声明签署状态（服务端持久化，重启/换浏览器保留） -->
      <div class="disc-status">
        <span class="disc-label">免责声明</span>
        <a-tag v-if="disc.accepted" color="green" class="disc-signed">
          <CheckCircleOutlined /> 已签署同意
        </a-tag>
        <a-tag v-else color="default">未签署</a-tag>
        <span v-if="disc.accepted && disc.accepted_at" class="disc-at">于 {{ disc.accepted_at }} 签署</span>
      </div>
    </a-card>

    <a-modal v-model:open="showModal" title="激活 / 更换 Key" @ok="doActivate" :confirm-loading="submitting" ok-text="提交激活">
      <a-form layout="vertical">
        <a-form-item label="授权凭证 (JWT)" required>
          <a-textarea v-model:value="newKey" :rows="4" placeholder="粘贴从分发系统注册页获取的 JWT 凭证" />
        </a-form-item>
      </a-form>
    </a-modal>
  </PageContainer>
</template>

<script setup lang="ts">
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
  if (i.activated) return '已激活'
  if (i.revoked) return '已被吊销'
  if (i.expired) return '已过期'
  return '未激活'
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
  if (!newKey.value.trim()) return message.warning('请输入授权凭证')
  submitting.value = true
  try {
    await submitActivation(newKey.value.trim())
    message.success('激活成功')
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
.act-badge--ok { background: #f0fdf4; color: #16a34a; }
.act-badge--off { background: #fef2f2; color: #dc2626; }
.act-label { color: var(--dt-muted); font-size: 13px; margin-bottom: 4px; }
.act-tag { font-size: 14px; }
.act-desc { max-width: 560px; }
.key-masked { font-family: monospace; font-size: 12px; word-break: break-all; color: var(--dt-muted); }
.danger-text { color: #dc2626; font-weight: 600; }
.disc-status { display: flex; align-items: center; gap: 10px; flex-wrap: wrap; }
.disc-label { font-size: 13px; color: var(--dt-muted); }
.disc-signed { background: #f0fdf4 !important; color: #16a34a !important; border-color: #bbf7d0 !important; }
.disc-at { font-size: 12px; color: var(--dt-muted); }
</style>
