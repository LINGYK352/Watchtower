<template>
  <!-- Step 1: Activation (mandatory, cannot close) -->
  <a-modal :open="showActivation" :closable="false" :maskClosable="false" :footer="null" centered width="440px" :keyboard="false">
    <div class="setup-wrap">
      <div class="setup-icon">
        <ClockCircleOutlined v-if="expired" style="font-size: 40px; color: #fa8c16" />
        <LockOutlined v-else style="font-size: 40px; color: var(--dt-primary, #1677ff)" />
      </div>
      <h2 class="setup-title">{{ expired ? '授权已过期' : '系统激活' }}</h2>
      <p class="setup-desc">
        <template v-if="expired">
          您的更新授权 Key 已过期（有效期 60 天），请重新免费获取新 Key。
          <br /><span v-if="expiresAt" class="setup-exp">过期时间：{{ expiresAt }}</span>
        </template>
        <template v-else>
          请输入更新授权 Key 以激活系统。Key 免费获取，用于接收自动更新。
        </template>
      </p>
      <div class="setup-link">
        <a :href="sourceUrl" target="_blank" rel="noopener noreferrer">前往获取 →</a>
        <a-tag color="green" class="setup-badge">免费</a-tag>
      </div>
      <a-input-password
        v-model:value="keyInput"
        placeholder="请粘贴授权 Key（JWT 格式）"
        size="large"
        class="setup-input"
        @pressEnter="handleActivate"
      />
      <a-button type="primary" block size="large" :loading="activateLoading" class="setup-btn" @click="handleActivate">
        {{ expired ? '重新激活' : '激活' }}
      </a-button>
    </div>
  </a-modal>

  <!-- Step 2: AI Configuration prompt (dismissible) -->
  <a-modal :open="showAiPrompt" :closable="true" :maskClosable="false" :footer="null" centered width="440px" @cancel="dismissAi">
    <div class="setup-wrap">
      <div class="setup-icon">
        <RobotOutlined style="font-size: 40px; color: var(--dt-primary, #1677ff)" />
      </div>
      <h2 class="setup-title">配置 AI 模型</h2>
      <p class="setup-desc">
        AI 渗透功能需要配置至少一个 LLM 提供商（如 DeepSeek、OpenAI、Claude 等）。
        配置后即可使用智能渗透测试、代码审计等 AI 驱动功能。
      </p>
      <div class="setup-actions">
        <a-button type="primary" block size="large" @click="goAiConfig">前往配置</a-button>
        <a-button block size="large" class="setup-btn-later" @click="dismissAi">稍后配置</a-button>
      </div>
    </div>
  </a-modal>

  <!-- Step 3: API Keys prompt (dismissible) -->
  <a-modal :open="showKeysPrompt" :closable="true" :maskClosable="false" :footer="null" centered width="440px" @cancel="dismissKeys">
    <div class="setup-wrap">
      <div class="setup-icon">
        <KeyOutlined style="font-size: 40px; color: var(--dt-primary, #1677ff)" />
      </div>
      <h2 class="setup-title">配置 API 密钥</h2>
      <p class="setup-desc">
        资产测绘功能需要配置 FOFA 或鹰图（Hunter）等平台的 API Key。
        配置后即可使用资产发现、子域名收集等测绘能力。
      </p>
      <div class="setup-actions">
        <a-button type="primary" block size="large" @click="goKeysConfig">前往配置</a-button>
        <a-button block size="large" class="setup-btn-later" @click="dismissKeys">稍后配置</a-button>
      </div>
    </div>
  </a-modal>
</template>

<script setup lang="ts">
import { ref, onMounted, watch } from 'vue'
import { useRouter } from 'vue-router'
import { message } from 'ant-design-vue'
import { LockOutlined, ClockCircleOutlined, RobotOutlined, KeyOutlined } from '@ant-design/icons-vue'
import { checkActivation, submitActivation, getSetupStatus } from '../api/meta'

const props = defineProps<{ forceShow?: boolean }>()
const router = useRouter()

// Step 1: Activation state
const showActivation = ref(false)
const expired = ref(false)
const expiresAt = ref('')
const sourceUrl = ref('http://124.222.145.172:5080')
const keyInput = ref('')
const activateLoading = ref(false)

// Step 2 & 3: Config prompts state
const showAiPrompt = ref(false)
const showKeysPrompt = ref(false)

const DISMISS_KEY = 'setup_dismissed'

// Watch forceShow prop: when server rejects key, force show activation modal
watch(() => props.forceShow, (v) => {
  if (v) {
    expired.value = true
    showActivation.value = true
  }
})

onMounted(async () => {
  try {
    // Fetch both activation and setup status
    const [actRes, setupRes] = await Promise.all([
      checkActivation(),
      getSetupStatus().catch(() => null),
    ])

    // Step 1: Activation check
    if (!actRes.activated) {
      sourceUrl.value = actRes.source_url || sourceUrl.value
      expired.value = !!actRes.expired
      expiresAt.value = actRes.expires_at || ''
      showActivation.value = true
      return // Block on activation, don't show other steps
    }

    // If previously dismissed this session, skip prompts
    if (sessionStorage.getItem(DISMISS_KEY)) return
    if (!setupRes) return

    // Step 2: AI not configured
    if (!setupRes.ai_configured) {
      showAiPrompt.value = true
      return
    }

    // Step 3: API keys not configured
    if (!setupRes.keys_configured) {
      showKeysPrompt.value = true
    }
  } catch {
    // Check failure: don't block the app
  }
})

// Step 1 handlers
async function handleActivate() {
  const key = keyInput.value.trim()
  if (!key) return message.warning('请输入授权 Key')
  if (!key.startsWith('eyJ') || key.split('.').length !== 3) {
    return message.warning('请输入有效的 JWT 格式 Key（从注册页获取）')
  }
  activateLoading.value = true
  try {
    await submitActivation(key)
    message.success('激活成功')
    showActivation.value = false
    window.location.reload()
  } catch (e) {
    message.error(e instanceof Error ? e.message : String(e))
  } finally {
    activateLoading.value = false
  }
}

// Step 2 handlers
function goAiConfig() {
  showAiPrompt.value = false
  router.push('/ai-config')
}

function dismissAi() {
  showAiPrompt.value = false
  message.warning('不配置将无法使用 AI 渗透功能')
  sessionStorage.setItem(DISMISS_KEY, '1')
  // Check step 3 after dismissing step 2
  getSetupStatus().then(res => {
    if (!res.keys_configured) {
      showKeysPrompt.value = true
    }
  }).catch(() => {})
}

// Step 3 handlers
function goKeysConfig() {
  showKeysPrompt.value = false
  router.push('/api-keys')
}

function dismissKeys() {
  showKeysPrompt.value = false
  message.warning('不配置将无法使用资产测绘功能')
  sessionStorage.setItem(DISMISS_KEY, '1')
}
</script>

<style scoped>
.setup-wrap {
  text-align: center;
  padding: 16px 0 8px;
}
.setup-icon {
  margin-bottom: 16px;
}
.setup-title {
  font-size: 20px;
  font-weight: 600;
  margin-bottom: 8px;
}
.setup-desc {
  color: rgba(0, 0, 0, 0.55);
  font-size: 14px;
  margin-bottom: 16px;
  line-height: 1.6;
}
.setup-exp {
  color: #fa8c16;
  font-size: 12px;
}
.setup-link {
  margin-bottom: 20px;
  display: flex;
  align-items: center;
  justify-content: center;
  gap: 6px;
}
.setup-link a {
  color: var(--dt-primary, #1677ff);
  font-weight: 500;
}
.setup-badge {
  margin: 0;
}
.setup-input {
  margin-bottom: 16px;
}
.setup-btn {
  margin-top: 4px;
}
.setup-actions {
  display: flex;
  flex-direction: column;
  gap: 10px;
}
.setup-btn-later {
  color: rgba(0, 0, 0, 0.45);
}
</style>
