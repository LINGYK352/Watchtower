<template>
  <!-- Step 1: Activation (mandatory, cannot close) -->
  <a-modal :open="showActivation" :closable="false" :maskClosable="false" :footer="null" centered width="440px" :keyboard="false">
    <div class="setup-wrap">
      <div class="setup-icon">
        <ClockCircleOutlined v-if="expired" style="font-size: 40px; color: #fa8c16" />
        <LockOutlined v-else style="font-size: 40px; color: var(--dt-primary, #1677ff)" />
      </div>
      <h2 class="setup-title">{{ expired ? translate('ui.m_956ef6fafa63') : translate('ui.m_41504b9054e1') }}</h2>
      <p class="setup-desc">
        <template v-if="expired">
          {{ translate('ui.m_154a3d59d516') }}
          <br /><span v-if="expiresAt" class="setup-exp">{{ translate('ui.m_c4c1ad8ce3ab') }}{{ expiresAt }}</span>
        </template>
        <template v-else>
          {{ translate('ui.m_0e291e979a4d') }}
        </template>
      </p>
      <div class="setup-link">
        <a :href="sourceUrl" target="_blank" rel="noopener noreferrer">{{ translate('ui.m_44750486ac06') }}</a>
        <a-tag color="green" class="setup-badge">{{ translate('ui.m_649a0fc7237e') }}</a-tag>
      </div>
      <a-input-password
        v-model:value="keyInput"
        :placeholder="translate('ui.m_7d30d5a59f58')"
        size="large"
        class="setup-input"
        @pressEnter="handleActivate"
      />
      <a-button type="primary" block size="large" :loading="activateLoading" class="setup-btn" @click="handleActivate">
        {{ expired ? translate('ui.m_2036369fe36f') : translate('ui.m_dd1286c29e9b') }}
      </a-button>
    </div>
  </a-modal>

  <!-- Step 2: AI Configuration prompt (dismissible) -->
  <a-modal :open="showAiPrompt" :closable="true" :maskClosable="false" :footer="null" centered width="440px" @cancel="dismissAi">
    <div class="setup-wrap">
      <div class="setup-icon">
        <RobotOutlined style="font-size: 40px; color: var(--dt-primary, #1677ff)" />
      </div>
      <h2 class="setup-title">{{ translate('ui.m_31518ba7999a') }}</h2>
      <p class="setup-desc">
        {{ translate('ui.m_1fae1539a7f1') }}
      </p>
      <div class="setup-actions">
        <a-button type="primary" block size="large" @click="goAiConfig">{{ translate('ui.m_a34d0b8031af') }}</a-button>
        <a-button block size="large" class="setup-btn-later" @click="dismissAi">{{ translate('ui.m_c34ec1390c3e') }}</a-button>
      </div>
    </div>
  </a-modal>

  <!-- Step 3: API Keys prompt (dismissible) -->
  <a-modal :open="showKeysPrompt" :closable="true" :maskClosable="false" :footer="null" centered width="440px" @cancel="dismissKeys">
    <div class="setup-wrap">
      <div class="setup-icon">
        <KeyOutlined style="font-size: 40px; color: var(--dt-primary, #1677ff)" />
      </div>
      <h2 class="setup-title">{{ translate('ui.m_31115d26df65') }}</h2>
      <p class="setup-desc">
        {{ translate('ui.m_f5555854f6aa') }}
      </p>
      <div class="setup-actions">
        <a-button type="primary" block size="large" @click="goKeysConfig">{{ translate('ui.m_a34d0b8031af') }}</a-button>
        <a-button block size="large" class="setup-btn-later" @click="dismissKeys">{{ translate('ui.m_c34ec1390c3e') }}</a-button>
      </div>
    </div>
  </a-modal>
</template>

<script setup lang="ts">
import { t as translate } from '../i18n'

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
const sourceUrl = ref('https://watchtowers.info')
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
  if (!key) return message.warning(translate('ui.m_9c04fe5c2eec'))
  if (!key.startsWith('eyJ') || key.split('.').length !== 3) {
    return message.warning(translate('ui.m_ea863f345852'))
  }
  activateLoading.value = true
  try {
    await submitActivation(key)
    message.success(translate('ui.m_66dcb20e4a76'))
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
  message.warning(translate('ui.m_54d94f6eb74c'))
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
  message.warning(translate('ui.m_e4753cef23a2'))
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
