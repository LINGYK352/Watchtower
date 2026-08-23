<template>
  <a-modal
    :open="visible"
    :title="title"
    :closable="false"
    :maskClosable="false"
    :keyboard="false"
    :footer="null"
    width="640px"
    wrap-class-name="disclaimer-modal"
    :z-index="2000">
    <div class="dc-body">
      <a-alert type="warning" show-icon banner style="margin-bottom:14px"
        message="请仔细阅读以下条款，同意后方可使用本系统。" />
      <div class="dc-scroll">
        <div v-for="sec in sections" :key="sec.h" class="dc-sec">
          <h4 class="dc-h">{{ sec.h }}</h4>
          <ul class="dc-list">
            <li v-for="(it, i) in sec.items" :key="i">{{ it }}</li>
          </ul>
        </div>
      </div>
      <a-checkbox v-model:checked="agreed" class="dc-check">{{ agreeText }}</a-checkbox>
      <div class="dc-actions">
        <a-button danger @click="onReject">不同意并退出</a-button>
        <a-button type="primary" :disabled="!agreed" :loading="submitting" @click="onAgree">同意并继续</a-button>
      </div>
    </div>
  </a-modal>
</template>

<script setup lang="ts">
import { ref, onMounted } from 'vue'
import { message } from 'ant-design-vue'
import { clearToken } from '../api/request'
import { getDisclaimerStatus, acceptDisclaimer } from '../api/meta'
import {
  DISCLAIMER_SECTIONS, DISCLAIMER_TITLE, DISCLAIMER_AGREE_TEXT, DISCLAIMER_VERSION,
} from '../config/disclaimer'

const sections = DISCLAIMER_SECTIONS
const title = DISCLAIMER_TITLE
const agreeText = DISCLAIMER_AGREE_TEXT
const visible = ref(false)
const agreed = ref(false)
const submitting = ref(false)

onMounted(async () => {
  // 首次登录判断改为**服务端持久化**（治"换浏览器/重启服务器就重弹"）：
  // 服务端已签署且条款版本匹配当前 DISCLAIMER_VERSION → 不弹；否则弹。
  // 仅清目录/重装（磁盘标记丢失）才需重签，条款升级(版本号变)也会要求重新确认。
  try {
    const st = await getDisclaimerStatus()
    if (st.accepted && st.accepted_version === DISCLAIMER_VERSION) {
      visible.value = false
      return
    }
  } catch {
    // 服务端不可达（极端）：保守起见弹窗，避免未签署却放行。
  }
  visible.value = true
})

async function onAgree() {
  if (!agreed.value || submitting.value) return
  submitting.value = true
  try {
    await acceptDisclaimer(DISCLAIMER_VERSION)   // 写服务端磁盘标记，重启/换浏览器保留
    visible.value = false
  } catch (e) {
    message.error('保存同意状态失败：' + (e instanceof Error ? e.message : String(e)))
  } finally {
    submitting.value = false
  }
}

function onReject() {
  // 不同意 = 不允许使用：清凭证并回登录页。
  clearToken()
  visible.value = false
  location.href = '/login'
}
</script>

<style scoped>
.dc-scroll { max-height: 46vh; overflow-y: auto; padding: 4px 12px; border: 1px solid var(--dt-border, #e8e8e8); border-radius: 8px; background: var(--dt-hover, #fafafa); }
.dc-sec { margin-bottom: 14px; }
.dc-h { font-size: 14px; font-weight: 700; margin: 6px 0; color: var(--dt-text, #1f2328); }
.dc-list { padding-left: 20px; margin: 0; }
.dc-list li { font-size: 13px; line-height: 1.9; color: var(--dt-text, #333); }
.dc-check { margin: 16px 0 4px; font-size: 13px; font-weight: 600; }
.dc-actions { display: flex; justify-content: flex-end; gap: 12px; margin-top: 12px; }
</style>

