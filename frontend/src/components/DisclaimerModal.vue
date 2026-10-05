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
        :message="translate('ui.m_8eaf04cf69bb')" />
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
        <a-button danger @click="onReject">{{ translate('ui.m_40b0aade58d7') }}</a-button>
        <a-button type="primary" :disabled="!agreed || countdown > 0" :loading="submitting" @click="onAgree">
          {{ countdown > 0 ? translate('ui.m_e5c44f9be14d', { p0: (countdown) }) : translate('ui.m_81c92013219d') }}
        </a-button>
      </div>
    </div>
  </a-modal>
</template>

<script setup lang="ts">
import { t as translate } from '../i18n'

import { ref, onMounted, onUnmounted } from 'vue'
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
// 签署按钮 5 秒倒计时：强制用户至少停留阅读条款，倒计时结束前无法点"同意"
const READ_SECONDS = 5
const countdown = ref(READ_SECONDS)
let cdTimer: number | null = null

function startCountdown() {
  countdown.value = READ_SECONDS
  if (cdTimer) clearInterval(cdTimer)
  cdTimer = window.setInterval(() => {
    countdown.value -= 1
    if (countdown.value <= 0 && cdTimer) { clearInterval(cdTimer); cdTimer = null }
  }, 1000)
}
onUnmounted(() => { if (cdTimer) { clearInterval(cdTimer); cdTimer = null } })

onMounted(async () => {
  // 首次登录判断改为**服务端持久化**（治"换浏览器/重启服务器就重弹"）：
  // 服务端已签署且条款版本匹配当前 DISCLAIMER_VERSION → 不弹；否则弹。
  // 仅清目录/重装（磁盘标记丢失）才需重签，条款升级(版本号变)也会要求重新确认。
  // 抖动重试（治「服务端一次抖动/重启窗口 → 签署状态请求失败 → fail-open 误弹」，2026-09-13 事故）：
  // 已签署是稳定事实，一次请求失败不该翻成「未签署」而重弹。重试 3 次 + 退避，全失败才保守弹窗。
  // 关联铁律 feedback-retry-not-cache-for-flaky-probe：间歇失败优先重试自愈，别让抖动改变判定。
  for (let attempt = 0; attempt < 3; attempt++) {
    try {
      const st = await getDisclaimerStatus()
      if (st.accepted && st.accepted_version === DISCLAIMER_VERSION) {
        visible.value = false
        return
      }
      // 成功拿到状态且确为「未签署/版本不符」→ 该弹，跳出重试
      break
    } catch {
      // 请求失败（服务端重启窗口/网络抖动）：退避后重试；最后一次仍失败则 fail-open 弹窗（保守，不放行未签署）
      if (attempt < 2) await new Promise(r => setTimeout(r, 800 * (attempt + 1)))
    }
  }
  visible.value = true
  startCountdown()   // 弹出即开始 5 秒阅读倒计时
})

async function onAgree() {
  if (!agreed.value || submitting.value) return
  submitting.value = true
  try {
    await acceptDisclaimer(DISCLAIMER_VERSION)   // 写服务端磁盘标记，重启/换浏览器保留
    visible.value = false
  } catch (e) {
    message.error(translate('ui.m_60b699584716') + (e instanceof Error ? e.message : String(e)))
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

