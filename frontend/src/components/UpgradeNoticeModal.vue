<!--
  升级提示弹窗：更新完成后,按版本区间 (上次已确认版本, 当前版本] 收集各版声明的 upgrade_notice,
  合并叠加到一个弹窗分条显示。跨版更新(如 147→149)多条提示不重复弹、汇总在一起。
  确认后记 last_seen_version=当前版本,不再弹。首次安装(无记录)不弹,直接记当前版本。
  数据源：changelog.json 每条可选 upgrade_notice 字段(该版升级后需用户复查的事)。
-->
<template>
  <a-modal v-model:open="open" title="更新提示 · 请复查以下配置" :footer="null" :width="560" :mask-closable="false">
    <a-alert type="info" show-icon style="margin-bottom:12px"
      :message="`已更新到 ${curVer}。以下是本次更新途经版本需要你复查/知晓的事项：`" />
    <div v-for="item in notices" :key="item.ver" class="up-notice-item">
      <div class="up-notice-ver"><a-tag color="blue">{{ item.ver }}</a-tag></div>
      <div class="up-notice-text">{{ item.notice }}</div>
    </div>
    <div style="text-align:right;margin-top:16px">
      <a-space>
        <a-button @click="goProxy">去代理中心</a-button>
        <a-button @click="goPolicy">去策略配置</a-button>
        <a-button type="primary" @click="confirm">我知道了</a-button>
      </a-space>
    </div>
  </a-modal>
</template>

<script setup lang="ts">
import { ref, onMounted } from 'vue'
import { useRouter } from 'vue-router'
import { getChangelog } from '../api/about'
import { fetchServerVersion } from '../composables/useServerVersion'

const SEEN_KEY = 'upgrade_notice_seen_ver'   // localStorage：上次已确认升级提示的版本
const router = useRouter()
const open = ref(false)
// 「当前版本」用**后端真实版本**（version.txt），非编译进包的 APP_VERSION——跳板逐级更新时前端产物
// brand 标签可能滞后/错配，用错版本会漏/误显升级提示、错误推进 seen。onMounted 内异步拉取后赋值。
const curVer = ref('')
const notices = ref<Array<{ ver: string; notice: string }>>([])

// 版本号数值比较（复用 UpdateNotice 同款逻辑）：v1.21.149-1 → [1,21,149,1]
function parseVer(v: string): number[] {
  return String(v || '').replace(/^v/i, '').split(/[.\-]/).map(x => parseInt(x, 10) || 0)
}
function cmpVer(a: string, b: string): number {
  const ta = parseVer(a), tb = parseVer(b)
  const n = Math.max(ta.length, tb.length)
  for (let i = 0; i < n; i++) {
    const x = ta[i] || 0, y = tb[i] || 0
    if (x !== y) return x > y ? 1 : -1
  }
  return 0
}

function goProxy() { confirm(); router.push('/proxy') }
function goPolicy() { confirm(); router.push('/policy') }
function confirm() {
  try { localStorage.setItem(SEEN_KEY, curVer.value) } catch { /* ignore */ }
  open.value = false
}

onMounted(async () => {
  curVer.value = await fetchServerVersion()   // 后端真实版本；拉不到时兜底 APP_VERSION（composable 内部保证）
  const seen = localStorage.getItem(SEEN_KEY)
  // 首次安装(无记录)：不弹,直接记当前版本(避免新装机弹历史提示)
  if (!seen) { try { localStorage.setItem(SEEN_KEY, curVer.value) } catch { /* ignore */ } return }
  // 未升级(seen >= 当前)：不弹
  if (cmpVer(seen, curVer.value) >= 0) return
  try {
    const logs = await getChangelog()
    // 收集区间 (seen, curVer] 内所有带 upgrade_notice 的版本,按版本从旧到新排列(升级顺序)
    const items = (logs || [])
      .filter((l: any) => l && l.upgrade_notice && cmpVer(l.ver, seen) > 0 && cmpVer(l.ver, curVer.value) <= 0)
      .sort((a: any, b: any) => cmpVer(a.ver, b.ver))
      .map((l: any) => ({ ver: String(l.ver), notice: String(l.upgrade_notice) }))
    if (items.length) {
      notices.value = items
      open.value = true
    } else {
      // 区间内无提示：静默推进 seen,不弹
      try { localStorage.setItem(SEEN_KEY, curVer.value) } catch { /* ignore */ }
    }
  } catch { /* 拉取失败不打扰,下次再试(不推进 seen) */ }
})
</script>

<style scoped>
.up-notice-item { display: flex; gap: 10px; padding: 10px 0; border-bottom: 1px solid var(--dt-border, #f0f0f0); }
.up-notice-item:last-child { border-bottom: none; }
.up-notice-ver { flex: 0 0 auto; }
.up-notice-text { flex: 1; line-height: 1.7; color: var(--dt-text, #333); }
</style>
