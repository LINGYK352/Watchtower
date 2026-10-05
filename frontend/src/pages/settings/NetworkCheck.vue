<template>
  <PageContainer :title="translate('ui.m_e67f6bb5fb9e')" kicker="Network" :description="translate('ui.m_1d67b7883d04')">
    <a-card :title="translate('ui.m_0b3ee5cb9232')" :bordered="false" style="margin-bottom: 16px">
      <template #extra>
        <a-space>
          <span v-if="dirty" style="color:#d48806;font-size:12px;font-weight:600">{{ translate('ui.m_e08bdc3722e2') }}</span>
          <a-button type="primary" size="small" :loading="dnsSaving" @click="saveDns">{{ translate('ui.m_5e6d3759fecc') }}</a-button>
        </a-space>
      </template>
      <!-- 自定义 DNS：用户可加/改/删（平台自身 Ping/解析优先用）——列表式 -->
      <div class="dns-block">
        <div class="dns-h">{{ translate('ui.m_4c7428aca8c3') }} <span class="muted">{{ translate('ui.m_aff47c0eecac') }}</span></div>
        <div v-for="(d, i) in customDns" :key="i" class="dns-row">
          <a-input v-model:value="customDns[i]" :placeholder="translate('ui.m_8c79d25a337d')" style="width: 260px" size="small" />
          <a-button type="text" danger size="small" @click="customDns.splice(i, 1)">{{ translate('ui.m_2f9daa828907') }}</a-button>
        </div>
        <a-button size="small" type="dashed" style="margin-top:6px" @click="customDns.push('')">{{ translate('ui.m_e670c5ede9d4') }}</a-button>
        <div v-if="!customDns.length" class="muted" style="margin-top:4px">{{ translate('ui.m_965e671d1cdd') }}</div>
      </div>
      <!-- 内置 DNS 表：dnsserver.txt（侦察 dnsx/massdns 用 + 探活轮换），只读，折叠 -->
      <a-collapse ghost style="margin-top:10px">
        <a-collapse-panel key="builtin">
          <template #header>
            <span class="dns-h">{{ translate('ui.m_4d77113a8bab') }} <span class="muted">（{{ builtinDns.length }} {{ translate('ui.m_aa79bc634f9b') }}</span></span>
          </template>
          <div class="dns-builtin-list">
            <a-tag v-for="s in builtinDns" :key="s" color="blue">{{ s }}</a-tag>
            <span v-if="!builtinDns.length" class="muted">{{ translate('ui.m_3308b1fcfb11') }}</span>
          </div>
          <div class="muted" style="margin-top:6px;font-size:12px">
            {{ translate('ui.m_f8f0d0d53f3a') }}
          </div>
        </a-collapse-panel>
      </a-collapse>
    </a-card>

    <!-- 网络质量体检：一键诊断"网络为什么差"（丢包抖动/出网稳定/DNS健康/依赖可达/代理出口）-->
    <a-card :title="translate('ui.m_938a81b3dbab')" :bordered="false" style="margin-bottom: 16px">
      <template #extra>
        <a-button type="primary" size="small" :loading="qLoading" @click="runQuality">{{ translate('ui.m_3be9381d0914') }}</a-button>
      </template>
      <div style="margin-bottom:12px;color:#888;font-size:12px">
        {{ translate('ui.m_8fa4abe061b4') }}
        <span style="margin-left:8px">{{ translate('ui.m_acef7aaf1009') }}</span>
        <span v-if="checkedAt" style="color:#52c41a">{{ translate('ui.m_755b69eb6bc3') }}{{ checkedAt }}</span>
      </div>
      <a-empty v-if="!q && !qLoading" :description="translate('ui.m_1a89874c57a2')" />
      <a-spin v-if="qLoading" :tip="translate('ui.m_62d28b984e89')" style="display:block;padding:24px 0" />
      <!-- 总评横幅：大号评级 + 总分 + 一句诊断 -->
      <div v-if="q && assess" class="q-overall" :class="'ov-' + assess.level">
        <div class="ov-badge">
          <div class="ov-level">{{ assess.level_text }}</div>
          <div class="ov-score">{{ assess.score }}<span>{{ translate('ui.m_b6a993c256ef') }}</span></div>
        </div>
        <div class="ov-body">
          <div class="ov-title">{{ translate('ui.m_9f940632f7de') }}</div>
          <div class="ov-summary">{{ assess.summary }}</div>
        </div>
      </div>
      <!-- 5项详情默认展开：网络体检是"专程来看细节"的页面，进页即见全部（链路/出网/DNS/依赖/代理出口）；保留可折叠壳，想收起仍可点。 -->
      <a-collapse v-if="q" ghost :default-active-key="['detail']">
        <a-collapse-panel key="detail">
          <template #header><span style="font-weight:600">{{ translate('ui.m_7200e591a246') }}</span></template>
      <div class="q-wrap">
        <!-- ① 链路质量 -->
        <div class="q-sec"><span class="q-h">{{ translate('ui.m_047830b917f5') }}{{ qHost }}）</span>
          <a-tag v-if="q.ping" :color="gradeColor(q.ping.grade)">{{ gradeText(q.ping.grade) }}</a-tag>
          <span v-if="q.ping && !q.ping.error" class="q-metric">{{ translate('ui.m_b3d0b57da702') }} {{ q.ping.loss_pct }}{{ translate('ui.m_f006e08a1f70') }} {{ q.ping.avg_ms }}ms(min {{ q.ping.min_ms }}/max {{ q.ping.max_ms }}{{ translate('ui.m_82b62162a091') }} {{ q.ping.jitter_ms }}ms</span>
          <span v-if="q.ping && q.ping.error" class="q-err">{{ q.ping.error }}</span>
        </div>
        <!-- ② 出网稳定性 -->
        <div class="q-sec"><span class="q-h">{{ translate('ui.m_48246869a516') }}</span>
          <div v-for="t in (q.stability && q.stability.targets) || []" :key="t.url" class="q-row">
            <a-tag :color="gradeColor(t.grade)">{{ gradeText(t.grade) }}</a-tag>
            <span class="q-name">{{ t.name }}</span>
            <span class="q-metric">{{ translate('ui.m_47d2ca135212') }} {{ t.success_rate }}%（{{ t.success }}/{{ t.rounds }}{{ translate('ui.m_11a0193f4c98') }} {{ t.avg_ms }}ms</span>
          </div>
        </div>
        <!-- ③ DNS 健康 -->
        <div class="q-sec"><span class="q-h">{{ translate('ui.m_20e4f5a18eb8') }}</span>
          <a-tag v-if="q.dns" :color="gradeColor(q.dns.grade)">{{ q.dns.ok_count }}/{{ q.dns.total }} {{ translate('ui.m_4d99c976beb8') }}</a-tag>
          <div v-for="d in (q.dns && q.dns.servers) || []" :key="d.server" class="q-row">
            <a-tag :color="d.ok ? 'green' : 'red'">{{ d.ok ? '✓' : '✗' }}</a-tag>
            <span class="q-name">{{ d.server }}</span>
            <span class="q-metric">{{ d.ok ? (d.ip + ' · ' + d.ms + 'ms') : translate('ui.m_b3ff4d8c13b5') }}</span>
          </div>
        </div>
        <!-- ④ 关键依赖体检（通/慢/断三态：慢=连得上但延迟高，能用但体验差，会拉低总评） -->
        <div class="q-sec"><span class="q-h">{{ translate('ui.m_a787b1391558') }}</span>
          <a-tag v-if="q.deps" :color="q.deps.down_count ? 'red' : (q.deps.slow_count ? 'gold' : 'green')">{{ q.deps.total - q.deps.down_count }}/{{ q.deps.total }} {{ translate('ui.m_1e3106255275') }}<template v-if="q.deps.slow_count">（{{ q.deps.slow_count }} {{ translate('ui.m_08cc297308b5') }}</template></a-tag>
          <div v-for="d in (q.deps && q.deps.deps) || []" :key="d.name" class="q-row">
            <a-tag :color="!d.reachable ? 'red' : (d.slow ? 'gold' : 'green')">{{ !d.reachable ? translate('ui.m_df9ac46e7b5a') : (d.slow ? translate('ui.m_42269e2627f4') : translate('ui.m_fc2d4ab36f05')) }}</a-tag>
            <span class="q-name">{{ d.name }}</span>
            <span class="q-metric">{{ d.reachable ? ('HTTP ' + d.status + ' · ' + d.ms + 'ms' + (d.slow ? translate('ui.m_84372038ee66') : '')) : (translate('ui.m_8d7c03019f1d') + (d.err || '')) }}</span>
          </div>
        </div>
        <!-- ⑤ 代理出口质量 -->
        <div class="q-sec"><span class="q-h">{{ translate('ui.m_bf1300d74acf') }}</span>
          <a-tag v-if="q.proxy" :color="gradeColor(q.proxy.grade)">{{ gradeText(q.proxy.grade) }}</a-tag>
          <span v-if="q.proxy" class="q-metric">{{ q.proxy.note }}<template v-if="q.proxy.proxy_ip">{{ translate('ui.m_ddc199056db2') }} {{ q.proxy.proxy_ip }} {{ translate('ui.m_17a855adc7c7') }} {{ q.proxy.direct_ip }}）</template></span>
        </div>
      </div>
        </a-collapse-panel>
      </a-collapse>
    </a-card>

    <a-card :title="translate('ui.m_df59d202685f')" :bordered="false">
      <a-form layout="inline" style="margin-bottom: 16px">
        <a-form-item :label="translate('ui.m_252e26071ac9')">
          <a-input v-model:value="host" placeholder="baidu.com" style="width: 260px" @pressEnter="doPing" />
        </a-form-item>
        <a-form-item :label="translate('ui.m_05c518eb94a0')">
          <a-input-number v-model:value="count" :min="1" :max="20" style="width: 80px" />
        </a-form-item>
        <a-form-item>
          <a-button type="primary" :loading="loading" @click="doPing">Ping</a-button>
        </a-form-item>
      </a-form>
      <div class="terminal-box">
        <pre class="terminal-output">{{ output || translate('ui.m_40eba6a98935') }}</pre>
      </div>
    </a-card>
  </PageContainer>
</template>

<script setup lang="ts">
import { t as translate } from '../../i18n'

import { onMounted, ref } from 'vue'
import { message } from 'ant-design-vue'
import { useUnsavedGuard } from '../../composables/useUnsavedGuard'
import PageContainer from '../../layouts/PageContainer.vue'
import { request } from '../../api/request'

// DNS 配置：customDns=用户自定义(可增删改,存mongo)；builtinDns=内置dnsserver.txt(侦察用,只读)
const customDns = ref<string[]>([])
const builtinDns = ref<string[]>([])
const dnsSaving = ref(false)

// 未保存提示（问题4）：自定义 DNS 改了没点保存就切走会丢失（只跟踪 customDns，builtinDns 只读）。
const { dirty, markSaved } = useUnsavedGuard(() => JSON.stringify(customDns.value),
  { get content() { return translate('ui.m_92dc07c7571d') } })

async function loadDns() {
  try {
    const res = await request<{ servers: string[] }>('/api/network/dns')
    customDns.value = (res.servers || []).slice()
    markSaved()   // 载入后设为基线
  } catch { /* ignore */ }
  try {
    const b = await request<{ servers: string[] }>('/api/network/dns/builtin')
    builtinDns.value = b.servers || []
  } catch { /* 内置表读不到不影响 */ }
}

async function saveDns() {
  dnsSaving.value = true
  try {
    const servers = customDns.value.map(s => s.trim()).filter(Boolean)
    await request('/api/network/dns', { method: 'POST', body: JSON.stringify({ servers }) })
    customDns.value = servers   // 回填去空后的
    markSaved()                 // 保存成功后重置基线
    message.success(translate('ui.m_d343236d2b74'))
  } catch (e) {
    message.error(e instanceof Error ? e.message : String(e))
  } finally {
    dnsSaving.value = false
  }
}

// 网络质量体检
const qLoading = ref(false)
const q = ref<Record<string, any> | null>(null)
const assess = ref<Record<string, any> | null>(null)
const checkedAt = ref('')          // 最近检测时间（缓存结果或本次体检）
const qHost = 'scanme.nmap.org'
function gradeColor(g: string) { return ({ good: 'green', fair: 'gold', poor: 'orange', dead: 'red', na: 'default' } as Record<string, string>)[g] || 'default' }
function gradeText(g: string) { return ({ get good() { return translate('ui.m_cfea0dce5c5d') }, get fair() { return translate('ui.m_91e25f4ddc6f') }, get poor() { return translate('ui.m_895dcef3f1bd') }, get dead() { return translate('ui.m_7badfabc6ef1') }, get na() { return translate('ui.m_f95ea7f4c063') } } as Record<string, string>)[g] || g }
// 进页读最新缓存结果（定时监测产出）——无需每次进页都现跑
async function loadLatestQuality() {
  try {
    const r = await request<any>('/api/network/quality/latest')
    if (r && r.has_data) {
      q.value = { ping: r.ping, stability: r.stability, dns: r.dns, deps: r.deps, proxy: r.proxy }
      assess.value = r.assess || null
      checkedAt.value = r.checked_at || ''
    }
  } catch { /* 无缓存不影响，可手动体检 */ }
}
async function runQuality() {
  qLoading.value = true; q.value = null; assess.value = null
  try {
    // 并行跑5项（各自独立，一项慢/失败不拖累其余）
    const [ping, stability, dns, deps, proxy] = await Promise.all([
      request<any>('/api/network/quality/ping', { method: 'POST', body: JSON.stringify({ host: qHost, count: 10 }) }).catch(e => ({ error: String(e?.message || e) })),
      request<any>('/api/network/quality/stability', { method: 'POST', body: JSON.stringify({ rounds: 5 }) }).catch(() => null),
      request<any>('/api/network/quality/dns', { method: 'POST', body: JSON.stringify({ host: 'www.baidu.com' }) }).catch(() => null),
      request<any>('/api/network/quality/deps').catch(() => null),
      request<any>('/api/network/quality/proxy').catch(() => null),
    ])
    q.value = { ping, stability, dns, deps, proxy }
    // 落库（后端算总评+存最新，供态势总览/下次进页读）——手动体检与定时监测统一落库
    const saved = await request<any>('/api/network/quality/latest', {
      method: 'POST', body: JSON.stringify({ ping, stability, dns, deps, proxy })
    }).catch(() => null)
    assess.value = saved?.assess || null
    checkedAt.value = saved?.checked_at || new Date().toLocaleString()
  } catch (e) {
    message.error(e instanceof Error ? e.message : String(e))
  } finally {
    qLoading.value = false
  }
}

// Ping
const host = ref('baidu.com')
const count = ref(4)
const loading = ref(false)
const output = ref('')

async function doPing() {
  if (!host.value.trim()) return message.warning(translate('ui.m_41408748ac10'))
  loading.value = true
  output.value = `PING ${host.value} ...\n`
  try {
    const res = await request<{ host: string; output: string; returncode: number }>('/api/network/ping', {
      method: 'POST',
      body: JSON.stringify({ host: host.value.trim(), count: count.value })
    })
    output.value = res.output || '无输出'
  } catch (e) {
    output.value = `错误: ${e instanceof Error ? e.message : String(e)}`
  } finally {
    loading.value = false
  }
}

onMounted(() => { loadDns(); loadLatestQuality() })
</script>

<style scoped>
.terminal-box {
  background: #1e1e1e;
  border-radius: 8px;
  padding: 16px;
  min-height: 300px;
  max-height: 500px;
  overflow-y: auto;
}
.terminal-output {
  color: #d4d4d4;
  font-family: 'Consolas', 'Monaco', 'Courier New', monospace;
  font-size: 13px;
  line-height: 1.6;
  margin: 0;
  white-space: pre-wrap;
  word-break: break-all;
}
/* 总评横幅 */
.q-overall { display: flex; align-items: center; gap: 18px; padding: 16px 20px; border-radius: 12px;
  margin-bottom: 16px; border: 1px solid var(--dt-line, #eee); }
.q-overall .ov-badge { display: flex; flex-direction: column; align-items: center; justify-content: center;
  min-width: 96px; padding: 8px 16px; border-radius: 10px; color: #fff; }
.q-overall .ov-level { font-size: 28px; font-weight: 700; line-height: 1.1; }
.q-overall .ov-score { font-size: 15px; opacity: .95; }
.q-overall .ov-score span { font-size: 11px; margin-left: 1px; }
.q-overall .ov-title { font-size: 13px; color: var(--dt-muted, #888); margin-bottom: 4px; }
.q-overall .ov-summary { font-size: 15px; font-weight: 500; color: var(--dt-text, #333); }
/* 各级配色（徽章底色 + 横幅浅底） */
.ov-excellent { background: #f6ffed; } .ov-excellent .ov-badge { background: #52c41a; }
.ov-good { background: #f6ffed; } .ov-good .ov-badge { background: #73d13d; }
.ov-fair { background: #fffbe6; } .ov-fair .ov-badge { background: #faad14; }
.ov-poor { background: #fff7e6; } .ov-poor .ov-badge { background: #fa8c16; }
.ov-critical { background: #fff1f0; } .ov-critical .ov-badge { background: #cf1322; }
/* 网络质量体检结果 */
.q-wrap { display: flex; flex-direction: column; gap: 14px; }
.q-sec { padding: 10px 12px; border: 1px solid var(--dt-line, #eee); border-radius: 8px; }
.q-h { font-weight: 600; margin-right: 10px; }
.q-row { display: flex; align-items: center; gap: 8px; margin-top: 6px; padding-left: 4px; }
.q-name { min-width: 130px; color: var(--dt-text, #333); font-size: 13px; }
.q-metric { color: var(--dt-muted, #888); font-size: 12px; }
.q-err { color: #cf1322; font-size: 12px; }
/* DNS 区 */
.dns-block { margin-bottom: 4px; }
.dns-h { font-weight: 600; font-size: 13px; }
.dns-row { display: flex; align-items: center; gap: 8px; margin-top: 6px; }
.dns-builtin-list { display: flex; flex-wrap: wrap; gap: 6px; }
.muted { color: var(--dt-muted, #999); font-size: 12px; font-weight: normal; }
</style>
