<template>
  <PageContainer title="网络检测" kicker="Network" description="检测服务器网络连通性，配置 DNS 服务器。">
    <a-card title="DNS 服务器" :bordered="false" style="margin-bottom: 16px">
      <template #extra><a-button type="primary" size="small" :loading="dnsSaving" @click="saveDns">保存自定义</a-button></template>
      <!-- 自定义 DNS：用户可加/改/删（平台自身 Ping/解析优先用）——列表式 -->
      <div class="dns-block">
        <div class="dns-h">自定义 DNS <span class="muted">（可增删改，平台 Ping/域名解析优先使用）</span></div>
        <div v-for="(d, i) in customDns" :key="i" class="dns-row">
          <a-input v-model:value="customDns[i]" placeholder="如 8.8.8.8" style="width: 260px" size="small" />
          <a-button type="text" danger size="small" @click="customDns.splice(i, 1)">删除</a-button>
        </div>
        <a-button size="small" type="dashed" style="margin-top:6px" @click="customDns.push('')">+ 添加 DNS</a-button>
        <div v-if="!customDns.length" class="muted" style="margin-top:4px">未配置自定义 DNS，将依次尝试系统 DNS → 内置 DNS 表。</div>
      </div>
      <!-- 内置 DNS 表：dnsserver.txt（侦察 dnsx/massdns 用 + 探活轮换），只读，折叠 -->
      <a-collapse ghost style="margin-top:10px">
        <a-collapse-panel key="builtin">
          <template #header>
            <span class="dns-h">内置 DNS 解析器表 <span class="muted">（{{ builtinDns.length }} 个 · 侦察工具用 · 自动探活轮换 · 只读）</span></span>
          </template>
          <div class="dns-builtin-list">
            <a-tag v-for="s in builtinDns" :key="s" color="blue">{{ s }}</a-tag>
            <span v-if="!builtinDns.length" class="muted">（未加载）</span>
          </div>
          <div class="muted" style="margin-top:6px;font-size:12px">
            这是随代码分发的内置解析器表，侦察扫描时自动探测可用性、剔除不通的、轮换使用。如需修改请走版本更新（不在此编辑）。
          </div>
        </a-collapse-panel>
      </a-collapse>
    </a-card>

    <!-- 网络质量体检：一键诊断"网络为什么差"（丢包抖动/出网稳定/DNS健康/依赖可达/代理出口）-->
    <a-card title="网络质量体检" :bordered="false" style="margin-bottom: 16px">
      <template #extra>
        <a-button type="primary" size="small" :loading="qLoading" @click="runQuality">一键体检</a-button>
      </template>
      <div style="margin-bottom:12px;color:#888;font-size:12px">
        诊断宿主机网络环境：链路丢包/抖动、国内外出网稳定性、DNS 健康、平台关键依赖(LLM/更新源/情报源)可达性、代理出口质量。
        <span style="margin-left:8px">系统每 30 分钟自动监测一次。</span>
        <span v-if="checkedAt" style="color:#52c41a">最近检测：{{ checkedAt }}</span>
      </div>
      <a-empty v-if="!q && !qLoading" description="点击「一键体检」开始全面检测（约需 20~40 秒）" />
      <a-spin v-if="qLoading" tip="正在体检，请稍候…" style="display:block;padding:24px 0" />
      <!-- 总评横幅：大号评级 + 总分 + 一句诊断 -->
      <div v-if="q && assess" class="q-overall" :class="'ov-' + assess.level">
        <div class="ov-badge">
          <div class="ov-level">{{ assess.level_text }}</div>
          <div class="ov-score">{{ assess.score }}<span>分</span></div>
        </div>
        <div class="ov-body">
          <div class="ov-title">网络环境总评</div>
          <div class="ov-summary">{{ assess.summary }}</div>
        </div>
      </div>
      <!-- 5项详情默认折叠：进页看总评卡即可，要细节再展开（对齐态势总览"卡片+详情折叠"体验） -->
      <a-collapse v-if="q" ghost>
        <a-collapse-panel key="detail">
          <template #header><span style="font-weight:600">体检详情（链路 / 出网 / DNS / 依赖 / 代理出口）</span></template>
      <div class="q-wrap">
        <!-- ① 链路质量 -->
        <div class="q-sec"><span class="q-h">① 链路质量（{{ qHost }}）</span>
          <a-tag v-if="q.ping" :color="gradeColor(q.ping.grade)">{{ gradeText(q.ping.grade) }}</a-tag>
          <span v-if="q.ping && !q.ping.error" class="q-metric">丢包 {{ q.ping.loss_pct }}% · 延迟 {{ q.ping.avg_ms }}ms(min {{ q.ping.min_ms }}/max {{ q.ping.max_ms }}) · 抖动 {{ q.ping.jitter_ms }}ms</span>
          <span v-if="q.ping && q.ping.error" class="q-err">{{ q.ping.error }}</span>
        </div>
        <!-- ② 出网稳定性 -->
        <div class="q-sec"><span class="q-h">② 出网稳定性</span>
          <div v-for="t in (q.stability && q.stability.targets) || []" :key="t.url" class="q-row">
            <a-tag :color="gradeColor(t.grade)">{{ gradeText(t.grade) }}</a-tag>
            <span class="q-name">{{ t.name }}</span>
            <span class="q-metric">成功率 {{ t.success_rate }}%（{{ t.success }}/{{ t.rounds }}）· 均延迟 {{ t.avg_ms }}ms</span>
          </div>
        </div>
        <!-- ③ DNS 健康 -->
        <div class="q-sec"><span class="q-h">③ DNS 健康</span>
          <a-tag v-if="q.dns" :color="gradeColor(q.dns.grade)">{{ q.dns.ok_count }}/{{ q.dns.total }} 可用</a-tag>
          <div v-for="d in (q.dns && q.dns.servers) || []" :key="d.server" class="q-row">
            <a-tag :color="d.ok ? 'green' : 'red'">{{ d.ok ? '✓' : '✗' }}</a-tag>
            <span class="q-name">{{ d.server }}</span>
            <span class="q-metric">{{ d.ok ? (d.ip + ' · ' + d.ms + 'ms') : '解析失败/超时' }}</span>
          </div>
        </div>
        <!-- ④ 关键依赖体检（通/慢/断三态：慢=连得上但延迟高，能用但体验差，会拉低总评） -->
        <div class="q-sec"><span class="q-h">④ 平台关键依赖</span>
          <a-tag v-if="q.deps" :color="q.deps.down_count ? 'red' : (q.deps.slow_count ? 'gold' : 'green')">{{ q.deps.total - q.deps.down_count }}/{{ q.deps.total }} 可达<template v-if="q.deps.slow_count">（{{ q.deps.slow_count }} 慢）</template></a-tag>
          <div v-for="d in (q.deps && q.deps.deps) || []" :key="d.name" class="q-row">
            <a-tag :color="!d.reachable ? 'red' : (d.slow ? 'gold' : 'green')">{{ !d.reachable ? '断' : (d.slow ? '慢' : '通') }}</a-tag>
            <span class="q-name">{{ d.name }}</span>
            <span class="q-metric">{{ d.reachable ? ('HTTP ' + d.status + ' · ' + d.ms + 'ms' + (d.slow ? '（延迟偏高）' : '')) : ('不可达 ' + (d.err || '')) }}</span>
          </div>
        </div>
        <!-- ⑤ 代理出口质量 -->
        <div class="q-sec"><span class="q-h">⑤ 代理出口</span>
          <a-tag v-if="q.proxy" :color="gradeColor(q.proxy.grade)">{{ gradeText(q.proxy.grade) }}</a-tag>
          <span v-if="q.proxy" class="q-metric">{{ q.proxy.note }}<template v-if="q.proxy.proxy_ip">（代理出口 {{ q.proxy.proxy_ip }} / 直连 {{ q.proxy.direct_ip }}）</template></span>
        </div>
      </div>
        </a-collapse-panel>
      </a-collapse>
    </a-card>

    <a-card title="Ping 检测" :bordered="false">
      <a-form layout="inline" style="margin-bottom: 16px">
        <a-form-item label="目标主机">
          <a-input v-model:value="host" placeholder="baidu.com" style="width: 260px" @pressEnter="doPing" />
        </a-form-item>
        <a-form-item label="次数">
          <a-input-number v-model:value="count" :min="1" :max="20" style="width: 80px" />
        </a-form-item>
        <a-form-item>
          <a-button type="primary" :loading="loading" @click="doPing">Ping</a-button>
        </a-form-item>
      </a-form>
      <div class="terminal-box">
        <pre class="terminal-output">{{ output || '点击 Ping 开始检测...' }}</pre>
      </div>
    </a-card>
  </PageContainer>
</template>

<script setup lang="ts">
import { onMounted, ref } from 'vue'
import { message } from 'ant-design-vue'
import PageContainer from '../../layouts/PageContainer.vue'
import { request } from '../../api/request'

// DNS 配置：customDns=用户自定义(可增删改,存mongo)；builtinDns=内置dnsserver.txt(侦察用,只读)
const customDns = ref<string[]>([])
const builtinDns = ref<string[]>([])
const dnsSaving = ref(false)

async function loadDns() {
  try {
    const res = await request<{ servers: string[] }>('/api/network/dns')
    customDns.value = (res.servers || []).slice()
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
    message.success('自定义 DNS 已保存')
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
function gradeText(g: string) { return ({ good: '良好', fair: '一般', poor: '较差', dead: '不通', na: '未启用' } as Record<string, string>)[g] || g }
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
  if (!host.value.trim()) return message.warning('请输入目标主机')
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
