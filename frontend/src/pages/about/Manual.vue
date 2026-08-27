<template>
  <PageContainer title="使用手册" kicker="Manual" description="瞭望塔 Watchtower 面向使用者的操作说明与常见问题。">
    <div class="manual-wrap">
      <!-- 左侧分类导航 -->
      <div class="manual-nav">
        <a-input v-model:value="keyword" placeholder="搜索手册" allow-clear size="small" style="margin-bottom:10px">
          <template #prefix><SearchOutlined /></template>
        </a-input>
        <div v-for="sec in filteredSections" :key="sec.key"
          class="nav-item" :class="{ active: sec.key === activeKey }" @click="go(sec.key)">
          <component :is="sec.icon" class="nav-icon" />
          <span>{{ sec.title }}</span>
        </div>
        <a-empty v-if="!filteredSections.length" :image="false" description="无匹配" />
      </div>

      <!-- 右侧正文 -->
      <a-card class="manual-body" :bordered="false">
        <template v-if="active">
          <h2 class="doc-h1"><component :is="active.icon" /> {{ active.title }}</h2>
          <!-- 免责声明章节：显示服务端签署状态徽标（已签署=淡绿） -->
          <a-tag v-if="activeKey === 'disclaimer' && disc.accepted" color="green" class="disc-signed-tag">
            <CheckCircleOutlined /> 已签署同意<template v-if="disc.accepted_at"> · {{ disc.accepted_at }}</template>
          </a-tag>
          <p class="doc-lead">{{ active.lead }}</p>
          <template v-for="(blk, i) in active.blocks" :key="i">
            <h3 v-if="blk.h" class="doc-h2">{{ blk.h }}</h3>
            <p v-if="blk.p" class="doc-p">{{ blk.p }}</p>
            <ul v-if="blk.list" class="doc-list">
              <li v-for="(li, j) in blk.list" :key="j"><span v-html="renderInline(li)" /></li>
            </ul>
            <ol v-if="blk.steps" class="doc-steps">
              <li v-for="(st, j) in blk.steps" :key="j"><span v-html="renderInline(st)" /></li>
            </ol>
            <div v-if="blk.tip" class="doc-tip"><BulbOutlined /> {{ blk.tip }}</div>
            <div v-if="blk.warn" class="doc-warn"><WarningOutlined /> {{ blk.warn }}</div>
            <div v-if="blk.verse" class="doc-verse">
              <div class="verse-scroll">
                <div v-if="blk.verse.cipai" class="verse-title">
                  <span class="verse-cipai">{{ blk.verse.cipai }}</span>
                  <span v-if="blk.verse.title" class="verse-sep">·</span>
                  <span v-if="blk.verse.title" class="verse-topic">{{ blk.verse.title }}</span>
                </div>
                <div class="verse-body">
                  <div v-for="(stz, si) in blk.verse.stanzas" :key="si" class="verse-stanza">
                    <p v-for="(ln, li) in stz" :key="li" class="verse-line">{{ ln }}</p>
                  </div>
                </div>
                <p v-if="blk.verse.author" class="verse-author">— {{ blk.verse.author }}</p>
              </div>
            </div>
          </template>
        </template>
      </a-card>
    </div>
  </PageContainer>
</template>

<script setup lang="ts">
import { ref, computed, reactive, onMounted } from 'vue'
import {
  SearchOutlined, BulbOutlined, WarningOutlined, RocketOutlined, RadarChartOutlined,
  RobotOutlined, BugOutlined, GlobalOutlined, SafetyOutlined, CloudSyncOutlined, QuestionCircleOutlined,
  ExclamationCircleOutlined, CheckCircleOutlined, ReadOutlined,
} from '@ant-design/icons-vue'

import { DISCLAIMER_SECTIONS } from '../../config/disclaimer'
import { getDisclaimerStatus } from '../../api/meta'

// 免责声明签署状态（服务端持久化）——章节顶部显示已签署淡绿徽标。
const disc = reactive({ accepted: false, accepted_version: '', accepted_at: '' })
onMounted(async () => {
  try { Object.assign(disc, await getDisclaimerStatus()) } catch { /* ignore */ }
})

interface Verse { cipai?: string; title?: string; stanzas: string[][]; author?: string }
interface Block { h?: string; p?: string; list?: string[]; steps?: string[]; tip?: string; warn?: string; verse?: Verse }
interface Section { key: string; title: string; icon: any; lead: string; blocks: Block[] }

// 面向用户的说明（依据 云端/docs 提炼，非内部架构）。纯内置，离线可用。
const sections: Section[] = [
  {
    key: 'disclaimer', title: '免责声明', icon: ExclamationCircleOutlined,
    lead: '使用本系统前请务必阅读。仅限授权范围内使用，一切法律责任由使用者自负。',
    blocks: [
      ...DISCLAIMER_SECTIONS.map(s => ({ h: s.h, list: s.items })),
      { warn: '你已在首次登录时确认同意本声明（签署状态已在服务端留存）。继续使用即视为持续接受上述全部条款。' },
    ],
  },
  {
    key: 'quickstart', title: '快速上手', icon: RocketOutlined,
    lead: '瞭望塔是面向授权安全工作的综合平台：从目标录入到资产侦察、AI 自主渗透、漏洞与情报闭环，一条龙完成。',
    blocks: [
      { h: '第一步：激活系统', steps: [
        '首次使用前，前往「关于系统 → 激活设置」粘贴授权凭证并激活。',
        '未激活不影响本地已部署功能的运行，但无法获取更新与扩展商店。',
      ] },
      { h: '第二步：配置能力', list: [
        '「系统设置 → API 密钥」：填入 FOFA / Hunter 等测绘源密钥，用于资产收集。',
        '「AI 配置」：配置 LLM Provider（如 Claude），AI 自主渗透依赖它。',
        '「代理中心」：需要走代理时导入订阅或节点。',
      ] },
      { h: '第三步：跑通主流程', steps: [
        '「任务 → 新建任务」录入目标（域名 / IP / 单位名 / FOFA 语句）。',
        '选择扫描策略后启动，系统自动完成侦察并把资产沉淀到情报中心。',
        '侦察产出的资产按价值评分自动派发 AI 渗透会话，或手动发起。',
        '在「漏洞中心」查看产出，在「AI 渗透」查看会话过程与报告。',
      ] },
      { tip: '不确定从哪开始，就先建一个单目标任务跑通全链路，再逐步调策略。' },
    ],
  },
  {
    key: 'recon', title: '资产侦察', icon: RadarChartOutlined,
    lead: '侦察引擎把一个目标展开成完整攻击面：子域名、DNS、端口、站点、证书、爬虫、泄露、指纹、PoC。',
    blocks: [
      { h: '收集模式', list: [
        '单目标（single）：只处理给定目标，不做子域名枚举，最快最省。',
        '被动（passive）：用测绘源被动收集，不主动爆破。',
        '爆破（brute）：子域名字典爆破 + 全量侦察，最全但最重。',
      ] },
      { h: '外部数据源', list: [
        'FOFA / Hunter：资产测绘，直接拉取给定目标的资产，不额外扫端口/子域名。',
        'crt.sh / ICP：证书透明日志与备案反查，补充关联资产。',
      ] },
      { h: '去重与归集', p: '侦察结果流式归集到情报中心，按物理标识（主机名 / IP+端口）去重，绝不跨单位混合，避免误判。' },
      { warn: '关闭扫描时（纯导入 FOFA），系统直接探测给定目标，不会主动扩面，符合最小 scope 原则。' },
    ],
  },
  {
    key: 'pentest', title: 'AI 自主渗透', icon: RobotOutlined,
    lead: 'AI 按资产自动发起渗透会话：大模型自主选工具、真实发包验证、产出 finding 与攻击链，全程可观察、可接管。',
    blocks: [
      { h: '会话怎么来', list: [
        '自动派发：侦察归集后，系统按资产价值评分自动创建渗透会话。',
        '手动发起：在「AI 渗透」对目标资产手动建会话。',
      ] },
      { h: '实时观察与接管', list: [
        '运行中会话点「🔴 实时」进入实时观察，SSE 推送工具调用与攻击面。',
        '「AI 会话台」可对已结束会话按 resume_key 恢复，人工接管继续对话。',
      ] },
      { h: 'AI 工作模式（四档，强度由轻到重，在扫描策略里选）', list: [
        '探测：最轻。匿名视角只过一遍接口（GET/只读 POST），看未授权裸奔的接口和 JS 里泄露的密钥凭证；全程不登录、不注册、不改参越权、不发注入探针、不打 RCE/CVE。适合只想快速摸清目标接口面暴露了什么、且不希望对目标有任何写入或利用动作的场景。',
        '保守：轻。抓全量 JS 逐接口 GET/POST 跑一遍即止，只读取证、取凭证、抓 JS；不做深度利用链、不动业务数据。适合高敏感目标。',
        '常规（SRC）：中。标准 SRC 挖洞——越权、注入、逻辑漏洞都测，自注册账号互测越权，闸刀拦高危写操作、放行自证的验证操作。日常评估的默认档。',
        '红队：重。授权范围内放开完整利用链（登录利用、RCE、提权、后台接管、横向），闸刀仅记录不拦截。仅限充分授权的红队演练目标。',
      ] },
      { h: '安全约束', list: [
        'scope 闸：会话锁定下发目标，不会越界打同主机的其他端口/站点（全模式生效）。',
        '监管闸刀：写操作经监管 AI 判定，探测/保守/常规三档各有对应严格度的判定标准；红队不过闸刀仅记录。破坏性操作（删库/清空/批量改他人数据/提权）任何模式都硬拦。',
        '探测模式最严：闸刀只放行 GET/只读 POST，任何写入/登录/注册/注入/RCE 一律拦。',
      ] },
      { tip: '不确定选哪档：先用「探测」快速看接口面 → 有价值再上「常规」深挖 → 充分授权的演练才用「红队」。高敏目标用「保守」。' },
      { warn: '仅在授权范围内使用。平台默认产出面向复现与修复的结论，不做无差别破坏。' },
    ],
  },
  {
    key: 'vuln', title: '漏洞与情报', icon: BugOutlined,
    lead: '所有产出在漏洞中心汇聚，情报体系让成果在单位内共享、跨单位借鉴打法。',
    blocks: [
      { h: '漏洞中心', list: [
        '三来源混排：侦察 PoC、AI 渗透 finding、漏洞情报，统一 CVSS 与处理状态标记。',
        '支持按单位、关键词、类型筛选，导出报告。',
      ] },
      { h: '情报中心', list: [
        '资产情报：任务成果持续富化资产画像。',
        '单位视图：按单位聚合资产与漏洞，看清一个组织的整体暴露面。',
        '攻击链情报：AI 渗透产出的利用链路可视化。',
      ] },
      { h: '漏洞情报库', p: '内置漏洞情报源（NVD/CISA 等），可手动刷新或配置定时拉取，为侦察 PoC 提供依据。' },
    ],
  },
  {
    key: 'proxy', title: '代理中心', icon: GlobalOutlined,
    lead: '代理分两条独立轨道：访问中转站的代理，与攻击出口的代理，互不干扰。',
    blocks: [
      { h: '导入节点', steps: [
        '「代理中心」粘贴订阅链接或导入 YAML 节点配置。',
        '系统解析后可测速、选组、启停。',
      ] },
      { h: '两条轨道', list: [
        '访问代理：访问 LLM 中转站等外部服务用，默认直连，可按 Provider 配置。',
        '攻击出口代理：AI 渗透 / 扫描流量的出口，由策略的出口代理开关控制。',
      ] },
      { warn: '扫描流量默认直连，需要隐藏真实出口 IP 时在策略里开启出口代理，否则会暴露本机 IP。' },
    ],
  },
  {
    key: 'system', title: '系统设置与权限', icon: SafetyOutlined,
    lead: '用户管理采用 RBAC 角色模型，日志监测覆盖运行报错、访问与闸刀拦截。',
    blocks: [
      { h: '角色权限（RBAC）', list: [
        'admin：全部权限 + 用户管理，内置不可改。',
        'operator：任务/资产/漏洞/AI 渗透读写 + 系统更新，无用户管理/密钥/AI 配置写。',
        'viewer：所有查看权限，无任何写操作。',
      ] },
      { h: '日志', list: [
        '日志监测：各进程 WARNING 及以上报错自动入库，可按级别/进程/关键词筛选。',
        '访问日志 / 拦截日志：记录访问与监管闸刀的放行/拦截。',
      ] },
      { h: '报错上传', steps: [
        '在「日志监测」勾选要反馈的报错日志。',
        '点「上传到云端」，填写问题描述后提交。',
        '系统会带上你的授权凭证归属、版本与出口 IP，上传到云端供开发方定位。',
      ] },
      { tip: '上传前请确认描述里不含敏感信息；日志正文会原样上传，注意脱敏。' },
    ],
  },
  {
    key: 'update', title: '更新与激活', icon: CloudSyncOutlined,
    lead: '瞭望塔支持一键热更新、按版本查看改动、以及回退到历史版本。更新链带凭证校验。',
    blocks: [
      { h: '检查与更新', steps: [
        '「更新检测」点「检查更新」，有新版会列出更新内容。',
        '点「立即更新」触发热更新，进度实时显示，完成后自动刷新。',
        '更新过程增量拉取变化文件，不影响现有业务。',
      ] },
      { h: '历史版本与回退', list: [
        '「更新检测」页下方「历史版本」列出所有已发布版本（需相应权限）。',
        '点「改动」查看某版相对上一版的新增/修改/删除文件清单。',
        '点「回退」把系统对齐到所选历史版本（含删除新版新增文件）。',
      ] },
      { h: '激活', p: '「激活设置」粘贴授权凭证激活。凭证只控制更新与扩展商店，不锁运行，可由运营方吊销。' },
      { warn: '回退是高危操作，会重启 worker/scheduler 并影响全站运行代码，仅在新版出现严重问题时使用。' },
    ],
  },
  {
    key: 'faq', title: '常见问题', icon: QuestionCircleOutlined,
    lead: '高频问题速查。',
    blocks: [
      { h: '一直提示有新版本？', p: '通常是浏览器缓存了旧构建。强制刷新（Ctrl+F5）即可；仍不行请确认前端已随新版本重新构建。' },
      { h: '检查更新报「凭证无效」？', p: '前往「激活设置」重新激活。凭证过期或被吊销都会导致更新链 403。' },
      { h: 'AI 渗透不出洞 / 空转？', list: [
        '确认 AI 配置的 Provider 可用、额度充足。',
        '确认目标资产侦察产出充分（有站点/接口/指纹），侦察太浅会限制渗透深度。',
      ] },
      { h: '扫描很慢 / 触发目标限速？', p: '同一 IP 的并发会触发目标侧限速，正常现象。跨 IP 并行、同 IP 串行是更稳的打法，可在策略里调并发。' },
      { h: 'FOFA 语句查不出结果？', p: '常见于从文档复制带入了全角引号/运算符。系统会自动归一化，若仍异常请检查语句语法。' },
    ],
  },
  {
    key: 'verse', title: '采桑子·鞭春', icon: ReadOutlined,
    lead: '',
    blocks: [
      {
        verse: {
          cipai: '采桑子',
          title: '鞭春',
          stanzas: [
            ['胥吏追呼昼夜逼，', '荒也吞糠，', '丰也吞糠，', '新苗破土带鞭伤。'],
            ['天造草昧岁相食，', '秋也杀人，', '冬也杀人，', '春生夏长又一轮。'],
          ],
          author: '佚名（现代）',
        },
      },
    ],
  },
]

const activeKey = ref('quickstart')
const keyword = ref('')
const active = computed(() => sections.find(s => s.key === activeKey.value) || sections[0])
const filteredSections = computed(() => {
  const kw = keyword.value.trim().toLowerCase()
  if (!kw) return sections
  return sections.filter(s =>
    s.title.toLowerCase().includes(kw) || s.lead.toLowerCase().includes(kw) ||
    JSON.stringify(s.blocks).toLowerCase().includes(kw))
})
function go(k: string) { activeKey.value = k }
function renderInline(text: string): string {
  // 极简内联渲染：`code` → <code>，「」保持原样，转义 < >
  const esc = text.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
  return esc.replace(/`([^`]+)`/g, '<code>$1</code>')
}
</script>

<style scoped>
.manual-wrap { display: flex; gap: 16px; align-items: flex-start; }
.manual-nav { width: 200px; flex: none; position: sticky; top: 12px; }
.nav-item { display: flex; align-items: center; gap: 8px; padding: 9px 12px; border-radius: 8px; cursor: pointer; color: var(--dt-muted); font-size: 14px; transition: all .15s; }
.nav-item:hover { background: var(--dt-hover, #f0f3f8); color: var(--dt-text, #1f2328); }
.nav-item.active { background: var(--dt-primary, #2f6bff); color: #fff; }
.nav-icon { font-size: 15px; }
.manual-body { flex: 1; min-width: 0; }
.doc-h1 { font-size: 22px; font-weight: 750; margin: 0 0 6px; display: flex; align-items: center; gap: 10px; }
.doc-lead { color: var(--dt-muted); font-size: 14px; margin-bottom: 18px; line-height: 1.7; }
.disc-signed-tag { background: #f0fdf4 !important; color: #16a34a !important; border-color: #bbf7d0 !important; margin: 4px 0 12px; font-size: 13px; padding: 4px 12px; }
.doc-h2 { font-size: 16px; font-weight: 650; margin: 20px 0 8px; padding-left: 10px; border-left: 3px solid var(--dt-primary, #2f6bff); }
.doc-p { font-size: 14px; line-height: 1.8; color: var(--dt-text, #333); margin: 6px 0; }
.doc-list, .doc-steps { padding-left: 22px; margin: 6px 0; }
.doc-list li, .doc-steps li { font-size: 14px; line-height: 1.9; }
.doc-tip { background: rgba(47,107,255,.08); border-radius: 8px; padding: 10px 14px; margin: 12px 0; font-size: 13px; color: #2f6bff; display: flex; gap: 8px; align-items: flex-start; }
.doc-warn { background: rgba(212,107,8,.1); border-radius: 8px; padding: 10px 14px; margin: 12px 0; font-size: 13px; color: #d46b08; display: flex; gap: 8px; align-items: flex-start; }
:deep(code) { background: rgba(0,0,0,.06); padding: 1px 6px; border-radius: 4px; font-family: 'JetBrains Mono', monospace; font-size: 12px; }
/* —— 诗词块：古典卷轴排版 —— */
.doc-verse { margin: 28px auto; max-width: 560px; padding: 40px 44px 32px; border-radius: 4px;
  position: relative; text-align: center;
  background:
    linear-gradient(180deg, rgba(180,140,80,.05), rgba(180,140,80,.02)),
    var(--dt-card-bg, #fbf8f2);
  border: 1px solid rgba(180,140,80,.28);
  box-shadow: 0 6px 24px rgba(120,90,40,.08), inset 0 0 0 1px rgba(180,140,80,.08); }
/* 卷轴上下描边装饰 */
.doc-verse::before, .doc-verse::after { content: ''; position: absolute; left: 44px; right: 44px; height: 1px;
  background: linear-gradient(90deg, transparent, rgba(180,140,80,.4), transparent); }
.doc-verse::before { top: 18px; }
.doc-verse::after { bottom: 18px; }
.verse-scroll { font-family: 'KaiTi', 'STKaiti', 'Kaiti SC', 'Songti SC', serif; }
.verse-title { margin: 0 0 22px; letter-spacing: 3px; color: var(--dt-text, #2b2b2b);
  font-weight: 700; }
.verse-cipai { font-size: 21px; }
.verse-sep { font-size: 17px; margin: 0 3px; color: rgba(180,140,80,.75); }
.verse-topic { font-size: 21px; }
.verse-body { display: flex; flex-direction: column; gap: 20px; }
.verse-stanza { display: flex; flex-direction: column; }
.verse-line { font-size: 18px; line-height: 2.15; letter-spacing: 3px; margin: 0;
  color: var(--dt-text, #23201b); }
.verse-author { margin: 26px 0 0; text-align: right; font-size: 14px; letter-spacing: 2px;
  color: var(--dt-muted, #9a8f7c); font-style: normal; }
[data-theme="dark"] .doc-verse {
  background: linear-gradient(180deg, rgba(212,175,120,.06), rgba(212,175,120,.02)), rgba(255,255,255,.02);
  border-color: rgba(212,175,120,.3); box-shadow: 0 6px 24px rgba(0,0,0,.3); }
[data-theme="dark"] .verse-title, [data-theme="dark"] .verse-line { color: #e7dcc6; }
[data-theme="dark"] .verse-author { color: #b8a988; }
</style>

