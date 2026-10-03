<template>
  <PageContainer :title="translate('ui.m_396c685466aa')" kicker="Manual" :description="translate('ui.m_0e788d30ca81')">
    <div class="manual-wrap">
      <!-- 左侧分类导航 -->
      <div class="manual-nav">
        <a-input v-model:value="keyword" :placeholder="translate('ui.m_9d61392dc653')" allow-clear size="small" style="margin-bottom:10px">
          <template #prefix><SearchOutlined /></template>
        </a-input>
        <div v-for="sec in filteredSections" :key="sec.key"
          class="nav-item" :class="{ active: sec.key === activeKey }" @click="go(sec.key)">
          <component :is="sec.icon" class="nav-icon" />
          <span>{{ sec.title }}</span>
        </div>
        <a-empty v-if="!filteredSections.length" :image="false" :description="translate('ui.m_7a54f3fc4716')" />
      </div>

      <!-- 右侧正文 -->
      <a-card class="manual-body" :bordered="false">
        <template v-if="active">
          <h2 class="doc-h1"><component :is="active.icon" /> {{ active.title }}</h2>
          <!-- 免责声明章节：显示服务端签署状态徽标（已签署=淡绿） -->
          <a-tag v-if="activeKey === 'disclaimer' && disc.accepted" color="green" class="disc-signed-tag">
            <CheckCircleOutlined /> {{ translate('ui.m_51ae950c5f10') }}<template v-if="disc.accepted_at"> · {{ disc.accepted_at }}</template>
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
import { t as translate } from '../../i18n'

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
const sections = computed<Section[]>(() => [
  {
    key: 'disclaimer', get title() { return translate('ui.m_280af617c87f') }, icon: ExclamationCircleOutlined,
    get lead() { return translate('ui.m_28d2a62baffa') },
    blocks: [
      ...DISCLAIMER_SECTIONS.value.map(s => ({ h: s.h, list: s.items })),
      { get warn() { return translate('ui.m_123fcbe11173') } },
    ],
  },
  {
    key: 'quickstart', get title() { return translate('ui.m_bfc47d6b4af9') }, icon: RocketOutlined,
    get lead() { return translate('ui.m_ac2b148571b4') },
    blocks: [
      { get h() { return translate('ui.m_a115f2034b79') }, steps: [
        translate('ui.m_d437a895f834'),
        translate('ui.m_a246a5776e48'),
      ] },
      { get h() { return translate('ui.m_be4213292380') }, list: [
        translate('ui.m_f0df653a9e96'),
        translate('ui.m_8b1d198bac90'),
        translate('ui.m_640c5b51e2d5'),
      ] },
      { get h() { return translate('ui.m_3e83f9c48a51') }, steps: [
        translate('ui.m_4e66dfac631e'),
        translate('ui.m_e4ec38af6d35'),
        translate('ui.m_d10315228561'),
        translate('ui.m_93d66e9f4870'),
      ] },
      { get tip() { return translate('ui.m_d0bb49e6ec4c') } },
    ],
  },
  {
    key: 'recon', get title() { return translate('ui.m_60d1ef084057') }, icon: RadarChartOutlined,
    get lead() { return translate('ui.m_6270bbde98c5') },
    blocks: [
      { get h() { return translate('ui.m_22735e17bbd1') }, list: [
        translate('ui.m_fbd4142fae30'),
        translate('ui.m_0270eceab9fc'),
        translate('ui.m_d0ae72c1605d'),
      ] },
      { get h() { return translate('ui.m_c6e3c505481a') }, list: [
        translate('ui.m_3e4f899c485b'),
        translate('ui.m_815fe802d153'),
      ] },
      { get h() { return translate('ui.m_f9347b066806') }, get p() { return translate('ui.m_c284007554c5') } },
      { get warn() { return translate('ui.m_99da50c34854') } },
    ],
  },
  {
    key: 'pentest', get title() { return translate('ui.m_d7de33b42843') }, icon: RobotOutlined,
    get lead() { return translate('ui.m_9640b68a573a') },
    blocks: [
      { get h() { return translate('ui.m_db4e5ff817af') }, list: [
        translate('ui.m_ecbea1775d26'),
        translate('ui.m_c07909e2879e'),
      ] },
      { get h() { return translate('ui.m_e975ce9308f8') }, list: [
        translate('ui.m_16c4f1896e1a'),
        translate('ui.m_44d3fae745db'),
      ] },
      { get h() { return translate('ui.m_833fe661f95a') }, list: [
        translate('ui.m_d61c63eb5fa4'),
        translate('ui.m_a24d4f5ff0fc'),
        translate('ui.m_12b9d18baeb2'),
        translate('ui.m_52f1004984f5'),
      ] },
      { get h() { return translate('ui.m_804196aef712') }, list: [
        translate('ui.m_5dec33d4f038'),
        translate('ui.m_466302d086ae'),
        translate('ui.m_491724604e42'),
      ] },
      { get tip() { return translate('ui.m_c6fa9a24eba8') } },
      { get warn() { return translate('ui.m_1f4b63e3edff') } },
    ],
  },
  {
    key: 'vuln', get title() { return translate('ui.m_e84c1409f5a9') }, icon: BugOutlined,
    get lead() { return translate('ui.m_9952511868d0') },
    blocks: [
      { get h() { return translate('ui.m_756d8eeb32a5') }, list: [
        translate('ui.m_53684d2d0cca'),
        translate('ui.m_b376e7628416'),
      ] },
      { get h() { return translate('ui.m_5938e567a70b') }, list: [
        translate('ui.m_b6eccd7bb255'),
        translate('ui.m_792fede7decf'),
        translate('ui.m_ff2bae64f982'),
      ] },
      { get h() { return translate('ui.m_0a5366f366d4') }, get p() { return translate('ui.m_60d762b20120') } },
    ],
  },
  {
    key: 'proxy', get title() { return translate('ui.m_23eae9eefda3') }, icon: GlobalOutlined,
    get lead() { return translate('ui.m_3af25db097d7') },
    blocks: [
      { get h() { return translate('ui.m_bd4efd1e6f12') }, steps: [
        translate('ui.m_b6ecfd374049'),
        translate('ui.m_30ec0218225f'),
      ] },
      { get h() { return translate('ui.m_af2ee0ea557a') }, list: [
        translate('ui.m_f98cad3c82ed'),
        translate('ui.m_aae0d0e29517'),
      ] },
      { get warn() { return translate('ui.m_121e8153667c') } },
    ],
  },
  {
    key: 'system', get title() { return translate('ui.m_495ee40ac3f4') }, icon: SafetyOutlined,
    get lead() { return translate('ui.m_8929e7d9d46d') },
    blocks: [
      { get h() { return translate('ui.m_f242860c2f47') }, list: [
        translate('ui.m_f9ea6e889739'),
        translate('ui.m_c933cb4743ba'),
        translate('ui.m_8a1d59b095e8'),
      ] },
      { get h() { return translate('ui.m_7dbac1c20f23') }, list: [
        translate('ui.m_653141ab8b0c'),
        translate('ui.m_021c69ce3b82'),
      ] },
      { get h() { return translate('ui.m_dac54049f5f1') }, steps: [
        translate('ui.m_52607382f9c1'),
        translate('ui.m_3ed332880af1'),
        translate('ui.m_eace3bca618b'),
      ] },
      { get tip() { return translate('ui.m_38c3858b9ff0') } },
    ],
  },
  {
    key: 'update', get title() { return translate('ui.m_89bb9156b82c') }, icon: CloudSyncOutlined,
    get lead() { return translate('ui.m_1e95ca23e1fa') },
    blocks: [
      { get h() { return translate('ui.m_cf59c9d217f2') }, steps: [
        translate('ui.m_f0c28e8491be'),
        translate('ui.m_0945ebfb4fa9'),
        translate('ui.m_8301beaf65da'),
      ] },
      { get h() { return translate('ui.m_094f0428c3b4') }, list: [
        translate('ui.m_6ed1c01edb95'),
        translate('ui.m_1d0d004504e4'),
        translate('ui.m_51d300ad95e6'),
      ] },
      { get h() { return translate('ui.m_dd1286c29e9b') }, get p() { return translate('ui.m_8e500c452025') } },
      { get warn() { return translate('ui.m_a11f00ab824e') } },
    ],
  },
  {
    key: 'faq', get title() { return translate('ui.m_45a6d115fdfb') }, icon: QuestionCircleOutlined,
    get lead() { return translate('ui.m_5d3f807b9bfd') },
    blocks: [
      { get h() { return translate('ui.m_b3880b826560') }, get p() { return translate('ui.m_f9bb76440bb8') } },
      { get h() { return translate('ui.m_b84c18024abf') }, get p() { return translate('ui.m_aad330c944dd') } },
      { get h() { return translate('ui.m_aa0bea547b2b') }, list: [
        translate('ui.m_0bb393be4711'),
        translate('ui.m_20018d7ffe64'),
      ] },
      { get h() { return translate('ui.m_7dba274589f2') }, get p() { return translate('ui.m_e7f184b903f1') } },
      { get h() { return translate('ui.m_c0307417e063') }, get p() { return translate('ui.m_9919d54086bd') } },
    ],
  },
  {
    key: 'verse', get title() { return translate('ui.m_9023a453b025') }, icon: ReadOutlined,
    lead: '',
    blocks: [
      {
        verse: {
          get cipai() { return translate('ui.m_7133fc1ef44d') },
          get title() { return translate('ui.m_9c891e614269') },
          stanzas: [
            [translate('ui.m_11f066c87a5f'), translate('ui.m_465748f4c64c'), translate('ui.m_76f58682138d'), translate('ui.m_b9b14a5318c7')],
            [translate('ui.m_72fb60147d3a'), translate('ui.m_48e471969301'), translate('ui.m_2f5f1e23236d'), translate('ui.m_589fc1d906ab')],
          ],
          get author() { return translate('ui.m_29c02b956e59') },
        },
      },
    ],
  },
])

const activeKey = ref('quickstart')
const keyword = ref('')
const active = computed(() => sections.value.find(s => s.key === activeKey.value) || sections.value[0])
const filteredSections = computed(() => {
  const kw = keyword.value.trim().toLowerCase()
  if (!kw) return sections.value
  return sections.value.filter(s =>
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

