<template>
  <PageContainer title="开发者" kicker="Developer" description="瞭望塔 Watchtower 由以下开发者独立设计与维护。">
    <a-card class="page-card dev-card">
      <div class="dev-hero">
        <div class="dev-avatar">
          <img src="/avatars/developer.jpg" alt="LINGYK" />
        </div>
        <div class="dev-hero-text">
          <h2>LINGYK</h2>
          <p>瞭望塔 Watchtower · 设计 / 研发 / 维护</p>
        </div>
      </div>

      <div class="dev-info-row">
        <a-descriptions :column="1" bordered size="middle" class="dev-desc">
          <a-descriptions-item label="开发者">LINGYK</a-descriptions-item>
          <a-descriptions-item label="邮箱">
            <CopyText :text="email" /> <span class="muted">(点击复制)</span>
          </a-descriptions-item>
          <a-descriptions-item label="微信">
            <CopyText :text="wechat" /> <span class="muted">(点击复制)</span>
          </a-descriptions-item>
          <a-descriptions-item label="当前版本">
            <a-tag color="blue">{{ version }}</a-tag>
          </a-descriptions-item>
        </a-descriptions>

        <div class="donate-section">
          <div class="donate-head">
            <span class="donate-title">捐赠支持</span>
          </div>
          <p class="donate-desc">如果瞭望塔对你有帮助<br/>欢迎请开发者喝杯咖啡 ☕</p>
          <div class="donate-qr">
            <img src="/avatars/donate-qr.png" alt="捐赠二维码" />
          </div>
        </div>
      </div>

      <a-alert
        class="dev-tip"
        type="info"
        show-icon
        message="联系与反馈"
        description="功能建议、缺陷反馈或合作，欢迎通过上方邮箱或微信联系开发者。本系统为开源安全平台，仅限授权范围内使用，请遵守相关法律法规。" />

      <div class="dev-credits">
        <div class="credits-head">
          <span class="credits-title">特别贡献</span>
          <span class="credits-sub">Special Thanks</span>
        </div>
        <ul class="credits-list">
          <li v-for="ct in contributors" :key="ct.name" class="credit-item">
            <div class="credit-avatar-wrap">
              <img :src="ct.avatar" :alt="ct.name" class="credit-avatar" />
            </div>
            <div class="credit-info">
              <div class="credit-name">{{ ct.name }}</div>
              <span class="credit-role">{{ ct.role }}</span>
              <div v-if="ct.wechat" class="credit-wx">
                <span class="wx-label">微信</span>
                <CopyText :text="ct.wechat" />
              </div>
            </div>
          </li>
        </ul>
        <p class="credits-foot">感谢为瞭望塔 Watchtower 的设计、测试与打磨提供帮助的每一位贡献者。</p>
      </div>

      <div class="dev-credits">
        <div class="credits-head">
          <span class="credits-title">项目推进者</span>
          <span class="credits-sub">Project Drivers</span>
        </div>
        <ul v-if="drivers.length" class="credits-list">
          <li v-for="dv in drivers" :key="dv.name" class="credit-item">
            <div class="credit-avatar-wrap">
              <img :src="dv.avatar" :alt="dv.name" class="credit-avatar" />
            </div>
            <div class="credit-info">
              <div class="credit-name">{{ dv.name }}</div>
              <span class="credit-role">{{ dv.role }}</span>
              <div v-if="dv.contribution" class="credit-contrib">{{ dv.contribution }}</div>
              <div class="credit-wx">
                <span class="wx-label">微信</span>
                <CopyText v-if="dv.wechat" :text="dv.wechat" />
                <span v-else class="wx-private">不公开</span>
              </div>
            </div>
          </li>
        </ul>
        <p v-else class="credits-foot">虚位以待 —— 你的下一条被采纳的建议，就能出现在这里。</p>
        <!-- "成为项目推进者"提示卡放推进者列表下方（用户要求：先展示已有推进者，再引导申请） -->
        <a-alert class="drivers-tip" type="success" show-icon
          message="成为项目推进者"
          description="凡为瞭望塔 Watchtower 提出问题、建议或缺陷，并被采纳落地的用户，均可申请成为「项目推进者」。你的每一条被采纳的反馈都在直接推动项目演进——被采纳后，欢迎通过上方邮箱或微信联系开发者申请。" />
      </div>
    </a-card>
  </PageContainer>
</template>

<script setup lang="ts">
import PageContainer from '../../layouts/PageContainer.vue'
import CopyText from '../../components/CopyText.vue'
import { useServerVersion } from '../../composables/useServerVersion'

const email = 'lingyangkang352@163.com'
const wechat = 'LINGYK352'
// 显示后端真实版本（version.txt），非编译进包的 APP_VERSION（跳板逐级更新时前端 brand 可能滞后/错配）
const { serverVersion: version } = useServerVersion()

// 特别贡献者（卡片网格展示，新增贡献者在此追加即可）。wechat 可空（不展示微信行）。
const contributors = [
  { name: '辞旧迎新', role: '特别贡献', wechat: 'msf_kali', avatar: '/avatars/contributor.jpg' },
  { name: 'LYX', role: '特别贡献', wechat: '', avatar: '/avatars/lyx.jpg' },
]

// 项目推进者（提出问题/建议并被采纳者，申请后在此追加）。contribution=被采纳的贡献简述，可空。
// 头像缺省用通用占位（driver.jpg 未提供时复用 contributor.jpg）。空数组时页面显示"虚位以待"。
const drivers: Array<{ name: string; role: string; contribution?: string; wechat?: string; avatar: string }> = [
  { name: '尤里曾', role: '项目推进者', wechat: 'Cavanture', avatar: '/avatars/yulizeng.jpg' },
]
</script>

<style scoped>
.dev-hero { display: flex; align-items: center; gap: 18px; padding: 8px 4px 22px; border-bottom: 1px solid var(--dt-border); margin-bottom: 22px; }
.dev-avatar { width: 76px; height: 76px; border-radius: 50%; overflow: hidden; flex: none; border: 3px solid #eef3f9; }
.dev-avatar img { width: 100%; height: 100%; object-fit: cover; }
.dev-hero-text h2 { margin: 0; font-size: 22px; font-weight: 750; letter-spacing: -.01em; }
.dev-hero-text p { margin: 6px 0 0; color: var(--dt-muted); }
.dev-desc { max-width: 420px; flex: 1; }
.dev-tip { margin-top: 22px; max-width: 700px; }
.muted { color: var(--dt-muted); font-size: 12px; margin-left: 6px; }
.dev-info-row { display: flex; align-items: flex-start; gap: 32px; flex-wrap: wrap; }
.donate-section { flex-shrink: 0; }
.donate-head { margin-bottom: 8px; }
.donate-title { font-size: 15px; font-weight: 700; }
.donate-desc { color: var(--dt-muted); font-size: 13px; margin: 0 0 12px; line-height: 1.6; }
.donate-qr { width: 160px; height: 160px; border-radius: 12px; overflow: hidden; border: 1px solid var(--dt-border); }
.donate-qr img { width: 100%; height: 100%; object-fit: cover; }
.dev-credits { margin-top: 28px; padding-top: 22px; border-top: 1px solid var(--dt-border); max-width: 720px; }
.credits-head { display: flex; align-items: baseline; gap: 10px; margin-bottom: 16px; }
.credits-title { font-size: 16px; font-weight: 700; }
.credits-sub { color: var(--dt-muted); font-size: 12px; letter-spacing: .04em; text-transform: uppercase; }
/* 贡献者卡片网格（优化：自适应多列，头像居中，hover 微抬升+主色描边） */
.credits-list { list-style: none; padding: 0; margin: 0;
  display: grid; grid-template-columns: repeat(auto-fill, minmax(180px, 1fr)); gap: 14px; }
.credit-item { display: flex; flex-direction: column; align-items: center; text-align: center;
  padding: 20px 16px 18px; border: 1px solid var(--dt-border); border-radius: 14px;
  background: var(--dt-gradient-soft, #f7fafc);
  transition: transform .2s cubic-bezier(.4,0,.2,1), box-shadow .2s, border-color .2s; }
.credit-item:hover { transform: translateY(-3px); box-shadow: var(--dt-shadow-hover); border-color: var(--dt-primary); }
.credit-avatar-wrap { width: 64px; height: 64px; border-radius: 50%; padding: 3px;
  background: var(--dt-gradient); margin-bottom: 12px; flex: none; }
.credit-avatar { width: 100%; height: 100%; border-radius: 50%; object-fit: cover; display: block;
  border: 2px solid var(--dt-card); }
.credit-info { display: flex; flex-direction: column; align-items: center; gap: 7px; }
.credit-name { font-size: 15px; font-weight: 700; }
.credit-role { display: inline-block; padding: 2px 12px; border-radius: 999px;
  background: var(--dt-gradient-soft); color: var(--dt-primary); font-size: 12px; font-weight: 600;
  border: 1px solid var(--dt-border); }
.credit-wx { color: var(--dt-muted); font-size: 12px; display: inline-flex; align-items: center; gap: 4px; }
.wx-label { opacity: .8; }
.wx-private { color: var(--dt-muted); opacity: .7; }   /* 未公开微信的推进者显示"不公开" */
.credit-contrib { color: var(--dt-muted); font-size: 12px; line-height: 1.5; max-width: 160px;
  word-break: break-word; overflow-wrap: anywhere; }
.credits-foot { margin: 18px 0 0; color: var(--dt-muted); font-size: 12px; }
.drivers-tip { margin-top: 20px; max-width: 720px; }   /* 挪到推进者列表下方后，与卡片拉开间距 */
</style>
