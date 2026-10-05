<template>
  <PageContainer :title="translate('ui.m_38084d301e3f')" kicker="Developer" :description="translate('ui.m_f9e6ca2e736c')">
    <a-card class="page-card dev-card">
      <div class="dev-hero">
        <div class="dev-avatar">
          <img src="/avatars/developer.jpg" alt="LINGYK" />
        </div>
        <div class="dev-hero-text">
          <h2>LINGYK</h2>
          <p>{{ translate('ui.m_f0e7016b835a') }}</p>
        </div>
      </div>

      <div class="dev-info-row">
        <a-descriptions :column="1" bordered size="middle" class="dev-desc">
          <a-descriptions-item :label="translate('ui.m_38084d301e3f')">LINGYK</a-descriptions-item>
          <a-descriptions-item :label="translate('ui.m_73075237fd0f')">
            <CopyText :text="email" /> <span class="muted">{{ translate('ui.m_c457bcdb2faf') }}</span>
          </a-descriptions-item>
          <a-descriptions-item :label="translate('ui.m_837bc9576721')">
            <a-tag color="blue">{{ version }}</a-tag>
          </a-descriptions-item>
        </a-descriptions>

        <div class="donate-section">
          <div class="donate-head">
            <span class="donate-title">{{ translate('ui.m_c16d780c585d') }}</span>
          </div>
          <p class="donate-desc">{{ translate('ui.m_efe83de50fe4') }}<br/>{{ translate('ui.m_e19f4de21d4f') }}</p>
          <div class="donate-qr">
            <img src="/avatars/donate-qr.png" alt="捐赠二维码" />
          </div>
        </div>
      </div>

      <a-alert
        class="dev-tip"
        type="info"
        show-icon
        :message="translate('ui.m_6dca22936b9c')"
        :description="translate('ui.m_bb3398ba7632')" />

      <div class="dev-credits">
        <div class="credits-head">
          <span class="credits-title">{{ translate('ui.m_66313a805bbe') }}</span>
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
            </div>
          </li>
        </ul>
        <p class="credits-foot">{{ translate('ui.m_a69536180fea') }}</p>
      </div>

      <div class="dev-credits">
        <div class="credits-head">
          <span class="credits-title">{{ translate('ui.m_50a524af35d6') }}</span>
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
            </div>
          </li>
        </ul>
        <p v-else class="credits-foot">{{ translate('ui.m_9a8ff8c6393f') }}</p>
        <!-- "成为项目推进者"提示卡放推进者列表下方（用户要求：先展示已有推进者，再引导申请） -->
        <a-alert class="drivers-tip" type="success" show-icon
          :message="translate('ui.m_ee1ee335f3e7')"
          :description="translate('ui.m_c63e1343d26d')" />
      </div>
    </a-card>
  </PageContainer>
</template>

<script setup lang="ts">
import { t as translate } from '../../i18n'

import PageContainer from '../../layouts/PageContainer.vue'
import CopyText from '../../components/CopyText.vue'
import { useServerVersion } from '../../composables/useServerVersion'

const email = 'lingyangkang352@163.com'
// 显示后端真实版本（version.txt），非编译进包的 APP_VERSION（跳板逐级更新时前端 brand 可能滞后/错配）
const { serverVersion: version } = useServerVersion()

// 特别贡献者。
const contributors = [
  { name: '辞旧迎新', role: '特别贡献', avatar: '/avatars/contributor.jpg' },
  { name: 'LYX', role: '特别贡献', avatar: '/avatars/lyx.jpg' },
]

// 项目推进者（提出问题/建议并被采纳者，申请后在此追加）。contribution=被采纳的贡献简述，可空。
// 头像缺省用通用占位（driver.jpg 未提供时复用 contributor.jpg）。空数组时页面显示"虚位以待"。
const drivers: Array<{ name: string; role: string; contribution?: string; avatar: string }> = [
  { name: '尤里曾', role: '项目推进者', avatar: '/avatars/yulizeng.jpg' },
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
.credit-contrib { color: var(--dt-muted); font-size: 12px; line-height: 1.5; max-width: 160px;
  word-break: break-word; overflow-wrap: anywhere; }
.credits-foot { margin: 18px 0 0; color: var(--dt-muted); font-size: 12px; }
.drivers-tip { margin-top: 20px; max-width: 720px; }   /* 挪到推进者列表下方后，与卡片拉开间距 */
</style>
