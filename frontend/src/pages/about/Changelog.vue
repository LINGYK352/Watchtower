<template>
  <PageContainer :title="translate('ui.m_de6811e73d40')" kicker="Changelog" :description="translate('ui.m_288369648f65')">
    <a-card class="page-card">
      <a-spin v-if="loading" :tip="translate('ui.m_4927a53bcc88')" style="display:block;padding:24px 0" />
      <a-timeline v-else class="cl-timeline">
        <a-timeline-item v-for="(log, i) in logs" :key="log.ver" :color="i === 0 ? 'blue' : 'gray'">
          <div class="cl-head">
            <a-tag :color="i === 0 ? 'blue' : 'default'">{{ log.ver }}</a-tag>
            <span class="cl-date">{{ log.date }}</span>
            <a-tag v-if="i === 0" color="green" style="margin-left:4px">{{ translate('ui.m_cb62ebd689ee') }}</a-tag>
          </div>
          <div class="cl-summary">{{ log.summary }}</div>
        </a-timeline-item>
      </a-timeline>
    </a-card>
  </PageContainer>
</template>

<script setup lang="ts">
import { t as translate } from '../../i18n'

import { ref, onMounted } from 'vue'
import PageContainer from '../../layouts/PageContainer.vue'
import { request } from '../../api/request'

interface LogItem { ver: string; date: string; summary: string }
const logs = ref<LogItem[]>([])
const loading = ref(true)

// 更新日志改为读后端 /api/about/changelog（后端优先读本地 changelog.json，权威且随版本部署即最新）——
// 根治「前端硬编码列表卡在旧版本」。接口失败时降级用本地内置 fallback（仅精简近版，保证离线可看）。
onMounted(async () => {
  try {
    const data = await request<LogItem[]>('/api/about/changelog')
    logs.value = Array.isArray(data) && data.length ? data : _fallback
  } catch {
    logs.value = _fallback
  } finally {
    loading.value = false
  }
})

// —— 内置 fallback（接口不可用时兜底，随手保留近版；正常走接口拿全量）——
const _fallback: LogItem[] = [
  { ver: 'v1.21.141', date: '2026-08-12', get summary() { return translate('ui.m_85a46ad9e594') } },
  { ver: 'v1.21.140', date: '2026-08-12', get summary() { return translate('ui.m_eb966ba7ca11') } },
  { ver: 'v1.21.139', date: '2026-08-11', get summary() { return translate('ui.m_33fc4d1dda8f') } },
  { ver: 'v1.21.138', date: '2026-08-10', get summary() { return translate('ui.m_a6033829cb2e') } },
  { ver: 'v1.21.137', date: '2026-08-10', get summary() { return translate('ui.m_5c776bfa952b') } },
  { ver: 'v1.21.136', date: '2026-08-10', get summary() { return translate('ui.m_e5a5a97e0743') } },
  { ver: 'v1.21.133-135', date: '2026-08-10', get summary() { return translate('ui.m_c7dc466af5eb') } },
  { ver: 'v1.21.130-132', date: '2026-08-10', get summary() { return translate('ui.m_b7f6df2b8e47') } },
  { ver: 'v1.21.126-129', date: '2026-08-08', get summary() { return translate('ui.m_01e51826accd') } },
  { ver: 'v1.21.119-125', date: '2026-08-08', get summary() { return translate('ui.m_deb209cf6b16') } },
  { ver: 'v1.21.116-118', date: '2026-08-08', get summary() { return translate('ui.m_dd20433ca543') } },
  { ver: 'v1.21.115', date: '2026-08-08', get summary() { return translate('ui.m_ad92c07d4e94') } },
  { ver: 'v1.21.114', date: '2026-08-08', get summary() { return translate('ui.m_7a5e2d3c23c0') } },
  { ver: 'v1.21.113', date: '2026-08-08', get summary() { return translate('ui.m_a3a9dcc3cbeb') } },
  { ver: 'v1.21.112', date: '2026-08-08', get summary() { return translate('ui.m_d11b455ffc6c') } },
  { ver: 'v1.21.111', date: '2026-08-07', get summary() { return translate('ui.m_8697969063bc') } },
  { ver: 'v1.21.110', date: '2026-08-07', get summary() { return translate('ui.m_6f819c4693b1') } },
  { ver: 'v1.21.109', date: '2026-08-07', get summary() { return translate('ui.m_4095de479288') } },
  { ver: 'v1.21.108', date: '2026-08-07', get summary() { return translate('ui.m_eed32299ec38') } },
  { ver: 'v1.21.107', date: '2026-08-05', get summary() { return translate('ui.m_786be70424c0') } },
  { ver: 'v1.21.106', date: '2026-08-05', get summary() { return translate('ui.m_7678e0cfda3f') } },
  { ver: 'v1.21.105', date: '2026-08-05', get summary() { return translate('ui.m_a92e1f7923e8') } },
  { ver: 'v1.21.104', date: '2026-08-05', get summary() { return translate('ui.m_8a1ee4f468dc') } },
  { ver: 'v1.21.103', date: '2026-08-04', get summary() { return translate('ui.m_ea193e5121df') } },
  { ver: 'v1.21.102', date: '2026-08-02', get summary() { return translate('ui.m_d78e1dbb8b7d') } },
  { ver: 'v1.21.101', date: '2026-08-02', get summary() { return translate('ui.m_39e9c4db93a5') } },
  { ver: 'v1.21.100', date: '2026-08-02', get summary() { return translate('ui.m_0565add3a0b4') } },
  { ver: 'v1.21.99', date: '2026-08-02', get summary() { return translate('ui.m_1652071260a0') } },
  { ver: 'v1.21.98', date: '2026-08-02', get summary() { return translate('ui.m_7db8324e04a7') } },
  { ver: 'v1.21.97', date: '2026-08-02', get summary() { return translate('ui.m_17b77a6aeaac') } },
  { ver: 'v1.21.96', date: '2026-08-02', get summary() { return translate('ui.m_99427b9c1e3c') } },
  { ver: 'v1.21.95', date: '2026-08-02', get summary() { return translate('ui.m_8296a7115a94') } },
  { ver: 'v1.21.94', date: '2026-08-02', get summary() { return translate('ui.m_c98d9487d7a7') } },
  { ver: 'v1.21.93', date: '2026-08-02', get summary() { return translate('ui.m_2d46297d674b') } },
  { ver: 'v1.21.92', date: '2026-07-27', get summary() { return translate('ui.m_3c50f78f4984') } },
  { ver: 'v1.21.91', date: '2026-07-27', get summary() { return translate('ui.m_9324f51f7a59') } },
  { ver: 'v1.21.90', date: '2026-07-27', get summary() { return translate('ui.m_f27e812d10e8') } },
  { ver: 'v1.21.89', date: '2026-07-27', get summary() { return translate('ui.m_5bdb5cc3d11b') } },
  { ver: 'v1.21.88', date: '2026-07-27', get summary() { return translate('ui.m_a83fe7648d6f') } },
  { ver: 'v1.21.87', date: '2026-07-27', get summary() { return translate('ui.m_45238af63884') } },
  { ver: 'v1.21.86', date: '2026-07-27', get summary() { return translate('ui.m_cffb9f61a43f') } },
  { ver: 'v1.21.85', date: '2026-07-27', get summary() { return translate('ui.m_3f6f3a64fc8f') } },
  { ver: 'v1.21.84', date: '2026-07-27', get summary() { return translate('ui.m_bfa6f123e941') } },
  { ver: 'v1.21.83', date: '2026-07-26', get summary() { return translate('ui.m_89b4c3c173a6') } },
  { ver: 'v1.21.82', date: '2026-07-26', get summary() { return translate('ui.m_23de366710ee') } },
  { ver: 'v1.21.81', date: '2026-07-24', get summary() { return translate('ui.m_92cbba143569') } },
  { ver: 'v1.21.80', date: '2026-07-24', get summary() { return translate('ui.m_f62af8f17082') } },
  { ver: 'v1.21.79', date: '2026-07-23', get summary() { return translate('ui.m_1b3c68c584d1') } },
  { ver: 'v1.21.78', date: '2026-07-23', get summary() { return translate('ui.m_00f069c1b435') } },
  { ver: 'v1.21.77', date: '2026-07-23', get summary() { return translate('ui.m_3cdedc923e5a') } },
  { ver: 'v1.21.76', date: '2026-07-23', get summary() { return translate('ui.m_70872fb3e7d7') } },
  { ver: 'v1.21.75', date: '2026-07-21', get summary() { return translate('ui.m_34880a61b0a8') } },
  { ver: 'v1.21.74', date: '2026-07-20', get summary() { return translate('ui.m_208d6a32dc92') } },
  { ver: 'v1.21.73', date: '2026-07-20', get summary() { return translate('ui.m_60b48b5c9d95') } },
  { ver: 'v1.21.72', date: '2026-07-20', get summary() { return translate('ui.m_68c113fe9d30') } },
  { ver: 'v1.21.70', date: '2026-07-20', get summary() { return translate('ui.m_a40e09ad7c78') } },
  { ver: 'v1.21.69', date: '2026-07-20', get summary() { return translate('ui.m_bc1c16c15608') } },
  { ver: 'v1.21.68', date: '2026-07-20', get summary() { return translate('ui.m_a525cf0f1e5b') } },
  { ver: 'v1.21.67', date: '2026-07-17', get summary() { return translate('ui.m_82e4f68cedca') } },
  { ver: 'v1.21.66', date: '2026-07-17', get summary() { return translate('ui.m_7a2b3e63abea') } },
  { ver: 'v1.21.65', date: '2026-07-17', get summary() { return translate('ui.m_3681802a8247') } },
  { ver: 'v1.21.64', date: '2026-07-17', get summary() { return translate('ui.m_37207a550e98') } },
  { ver: 'v1.21.63', date: '2026-07-16', get summary() { return translate('ui.m_a17622ff5e73') } },
  { ver: 'v1.21.62', date: '2026-07-15', get summary() { return translate('ui.m_40b18ec97c8a') } },
  { ver: 'v1.21.61', date: '2026-07-15', get summary() { return translate('ui.m_ea47a9c76935') } },
  { ver: 'v1.21.60', date: '2026-07-14', get summary() { return translate('ui.m_59160f8ce794') } },
  { ver: 'v1.21.59', date: '2026-07-14', get summary() { return translate('ui.m_2c8491c9d7ba') } },
  { ver: 'v1.21.58', date: '2026-07-14', get summary() { return translate('ui.m_ef698ef07463') } },
  { ver: 'v1.21.57', date: '2026-07-14', get summary() { return translate('ui.m_0639e3f2d998') } },
  { ver: 'v1.21.56', date: '2026-07-14', get summary() { return translate('ui.m_4f1583eaf6f8') } },
  { ver: 'v1.21.55', date: '2026-07-14', get summary() { return translate('ui.m_fc16b662a1ad') } },
  { ver: 'v1.21.54', date: '2026-07-14', get summary() { return translate('ui.m_9bd0387e67e7') } },
  { ver: 'v1.21.53', date: '2026-07-14', get summary() { return translate('ui.m_306254efc636') } },
  { ver: 'v1.21.52', date: '2026-07-14', get summary() { return translate('ui.m_ddf4f8a018ed') } },
  { ver: 'v1.21.51', date: '2026-07-14', get summary() { return translate('ui.m_32fd8c158b14') } },
  { ver: 'v1.21.50', date: '2026-07-14', get summary() { return translate('ui.m_a8e9438209ec') } },
  { ver: 'v1.21.49', date: '2026-07-14', get summary() { return translate('ui.m_fea4cbdf9eb3') } },
  { ver: 'v1.21.48', date: '2026-07-14', get summary() { return translate('ui.m_888228283b81') } },
  { ver: 'v1.21.47', date: '2026-07-14', get summary() { return translate('ui.m_a028abe919e6') } },
  { ver: 'v1.21.46', date: '2026-07-13', get summary() { return translate('ui.m_cd0ec8a9282a') } },
  { ver: 'v1.21.45', date: '2026-07-13', get summary() { return translate('ui.m_befa303b0aaa') } },
  { ver: 'v1.21.44', date: '2026-07-13', get summary() { return translate('ui.m_c5fb6033ab98') } },
  { ver: 'v1.21.43', date: '2026-07-13', get summary() { return translate('ui.m_e4ae0235117c') } },
  { ver: 'v1.21.42', date: '2026-07-13', get summary() { return translate('ui.m_ed1b75fa4faf') } },
  { ver: 'v1.21.41', date: '2026-07-13', get summary() { return translate('ui.m_fcc3112258fa') } },
  { ver: 'v1.21.40', date: '2026-07-13', get summary() { return translate('ui.m_57ac12e9f13b') } },
  { ver: 'v1.21.39', date: '2026-07-13', get summary() { return translate('ui.m_c8d86e8be227') } },
  { ver: 'v1.21.38', date: '2026-07-13', get summary() { return translate('ui.m_fda05d2e9303') } },
  { ver: 'v1.21.37', date: '2026-07-13', get summary() { return translate('ui.m_708058c058d1') } },
  { ver: 'v1.21.36', date: '2026-07-13', get summary() { return translate('ui.m_143ae0644f16') } },
  { ver: 'v1.21.35', date: '2026-07-13', get summary() { return translate('ui.m_ab06c8ad4204') } },
  { ver: 'v1.21.34', date: '2026-07-13', get summary() { return translate('ui.m_c3ac9936b120') } },
  { ver: 'v1.21.33', date: '2026-07-12', get summary() { return translate('ui.m_2a92314f636a') } },
  { ver: 'v1.21.32', date: '2026-07-12', get summary() { return translate('ui.m_e3d996ac0e54') } },
  { ver: 'v1.21.31', date: '2026-07-12', get summary() { return translate('ui.m_1fa2b1922a29') } },
  { ver: 'v1.21.30', date: '2026-07-12', get summary() { return translate('ui.m_b35846560841') } },
  { ver: 'v1.21.29', date: '2026-07-08', get summary() { return translate('ui.m_26e037ee480d') } },
  { ver: 'v1.21.28', date: '2026-07-08', get summary() { return translate('ui.m_faf38349c528') } },
  { ver: 'v1.21.27', date: '2026-07-08', get summary() { return translate('ui.m_1f2b57de5110') } },
  { ver: 'v1.21.26', date: '2026-07-08', get summary() { return translate('ui.m_11a7c8cde6c6') } },
  { ver: 'v1.21.25', date: '2026-07-08', get summary() { return translate('ui.m_e9c1fd77ca17') } },
  { ver: 'v1.21.24', date: '2026-07-07', get summary() { return translate('ui.m_2d7e27741f90') } },
  { ver: 'v1.21.23', date: '2026-07-07', get summary() { return translate('ui.m_4e1fa8118d32') } },
  { ver: 'v1.21.22', date: '2026-07-07', get summary() { return translate('ui.m_779f48054658') } },
  { ver: 'v1.21.21', date: '2026-07-07', get summary() { return translate('ui.m_5f9d24f17f84') } },
  { ver: 'v1.21.20', date: '2026-07-06', get summary() { return translate('ui.m_be9154038294') } },
  { ver: 'v1.21.19', date: '2026-07-04', get summary() { return translate('ui.m_f0d6dc13f893') } },
  { ver: 'v1.21.18', date: '2026-07-02', get summary() { return translate('ui.m_aca961aee379') } },
  { ver: 'v1.21.17', date: '2026-07-02', get summary() { return translate('ui.m_b4b36847bce5') } },
  { ver: 'v1.21.16', date: '2026-07-02', get summary() { return translate('ui.m_8100c21da272') } },
  { ver: 'v1.21.15', date: '2026-07-02', get summary() { return translate('ui.m_6ee423bbb00f') } },
  { ver: 'v1.21.14', date: '2026-07-02', get summary() { return translate('ui.m_0bc29e6c2f2a') } },
  { ver: 'v1.21.13', date: '2026-07-02', get summary() { return translate('ui.m_bc02545b5c1e') } },
  { ver: 'v1.21.12', date: '2026-07-02', get summary() { return translate('ui.m_5885ee4ac4c8') } },
  { ver: 'v1.21.11', date: '2026-07-02', get summary() { return translate('ui.m_33737633b245') } },
  { ver: 'v1.21.10', date: '2026-07-02', get summary() { return translate('ui.m_50876ce21efa') } },
  { ver: 'v1.21.9', date: '2026-07-02', get summary() { return translate('ui.m_b63b1c85b239') } },
  { ver: 'v1.21.8', date: '2026-07-02', get summary() { return translate('ui.m_389ae64d7b36') } },
  { ver: 'v1.21.7', date: '2026-07-02', get summary() { return translate('ui.m_77ad64e73867') } },
  { ver: 'v1.21.6', date: '2026-07-02', get summary() { return translate('ui.m_7485b5e980cb') } },
  { ver: 'v1.21.5', date: '2026-07-01', get summary() { return translate('ui.m_7edd95d2d8a6') } },
  { ver: 'v1.21.0', date: '2026-06-30', get summary() { return translate('ui.m_21de9821e6a6') } },
  { ver: 'v1.20.0', date: '2026-06-24', get summary() { return translate('ui.m_580755c85402') } },
  { ver: 'v1.18.0', date: '2026-06-14', get summary() { return translate('ui.m_d84afd9a0e35') } },
  { ver: 'v1.10.0', date: '2026-06-07', get summary() { return translate('ui.m_534eee34a62a') } },
]
</script>

<style scoped>
.cl-timeline { margin-top: 6px; padding: 8px 4px; }
.cl-head { display: flex; align-items: center; gap: 8px; margin-bottom: 4px; }
.cl-date { color: var(--dt-muted); font-size: 12px; }
.cl-summary { color: var(--dt-text); line-height: 1.6; white-space: pre-line; }
</style>
