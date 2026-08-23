<template>
  <PageContainer title="指纹管理" kicker="Fingerprint" description="自定义 Web 指纹规则库（开发中）。">
    <a-result status="info" title="指纹管理 · 功能开发中">
      <template #subTitle>
        <div style="max-width: 640px; margin: 0 auto; text-align: left; line-height: 1.9">
          手动指纹规则库的<b>识别接入</b>正在开发中（规则暂不参与扫描识别），本功能已冻结。<br />
          哨兵扫描<b>自主学习</b>的指纹（httpx 识别 + AI 渗透确认纠错后沉淀到系统身份）已在运行，
          可在 <a @click="goIntel">情报中心 → 系统知识</a> 查看、检索、按指纹反查资产。
        </div>
      </template>
      <template #extra>
        <a-button type="primary" @click="goIntel">前往情报中心</a-button>
      </template>
    </a-result>
  </PageContainer>
</template>

<script setup lang="ts">
import { useRouter } from 'vue-router'
import PageContainer from '../../layouts/PageContainer.vue'

const router = useRouter()
function goIntel() { router.push('/intel') }
</script>
