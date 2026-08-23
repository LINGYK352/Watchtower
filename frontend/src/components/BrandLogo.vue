<template>
  <!-- Sentinel 专属徽标:盾(防护/加固·契合哨兵守望之名) + 竖直向下的剑(主动渗透/出洞·进攻)
       = 攻防一体,即授权安全平台的本质。克制钢蓝+银色双色,不用 AI 味渐变。 -->
  <svg :width="size" :height="size" viewBox="0 0 32 32" fill="none"
       xmlns="http://www.w3.org/2000/svg" class="brand-logo" aria-label="Sentinel">
    <!-- 盾体 -->
    <path d="M16 2.5 L26.5 6 V15.2 C26.5 21.8 21.9 27 16 29.5 C10.1 27 5.5 21.8 5.5 15.2 V6 Z"
          :fill="shield" :stroke="shieldEdge" stroke-width="1" stroke-linejoin="round"/>
    <!-- 盾内描边:精致收口 -->
    <path d="M16 5.2 L23.9 7.8 V15 C23.9 20.1 20.3 24.2 16 26.4 C11.7 24.2 8.1 20.1 8.1 15 V7.8 Z"
          fill="none" :stroke="shieldInner" stroke-width="0.8" opacity="0.55" stroke-linejoin="round"/>
    <!-- 剑身(剑尖向下,微收尖) -->
    <path d="M14.5 11 L17.5 11 L16.7 21.2 L16 23.6 L15.3 21.2 Z"
          :fill="blade" :stroke="bladeEdge" stroke-width="0.5" stroke-linejoin="round"/>
    <!-- 剑身中脊(fuller) -->
    <line x1="16" y1="11.6" x2="16" y2="20.8" :stroke="bladeEdge" stroke-width="0.5" opacity="0.5"/>
    <!-- 护手 -->
    <rect x="11.4" y="9.9" width="9.2" height="1.9" rx="0.95" :fill="fitting"/>
    <!-- 握柄 -->
    <rect x="15.05" y="6" width="1.9" height="4" :fill="fitting"/>
    <!-- 柄首 -->
    <circle cx="16" cy="5.4" r="1.35" :fill="fitting"/>
  </svg>
</template>

<script setup lang="ts">
defineProps<{ size?: number | string }>()
// 固定品牌配色(在深色侧栏/浅色登录卡上都清晰):钢蓝盾 + 银剑 + 浅钢配件
const shield = '#1c4c82'
const shieldEdge = '#0f3157'
const shieldInner = '#4d7cb0'
const blade = '#eef3f9'
const bladeEdge = '#b9c8db'
const fitting = '#9fb2c8'
</script>

<style scoped>
.brand-logo { display: block; }
</style>
