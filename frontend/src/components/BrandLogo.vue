<template>
  <!-- 瞭望塔 Watchtower 品牌图标（现代版 W 字标）：白色 W + 右上青色描边，深藏青圆角方底。
       图标本身已带圆角与透明外边，直接以 <img> 呈现，登录卡/侧栏/顶栏通用。 -->
  <img :src="src" :width="size" :height="size" class="brand-logo" alt="Watchtower" draggable="false" />
</template>

<script setup lang="ts">
defineProps<{ size?: number | string }>()
// public/logo.png（构建后位于站点根 /logo.png），与 favicon 同源图标
const src = '/logo.png'
</script>

<style scoped>
.brand-logo { display: block; object-fit: contain; }
</style>
