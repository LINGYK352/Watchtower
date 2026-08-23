<template>
  <a-popconfirm :title="title" ok-text="确认" cancel-text="取消" @confirm="$emit('confirm')">
    <a-button :danger="danger" :type="type" :size="size"><slot /></a-button>
  </a-popconfirm>
</template>

<script setup lang="ts">
withDefaults(defineProps<{ title?: string; danger?: boolean; type?: 'link' | 'text' | 'default' | 'primary' | 'dashed'; size?: 'small' | 'middle' | 'large' }>(), {
  title: '确认执行该操作？',
  type: 'link',
  size: 'small'
})
defineEmits<{ confirm: [] }>()
</script>
