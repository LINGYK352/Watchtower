<template>
  <a-popconfirm :title="title" ok-text="确认" cancel-text="取消" :disabled="disabled" @confirm="$emit('confirm')">
    <a-button :danger="danger" :type="type" :size="size" :disabled="disabled"><slot /></a-button>
  </a-popconfirm>
</template>

<script setup lang="ts">
withDefaults(defineProps<{ title?: string; danger?: boolean; type?: 'link' | 'text' | 'default' | 'primary' | 'dashed'; size?: 'small' | 'middle' | 'large'; disabled?: boolean }>(), {
  title: '确认执行该操作？',
  type: 'link',
  size: 'small',
  disabled: false
})
defineEmits<{ confirm: [] }>()
</script>
