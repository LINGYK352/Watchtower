<template>
  <a-popconfirm :title="title" :ok-text="translate('ui.m_36f33adaf094')" :cancel-text="translate('ui.m_2cd0f3be8738')" :disabled="disabled" @confirm="$emit('confirm')">
    <a-button :danger="danger" :type="type" :size="size" :disabled="disabled"><slot /></a-button>
  </a-popconfirm>
</template>

<script setup lang="ts">
import { t as translate } from '../i18n'

withDefaults(defineProps<{ title?: string; danger?: boolean; type?: 'link' | 'text' | 'default' | 'primary' | 'dashed'; size?: 'small' | 'middle' | 'large'; disabled?: boolean }>(), {
  get title() { return translate('ui.m_c7c8c41e8108') },
  type: 'link',
  size: 'small',
  disabled: false
})
defineEmits<{ confirm: [] }>()
</script>
