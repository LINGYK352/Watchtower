<template>
  <a-modal :open="open" :title="t('requestApproval.redteamTitle')" :mask-closable="false" :footer="null" width="540px" @cancel="$emit('cancel')" data-testid="redteam-notice">
    <p>{{ t('requestApproval.redteamPurpose') }}</p>
    <p>{{ t('requestApproval.redteamImpact') }}</p>
    <a-alert type="warning" show-icon :message="t('requestApproval.redteamRecommend')" :description="t('requestApproval.redteamReview')" />
    <div class="notice-actions"><a-button @click="$emit('cancel')">{{ t('requestApproval.cancel') }}</a-button><a-button type="primary" @click="$emit('confirm')" data-testid="redteam-understood">{{ t('requestApproval.understood') }}</a-button></div>
  </a-modal>
</template>
<script setup lang="ts">
import { t } from '../i18n'
defineProps<{ open: boolean }>()
defineEmits<{ confirm: []; cancel: [] }>()
</script>
<style scoped>
p{line-height:1.7}.notice-actions{display:flex;justify-content:flex-end;gap:12px;margin-top:20px}
</style>
