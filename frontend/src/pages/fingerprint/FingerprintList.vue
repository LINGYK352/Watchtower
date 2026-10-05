<template>
  <PageContainer :title="translate('ui.m_3b451ca9ab06')" kicker="Fingerprint" :description="translate('ui.m_03a1449acf0d')">
    <a-result status="info" :title="translate('ui.m_007dc6d91cc2')">
      <template #subTitle>
        <div style="max-width: 640px; margin: 0 auto; text-align: left; line-height: 1.9">
          {{ translate('ui.m_27cda90f95fe') }}<b>{{ translate('ui.m_f046f2772e8d') }}</b>{{ translate('ui.m_3ed92a375c8b') }}<br />
          {{ translate('ui.m_c4462b00c2a1') }}<b>{{ translate('ui.m_b352b5d478e3') }}</b>{{ translate('ui.m_d329e1067585') }} <a @click="goIntel">{{ translate('ui.m_28d436380de4') }}</a> {{ translate('ui.m_3ecd6b4bf5ff') }}
        </div>
      </template>
      <template #extra>
        <a-button type="primary" @click="goIntel">{{ translate('ui.m_c6cea77a2359') }}</a-button>
      </template>
    </a-result>
  </PageContainer>
</template>

<script setup lang="ts">
import { t as translate } from '../../i18n'

import { useRouter } from 'vue-router'
import PageContainer from '../../layouts/PageContainer.vue'

const router = useRouter()
function goIntel() { router.push('/intel') }
</script>
