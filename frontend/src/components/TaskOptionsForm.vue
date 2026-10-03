<template>
  <a-row :gutter="16">
    <a-col :xs="24" :md="12">
      <a-form-item :label="translate('ui.m_2479560deb33')" required><a-input v-model:value="model.name" :placeholder="translate('ui.m_1f01b74c3464')" /></a-form-item>
    </a-col>
    <a-col :xs="24" :md="12">
      <a-form-item :label="translate('ui.m_f617beed33b0')" required><a-textarea v-model:value="model.target" :rows="3" :placeholder="translate('ui.m_06a4b644d6ba')" /></a-form-item>
    </a-col>
    <a-col :xs="24" :md="8"><a-form-item :label="translate('ui.m_96ddb8d6e752')"><a-select v-model:value="model.domain_brute_type" :options="dictOptions" /></a-form-item></a-col>
    <a-col :xs="24" :md="8"><a-form-item :label="translate('ui.m_fb1968400ef1')"><a-select v-model:value="model.port_scan_type" :options="portOptions" /></a-form-item></a-col>
    <a-col :xs="24" :md="8"><a-form-item :label="translate('ui.m_ccd99f22e45f')"><a-space wrap><a-switch v-model:checked="model.domain_brute" checked-children="域名爆破" un-checked-children="域名爆破" /><a-switch v-model:checked="model.port_scan" checked-children="端口扫描" un-checked-children="端口扫描" /><a-switch v-model:checked="model.site_identify" checked-children="站点识别" un-checked-children="站点识别" /></a-space></a-form-item></a-col>
    <a-col :span="24">
      <a-form-item :label="translate('ui.m_b019f2704c5b')">
        <a-space wrap>
          <a-checkbox v-model:checked="model.service_detection">{{ translate('ui.m_43eee26f6c05') }}</a-checkbox>
          <a-checkbox v-model:checked="model.os_detection">{{ translate('ui.m_b4f8fc78bbdd') }}</a-checkbox>
          <a-checkbox v-model:checked="model.site_capture">{{ translate('ui.m_c7ce7d5484c9') }}</a-checkbox>
          <a-checkbox v-model:checked="model.file_leak">{{ translate('ui.m_ddca902e3201') }}</a-checkbox>
          <a-checkbox v-model:checked="model.search_engines">{{ translate('ui.m_82cbe72ab9d9') }}</a-checkbox>
          <a-checkbox v-model:checked="model.site_spider">{{ translate('ui.m_22577abc1cef') }}</a-checkbox>
          <a-checkbox v-model:checked="model.ssl_cert">{{ translate('ui.m_dca908ed4fae') }}</a-checkbox>
          <a-checkbox v-model:checked="model.skip_scan_cdn_ip">{{ translate('ui.m_76b7f9a3e76a') }}</a-checkbox>
          <a-checkbox v-model:checked="model.nuclei_scan">nuclei</a-checkbox>
          <a-checkbox v-model:checked="model.findvhost">{{ translate('ui.m_56f768987a2a') }}</a-checkbox>
          <a-checkbox v-model:checked="model.web_info_hunter">WIH</a-checkbox>
        </a-space>
      </a-form-item>
    </a-col>
  </a-row>
</template>

<script setup lang="ts">
import { t as translate } from '../i18n'

import type { TaskCreatePayload } from '../api/task'

defineProps<{ model: TaskCreatePayload }>()

const dictOptions = [
  { get label() { return translate('ui.m_54d477436531') }, value: 'test' },
  { get label() { return translate('ui.m_fbb7cf602234') }, value: 'big' }
]
const portOptions = [
  { get label() { return translate('ui.m_e136fb559b1e') }, value: 'test' },
  { label: 'TOP 10', value: 'top10' },
  { label: 'TOP 100', value: 'top100' },
  { label: 'TOP 1000', value: 'top1000' },
  { get label() { return translate('ui.m_c0121d94d897') }, value: 'all' }
]
</script>
