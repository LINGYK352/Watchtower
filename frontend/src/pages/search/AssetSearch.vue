<template>
  <PageContainer :title="translate('ui.m_15d01ccc18e1')" kicker="Asset Search" :description="translate('ui.m_5f31922395b0')">
    <a-tabs v-model:activeKey="active">
      <a-tab-pane v-for="t in tabs" :key="t.key" :tab="t.title" />
    </a-tabs>
    <keep-alive>
      <component :is="activeComponent" :key="active" />
    </keep-alive>
  </PageContainer>
</template>

<script setup lang="ts">
import { t as translate } from '../../i18n'

import { computed, ref } from 'vue'
import { useRoute } from 'vue-router'
import PageContainer from '../../layouts/PageContainer.vue'
import DomainTab from './collections/DomainTab.vue'
import IpTab from './collections/IpTab.vue'
import SiteTab from './collections/SiteTab.vue'
import UrlTab from './collections/UrlTab.vue'
import CertTab from './collections/CertTab.vue'
import ServiceTab from './collections/ServiceTab.vue'
import FileleakTab from './collections/FileleakTab.vue'
import WihTab from './collections/WihTab.vue'

const tabs = [
  { key: 'site', get title() { return translate('ui.m_a59fe62777ff') }, comp: SiteTab },
  { key: 'domain', get title() { return translate('ui.m_222952431147') }, comp: DomainTab },
  { key: 'ip', title: 'IP', comp: IpTab },
  { key: 'url', title: 'URL', comp: UrlTab },
  { key: 'cert', get title() { return translate('ui.m_69eb41708bcb') }, comp: CertTab },
  { key: 'service', get title() { return translate('ui.m_ec309ab207ef') }, comp: ServiceTab },
  { key: 'fileleak', get title() { return translate('ui.m_ddca902e3201') }, comp: FileleakTab },
  { key: 'wih', title: 'WIH', comp: WihTab }
]
const route = useRoute()
// 任务详情「查看」带 ?tab=domain 时定位到对应资产类型页（缺省/非法回退站点）
const initTab = String(route.query.tab || '')
const active = ref(tabs.some(t => t.key === initTab) ? initTab : 'site')
const activeComponent = computed(() => tabs.find(t => t.key === active.value)?.comp || SiteTab)
</script>
