<template>
  <PageContainer title="资产检索" kicker="Asset Search" description="按资产类型检索任务发现结果，每类资产提供专属字段、查询条件与导出。">
    <a-tabs v-model:activeKey="active">
      <a-tab-pane v-for="t in tabs" :key="t.key" :tab="t.title" />
    </a-tabs>
    <keep-alive>
      <component :is="activeComponent" :key="active" />
    </keep-alive>
  </PageContainer>
</template>

<script setup lang="ts">
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
  { key: 'site', title: '站点', comp: SiteTab },
  { key: 'domain', title: '域名', comp: DomainTab },
  { key: 'ip', title: 'IP', comp: IpTab },
  { key: 'url', title: 'URL', comp: UrlTab },
  { key: 'cert', title: '证书', comp: CertTab },
  { key: 'service', title: '服务', comp: ServiceTab },
  { key: 'fileleak', title: '文件泄露', comp: FileleakTab },
  { key: 'wih', title: 'WIH', comp: WihTab }
]
const route = useRoute()
// 任务详情「查看」带 ?tab=domain 时定位到对应资产类型页（缺省/非法回退站点）
const initTab = String(route.query.tab || '')
const active = ref(tabs.some(t => t.key === initTab) ? initTab : 'site')
const activeComponent = computed(() => tabs.find(t => t.key === active.value)?.comp || SiteTab)
</script>
