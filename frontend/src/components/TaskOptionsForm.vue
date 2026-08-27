<template>
  <a-row :gutter="16">
    <a-col :xs="24" :md="12">
      <a-form-item label="任务名称" required><a-input v-model:value="model.name" placeholder="请输入任务名称" /></a-form-item>
    </a-col>
    <a-col :xs="24" :md="12">
      <a-form-item label="任务目标" required><a-textarea v-model:value="model.target" :rows="3" placeholder="支持域名、IP、IP段；多目标换行" /></a-form-item>
    </a-col>
    <a-col :xs="24" :md="8"><a-form-item label="域名爆破类型"><a-select v-model:value="model.domain_brute_type" :options="dictOptions" /></a-form-item></a-col>
    <a-col :xs="24" :md="8"><a-form-item label="端口扫描类型"><a-select v-model:value="model.port_scan_type" :options="portOptions" /></a-form-item></a-col>
    <a-col :xs="24" :md="8"><a-form-item label="基础能力"><a-space wrap><a-switch v-model:checked="model.domain_brute" checked-children="域名爆破" un-checked-children="域名爆破" /><a-switch v-model:checked="model.port_scan" checked-children="端口扫描" un-checked-children="端口扫描" /><a-switch v-model:checked="model.site_identify" checked-children="站点识别" un-checked-children="站点识别" /></a-space></a-form-item></a-col>
    <a-col :span="24">
      <a-form-item label="扩展选项">
        <a-space wrap>
          <a-checkbox v-model:checked="model.service_detection">服务识别</a-checkbox>
          <a-checkbox v-model:checked="model.os_detection">操作系统识别</a-checkbox>
          <a-checkbox v-model:checked="model.site_capture">站点截图</a-checkbox>
          <a-checkbox v-model:checked="model.file_leak">文件泄露</a-checkbox>
          <a-checkbox v-model:checked="model.search_engines">搜索引擎</a-checkbox>
          <a-checkbox v-model:checked="model.site_spider">站点爬虫</a-checkbox>
          <a-checkbox v-model:checked="model.ssl_cert">SSL证书</a-checkbox>
          <a-checkbox v-model:checked="model.skip_scan_cdn_ip">跳过CDN</a-checkbox>
          <a-checkbox v-model:checked="model.nuclei_scan">nuclei</a-checkbox>
          <a-checkbox v-model:checked="model.findvhost">Host碰撞</a-checkbox>
          <a-checkbox v-model:checked="model.web_info_hunter">WIH</a-checkbox>
        </a-space>
      </a-form-item>
    </a-col>
  </a-row>
</template>

<script setup lang="ts">
import type { TaskCreatePayload } from '../api/task'

defineProps<{ model: TaskCreatePayload }>()

const dictOptions = [
  { label: '测试字典', value: 'test' },
  { label: '大字典', value: 'big' }
]
const portOptions = [
  { label: '测试端口', value: 'test' },
  { label: 'TOP 10', value: 'top10' },
  { label: 'TOP 100', value: 'top100' },
  { label: 'TOP 1000', value: 'top1000' },
  { label: '全部端口', value: 'all' }
]
</script>
