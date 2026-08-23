<template>
  <AssetCollectionTable :ctx="ctx" :columns="columns">
    <template #filters>
      <a-form-item label="站点"><a-input v-model:value="ctx.filters.site" allow-clear placeholder="站点 URL" /></a-form-item>
      <a-form-item label="标题"><a-input v-model:value="ctx.filters.title" allow-clear placeholder="标题" /></a-form-item>
      <a-form-item label="IP"><a-input v-model:value="ctx.filters.ip" allow-clear placeholder="IP" /></a-form-item>
      <a-form-item label="指纹"><a-input v-model:value="ctx.filters['finger.name']" allow-clear placeholder="指纹名" /></a-form-item>
      <a-form-item label="状态码"><a-input v-model:value="ctx.filters.status" allow-clear placeholder="如 200" /></a-form-item>
      <a-form-item label="任务ID"><a-input v-model:value="ctx.filters.task_id" allow-clear placeholder="task_id" /></a-form-item>
    </template>
    <template #bodyCell="{ column, record }">
      <template v-if="column.key === 'site'">
        <a :href="String(record.site)" target="_blank">{{ record.site }}</a>
        <a-tooltip v-if="Number(record._group_count) > 1" title="同一站点(域名+端口)的多条记录(含 http/https、不同路径、多次扫描)已合并,删除会一并删除整组">
          <a-tag color="default" style="margin-left:6px">合并 {{ record._group_count }} 条</a-tag>
        </a-tooltip>
      </template>
      <template v-else-if="column.key === 'status'"><a-tag :color="statusColor(Number(record.status))">{{ record.status || '-' }}</a-tag></template>
      <template v-else-if="column.key === 'finger'">
        <a-space wrap size="small"><a-tag v-for="f in fingers(record)" :key="f" color="geekblue">{{ f }}</a-tag></a-space>
      </template>
      <template v-else-if="column.key === 'tag'">
        <a-space wrap size="small">
          <a-tag v-for="t in tags(record)" :key="t" closable color="orange" @close="removeTag(record, t)">{{ t }}</a-tag>
          <a-tag style="cursor: pointer; border-style: dashed" @click="openTag(record)">+ 标签</a-tag>
        </a-space>
      </template>
      <template v-else-if="column.key === 'shot'">
        <a-image :src="shotUrl(record) || SHOT_PLACEHOLDER" :fallback="SHOT_PLACEHOLDER"
          :width="80" :height="48" style="object-fit: cover; border-radius: 2px" />
      </template>
      <template v-else-if="column.key === 'action'">
        <a-space size="small">
          <a-button type="link" size="small" @click="ctx.showDetail(record)">详情</a-button>
          <ConfirmAction danger title="确认删除？" @confirm="ctx.removeOne(String(record._id))">删除</ConfirmAction>
        </a-space>
      </template>
    </template>
  </AssetCollectionTable>

  <a-modal v-model:open="tagOpen" title="添加标签" @ok="submitTag">
    <a-input v-model:value="tagValue" placeholder="标签内容" />
  </a-modal>
</template>

<script setup lang="ts">
import { ref } from 'vue'
import { message } from 'ant-design-vue'
import AssetCollectionTable from '../AssetCollectionTable.vue'
import ConfirmAction from '../../../components/ConfirmAction.vue'
import { useAssetList } from '../useAssetList'
import { siteTagApi, imageUrl } from '../../../api/assets'
import type { RowRecord } from '../../../api/types'

const ctx = useAssetList('site', { site: undefined, title: undefined, ip: undefined, 'finger.name': undefined, status: undefined, task_id: undefined }, { dedup: true })
function statusColor(s: number) {
  if (s >= 200 && s < 300) return 'success'
  if (s >= 300 && s < 400) return 'blue'
  if (s >= 400 && s < 500) return 'orange'
  if (s >= 500) return 'red'
  return 'default'
}
function fingers(record: RowRecord) { return ((record.finger as { name: string }[]) || []).map(f => f.name) }
function tags(record: RowRecord) { const t = record.tag; return Array.isArray(t) ? t : (t ? [String(t)] : []) }
// screenshot 字段在新数据里已是完整相对路径 /image/{taskid}/xxx.jpg,直接拼 /api 即可;
// 旧数据若只存文件名(不以 / 开头)则走 imageUrl 兜底。修复原来重复拼 /image/{taskid} 导致全 404 的 bug。
function shotUrl(record: RowRecord) {
  const shot = record.screenshot ? String(record.screenshot) : ''
  if (!shot) return ''
  if (shot.startsWith('/')) return '/api' + shot
  if (!record.task_id) return ''
  return imageUrl(String(record.task_id), shot)
}
// 截图缺失/加载失败的占位图(内联 SVG,不依赖外部文件):灰底 + 图片图标 + “无截图”
const SHOT_PLACEHOLDER = 'data:image/svg+xml;charset=utf-8,' + encodeURIComponent(
  '<svg xmlns="http://www.w3.org/2000/svg" width="80" height="48"><rect width="80" height="48" fill="#f0f0f0"/>' +
  '<path d="M20 30l8-8 6 6 8-10 12 14H20z" fill="#d0d0d0"/><circle cx="30" cy="18" r="3" fill="#d0d0d0"/>' +
  '<text x="40" y="44" font-size="7" fill="#aaa" text-anchor="middle">无截图</text></svg>')
const columns = [
  { title: '站点', key: 'site', ellipsis: true, fixed: 'left', width: 260 },
  { title: '标题', dataIndex: 'title', key: 'title', ellipsis: true, width: 180 },
  { title: '状态', key: 'status', width: 80 },
  { title: 'Server', dataIndex: 'http_server', key: 'http_server', width: 120, ellipsis: true },
  { title: '指纹', key: 'finger', width: 200 },
  { title: '截图', key: 'shot', width: 100 },
  { title: '标签', key: 'tag', width: 180 },
  { title: '操作', key: 'action', width: 110, fixed: 'right' }
]

/* 标签操作 */
const tagOpen = ref(false)
const tagValue = ref('')
const tagTarget = ref<RowRecord>({})
function openTag(record: RowRecord) { tagTarget.value = record; tagValue.value = ''; tagOpen.value = true }
async function submitTag() {
  if (!tagValue.value) return
  try { await siteTagApi.addTag('site', String(tagTarget.value._id), tagValue.value); message.success('已添加'); tagOpen.value = false; ctx.load() }
  catch (error) { message.error(error instanceof Error ? error.message : String(error)) }
}
async function removeTag(record: RowRecord, tag: string) {
  try { await siteTagApi.deleteTag('site', String(record._id), tag); message.success('已删除'); ctx.load() }
  catch (error) { message.error(error instanceof Error ? error.message : String(error)) }
}
</script>
