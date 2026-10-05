<template>
  <AssetCollectionTable :ctx="ctx" :columns="columns">
    <template #filters>
      <a-form-item :label="translate('ui.m_a59fe62777ff')"><a-input v-model:value="ctx.filters.site" allow-clear :placeholder="translate('ui.m_fb952476c712')" /></a-form-item>
      <a-form-item :label="translate('ui.m_c3405f8c7d9d')"><a-input v-model:value="ctx.filters.title" allow-clear :placeholder="translate('ui.m_c3405f8c7d9d')" /></a-form-item>
      <a-form-item label="IP"><a-input v-model:value="ctx.filters.ip" allow-clear placeholder="IP" /></a-form-item>
      <a-form-item :label="translate('ui.m_0d6a14a9ab25')"><a-input v-model:value="ctx.filters['finger.name']" allow-clear :placeholder="translate('ui.m_49622332014e')" /></a-form-item>
      <a-form-item :label="translate('ui.m_06f7d7341212')"><a-input v-model:value="ctx.filters.status" allow-clear :placeholder="translate('ui.m_6860be5ef3f4')" /></a-form-item>
      <a-form-item :label="translate('ui.m_aa2353039024')"><a-input v-model:value="ctx.filters.task_id" allow-clear placeholder="task_id" /></a-form-item>
    </template>
    <template #bodyCell="{ column, record }">
      <template v-if="column.key === 'site'">
        <a :href="String(record.site)" target="_blank">{{ record.site }}</a>
        <a-tooltip v-if="Number(record._group_count) > 1" :title="translate('ui.m_4550250f3e8b')">
          <a-tag color="default" style="margin-left:6px">{{ translate('ui.m_b07ece270100') }} {{ record._group_count }} {{ translate('ui.m_f004f1d84cf9') }}</a-tag>
        </a-tooltip>
      </template>
      <template v-else-if="column.key === 'status'"><a-tag :color="statusColor(Number(record.status))">{{ record.status || '-' }}</a-tag></template>
      <template v-else-if="column.key === 'finger'">
        <a-space wrap size="small"><a-tag v-for="f in fingers(record)" :key="f" color="geekblue">{{ f }}</a-tag></a-space>
      </template>
      <template v-else-if="column.key === 'tag'">
        <a-space wrap size="small">
          <a-tag v-for="t in tags(record)" :key="t" closable color="orange" @close="removeTag(record, t)">{{ t }}</a-tag>
          <a-tag style="cursor: pointer; border-style: dashed" @click="openTag(record)">{{ translate('ui.m_c239db16cbba') }}</a-tag>
        </a-space>
      </template>
      <template v-else-if="column.key === 'shot'">
        <a-tooltip v-if="!shotUrl(record) && record._shot_off" :title="translate('ui.m_7ec0a1b6336a')">
          <a-image :src="SHOT_OFF_PLACEHOLDER" :preview="false"
            :width="80" :height="48" style="object-fit: cover; border-radius: 2px" />
        </a-tooltip>
        <a-image v-else :src="shotUrl(record) || SHOT_PLACEHOLDER" :fallback="shotPlaceholder(record)"
          :width="80" :height="48" style="object-fit: cover; border-radius: 2px" />
      </template>
      <template v-else-if="column.key === 'action'">
        <a-space size="small">
          <a-button type="link" size="small" @click="ctx.showDetail(record)">{{ translate('ui.m_979a332955c8') }}</a-button>
          <ConfirmAction danger :title="translate('ui.m_7e18d0731e35')" @confirm="ctx.removeOne(String(record._id))">{{ translate('ui.m_2f9daa828907') }}</ConfirmAction>
        </a-space>
      </template>
    </template>
  </AssetCollectionTable>

  <a-modal v-model:open="tagOpen" :title="translate('ui.m_795cbff909c4')" @ok="submitTag">
    <a-input v-model:value="tagValue" :placeholder="translate('ui.m_28b0d322da84')" />
  </a-modal>
</template>

<script setup lang="ts">
import { t as translate } from '../../../i18n'

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
  translate('ui.m_ca69ed251b9d'))
// “策略未截图”占位图:该站所属任务未勾选“站点截图”(site_capture=false),截图阶段被门控跳过——
// 与“截图失败/空白”区分,免得反复误以为截图功能坏了。虚线框 + 提示文案。
const SHOT_OFF_PLACEHOLDER = 'data:image/svg+xml;charset=utf-8,' + encodeURIComponent(
  '<svg xmlns="http://www.w3.org/2000/svg" width="80" height="48"><rect width="79" height="47" x="0.5" y="0.5" ' +
  'fill="#fafafa" stroke="#e0e0e0" stroke-dasharray="3 2"/>' +
  translate('ui.m_9b7bc48cfdef') +
  translate('ui.m_556dac83524e'))
// 无截图时选占位:任务策略未开截图(_shot_off) → “策略未截图”;否则 → 通用“无截图”。
function shotPlaceholder(record: RowRecord) {
  return record._shot_off ? SHOT_OFF_PLACEHOLDER : SHOT_PLACEHOLDER
}
const columns = [
  { get title() { return translate('ui.m_a59fe62777ff') }, key: 'site', ellipsis: true, fixed: 'left', width: 260 },
  { get title() { return translate('ui.m_c3405f8c7d9d') }, dataIndex: 'title', key: 'title', ellipsis: true, width: 180 },
  { get title() { return translate('ui.m_6320b4a8722a') }, key: 'status', width: 80 },
  { title: 'Server', dataIndex: 'http_server', key: 'http_server', width: 120, ellipsis: true },
  { get title() { return translate('ui.m_0d6a14a9ab25') }, key: 'finger', width: 200 },
  { get title() { return translate('ui.m_c95dc99afe57') }, key: 'shot', width: 100 },
  { get title() { return translate('ui.m_1d0fd5f9336d') }, key: 'tag', width: 180 },
  { get title() { return translate('ui.m_ed31fbb483ee') }, key: 'action', width: 110, fixed: 'right' }
]

/* 标签操作 */
const tagOpen = ref(false)
const tagValue = ref('')
const tagTarget = ref<RowRecord>({})
function openTag(record: RowRecord) { tagTarget.value = record; tagValue.value = ''; tagOpen.value = true }
async function submitTag() {
  if (!tagValue.value) return
  try { await siteTagApi.addTag('site', String(tagTarget.value._id), tagValue.value); message.success(translate('ui.m_889839915c3f')); tagOpen.value = false; ctx.load() }
  catch (error) { message.error(error instanceof Error ? error.message : String(error)) }
}
async function removeTag(record: RowRecord, tag: string) {
  try { await siteTagApi.deleteTag('site', String(record._id), tag); message.success(translate('ui.m_077a6d37719a')); ctx.load() }
  catch (error) { message.error(error instanceof Error ? error.message : String(error)) }
}
</script>
