<template>
  <PageContainer title="AI 工具" kicker="AI Tools" description="AI 渗透引擎当前可调用的全部工具。AI 在渗透会话中按需自主调用,此处仅供查阅。">
    <a-card class="page-card">
      <div class="tools-head">
        <span>共 <b>{{ total }}</b> 个工具,分 {{ categories.length }} 类</span>
        <a-button size="small" @click="load" :loading="loading">刷新</a-button>
      </div>
      <a-spin :spinning="loading">
        <div v-for="cat in categories" :key="cat.name" class="cat-block">
          <a-divider orientation="left">
            <component :is="catIcon(cat.name)" style="margin-right:6px" />{{ cat.name }}
            <a-tag color="blue" style="margin-left:6px">{{ cat.tools.length }}</a-tag>
          </a-divider>
          <a-collapse ghost>
            <a-collapse-panel v-for="t in cat.tools" :key="t.name">
              <template #header>
                <component :is="catIcon(cat.name)" class="tool-ic" />
                <code class="tool-name">{{ t.name }}</code>
                <a-tag :color="t.available ? 'green' : 'default'">{{ t.available ? '可调用' : '未接入' }}</a-tag>
                <span class="tool-sum">{{ t.summary }}</span>
              </template>
              <div class="tool-full">{{ t.description }}</div>
              <a-alert v-if="!t.available && t.degraded_reason" type="warning" :message="t.degraded_reason" show-icon class="tool-alert" />
              <div v-if="t.params.length" class="tool-params">
                参数:{{ t.params.map(p => p.name + (p.required ? '*' : '')).join('、') }}
              </div>
            </a-collapse-panel>
          </a-collapse>
        </div>
      </a-spin>
    </a-card>
  </PageContainer>
</template>

<script setup lang="ts">
import { computed, onMounted, ref } from 'vue'
import { message } from 'ant-design-vue'
import {
  SearchOutlined, FileSearchOutlined, GlobalOutlined, SecurityScanOutlined,
  PartitionOutlined, NodeIndexOutlined, ToolOutlined, ApiOutlined, ClusterOutlined
} from '@ant-design/icons-vue'
import PageContainer from '../../layouts/PageContainer.vue'
import { pentestApi } from '../../api/pentest'

interface ToolParam { name: string; desc: string; required: boolean }
interface ToolItem { name: string; category: string; summary: string; description: string; params: ToolParam[];
  implemented?: boolean; available?: boolean; degraded_reason?: string }

const loading = ref(false)
const list = ref<ToolItem[]>([])
const total = ref(0)

// 与后端 TOOL_CATALOG 的 7 类功能维度对齐（ai_tools.py）
const CAT_ICON: Record<string, unknown> = {
  '资产收集': FileSearchOutlined,
  '漏洞验证': SecurityScanOutlined,
  '情报查询': SearchOutlined,
  '情报回写': PartitionOutlined,
  '带外通道': ApiOutlined,
  '浏览器': GlobalOutlined,
  '内网后渗透': ClusterOutlined,
}
// 分类展示顺序：侦察→验证→情报→带外→浏览器→后渗透（渗透工作流自然序）
const CAT_ORDER = ['资产收集', '漏洞验证', '情报查询', '情报回写', '带外通道', '浏览器', '内网后渗透']
function catIcon(name: string) { return CAT_ICON[name] || ToolOutlined }

const categories = computed(() => {
  const map = new Map<string, ToolItem[]>()
  for (const t of list.value) {
    if (!map.has(t.category)) map.set(t.category, [])
    map.get(t.category)!.push(t)
  }
  // 按 CAT_ORDER 排序，未登记的新分类排在最后（不丢）
  return Array.from(map.entries())
    .map(([name, tools]) => ({ name, tools }))
    .sort((a, b) => {
      const ia = CAT_ORDER.indexOf(a.name), ib = CAT_ORDER.indexOf(b.name)
      return (ia < 0 ? 99 : ia) - (ib < 0 ? 99 : ib)
    })
})

async function load() {
  loading.value = true
  try {
    const data = await pentestApi.tools()
    list.value = data.tools || []
    total.value = data.total || list.value.length
  } catch (e) {
    message.error(e instanceof Error ? e.message : String(e))
  } finally {
    loading.value = false
  }
}

onMounted(load)
</script>

<style scoped>
.tools-head { display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px; color: var(--dt-muted); }
.cat-block { margin-bottom: 8px; }
.tool-ic { color: #1677ff; margin-right: 8px; }
.tool-name { font-weight: 600; color: #1677ff; margin-right: 10px; }
.tool-sum { color: var(--dt-muted); font-size: 13px; }
.tool-full { color: var(--dt-text); font-size: 12px; line-height: 1.7; padding: 4px 0 4px 24px; }
.tool-params { color: var(--dt-muted); font-size: 12px; padding-left: 24px; }
.tool-alert { margin: 6px 0 6px 24px; }
</style>
