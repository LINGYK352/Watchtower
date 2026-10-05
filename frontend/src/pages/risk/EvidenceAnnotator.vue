<template>
  <a-modal :open="true" :title="translate('ui.m_147c7e48f1e3')" width="1000px" :confirm-loading="saving" :ok-button-props="{ disabled: !ready || !marks.length }"
    :ok-text="translate('ui.m_c5acaaf0992f')" :cancel-text="translate('ui.m_2cd0f3be8738')" @ok="save" @cancel="$emit('cancel')">
    <a-space wrap style="margin-bottom:12px">
      <a-radio-group v-model:value="mode" button-style="solid">
        <a-radio-button value="arrow">{{ translate('ui.m_83fa01a2d780') }}</a-radio-button>
        <a-radio-button value="box">{{ translate('ui.m_2e74a84eae0e') }}</a-radio-button>
        <a-radio-button value="mask">{{ translate('ui.m_0341debcbbd0') }}</a-radio-button>
      </a-radio-group>
      <a-button :disabled="!marks.length" @click="undo">{{ translate('ui.m_926a50b98ece') }}</a-button>
      <span class="hint">{{ translate('ui.m_215c2727345a') }}</span>
    </a-space>
    <a-alert v-if="error" type="error" :message="error" />
    <div class="canvas-scroll">
      <canvas ref="canvas" :aria-label="translate('ui.m_02c7b35dbc31')" @pointerdown="start" @pointermove="move" @pointerup="finish" @pointercancel="cancelDrag" />
    </div>
  </a-modal>
</template>

<script setup lang="ts">
import { t as translate } from '../../i18n'

import { onMounted, onBeforeUnmount, ref } from 'vue'
const props = defineProps<{ src: string; saving: boolean }>()
const emit = defineEmits<{ save: [file: File]; cancel: [] }>()
type Mode = 'arrow' | 'box' | 'mask'
type Mark = { mode: Mode; x: number; y: number; toX: number; toY: number }
const canvas = ref<HTMLCanvasElement>()
const mode = ref<Mode>('arrow')
const marks = ref<Mark[]>([])
const ready = ref(false)
const error = ref('')
const source = new Image()
let drag: Mark | null = null
let disposed = false
function point(e: PointerEvent) {
  const c = canvas.value!
  const rect = c.getBoundingClientRect()
  return { x: Math.max(0, Math.min(c.width, (e.clientX - rect.left) * c.width / rect.width)),
    y: Math.max(0, Math.min(c.height, (e.clientY - rect.top) * c.height / rect.height)) }
}
function draw() {
  const c = canvas.value
  const ctx = c?.getContext('2d')
  if (!c || !ctx || !ready.value) return
  ctx.clearRect(0, 0, c.width, c.height)
  ctx.drawImage(source, 0, 0)
  const thickness = Math.max(3, Math.round(c.width / 350))
  for (const m of [...marks.value, ...(drag ? [drag] : [])]) {
    ctx.strokeStyle = '#e32636'; ctx.fillStyle = '#e32636'; ctx.lineWidth = thickness
    if (m.mode === 'mask') {
      ctx.fillStyle = '#000'; ctx.fillRect(Math.min(m.x, m.toX), Math.min(m.y, m.toY), Math.abs(m.toX - m.x), Math.abs(m.toY - m.y))
    } else if (m.mode === 'box') {
      ctx.strokeRect(m.x, m.y, m.toX - m.x, m.toY - m.y)
    } else {
      ctx.beginPath(); ctx.moveTo(m.x, m.y); ctx.lineTo(m.toX, m.toY); ctx.stroke()
      const angle = Math.atan2(m.toY - m.y, m.toX - m.x)
      const length = thickness * 5
      ctx.beginPath(); ctx.moveTo(m.toX, m.toY)
      ctx.lineTo(m.toX - length * Math.cos(angle - Math.PI / 6), m.toY - length * Math.sin(angle - Math.PI / 6))
      ctx.lineTo(m.toX - length * Math.cos(angle + Math.PI / 6), m.toY - length * Math.sin(angle + Math.PI / 6))
      ctx.closePath(); ctx.fill()
    }
  }
}
function start(e: PointerEvent) {
  if (!ready.value || props.saving || e.button !== 0) return
  const p = point(e); drag = { mode: mode.value, ...p, toX: p.x, toY: p.y }
  canvas.value!.setPointerCapture(e.pointerId)
}
function move(e: PointerEvent) {
  if (!drag) return
  const p = point(e); drag.toX = p.x; drag.toY = p.y; draw()
}
function finish(e: PointerEvent) {
  if (!drag) return
  move(e)
  if (Math.hypot(drag.toX - drag.x, drag.toY - drag.y) >= 3) marks.value.push(drag)
  drag = null; draw()
}
function cancelDrag() { drag = null; draw() }
function undo() { marks.value.pop(); draw() }
function save() {
  if (!ready.value || props.saving || !marks.value.length) return
  canvas.value?.toBlob(blob => { if (blob) emit('save', new File([blob], 'annotated.png', { type: 'image/png' })) }, 'image/png')
}
onMounted(() => {
  source.onload = () => {
    if (disposed || !canvas.value) return
    if (source.width * source.height > 40_000_000) { error.value = '截图像素过大，请分段后标注'; return }
    canvas.value.width = source.width; canvas.value.height = source.height
    ready.value = true; draw()
  }
  source.onerror = () => { error.value = '截图读取失败，原图未改变' }
  source.src = props.src
})
onBeforeUnmount(() => { disposed = true; source.onload = null; source.onerror = null })
</script>

<style scoped>
.canvas-scroll { max-height: 65vh; overflow: auto; background: #eee; }
canvas { display: block; max-width: 100%; height: auto; touch-action: none; cursor: crosshair; }
.hint { color: #777; font-size: 12px; }
</style>
