<template>
  <a-modal :open="true" title="截图标注" width="1000px" :confirm-loading="saving" :ok-button-props="{ disabled: !ready || !marks.length }"
    ok-text="保存标注副本" cancel-text="取消" @ok="save" @cancel="$emit('cancel')">
    <a-space wrap style="margin-bottom:12px">
      <a-radio-group v-model:value="mode" button-style="solid">
        <a-radio-button value="arrow">箭头</a-radio-button>
        <a-radio-button value="box">红框</a-radio-button>
        <a-radio-button value="mask">遮盖脱敏</a-radio-button>
      </a-radio-group>
      <a-button :disabled="!marks.length" @click="undo">撤销</a-button>
      <span class="hint">拖动绘制；保存后替换本报告的图片引用，原图保留。</span>
    </a-space>
    <a-alert v-if="error" type="error" :message="error" />
    <div class="canvas-scroll">
      <canvas ref="canvas" aria-label="截图标注画布" @pointerdown="start" @pointermove="move" @pointerup="finish" @pointercancel="cancelDrag" />
    </div>
  </a-modal>
</template>

<script setup lang="ts">
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
