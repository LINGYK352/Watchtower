<template>
  <div v-if="visible" ref="petEl" class="deskpet" :class="{ dragging, flip: facing < 0 }"
    :style="{ left: pos.x + 'px', top: pos.y + 'px' }"
    @mousedown="onDown" @click="onClick" @dblclick="onDblClick" @contextmenu.prevent="openMenu">
    <!-- 台词气泡 -->
    <transition name="bubble">
      <div v-if="bubble" class="dp-bubble">{{ bubble }}</div>
    </transition>

    <!-- AI 对话输入框（接入 AI 后双击弹出） -->
    <transition name="bubble">
      <div v-if="chatOpen" class="dp-chat" @mousedown.stop @click.stop @dblclick.stop @contextmenu.stop.prevent>
        <input ref="chatInput" v-model="chatText" class="dp-chat-input" type="text"
          :placeholder="sending ? '思考中…' : '和鲸鱼娘说点什么~'" :disabled="sending"
          @keyup.enter="sendChat" maxlength="500" />
        <button class="dp-chat-send" :disabled="sending || !chatText.trim()" @click="sendChat">发送</button>
        <button class="dp-chat-close" title="关闭" @click="closeChat">×</button>
      </div>
    </transition>

    <!-- 右键设置菜单 -->
    <transition name="bubble">
      <div v-if="menuOpen" class="dp-menu" :style="menuStyle"
        @mousedown.stop @click.stop @dblclick.stop @contextmenu.stop.prevent>
        <div class="dp-menu-item" @click="onMenuChat">
          <span class="dp-menu-ico">💬</span>和 AI 对话
          <span class="dp-menu-tag">{{ aiEnabled ? '双击也可' : '需先接入' }}</span>
        </div>
        <div class="dp-menu-item" @click="toggleAi">
          <span class="dp-menu-ico">{{ aiEnabled ? '✓' : '○' }}</span>接入 AI
        </div>
        <div class="dp-menu-item" @click="toggleCalm">
          <span class="dp-menu-ico">{{ calm ? '✓' : '○' }}</span>安静模式<span class="dp-menu-tag">少走动</span>
        </div>
        <div class="dp-menu-sep"></div>
        <div class="dp-menu-item" @click="onMenuHide"><span class="dp-menu-ico">🙈</span>隐藏桌宠</div>
      </div>
    </transition>

    <!-- DeepSeek娘（女仆装·白发蓝眼·头顶小蓝鲸）—— state 驱动动作 -->
    <!-- 立绘：优先 PNG 精灵图（AI 生成），加载失败回退旧手绘 SVG -->
    <div class="dp-body" :class="'st-' + state">
      <img v-if="!svgFallback" class="dp-sprite" :src="spriteSrc" alt="DeepSeek 娘（女仆装）"
        draggable="false" @error="onSpriteError" />
      <svg v-else viewBox="0 0 120 130" width="88" height="95" aria-label="DeepSeek 娘（女仆装）">
        <defs>
          <linearGradient id="dpDress" x1="0" y1="0" x2="0" y2="1">
            <stop offset="0" stop-color="#4a72e8" /><stop offset="1" stop-color="#3355c4" />
          </linearGradient>
          <linearGradient id="dpHair" x1="0" y1="0" x2="0" y2="1">
            <stop offset="0" stop-color="#f2f6ff" /><stop offset="1" stop-color="#dfe8fb" />
          </linearGradient>
          <linearGradient id="dpWhale" x1="0" y1="0" x2="0" y2="1">
            <stop offset="0" stop-color="#5b8cff" /><stop offset="1" stop-color="#3f6ae0" />
          </linearGradient>
        </defs>

        <!-- 身体：蓝白女仆裙（梯形裙 + 白围裙） -->
        <path d="M42 96 Q60 88 78 96 L86 122 Q60 130 34 122 Z" fill="url(#dpDress)" />
        <path d="M52 96 L68 96 L72 122 Q60 126 48 122 Z" fill="#f4f8ff" />       <!-- 白围裙 -->
        <rect x="47" y="92" width="26" height="6" rx="3" fill="#eef3ff" />       <!-- 围裙胸挡 -->
        <!-- 两只小手 -->
        <circle class="dp-hand dp-hand-l" cx="38" cy="104" r="6" fill="#ffe0c4" />
        <circle class="dp-hand dp-hand-r" cx="82" cy="104" r="6" fill="#ffe0c4" />

        <!-- 脸（圆脸） -->
        <circle cx="60" cy="66" r="30" fill="#fff2e4" />
        <!-- 头发：刘海 + 两侧长发 -->
        <path d="M30 62 Q28 30 60 28 Q92 30 90 62 Q86 44 74 42 Q80 52 68 48 Q72 40 60 40 Q48 40 52 48 Q40 52 46 42 Q34 44 30 62 Z" fill="url(#dpHair)" />
        <path class="dp-hair-l" d="M30 60 Q22 78 30 96 Q36 82 34 62 Z" fill="url(#dpHair)" />
        <path class="dp-hair-r" d="M90 60 Q98 78 90 96 Q84 82 86 62 Z" fill="url(#dpHair)" />
        <!-- 蓝色挑染发缕 -->
        <path d="M46 42 Q44 60 48 74 Q50 60 50 44 Z" fill="#7aa2ff" opacity="0.8" />

        <!-- 女仆头饰（白蕾丝发带） -->
        <path d="M40 40 Q60 30 80 40 L80 46 Q60 38 40 46 Z" fill="#ffffff" />
        <rect x="46" y="34" width="28" height="7" rx="3" fill="#f0f4ff" />

        <!-- 头顶小蓝鲸（DeepSeek 标志） -->
        <g class="dp-whale">
          <ellipse cx="60" cy="26" rx="13" ry="9" fill="url(#dpWhale)" />
          <path d="M49 26 Q44 22 45 30 Z" fill="#3f6ae0" />          <!-- 鲸尾 -->
          <circle cx="64" cy="24" r="1.6" fill="#fff" />               <!-- 鲸眼 -->
          <path class="dp-spout" d="M60 17 Q59 12 61 10" stroke="#8fb4ff" stroke-width="2" fill="none" stroke-linecap="round" />
        </g>

        <!-- 腮红 -->
        <ellipse cx="44" cy="72" rx="5.5" ry="3.5" fill="#ff9fb2" opacity="0.7" />
        <ellipse cx="76" cy="72" rx="5.5" ry="3.5" fill="#ff9fb2" opacity="0.7" />
        <!-- 大眼（蓝瞳） -->
        <g class="dp-eyes">
          <ellipse cx="50" cy="66" rx="6" ry="8" fill="#fff" />
          <ellipse cx="70" cy="66" rx="6" ry="8" fill="#fff" />
          <circle cx="50" cy="67" r="5" fill="#3f6ae0" /><circle cx="70" cy="67" r="5" fill="#3f6ae0" />
          <circle cx="50" cy="67" r="2.4" fill="#12224a" /><circle cx="70" cy="67" r="2.4" fill="#12224a" />
          <circle cx="52" cy="64" r="1.6" fill="#fff" /><circle cx="72" cy="64" r="1.6" fill="#fff" />
        </g>
        <!-- 嘴（微笑） -->
        <path class="dp-mouth" d="M55 78 Q60 83 65 78" stroke="#c7708a" stroke-width="2"
          fill="none" stroke-linecap="round" />
      </svg>
    </div>
  </div>
  <!-- 被藏起来时的小唤回按钮 -->
  <button v-else class="dp-recall" title="召回鲸鱼娘" @click="recall">🐳</button>
</template>

<script setup lang="ts">
import { ref, reactive, computed, nextTick, onMounted, onUnmounted } from 'vue'
import { mascotChat, type MascotMsg } from '../api/mascot'

const PET = 104                                 // 桌宠尺寸（与 .deskpet/.dp-body 宽度一致）
// 默认隐藏：仅当用户显式召回过（deskpet_shown==='1'）才显示；新用户/未召回一律藏为角落小按钮
const visible = ref(localStorage.getItem('deskpet_shown') === '1')
const petEl = ref<HTMLElement | null>(null)
const pos = reactive({ x: 120, y: 200 })
const target = reactive({ x: 120, y: 200 })
const facing = ref(1)                           // 朝向：1右 -1左（flip）
const state = ref<'idle' | 'swim' | 'happy' | 'jump' | 'sleep'>('idle')
const bubble = ref('')
const dragging = ref(false)

// —— 设置（localStorage 持久化） ——
const aiEnabled = ref(localStorage.getItem('deskpet_ai_enabled') === '1')   // 接入 AI
const calm = ref(localStorage.getItem('deskpet_calm') === '1')              // 安静模式（少走动）

// —— 右键菜单 ——
const menuOpen = ref(false)
const menuStyle = reactive<{ left: string; top: string }>({ left: '0px', top: '0px' })

// —— AI 对话 ——
const chatOpen = ref(false)
const chatText = ref('')
const chatInput = ref<HTMLInputElement | null>(null)
const sending = ref(false)
const history = ref<MascotMsg[]>([])

// —— 立绘精灵图（透明 PNG，放在 public/mascot/） ——
// state → 精灵图名。待机时偶发“特写”（work/coding/laptop/think）由 feature 控制；跳跃有 jump/cheer 两姿势
const SPRITE: Record<string, string> = {
  idle: 'normal', swim: 'normal', happy: 'happy', jump: 'jump', sleep: 'sleep',
}
// 待机偶发特写：图名 + 对应台词（呼应安全平台“巡逻/分析/查情报/思考”）
const IDLE_FEATURES: { name: string; line: string }[] = [
  { name: 'work',   line: '本鲸巡逻中…有没有漏洞露头？🔍' },
  { name: 'coding', line: '敲代码分析中…让本鲸看看这段逻辑~💻' },
  { name: 'laptop', line: '查到有意思的情报啦！✨' },
  { name: 'think',  line: '唔…这里怎么有点可疑呢？🤔' },
]
const feature = ref('')                         // idle 时的特写图名（''=无特写，显示 normal）
const jumpVariant = ref('jump')                 // 跳跃姿势：'jump' 或 'cheer'（握拳腾空），每次随机
// 某张图缺失时只回落到 normal（不整体退 SVG）；连 normal 都加载失败才退旧手绘 SVG
const missing = reactive<Record<string, boolean>>({})
const svgFallback = ref(false)
const spriteName = computed(() => {
  if (state.value === 'idle' && feature.value) return feature.value
  if (state.value === 'jump') return jumpVariant.value
  return SPRITE[state.value] || 'normal'
})
const spriteSrc = computed(() => {
  const n = spriteName.value
  return `/mascot/${missing[n] ? 'normal' : n}.png`
})
function onSpriteError() {
  const n = spriteName.value
  if (n === 'normal') { svgFallback.value = true }   // normal 都没有 → 退回手绘 SVG
  else { missing[n] = true }                         // 该表情缺失 → 以后一律用 normal
}

// —— 可爱台词 ——
const IDLE_LINES = ['唔…在看什么呢~', '要一起找漏洞吗？🐟', '本鲸在此巡逻！', '摸鱼中…啊不，巡查中！',
  '发现新资产啦？', 'DeepSeek 鲸鱼娘为你护航~', '累了就点点我吧', '咕噜咕噜~']
const CLICK_LINES = ['嘿嘿，被你抓到啦！', '呀！别戳我腮帮子~', '要开始渗透了吗？💠', '本鲸最可爱！', '摸摸头也是可以的~']
const bubbleTimer = ref<number | undefined>()
function say(text: string, ms = 2600) {
  bubble.value = text
  if (bubbleTimer.value) clearInterval(bubbleTimer.value)
  bubbleTimer.value = window.setTimeout(() => { bubble.value = '' }, ms)
}
// AI 回复气泡时长：随字数动态延长——基础 4s；超过 30 字的部分每字 +0.1s，上限 30s
function replyDuration(text: string) {
  const base = 4000
  const extra = Math.max(0, text.length - 30) * 100
  return Math.min(30000, base + extra)
}

// —— 边界 ——
function bounds() {
  return { w: window.innerWidth - PET, h: window.innerHeight - PET }
}
function pickTarget() {
  const b = bounds()
  target.x = Math.random() * Math.max(60, b.w)
  target.y = 80 + Math.random() * Math.max(60, b.h - 120)
}

// —— 主循环：朝目标游动 ——
let raf = 0
let lastActed = Date.now()
// 对话/菜单打开或安静模式拖拽时，桌宠不主动游走（专心陪聊，别乱跑）
function movePaused() {
  return dragging.value || chatOpen.value || menuOpen.value
}
function tick() {
  if (!movePaused() && state.value !== 'sleep') {
    const dx = target.x - pos.x
    const dy = target.y - pos.y
    const dist = Math.hypot(dx, dy)
    if (dist > 4) {
      const sp = Math.min(0.4, dist * 0.04) + 0.1     // 缓动速度（再放慢，慢悠悠散步不乱窜）
      pos.x += (dx / dist) * sp
      pos.y += (dy / dist) * sp
      if (Math.abs(dx) > 2) facing.value = dx > 0 ? 1 : -1
      if (state.value !== 'happy' && state.value !== 'jump') state.value = 'swim'
    } else if (state.value === 'swim') {
      state.value = 'idle'
    }
  }
  raf = requestAnimationFrame(tick)
}

// —— 行为调度：闲时随机换目标 / 冒台词 / 偶尔跳一下（降频，避免频繁乱窜） ——
let behaveTimer = 0
function behave() {
  if (movePaused()) return
  const now = Date.now()
  feature.value = ''                             // 每轮先复位待机特写
  const r = Math.random()
  // 安静模式：几乎不主动游走，只偶尔待机/冒句台词
  if (calm.value) {
    if (r < 0.25) say(IDLE_LINES[Math.floor(Math.random() * IDLE_LINES.length)])
    else state.value = 'idle'
    lastActed = now
    return
  }
  if (r < 0.18) {
    pickTarget()                                // 游到新位置（概率大幅降低）
  } else if (r < 0.44) {
    say(IDLE_LINES[Math.floor(Math.random() * IDLE_LINES.length)])
  } else if (r < 0.58) {
    doJump()                                    // 蹦一下（jump/cheer 随机）
  } else if (r < 0.86) {
    // 原地特写：巡逻找漏洞 / 敲代码 / 查情报 / 思考（随机一种，配对应台词）
    const f = IDLE_FEATURES[Math.floor(Math.random() * IDLE_FEATURES.length)]
    state.value = 'idle'
    feature.value = f.name
    say(f.line)
  } else {
    state.value = 'idle'
  }
  lastActed = now
}

function doJump() {
  jumpVariant.value = Math.random() < 0.5 ? 'jump' : 'cheer'   // 两种腾空姿势随机
  state.value = 'jump'
  setTimeout(() => { if (state.value === 'jump') state.value = 'idle' }, 700)
}

// —— 交互：点击 ——
let downPos = { x: 0, y: 0 }; let moved = false
function onClick() {
  if (moved) return                             // 拖拽不算点击
  state.value = 'happy'
  say(CLICK_LINES[Math.floor(Math.random() * CLICK_LINES.length)])
  doJump()
  setTimeout(() => { if (state.value === 'happy') state.value = 'idle' }, 900)
}

// —— 交互：拖拽 ——
function onDown(e: MouseEvent) {
  if (e.button !== 0) return                    // 仅左键拖拽（右键留给上下文菜单）
  if (menuOpen.value) closeMenu()               // 开始拖动前先收起菜单
  dragging.value = true; moved = false
  downPos = { x: e.clientX - pos.x, y: e.clientY - pos.y }
  window.addEventListener('mousemove', onMove)
  window.addEventListener('mouseup', onUp)
  e.preventDefault()
}
function onMove(e: MouseEvent) {
  const nx = e.clientX - downPos.x
  const ny = e.clientY - downPos.y
  if (Math.abs(nx - pos.x) + Math.abs(ny - pos.y) > 3) moved = true
  const b = bounds()
  pos.x = Math.max(0, Math.min(b.w, nx))
  pos.y = Math.max(0, Math.min(b.h, ny))
  target.x = pos.x; target.y = pos.y
}
function onUp() {
  dragging.value = false
  window.removeEventListener('mousemove', onMove)
  window.removeEventListener('mouseup', onUp)
  if (moved) { say('哇~被拎起来了！'); state.value = 'idle' }
}

// 隐藏（藏进角落小按钮，入口挪到右键菜单）；召回状态用正向标记 deskpet_shown 持久化
function hide() { visible.value = false; localStorage.setItem('deskpet_shown', '0') }
function recall() { visible.value = true; localStorage.setItem('deskpet_shown', '1'); pos.x = 120; pos.y = 200; pickTarget() }

// —— 右键设置菜单 ——
function openMenu(e: MouseEvent) {
  // 菜单相对桌宠定位：贴在桌宠右侧偏上；靠右边界则翻到左侧
  const nearRight = pos.x > window.innerWidth - 240
  menuStyle.left = nearRight ? '-150px' : `${PET + 6}px`
  menuStyle.top = '0px'
  menuOpen.value = true
}
function closeMenu() { menuOpen.value = false }
function toggleAi() {
  aiEnabled.value = !aiEnabled.value
  localStorage.setItem('deskpet_ai_enabled', aiEnabled.value ? '1' : '0')
  say(aiEnabled.value ? '已接入 AI，双击我就能聊天啦~💠' : '已断开 AI 连接~')
  closeMenu()
}
function toggleCalm() {
  calm.value = !calm.value
  localStorage.setItem('deskpet_calm', calm.value ? '1' : '0')
  say(calm.value ? '进入安静模式，我少走动啦~' : '恢复活力！本鲸继续巡逻~')
  closeMenu()
}
function onMenuHide() { closeMenu(); hide() }
function onMenuChat() { closeMenu(); openChat() }

// —— 双击：接入 AI 后开对话，否则提示 ——
function onDblClick() {
  if (aiEnabled.value) openChat()
  else say('想和我聊天？右键选「接入 AI」先~')
}

// —— AI 对话 ——
function openChat() {
  if (!aiEnabled.value) { say('先右键「接入 AI」哦~'); return }
  chatOpen.value = true
  state.value = 'idle'
  nextTick(() => chatInput.value?.focus())
}
function closeChat() { chatOpen.value = false; chatText.value = '' }
async function sendChat() {
  const text = chatText.value.trim()
  if (!text || sending.value) return
  closeChat()                                   // 发送后立即收起输入栏，回复走气泡显示
  sending.value = true
  say('让本鲸想想…🐟', 60000)
  const hist = history.value.slice(-8)
  try {
    const res = await mascotChat(text, hist)
    const reply = (res?.reply || '').trim() || '（本鲸一时语塞…）'
    history.value.push({ role: 'user', content: text }, { role: 'assistant', content: reply })
    if (history.value.length > 16) history.value.splice(0, history.value.length - 16)
    state.value = 'happy'
    say(reply, replyDuration(reply))
    setTimeout(() => { if (state.value === 'happy') state.value = 'idle' }, 1200)
  } catch (e: any) {
    say('呜…我出错了：' + (e?.message || '调用失败'), 5000)
  } finally {
    sending.value = false
  }
}

// 点桌宠以外任意处 / Esc：关右键菜单（不关对话框，对话框有自己的关闭按钮）
function onDocDown() { if (menuOpen.value) closeMenu() }
function onKeydown(e: KeyboardEvent) {
  if (e.key === 'Escape') { closeMenu(); if (chatOpen.value) closeChat() }
}
onMounted(() => {
  pos.x = 120; pos.y = window.innerHeight - 220
  pickTarget()
  raf = requestAnimationFrame(tick)
  behaveTimer = window.setInterval(behave, 12000)   // 放慢行为节奏（6s → 12s，别频繁乱窜）
  document.addEventListener('mousedown', onDocDown)
  window.addEventListener('keydown', onKeydown)
  window.addEventListener('resize', clampInside)
})
function clampInside() {
  const b = bounds()
  pos.x = Math.max(0, Math.min(b.w, pos.x))
  pos.y = Math.max(0, Math.min(b.h, pos.y))
}
onUnmounted(() => {
  cancelAnimationFrame(raf)
  if (behaveTimer) clearInterval(behaveTimer)
  if (bubbleTimer.value) clearTimeout(bubbleTimer.value)
  window.removeEventListener('mousemove', onMove)
  window.removeEventListener('mouseup', onUp)
  document.removeEventListener('mousedown', onDocDown)
  window.removeEventListener('keydown', onKeydown)
  window.removeEventListener('resize', clampInside)
})

defineExpose({ hide, recall })
</script>

<style scoped>
.deskpet {
  position: fixed; z-index: 9998; width: 104px; height: 118px;
  cursor: grab; user-select: none; -webkit-user-select: none; touch-action: none;
  filter: drop-shadow(0 6px 10px rgba(63,106,224,.35));
}
.deskpet.dragging { cursor: grabbing; }
.deskpet.flip .dp-body { transform: scaleX(-1); }   /* 朝向翻转 */

.dp-body { width: 104px; height: 118px; transition: transform .12s; transform-origin: 50% 85%; }
/* PNG 立绘：保持比例填入 body 盒，禁止浏览器默认拖影/选中 */
.dp-sprite {
  width: 100%; height: 100%; object-fit: contain; object-position: 50% 100%;
  display: block; pointer-events: none; -webkit-user-drag: none; user-select: none;
}

/* 台词气泡 */
.dp-bubble {
  position: absolute; bottom: 118px; left: 50%; transform: translateX(-50%);
  white-space: nowrap; background: #fff; color: #2b3a55; font-size: 12px;
  padding: 6px 10px; border-radius: 12px; box-shadow: 0 3px 8px rgba(0,0,0,.15);
  border: 1px solid rgba(91,140,255,.3);
}
.dp-bubble::after {
  content: ''; position: absolute; top: 100%; left: 50%; transform: translateX(-50%);
  border: 6px solid transparent; border-top-color: #fff;
}
.bubble-enter-active, .bubble-leave-active { transition: opacity .2s, transform .2s; }
.bubble-enter-from, .bubble-leave-to { opacity: 0; transform: translateX(-50%) translateY(4px); }

/* —— 动作 —— */
/* 待机：轻微上下浮动 + 呼吸 */
.st-idle { animation: dp-float 3s ease-in-out infinite; }
@keyframes dp-float { 0%,100% { transform: translateY(0) } 50% { transform: translateY(-4px) } }

/* 游动：身体左右轻晃（PNG 立绘用小幅旋转，避免生硬） */
.st-swim { animation: dp-swim .6s ease-in-out infinite; }
@keyframes dp-swim { 0%,100% { transform: rotate(-2deg) } 50% { transform: rotate(2deg) } }

/* 开心：轻快上下弹跳（PNG 立绘不做挤压变形，改用位移+微缩放） */
.st-happy { animation: dp-happy .45s ease-in-out infinite; }
@keyframes dp-happy { 0%,100% { transform: translateY(0) scale(1) } 50% { transform: translateY(-6px) scale(1.04) } }

/* 跳：蹦一下 */
.st-jump { animation: dp-jump .7s ease-out; }
@keyframes dp-jump { 0% { transform: translateY(0) } 30% { transform: translateY(-26px) } 55% { transform: translateY(0) } 70% { transform: translateY(-10px) } 100% { transform: translateY(0) } }

/* 睡：略微下沉 */
.st-sleep { transform: translateY(4px); opacity: .85; }

/* 头顶小蓝鲸：轻轻上下浮 */
.dp-whale { transform-origin: 60px 26px; animation: dp-whalebob 2.4s ease-in-out infinite; }
@keyframes dp-whalebob { 0%,100% { transform: translateY(0) rotate(-2deg) } 50% { transform: translateY(-2px) rotate(2deg) } }
/* 鲸鱼喷水口一闪一闪 */
.dp-spout { animation: dp-spout 2s ease-in-out infinite; }
@keyframes dp-spout { 0%,60%,100% { opacity: .3 } 30% { opacity: 1 } }

/* 两侧长发随身摆 */
.dp-hair-l { transform-origin: 30px 60px; animation: dp-hairsway 2.8s ease-in-out infinite; }
.dp-hair-r { transform-origin: 90px 60px; animation: dp-hairsway 2.8s ease-in-out infinite reverse; }
@keyframes dp-hairsway { 0%,100% { transform: rotate(-2deg) } 50% { transform: rotate(3deg) } }

/* 小手：开心时挥动 */
.st-happy .dp-hand-l { animation: dp-wave .3s ease-in-out infinite; }
.st-happy .dp-hand-r { animation: dp-wave .3s ease-in-out infinite reverse; }
@keyframes dp-wave { 0%,100% { transform: translateY(0) } 50% { transform: translateY(-5px) } }

/* 眨眼 */
.dp-eyes { transform-origin: 60px 66px; animation: dp-blink 4s infinite; }
@keyframes dp-blink { 0%,92%,100% { transform: scaleY(1) } 96% { transform: scaleY(.1) } }

/* 藏起后的召回小按钮 */
.dp-recall {
  position: fixed; right: 14px; bottom: 14px; z-index: 9998;
  width: 40px; height: 40px; border-radius: 50%; border: none; cursor: pointer;
  background: linear-gradient(135deg,#5b8cff,#3f6ae0); color: #fff; font-size: 20px;
  box-shadow: 0 4px 10px rgba(63,106,224,.4);
}
.dp-recall:hover { transform: scale(1.08); }

/* —— 右键设置菜单 —— */
.dp-menu {
  position: absolute; z-index: 10000; min-width: 148px;
  background: var(--dt-card, #1f2a44); color: var(--dt-text, #eef3ff);
  border: 1px solid rgba(91,140,255,.35); border-radius: 10px;
  box-shadow: 0 8px 24px rgba(0,0,0,.35); padding: 5px; font-size: 13px;
  cursor: default;
}
.dp-menu-item {
  display: flex; align-items: center; gap: 7px;
  padding: 7px 9px; border-radius: 7px; white-space: nowrap; cursor: pointer;
}
.dp-menu-item:hover { background: rgba(91,140,255,.18); }
.dp-menu-ico { width: 16px; text-align: center; opacity: .9; }
.dp-menu-tag { margin-left: auto; font-size: 11px; opacity: .55; padding-left: 8px; }
.dp-menu-sep { height: 1px; margin: 4px 6px; background: rgba(255,255,255,.12); }

/* —— AI 对话输入框 —— */
.dp-chat {
  position: absolute; bottom: 122px; left: 50%; transform: translateX(-50%);
  z-index: 10000; display: flex; align-items: center; gap: 6px;
  background: #fff; border: 1px solid rgba(91,140,255,.35); border-radius: 20px;
  padding: 5px 6px 5px 12px; box-shadow: 0 6px 18px rgba(0,0,0,.2); cursor: default;
}
.dp-chat-input {
  width: 190px; border: none; outline: none; background: transparent;
  color: #2b3a55; font-size: 13px;
}
.dp-chat-input::placeholder { color: #9aa7c2; }
.dp-chat-send {
  border: none; cursor: pointer; color: #fff; font-size: 12px;
  padding: 5px 12px; border-radius: 14px;
  background: linear-gradient(135deg,#5b8cff,#3f6ae0);
}
.dp-chat-send:disabled { opacity: .5; cursor: not-allowed; }
.dp-chat-close {
  border: none; background: transparent; cursor: pointer; color: #9aa7c2;
  font-size: 18px; line-height: 1; padding: 0 4px;
}
.dp-chat-close:hover { color: #2b3a55; }
</style>


