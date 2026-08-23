<template>
  <a-layout class="app-shell">
    <a-layout-sider class="app-sider" :width="224" :collapsed-width="64" v-model:collapsed="collapsed" collapsible :trigger="null">
      <div class="brand" @click="router.push('/')">
        <div class="brand-mark"><BrandLogo :size="26" /></div>
        <div v-if="!collapsed" class="brand-text">
          <strong>{{ APP_NAME }}</strong>
          <span>{{ APP_NAME_EN }}</span>
        </div>
      </div>
      <div class="sider-menu">
        <a-menu theme="dark" mode="inline" :selectedKeys="selectedKeys" :openKeys="openKeys" @openChange="onOpenChange" @click="onMenuClick">
          <a-sub-menu v-for="group in visibleGroups" :key="group.key">
            <template #title><component :is="icons[group.icon]" /><span>{{ group.title }}</span></template>
            <a-menu-item v-for="item in group.children" :key="item.key">
              <component :is="icons[item.icon]" />
              <span>{{ item.title }}</span>
            </a-menu-item>
          </a-sub-menu>
        </a-menu>
      </div>
    </a-layout-sider>
    <a-layout>
      <a-layout-header class="app-header">
        <div class="header-left">
          <MenuFoldOutlined v-if="!collapsed" class="trigger" @click="collapsed = true" />
          <MenuUnfoldOutlined v-else class="trigger" @click="collapsed = false" />
          <div>
            <a-breadcrumb :items="breadcrumbItems" />
            <span class="page-title">{{ pageTitle }}</span>
          </div>
        </div>
        <a-space :size="16">
          <a-tag v-if="licenseDays !== null && licenseDays > 0" color="green" style="cursor:pointer" @click="router.push('/about/activation')">
            已激活 · 剩余 {{ licenseDays }} 天
          </a-tag>
          <a-tag v-else-if="licenseDays === 0" color="red" style="cursor:pointer" @click="router.push('/about/activation')">
            授权已过期
          </a-tag>
          <!-- BUG-005：移除旧「未激活(-1)」分支——它此前仅由 onUnauthorized(更新源鉴权失败)误置，
               导致 SPA 跳转偶发闪「未激活」。激活状态以 /api/meta/activation 为唯一权威，null 时不显徽标(不闪)。 -->
          <a-tag color="blue">{{ APP_VERSION }}</a-tag>
          <a-button type="text" @click="router.push('/proxy')"><template #icon><GlobalOutlined /></template>代理中心</a-button>
          <button class="theme-toggle" :class="{ dark: isDark }" @click="toggleTheme"
            :title="isDark ? '切换到日间模式' : '切换到夜间模式'" aria-label="切换主题">
            <span class="tt-track">
              <span class="tt-ico sun">☀</span>
              <span class="tt-ico moon">🌙</span>
              <span class="tt-thumb"></span>
            </span>
          </button>
          <a-dropdown>
            <a class="user-entry" @click.prevent>
              <a-avatar size="small" class="user-avatar"><template #icon><UserOutlined /></template></a-avatar>
              <span class="user-name">{{ username }}</span>
              <DownOutlined class="user-caret" />
            </a>
            <template #overlay>
              <a-menu>
                <a-menu-item key="pass" @click="openChangePass"><LockOutlined /> 修改密码</a-menu-item>
                <a-menu-divider />
                <a-menu-item key="logout" danger @click="logout"><LogoutOutlined /> 退出登录</a-menu-item>
              </a-menu>
            </template>
          </a-dropdown>
        </a-space>
      </a-layout-header>
      <!-- 分发系统下发的通告：默认仅顶部通告条展示，popup 通告才弹窗 -->
      <AnnouncementBar />
      <a-layout-content class="app-content">
        <router-view />
      </a-layout-content>
    </a-layout>

    <a-modal v-model:open="passOpen" title="修改密码" @ok="submitChangePass" :confirm-loading="passLoading">
      <a-form layout="vertical">
        <a-form-item label="旧密码" required><a-input-password v-model:value="passForm.old_password" placeholder="旧密码" /></a-form-item>
        <a-form-item label="新密码" required><a-input-password v-model:value="passForm.new_password" placeholder="新密码" /></a-form-item>
        <a-form-item label="确认新密码" required><a-input-password v-model:value="passForm.check_password" placeholder="再次输入新密码" /></a-form-item>
      </a-form>
    </a-modal>

    <!-- 首次登录强制免责声明（最高优先级，不同意不放行；法律确认先于一切） -->
    <DisclaimerModal />

    <!-- 全局更新提示弹窗（检测到新版本弹出，可关闭，一键更新带进度条+自动刷新）-->
    <UpdateNotice @unauthorized="onUnauthorized" />

    <!-- 首次配置向导（激活 + AI 配置 + API 密钥，按步骤引导） -->
    <SetupWizard :force-show="forceActivation" />
  </a-layout>
</template>

<script setup lang="ts">
import { computed, onMounted, reactive, ref } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { message } from 'ant-design-vue'
import {
  ApiOutlined,
  AppstoreAddOutlined,
  AppstoreOutlined,
  BugOutlined,
  CodeOutlined,
  ControlOutlined,
  DashboardOutlined,
  DatabaseOutlined,
  NodeIndexOutlined,
  ApartmentOutlined,
  DownOutlined,
  ExperimentOutlined,
  FileSearchOutlined,
  GithubOutlined,
  GlobalOutlined,
  InfoCircleOutlined,
  CloudSyncOutlined,
  HistoryOutlined,
  ReadOutlined,
  KeyOutlined,
  LockOutlined,
  LogoutOutlined,
  MenuFoldOutlined,
  MenuUnfoldOutlined,
  MonitorOutlined,
  PartitionOutlined,
  ProfileOutlined,
  RadarChartOutlined,
  RobotOutlined,
  ScheduleOutlined,
  SearchOutlined,
  SecurityScanOutlined,
  SettingOutlined,
  TagsOutlined,
  TeamOutlined,
  ToolOutlined,
  UserOutlined,
  WifiOutlined
} from '@ant-design/icons-vue'
import { clearToken, getUser, getPerms } from '../api/request'
import { userApi } from '../api/user'
import { menuGroups } from '../router'
import { APP_NAME, APP_NAME_EN, APP_VERSION } from '../config/brand'
import { checkActivation } from '../api/meta'
import BrandLogo from '../components/BrandLogo.vue'
import UpdateNotice from '../components/UpdateNotice.vue'
import SetupWizard from '../components/SetupWizard.vue'
import DisclaimerModal from '../components/DisclaimerModal.vue'
import AnnouncementBar from '../components/AnnouncementBar.vue'
import { useTheme } from '../composables/useTheme'

const { isDark, toggleTheme } = useTheme()

const router = useRouter()
const route = useRoute()
const collapsed = ref(false)
const openKeys = ref(menuGroups.map(group => group.key))
const username = computed(() => getUser() || '管理员')
const licenseDays = ref<number | null>(null)
const forceActivation = ref(false)

onMounted(async () => {
  try {
    const res = await checkActivation()
    if (res.activated) {
      licenseDays.value = res.remaining_days ?? Math.max(0, Math.ceil((new Date(res.expires_at || '').getTime() - Date.now()) / 86400000))
    } else if (res.expired) {
      licenseDays.value = 0
    }
  } catch { /* ignore */ }
})

function onUnauthorized() {
  // BUG-001：更新源 key 过期只应「卡更新检测」，绝不阻断运行时操作（设计:捐赠换 key「只卡更新不卡运行」）。
  // 平台激活状态以 /api/meta/activation 为唯一权威（licenseDays 由它设），更新源鉴权失败**不改** licenseDays、
  // **不弹** forceActivation 全屏阻断模态。更新检测专页(UpdateCheck.vue)已就地内联提示「请重新激活」，足够。
  // 故此处不做任何全局阻断处理（保留回调仅为语义占位/未来可加非阻断 toast）。
}

const icons: Record<string, unknown> = {
  ApiOutlined,
  AppstoreAddOutlined,
  AppstoreOutlined,
  BugOutlined,
  CodeOutlined,
  ControlOutlined,
  DashboardOutlined,
  DatabaseOutlined,
  NodeIndexOutlined,
  ApartmentOutlined,
  ExperimentOutlined,
  FileSearchOutlined,
  GithubOutlined,
  GlobalOutlined,
  InfoCircleOutlined,
  CloudSyncOutlined,
  HistoryOutlined,
  ReadOutlined,
  UserOutlined,
  KeyOutlined,
  MonitorOutlined,
  PartitionOutlined,
  ProfileOutlined,
  RadarChartOutlined,
  RobotOutlined,
  ScheduleOutlined,
  SearchOutlined,
  SecurityScanOutlined,
  SettingOutlined,
  TagsOutlined,
  TeamOutlined,
  ToolOutlined,
  WifiOutlined
}

const flatItems = computed(() => menuGroups.flatMap(group => group.children.map(item => ({ ...item, groupTitle: group.title }))))
// 按当前用户权限过滤菜单:item.perm 有值时须命中 permissions;空组(子项全被过滤)不显示。
// 注:这只是 UX 隐藏,后端 RBAC 网关才是权威闸。
const permsVersion = ref(0)   // profile 刷新后 +1,驱动 visibleGroups 重算(localStorage 非响应式)
const visibleGroups = computed(() => {
  void permsVersion.value     // 建立响应依赖
  const perms = getPerms()
  // 无 perms 记录(存量登录态/旧缓存)→ 不过滤(避免误隐藏);有记录则按 perm 过滤
  const noPermInfo = perms.length === 0
  return menuGroups
    .map(group => ({
      ...group,
      children: group.children.filter(item => !item.perm || noPermInfo || perms.includes(item.perm)),
    }))
    .filter(group => group.children.length > 0)
})
// 先精确匹配,再按最长前缀兜底——否则 /tasks/create 会被 /tasks 的 startsWith 抢先命中“任务列表”而非“新建任务”
const activeItem = computed(() => {
  const exact = flatItems.value.find(item => route.path === item.path)
  if (exact) return exact
  return flatItems.value
    .filter(item => route.path.startsWith(`${item.path}/`))
    .sort((a, b) => b.path.length - a.path.length)[0]
})
const selectedKeys = computed(() => [activeItem.value?.key || 'dashboard'])
const pageTitle = computed(() => activeItem.value?.title || String(route.meta.title || APP_NAME))
const breadcrumbItems = computed(() => [{ title: activeItem.value?.groupTitle || '工作台' }, { title: pageTitle.value }])

function onOpenChange(keys: string[]) {
  openKeys.value = keys
}

function onMenuClick({ key }: { key: string }) {
  const item = flatItems.value.find(menu => menu.key === key)
  if (item) router.push(item.path)
}
function logout() {
  clearToken()
  router.push('/login')
}

// 刷新当前用户权限(升级前已登录/缓存陈旧时,拿到最新 role/permissions 驱动菜单过滤)
import { setPerms } from '../api/request'
onMounted(async () => {
  try {
    const p = await userApi.profile()
    setPerms(String(p.role || ''), Array.isArray(p.permissions) ? p.permissions : [])
    permsVersion.value++   // 触发 visibleGroups 重算
  } catch {
    // profile 拿不到不阻塞(网关白名单放行,失败按现有缓存渲染)
  }
})

/* 修改密码 */
const passOpen = ref(false)
const passLoading = ref(false)
const passForm = reactive({ old_password: '', new_password: '', check_password: '' })
function openChangePass() { passForm.old_password = ''; passForm.new_password = ''; passForm.check_password = ''; passOpen.value = true }
async function submitChangePass() {
  if (!passForm.old_password || !passForm.new_password) return message.warning('请填写旧密码和新密码')
  if (passForm.new_password !== passForm.check_password) return message.warning('两次新密码不一致')
  passLoading.value = true
  try {
    await userApi.changePassword(passForm.old_password, passForm.new_password, passForm.check_password)
    message.success('密码已修改，请重新登录')
    passOpen.value = false
    clearToken()
    router.push('/login')
  } catch (error) {
    message.error(error instanceof Error ? error.message : String(error))
  } finally {
    passLoading.value = false
  }
}
</script>
