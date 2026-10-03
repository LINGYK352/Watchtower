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
          <BrokerDegradeTag />
          <LanguageSwitch />
          <TimezoneTag />
          <!-- 激活时钟统一：activated/expired/revoked 为权威，remaining_days 用 ceil（剩<1天显示1天） -->
          <a-tag v-if="licenseActivated && licenseDays !== null && licenseDays > 1" color="green" style="cursor:pointer" @click="router.push('/about/activation')">
            {{ t('header.activated', { days: licenseDays }) }}
          </a-tag>
          <a-tag v-else-if="licenseActivated && licenseDays === 1" color="orange" style="cursor:pointer" @click="router.push('/about/activation')">
            {{ t('header.expiring') }}
          </a-tag>
          <a-tag v-else-if="licenseExpired" color="red" style="cursor:pointer" @click="router.push('/about/activation')">
            {{ t('header.expired') }}
          </a-tag>
          <!-- 未激活/无key时不显徽标，由 402 事件驱动的激活向导全屏阻断 -->
          <a-tag color="blue">{{ serverVersion }}</a-tag>
          <a-button type="text" @click="router.push('/proxy')"><template #icon><GlobalOutlined /></template>{{ t('header.proxy') }}</a-button>
          <button class="theme-toggle" :class="{ dark: isDark }" @click="toggleTheme"
            :title="isDark ? t('header.dayMode') : t('header.nightMode')" :aria-label="t('header.theme')">
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
                <a-menu-item key="pass" @click="openChangePass"><LockOutlined /> {{ t('header.password') }}</a-menu-item>
                <a-menu-divider />
                <a-menu-item key="logout" danger @click="logout"><LogoutOutlined /> {{ t('header.logout') }}</a-menu-item>
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

    <a-modal v-model:open="passOpen" :title="t('header.password')" @ok="submitChangePass" :confirm-loading="passLoading">
      <a-form layout="vertical">
        <a-form-item :label="t('header.oldPassword')" required><a-input-password v-model:value="passForm.old_password" :placeholder="t('header.oldPassword')" /></a-form-item>
        <a-form-item :label="t('header.newPassword')" required><a-input-password v-model:value="passForm.new_password" :placeholder="t('header.newPassword')" /></a-form-item>
        <a-form-item :label="t('header.confirmPassword')" required><a-input-password v-model:value="passForm.check_password" :placeholder="t('header.reenterPassword')" /></a-form-item>
      </a-form>
    </a-modal>

    <!-- 首次登录强制免责声明（最高优先级，不同意不放行；法律确认先于一切） -->
    <DisclaimerModal />

    <!-- 全局更新提示弹窗（检测到新版本弹出，可关闭，一键更新带进度条+自动刷新）-->
    <UpdateNotice @unauthorized="onUnauthorized" />

    <!-- 升级后提示弹窗（更新完成后按版本区间合并提示需复查的配置，弹一次记 seen）-->
    <UpgradeNoticeModal />

    <!-- 网络质量告警弹窗（体检分数<40 时弹，列排查项；每轮新自检仍<40 再弹）-->
    <NetQualityAlertModal />

    <!-- 系统资源告警弹窗（内存/CPU/磁盘达 critical 时弹，列超标项+排查建议；回落后再恶化才再弹）-->
    <ResourceAlertModal />

    <!-- 激活到期提醒弹窗（剩余 ≤5 天时提醒续期，24h 最多弹一次，访问才触发）-->
    <LicenseExpiryModal />

    <!-- 首次配置向导（激活 + AI 配置 + API 密钥，按步骤引导） -->
    <SetupWizard :force-show="forceActivation" />

    <!-- DeepSeek 鲸鱼娘桌宠（全站游走，可拖可点，双击隐藏，右下角🐳召回） -->
    <DeskPet />
  </a-layout>
</template>

<script setup lang="ts">
import { computed, onMounted, reactive, ref } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { message } from 'ant-design-vue'
import {
  AlertOutlined,
  ApiOutlined,
  AppstoreAddOutlined,
  AppstoreOutlined,
  BugOutlined,
  CodeOutlined,
  ControlOutlined,
  DashboardOutlined,
  DatabaseOutlined,
  DeploymentUnitOutlined,
  ThunderboltOutlined,
  WechatOutlined,
  MobileOutlined,
  NodeIndexOutlined,
  ApartmentOutlined,
  DownOutlined,
  ExperimentOutlined,
  FileSearchOutlined,
  FileTextOutlined,
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
import { APP_NAME, APP_NAME_EN } from '../config/brand'
import { useServerVersion } from '../composables/useServerVersion'
import { checkActivation } from '../api/meta'
import BrandLogo from '../components/BrandLogo.vue'
import UpdateNotice from '../components/UpdateNotice.vue'
import UpgradeNoticeModal from '../components/UpgradeNoticeModal.vue'
import NetQualityAlertModal from '../components/NetQualityAlertModal.vue'
import ResourceAlertModal from '../components/ResourceAlertModal.vue'
import LicenseExpiryModal from '../components/LicenseExpiryModal.vue'
import SetupWizard from '../components/SetupWizard.vue'
import DisclaimerModal from '../components/DisclaimerModal.vue'
import DeskPet from '../components/DeskPet.vue'
import AnnouncementBar from '../components/AnnouncementBar.vue'
import TimezoneTag from '../components/TimezoneTag.vue'
import BrokerDegradeTag from '../components/BrokerDegradeTag.vue'
import LanguageSwitch from '../components/LanguageSwitch.vue'
import { appLocale, t } from '../i18n'
import { useTheme } from '../composables/useTheme'

const { isDark, toggleTheme } = useTheme()

// 顶栏「当前版本」显示后端真实版本（version.txt），非编译进包的静态 APP_VERSION——
// 跳板逐级更新时前端产物 brand 标签可能滞后/错配，运行时拉后端版本才准。
const { serverVersion } = useServerVersion()

const router = useRouter()
const route = useRoute()
const collapsed = ref(false)
const openKeys = ref(menuGroups.map(group => group.key))
const username = computed(() => getUser() || t('common.administrator'))
const licenseActivated = ref(false)
const licenseExpired = ref(false)
const licenseDays = ref<number | null>(null)
const forceActivation = ref(false)

onMounted(async () => {
  try {
    const res = await checkActivation()
    licenseActivated.value = res.activated || false
    licenseExpired.value = res.expired || res.revoked || false
    if (res.activated) {
      // remaining_days 后端已用 ceil，activated 时至少为 1
      licenseDays.value = res.remaining_days ?? Math.max(1, Math.ceil((new Date(res.expires_at || '').getTime() - Date.now()) / 86400000))
    } else {
      licenseDays.value = null
    }
  } catch { /* ignore */ }
  // 后端网关对核心业务端点做激活硬门控，未激活/过期时返回 402。收到该事件说明用户点了「值钱功能」
  // 但系统未激活——弹激活向导引导激活（与首登向导同一入口），并把徽标置为过期态。
  window.addEventListener('sentinel:activation-required', () => {
    forceActivation.value = true
    licenseActivated.value = false
    licenseExpired.value = true
  })
})

function onUnauthorized() {
  // BUG-001：更新源 key 过期只应「卡更新检测」，绝不阻断运行时操作（设计:捐赠换 key「只卡更新不卡运行」）。
  // 平台激活状态以 /api/meta/activation 为唯一权威（licenseDays 由它设），更新源鉴权失败**不改** licenseDays、
  // **不弹** forceActivation 全屏阻断模态。更新检测专页(UpdateCheck.vue)已就地内联提示「请重新激活」，足够。
  // 故此处不做任何全局阻断处理（保留回调仅为语义占位/未来可加非阻断 toast）。
}

const icons: Record<string, unknown> = {
  AlertOutlined,
  ApiOutlined,
  AppstoreAddOutlined,
  AppstoreOutlined,
  BugOutlined,
  CodeOutlined,
  ControlOutlined,
  DashboardOutlined,
  DatabaseOutlined,
  DeploymentUnitOutlined,
  ThunderboltOutlined,
  WechatOutlined,
  MobileOutlined,
  NodeIndexOutlined,
  ApartmentOutlined,
  ExperimentOutlined,
  FileSearchOutlined,
  FileTextOutlined,
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

const localizedGroups = computed(() => {
  void appLocale.value
  return menuGroups.map(group => ({ ...group, title: t(`navigation.${group.key}`), children: group.children.map(item => ({ ...item, title: t(`navigation.${item.key}`) })) }))
})
const flatItems = computed(() => localizedGroups.value.flatMap(group => group.children.map(item => ({ ...item, groupTitle: group.title }))))
// 按当前用户权限过滤菜单:item.perm 有值时须命中 permissions;空组(子项全被过滤)不显示。
// 注:这只是 UX 隐藏,后端 RBAC 网关才是权威闸。
const permsVersion = ref(0)   // profile 刷新后 +1,驱动 visibleGroups 重算(localStorage 非响应式)
const visibleGroups = computed(() => {
  void permsVersion.value     // 建立响应依赖
  const perms = getPerms()
  // 无 perms 记录(存量登录态/旧缓存)→ 不过滤(避免误隐藏);有记录则按 perm 过滤
  const noPermInfo = perms.length === 0
  return localizedGroups.value
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
const breadcrumbItems = computed(() => [{ title: activeItem.value?.groupTitle || t('navigation.workspace') }, { title: pageTitle.value }])

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
  if (!passForm.old_password || !passForm.new_password) return message.warning(t('header.passwordRequired'))
  if (passForm.new_password !== passForm.check_password) return message.warning(t('header.passwordMismatch'))
  passLoading.value = true
  try {
    await userApi.changePassword(passForm.old_password, passForm.new_password, passForm.check_password)
    message.success(t('header.passwordChanged'))
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
