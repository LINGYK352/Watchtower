import { createRouter, createWebHistory, type RouteRecordRaw } from 'vue-router'
import AppLayout from '../layouts/AppLayout.vue'
import AuthLayout from '../layouts/AuthLayout.vue'
import { getToken } from '../api/request'

export interface MenuItem {
  key: string
  title: string
  icon: string
  path: string
  perm?: string  // 需要的权限点;有则按 permissions 过滤,无则所有登录用户可见
}

export interface MenuGroup {
  key: string
  title: string
  icon: string
  children: MenuItem[]
}

export const menuGroups: MenuGroup[] = [
  { key: 'workspace', title: '工作台', icon: 'DashboardOutlined', children: [
    { key: 'dashboard', title: '态势总览', icon: 'DashboardOutlined', path: '/dashboard' },
    { key: 'systemExtension', title: '系统扩展', icon: 'AppstoreAddOutlined', path: '/system-extensions', perm: 'ai_extension:read' }
  ] },
  { key: 'taskPlan', title: '任务与计划', icon: 'ProfileOutlined', children: [
    { key: 'tasks', title: '任务列表', icon: 'ProfileOutlined', path: '/tasks' },
    { key: 'taskCreate', title: '新建任务', icon: 'RadarChartOutlined', path: '/tasks/create' },
    { key: 'policy', title: '策略配置', icon: 'ControlOutlined', path: '/policy' },
    { key: 'taskSchedule', title: '计划任务', icon: 'ScheduleOutlined', path: '/task-schedule' }
  ] },
  { key: 'aiPentest', title: '渗透控制台', icon: 'RobotOutlined', children: [
    { key: 'pentest', title: '渗透会话', icon: 'BugOutlined', path: '/pentest' },
    { key: 'pentestConsole', title: 'AI 控制台', icon: 'CodeOutlined', path: '/pentest/console' },
    { key: 'miniapp', title: '小程序渗透', icon: 'WechatOutlined', path: '/miniapp' },
    { key: 'probeManage', title: '免杀与探针', icon: 'ThunderboltOutlined', path: '/probe' },
    { key: 'aiConfig', title: 'AI 配置', icon: 'ApiOutlined', path: '/ai-config' }
  ] },
  { key: 'riskIntel', title: '漏洞与情报', icon: 'SecurityScanOutlined', children: [
    { key: 'vulnCenter', title: '漏洞中心', icon: 'SecurityScanOutlined', path: '/vuln-center' },
    { key: 'poc', title: 'PoC 信息', icon: 'ExperimentOutlined', path: '/poc' },
    { key: 'vulnIntel', title: '漏洞情报', icon: 'BugOutlined', path: '/vuln-intel' },
    { key: 'attackChain', title: '攻击链情报', icon: 'NodeIndexOutlined', path: '/attack-chain' },
    { key: 'unitView', title: '单位视图', icon: 'ApartmentOutlined', path: '/unit-view' },
    { key: 'intel', title: '资产情报', icon: 'DatabaseOutlined', path: '/intel' }
  ] },
  { key: 'asset', title: '资产中心', icon: 'SearchOutlined', children: [
    { key: 'search', title: '资产检索', icon: 'SearchOutlined', path: '/search' },
    { key: 'assetGroups', title: '资产分组', icon: 'AppstoreOutlined', path: '/asset-groups' },
    { key: 'assetMonitor', title: '资产监控', icon: 'MonitorOutlined', path: '/asset-monitor' },
    { key: 'fingerprint', title: '指纹管理', icon: 'TagsOutlined', path: '/fingerprint' },
    { key: 'githubTasks', title: 'GitHub 任务', icon: 'GithubOutlined', path: '/github/tasks' },
    { key: 'githubMonitor', title: 'GitHub 监控', icon: 'MonitorOutlined', path: '/github/monitor' }
  ] },
  { key: 'system', title: '系统设置', icon: 'SettingOutlined', children: [
    { key: 'userManage', title: '用户管理', icon: 'TeamOutlined', path: '/user-manage', perm: 'user:manage' },
    { key: 'proxy', title: '代理中心', icon: 'GlobalOutlined', path: '/proxy' },
    { key: 'networkCheck', title: '网络检测', icon: 'WifiOutlined', path: '/network-check' },
    { key: 'apiKeys', title: 'API 密钥', icon: 'KeyOutlined', path: '/api-keys' },
    { key: 'logs', title: '日志监测', icon: 'FileSearchOutlined', path: '/logs' },
    { key: 'accessLog', title: '访问日志', icon: 'ProfileOutlined', path: '/access-log' },
    { key: 'guardLog', title: '拦截日志', icon: 'SecurityScanOutlined', path: '/guard-log' }
  ] },
  { key: 'about', title: '关于系统', icon: 'InfoCircleOutlined', children: [
    { key: 'manual', title: '使用手册', icon: 'ReadOutlined', path: '/about/manual' },
    { key: 'activation', title: '激活设置', icon: 'KeyOutlined', path: '/about/activation' },
    { key: 'updateCheck', title: '更新检测', icon: 'CloudSyncOutlined', path: '/about/update' },
    { key: 'changelog', title: '更新日志', icon: 'HistoryOutlined', path: '/about/changelog' },
    { key: 'developer', title: '开发者', icon: 'UserOutlined', path: '/about/developer' }
  ] }
]

const routes: RouteRecordRaw[] = [
  { path: '/login', component: AuthLayout, children: [{ path: '', name: 'login', component: () => import('../pages/auth/Login.vue'), meta: { public: true, title: '登录' } }] },
  {
    path: '/',
    component: AppLayout,
    redirect: '/dashboard',
    children: [
      { path: 'dashboard', name: 'dashboard', component: () => import('../pages/dashboard/Dashboard.vue'), meta: { title: '态势总览' } },
      { path: 'tasks', name: 'tasks', component: () => import('../pages/tasks/TaskList.vue'), meta: { title: '任务列表' } },
      { path: 'tasks/create', name: 'taskCreate', component: () => import('../pages/tasks/TaskCreate.vue'), meta: { title: '新建任务' } },
      { path: 'tasks/:id', name: 'taskDetail', component: () => import('../pages/tasks/TaskDetail.vue'), meta: { title: '任务详情' } },
      { path: 'search', name: 'search', component: () => import('../pages/search/AssetSearch.vue'), meta: { title: '资产检索' } },
      { path: 'asset-groups', name: 'assetGroups', component: () => import('../pages/assets/AssetGroupList.vue'), meta: { title: '资产分组' } },
      { path: 'asset-groups/:id', name: 'assetGroupDetail', component: () => import('../pages/assets/AssetGroupDetail.vue'), meta: { title: '分组详情' } },
      { path: 'asset-monitor', name: 'assetMonitor', component: () => import('../pages/assets/AssetMonitor.vue'), meta: { title: '资产监控' } },
      { path: 'policy', name: 'policy', component: () => import('../pages/policy/PolicyList.vue'), meta: { title: '策略配置' } },
      { path: 'policy/:id', name: 'policyEdit', component: () => import('../pages/policy/PolicyEdit.vue'), meta: { title: '策略编辑' } },
      { path: 'fingerprint', name: 'fingerprint', component: () => import('../pages/fingerprint/FingerprintList.vue'), meta: { title: '指纹管理' } },
      { path: 'poc', name: 'poc', component: () => import('../pages/poc/PocList.vue'), meta: { title: 'PoC 信息' } },
      { path: 'vuln-center', name: 'vulnCenter', component: () => import('../pages/risk/VulnCenter.vue'), meta: { title: '漏洞中心' } },
      { path: 'vuln', redirect: '/vuln-center' },
      { path: 'ai-findings', redirect: '/vuln-center' },
      { path: 'task-schedule', name: 'taskSchedule', component: () => import('../pages/scheduler/TaskScheduleList.vue'), meta: { title: '计划任务' } },
      { path: 'github/tasks', name: 'githubTasks', component: () => import('../pages/github/GithubTaskList.vue'), meta: { title: 'GitHub任务' } },
      { path: 'github/monitor', name: 'githubMonitor', component: () => import('../pages/github/GithubMonitorList.vue'), meta: { title: 'GitHub监控' } },
      { path: 'proxy', name: 'proxy', component: () => import('../pages/proxy/ProxySetting.vue'), meta: { title: '代理中心' } },
      { path: 'network-check', name: 'networkCheck', component: () => import('../pages/settings/NetworkCheck.vue'), meta: { title: '网络检测' } },
      { path: 'api-keys', name: 'apiKeys', component: () => import('../pages/settings/ApiKeys.vue'), meta: { title: 'API 密钥' } },
      { path: 'logs', name: 'logs', component: () => import('../pages/logs/LogMonitor.vue'), meta: { title: '日志监测' } },
      { path: 'access-log', name: 'accessLog', component: () => import('../pages/logs/AccessLog.vue'), meta: { title: '访问日志' } },
      { path: 'guard-log', name: 'guardLog', component: () => import('../pages/logs/GuardLog.vue'), meta: { title: '拦截日志' } },
      { path: 'intel', name: 'intel', component: () => import('../pages/intel/IntelCenter.vue'), meta: { title: '资产情报' } },
      { path: 'vuln-intel', name: 'vulnIntel', component: () => import('../pages/intel/VulnIntel.vue'), meta: { title: '漏洞情报' } },
      { path: 'attack-chain', name: 'attackChain', component: () => import('../pages/intel/AttackChain.vue'), meta: { title: '攻击链情报' } },
      { path: 'unit-view', name: 'unitView', component: () => import('../pages/intel/UnitView.vue'), meta: { title: '单位视图' } },
      { path: 'ai-config', name: 'aiConfig', component: () => import('../pages/ai/AiConfig.vue'), meta: { title: 'AI 配置' } },
      { path: 'ai-tools', name: 'aiTools', component: () => import('../pages/ai/AiTools.vue'), meta: { title: 'AI 工具' } },
      { path: 'system-extensions', name: 'systemExtension', component: () => import('../pages/system/SystemExtension.vue'), meta: { title: '系统扩展' } },
      { path: 'pentest', name: 'pentest', component: () => import('../pages/pentest/PentestList.vue'), meta: { title: '渗透会话' } },
      { path: 'pentest/console', name: 'pentestConsole', component: () => import('../pages/pentest/PentestConsole.vue'), meta: { title: 'AI 控制台' } },
      { path: 'miniapp', name: 'miniapp', component: () => import('../pages/miniapp/MiniAppPentest.vue'), meta: { title: '小程序渗透' } },
      { path: 'probe', name: 'probeManage', component: () => import('../pages/probe/ProbeManage.vue'), meta: { title: '探针管理' } },
      { path: 'pentest/live/:id', name: 'pentestLive', component: () => import('../pages/pentest/PentestLive.vue'), meta: { title: '实时观察' } },
      { path: 'pentest/:id', name: 'pentestDetail', component: () => import('../pages/pentest/PentestDetail.vue'), meta: { title: '渗透会话详情' } },
      { path: 'user-manage', name: 'userManage', component: () => import('../pages/settings/UserManage.vue'), meta: { title: '用户管理' } },
      { path: 'about/manual', name: 'manual', component: () => import('../pages/about/Manual.vue'), meta: { title: '使用手册' } },
      { path: 'about/activation', name: 'activation', component: () => import('../pages/about/ActivationSetting.vue'), meta: { title: '激活设置' } },
      { path: 'about/update', name: 'updateCheck', component: () => import('../pages/about/UpdateCheck.vue'), meta: { title: '更新检测' } },
      { path: 'about/changelog', name: 'changelog', component: () => import('../pages/about/Changelog.vue'), meta: { title: '更新日志' } },
      { path: 'about/developer', name: 'developer', component: () => import('../pages/about/Developer.vue'), meta: { title: '开发者' } }
    ]
  },
  { path: '/proxy.html', redirect: '/proxy' },
  { path: '/:pathMatch(.*)*', redirect: '/dashboard' }
]

const router = createRouter({ history: createWebHistory(), routes })

router.beforeEach((to) => {
  if (!to.meta.public && !getToken()) {
    return { path: '/login', query: { redirect: to.fullPath } }
  }
})

export default router
