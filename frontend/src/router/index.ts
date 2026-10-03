import { t as translate } from '../i18n'
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
  { key: 'workspace', get title() { return translate('ui.m_f9e02d3c13aa') }, icon: 'DashboardOutlined', children: [
    { key: 'dashboard', get title() { return translate('ui.m_70a1534aa33c') }, icon: 'DashboardOutlined', path: '/dashboard' },
    { key: 'attackAlert', get title() { return translate('ui.m_22d1a41590ad') }, icon: 'AlertOutlined', path: '/attack-alert', perm: 'system:read' },
    { key: 'systemExtension', get title() { return translate('ui.m_f6c93a56a62a') }, icon: 'AppstoreAddOutlined', path: '/system-extensions', perm: 'ai_extension:read' }
  ] },
  { key: 'taskPlan', get title() { return translate('ui.m_f9cbf8329c61') }, icon: 'ProfileOutlined', children: [
    { key: 'tasks', get title() { return translate('ui.m_c5ced4b36c07') }, icon: 'ProfileOutlined', path: '/tasks' },
    { key: 'taskCreate', get title() { return translate('ui.m_6bee2372805a') }, icon: 'RadarChartOutlined', path: '/tasks/create' },
    { key: 'policy', get title() { return translate('ui.m_f5ef9152022d') }, icon: 'ControlOutlined', path: '/policy' },
    { key: 'taskSchedule', get title() { return translate('ui.m_b61129b1fbb2') }, icon: 'ScheduleOutlined', path: '/task-schedule' }
  ] },
  { key: 'aiPentest', get title() { return translate('ui.m_75c3fde836eb') }, icon: 'RobotOutlined', children: [
    { key: 'pentest', get title() { return translate('ui.m_4f5da0f7e962') }, icon: 'BugOutlined', path: '/pentest' },
    { key: 'pentestConsole', get title() { return translate('ui.m_6357c0524e1c') }, icon: 'CodeOutlined', path: '/pentest/console' },
    { key: 'miniapp', get title() { return translate('ui.m_5516ca2ce286') }, icon: 'WechatOutlined', path: '/miniapp' },
    { key: 'appPentest', get title() { return translate('ui.m_8bd7a912bed6') }, icon: 'MobileOutlined', path: '/app-pentest' },
    { key: 'probeManage', get title() { return translate('ui.m_5e308ea12929') }, icon: 'ThunderboltOutlined', path: '/probe' },
    { key: 'aiConfig', get title() { return translate('ui.m_4336ed2f9fad') }, icon: 'ApiOutlined', path: '/ai-config' }
  ] },
  { key: 'riskIntel', get title() { return translate('ui.m_e84c1409f5a9') }, icon: 'SecurityScanOutlined', children: [
    { key: 'vulnCenter', get title() { return translate('ui.m_756d8eeb32a5') }, icon: 'SecurityScanOutlined', path: '/vuln-center' },
    { key: 'reportEdit', get title() { return translate('ui.m_8468b4359dd8') }, icon: 'FileTextOutlined', path: '/report-edit' },
    { key: 'poc', get title() { return translate('ui.m_45f84bbf818e') }, icon: 'ExperimentOutlined', path: '/poc' },
    { key: 'vulnIntel', get title() { return translate('ui.m_152ea9270e8d') }, icon: 'BugOutlined', path: '/vuln-intel' },
    { key: 'attackChain', get title() { return translate('ui.m_c14a89bcd889') }, icon: 'NodeIndexOutlined', path: '/attack-chain' },
    { key: 'intel', get title() { return translate('ui.m_71f13524f302') }, icon: 'DatabaseOutlined', path: '/intel' }
  ] },
  { key: 'asset', get title() { return translate('ui.m_5035ae80160f') }, icon: 'SearchOutlined', children: [
    { key: 'search', get title() { return translate('ui.m_15d01ccc18e1') }, icon: 'SearchOutlined', path: '/search' },
    { key: 'assetGroups', get title() { return translate('ui.m_27f9488e7635') }, icon: 'AppstoreOutlined', path: '/asset-groups' },
    { key: 'assetMonitor', get title() { return translate('ui.m_cad3d4078857') }, icon: 'MonitorOutlined', path: '/asset-monitor' },
    { key: 'fingerprint', get title() { return translate('ui.m_3b451ca9ab06') }, icon: 'TagsOutlined', path: '/fingerprint' },
    { key: 'githubTasks', get title() { return translate('ui.m_8c09564f938a') }, icon: 'GithubOutlined', path: '/github/tasks' },
    { key: 'githubMonitor', get title() { return translate('ui.m_a05bcd6b3701') }, icon: 'MonitorOutlined', path: '/github/monitor' }
  ] },
  { key: 'system', get title() { return translate('ui.m_68ea5dd4d7af') }, icon: 'SettingOutlined', children: [
    { key: 'userManage', get title() { return translate('ui.m_fbf413d429bd') }, icon: 'TeamOutlined', path: '/user-manage', perm: 'user:manage' },
    { key: 'proxy', get title() { return translate('ui.m_23eae9eefda3') }, icon: 'GlobalOutlined', path: '/proxy' },
    { key: 'networkCheck', get title() { return translate('ui.m_e67f6bb5fb9e') }, icon: 'WifiOutlined', path: '/network-check' },
    { key: 'apiKeys', get title() { return translate('ui.m_5f600b307b4e') }, icon: 'KeyOutlined', path: '/api-keys' },
    { key: 'logs', get title() { return translate('ui.m_74f80eb72df3') }, icon: 'FileSearchOutlined', path: '/logs' },
    { key: 'accessLog', get title() { return translate('ui.m_b1ce859b30ae') }, icon: 'ProfileOutlined', path: '/access-log' },
    { key: 'guardLog', get title() { return translate('ui.m_3c944c82ba0c') }, icon: 'SecurityScanOutlined', path: '/guard-log' }
  ] },
  { key: 'about', get title() { return translate('ui.m_f9de79b5b2cb') }, icon: 'InfoCircleOutlined', children: [
    { key: 'manual', get title() { return translate('ui.m_396c685466aa') }, icon: 'ReadOutlined', path: '/about/manual' },
    { key: 'activation', get title() { return translate('ui.m_116636064123') }, icon: 'KeyOutlined', path: '/about/activation' },
    { key: 'updateCheck', get title() { return translate('ui.m_db216ba9c123') }, icon: 'CloudSyncOutlined', path: '/about/update' },
    { key: 'changelog', get title() { return translate('ui.m_de6811e73d40') }, icon: 'HistoryOutlined', path: '/about/changelog' },
    { key: 'developer', get title() { return translate('ui.m_38084d301e3f') }, icon: 'UserOutlined', path: '/about/developer' }
  ] }
]

const routes: RouteRecordRaw[] = [
  { path: '/login', component: AuthLayout, children: [{ path: '', name: 'login', component: () => import('../pages/auth/Login.vue'), meta: { public: true, get title() { return translate('ui.m_1e2df9c3075a') } } }] },
  {
    path: '/',
    component: AppLayout,
    redirect: '/dashboard',
    children: [
      { path: 'dashboard', name: 'dashboard', component: () => import('../pages/dashboard/Dashboard.vue'), meta: { get title() { return translate('ui.m_70a1534aa33c') } } },
      { path: 'attack-alert', name: 'attackAlert', component: () => import('../pages/workspace/AttackAlert.vue'), meta: { get title() { return translate('ui.m_22d1a41590ad') } } },
      { path: 'tasks', name: 'tasks', component: () => import('../pages/tasks/TaskList.vue'), meta: { get title() { return translate('ui.m_c5ced4b36c07') } } },
      { path: 'tasks/create', name: 'taskCreate', component: () => import('../pages/tasks/TaskCreate.vue'), meta: { get title() { return translate('ui.m_6bee2372805a') } } },
      { path: 'tasks/:id', name: 'taskDetail', component: () => import('../pages/tasks/TaskDetail.vue'), meta: { get title() { return translate('ui.m_56b3909705f3') } } },
      { path: 'search', name: 'search', component: () => import('../pages/search/AssetSearch.vue'), meta: { get title() { return translate('ui.m_15d01ccc18e1') } } },
      { path: 'asset-groups', name: 'assetGroups', component: () => import('../pages/assets/AssetGroupList.vue'), meta: { get title() { return translate('ui.m_27f9488e7635') } } },
      { path: 'asset-groups/:id', name: 'assetGroupDetail', component: () => import('../pages/assets/AssetGroupDetail.vue'), meta: { get title() { return translate('ui.m_b27132dff0e0') } } },
      { path: 'asset-monitor', name: 'assetMonitor', component: () => import('../pages/assets/AssetMonitor.vue'), meta: { get title() { return translate('ui.m_cad3d4078857') } } },
      { path: 'policy', name: 'policy', component: () => import('../pages/policy/PolicyList.vue'), meta: { get title() { return translate('ui.m_f5ef9152022d') } } },
      { path: 'policy/:id', name: 'policyEdit', component: () => import('../pages/policy/PolicyEdit.vue'), meta: { get title() { return translate('ui.m_7a2dc080920c') } } },
      { path: 'fingerprint', name: 'fingerprint', component: () => import('../pages/fingerprint/FingerprintList.vue'), meta: { get title() { return translate('ui.m_3b451ca9ab06') } } },
      { path: 'poc', name: 'poc', component: () => import('../pages/poc/PocList.vue'), meta: { get title() { return translate('ui.m_45f84bbf818e') } } },
      { path: 'vuln-center', name: 'vulnCenter', component: () => import('../pages/risk/VulnCenter.vue'), meta: { get title() { return translate('ui.m_756d8eeb32a5') } } },
      { path: 'report-edit', name: 'reportEdit', component: () => import('../pages/risk/ReportEdit.vue'), meta: { get title() { return translate('ui.m_8468b4359dd8') } } },
      { path: 'vuln', redirect: '/vuln-center' },
      { path: 'ai-findings', redirect: '/vuln-center' },
      { path: 'task-schedule', name: 'taskSchedule', component: () => import('../pages/scheduler/TaskScheduleList.vue'), meta: { get title() { return translate('ui.m_b61129b1fbb2') } } },
      { path: 'github/tasks', name: 'githubTasks', component: () => import('../pages/github/GithubTaskList.vue'), meta: { get title() { return translate('ui.m_cec86254a33c') } } },
      { path: 'github/monitor', name: 'githubMonitor', component: () => import('../pages/github/GithubMonitorList.vue'), meta: { get title() { return translate('ui.m_248228dd5873') } } },
      { path: 'proxy', name: 'proxy', component: () => import('../pages/proxy/ProxySetting.vue'), meta: { get title() { return translate('ui.m_23eae9eefda3') } } },
      { path: 'network-check', name: 'networkCheck', component: () => import('../pages/settings/NetworkCheck.vue'), meta: { get title() { return translate('ui.m_e67f6bb5fb9e') } } },
      { path: 'api-keys', name: 'apiKeys', component: () => import('../pages/settings/ApiKeys.vue'), meta: { get title() { return translate('ui.m_5f600b307b4e') } } },
      { path: 'logs', name: 'logs', component: () => import('../pages/logs/LogMonitor.vue'), meta: { get title() { return translate('ui.m_74f80eb72df3') } } },
      { path: 'access-log', name: 'accessLog', component: () => import('../pages/logs/AccessLog.vue'), meta: { get title() { return translate('ui.m_b1ce859b30ae') } } },
      { path: 'guard-log', name: 'guardLog', component: () => import('../pages/logs/GuardLog.vue'), meta: { get title() { return translate('ui.m_3c944c82ba0c') } } },
      { path: 'intel', name: 'intel', component: () => import('../pages/intel/IntelCenter.vue'), meta: { get title() { return translate('ui.m_71f13524f302') } } },
      { path: 'vuln-intel', name: 'vulnIntel', component: () => import('../pages/intel/VulnIntel.vue'), meta: { get title() { return translate('ui.m_152ea9270e8d') } } },
      { path: 'attack-chain', name: 'attackChain', component: () => import('../pages/intel/AttackChain.vue'), meta: { get title() { return translate('ui.m_c14a89bcd889') } } },
      { path: 'unit-view', name: 'unitView', component: () => import('../pages/intel/UnitView.vue'), meta: { get title() { return translate('ui.m_c0cfb43b13b4') } } },
      { path: 'ai-config', name: 'aiConfig', component: () => import('../pages/ai/AiConfig.vue'), meta: { get title() { return translate('ui.m_4336ed2f9fad') } } },
      { path: 'ai-tools', name: 'aiTools', component: () => import('../pages/ai/AiTools.vue'), meta: { get title() { return translate('ui.m_c252814845e2') } } },
      { path: 'system-extensions', name: 'systemExtension', component: () => import('../pages/system/SystemExtension.vue'), meta: { get title() { return translate('ui.m_f6c93a56a62a') } } },
      { path: 'pentest', name: 'pentest', component: () => import('../pages/pentest/PentestList.vue'), meta: { get title() { return translate('ui.m_4f5da0f7e962') } } },
      { path: 'pentest/console', name: 'pentestConsole', component: () => import('../pages/pentest/PentestConsole.vue'), meta: { get title() { return translate('ui.m_6357c0524e1c') } } },
      { path: 'pentest/live/:id', name: 'pentestLive', component: () => import('../pages/pentest/PentestLive.vue'), meta: { get title() { return translate('ui.m_a26f20d53096') } } },
      { path: 'pentest/:id', name: 'pentestDetail', component: () => import('../pages/pentest/PentestDetail.vue'), meta: { get title() { return translate('ui.m_dd4b71d0e950') } } },
      { path: 'miniapp', name: 'miniapp', component: () => import('../pages/miniapp/MiniAppPentest.vue'), meta: { get title() { return translate('ui.m_5516ca2ce286') } } },
      { path: 'app-pentest', name: 'appPentest', component: () => import('../pages/pentest/AppPentest.vue'), meta: { get title() { return translate('ui.m_8bd7a912bed6') } } },
      { path: 'probe', name: 'probeManage', component: () => import('../pages/probe/ProbeManage.vue'), meta: { get title() { return translate('ui.m_489906a14862') } } },
      { path: 'user-manage', name: 'userManage', component: () => import('../pages/settings/UserManage.vue'), meta: { get title() { return translate('ui.m_fbf413d429bd') } } },
      { path: 'about/manual', name: 'manual', component: () => import('../pages/about/Manual.vue'), meta: { get title() { return translate('ui.m_396c685466aa') } } },
      { path: 'about/activation', name: 'activation', component: () => import('../pages/about/ActivationSetting.vue'), meta: { get title() { return translate('ui.m_116636064123') } } },
      { path: 'about/update', name: 'updateCheck', component: () => import('../pages/about/UpdateCheck.vue'), meta: { get title() { return translate('ui.m_db216ba9c123') } } },
      { path: 'about/changelog', name: 'changelog', component: () => import('../pages/about/Changelog.vue'), meta: { get title() { return translate('ui.m_de6811e73d40') } } },
      { path: 'about/developer', name: 'developer', component: () => import('../pages/about/Developer.vue'), meta: { get title() { return translate('ui.m_38084d301e3f') } } }
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
