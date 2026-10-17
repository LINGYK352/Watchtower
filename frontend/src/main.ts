import { createApp, nextTick } from 'vue'
import Antd from 'ant-design-vue'
import 'ant-design-vue/dist/reset.css'
import './styles/global.css'
import App from './App.vue'
import router from './router'
import { i18n } from './i18n'

;(window as any).__watchtowerBootStatus?.('正在加载首个页面 / Loading initial page', '主程序已载入，正在等待登录页或工作台及其依赖完成加载。 / Main program loaded; waiting for the initial page and its dependencies.')
const app = createApp(App).use(i18n).use(router).use(Antd)
// Initial async routes must resolve before replacing the static startup view.
router.isReady().then(async () => {
  ;(window as any).__watchtowerBootStatus?.('正在绘制页面 / Rendering page', '页面资源已就绪，正在准备可交互界面。 / Page resources loaded; preparing the interactive interface.')
  app.mount('#app')
  await nextTick()
  ;(window as any).__watchtowerAppReady = true
  document.getElementById('watchtower-boot')?.remove()
}).catch((error) => { (window as any).__watchtowerBootFail?.('首个页面或其依赖加载失败 / Initial page or dependency loading failed', error instanceof Error ? { message: error.name + ': ' + error.message } : error) })
