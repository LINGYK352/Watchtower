import { createApp } from 'vue'
import Antd from 'ant-design-vue'
import 'ant-design-vue/dist/reset.css'
import './styles/global.css'
import App from './App.vue'
import router from './router'
import { i18n } from './i18n'

createApp(App).use(i18n).use(router).use(Antd).mount('#app')
