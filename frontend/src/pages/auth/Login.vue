<template>
  <a-form layout="vertical" :model="form" @finish="submit">
    <a-form-item :label="translate('ui.m_1a3f0617d6de')" name="username" :rules="[{ required: true, message: translate('ui.m_c723b1fab58f') }]">
      <a-input v-model:value="form.username" size="large" :placeholder="translate('ui.m_c723b1fab58f')">
        <template #prefix><UserOutlined /></template>
      </a-input>
    </a-form-item>
    <a-form-item :label="translate('ui.m_a621ab606db2')" name="password" :rules="[{ required: true, message: translate('ui.m_728a7b601c56') }]">
      <a-input-password v-model:value="form.password" size="large" :placeholder="translate('ui.m_728a7b601c56')">
        <template #prefix><LockOutlined /></template>
      </a-input-password>
    </a-form-item>
    <a-button type="primary" size="large" block html-type="submit" :loading="loading">{{ translate('ui.m_5d9cd64f608d') }}</a-button>
  </a-form>
</template>

<script setup lang="ts">
import { t as translate } from '../../i18n'

import { reactive, ref } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { message } from 'ant-design-vue'
import { UserOutlined, LockOutlined } from '@ant-design/icons-vue'
import { userApi } from '../../api/user'
import { setToken, setUser, setPerms } from '../../api/request'
import { loginDestination, navigateAfterLogin } from './navigationAfterLogin'

const router = useRouter()
const route = useRoute()
const loading = ref(false)
const form = reactive({ username: '', password: '' })

async function submit() {
  if (loading.value) return   // 重入锁:防表单回车与按钮等双触发并发登录(各生成不同 token 致竞态,登录后被弹回)
  if (!form.username || !form.password) return
  loading.value = true
  try {
    const data = await userApi.login(form.username, form.password)
    const token = String(data.token || data.Token || '')
    if (!token) throw new Error(translate('ui.m_7c744621470d'))
    setToken(token)
    setUser(String(data.username || form.username))
    setPerms(String(data.role || ''), Array.isArray(data.permissions) ? data.permissions : [])
    message.success(translate('ui.m_645b934deb86'))
    const destination = loginDestination(route.query.redirect, window.location.origin, router)
    await navigateAfterLogin(router, destination, target => window.location.replace(target))
  } catch (error) {
    message.error(error instanceof Error ? error.message : String(error))
  } finally {
    loading.value = false
  }
}
</script>
