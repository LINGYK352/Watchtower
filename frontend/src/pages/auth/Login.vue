<template>
  <a-form layout="vertical" :model="form" @finish="submit">
    <a-form-item label="用户名" name="username" :rules="[{ required: true, message: '请输入用户名' }]">
      <a-input v-model:value="form.username" size="large" placeholder="请输入用户名">
        <template #prefix><UserOutlined /></template>
      </a-input>
    </a-form-item>
    <a-form-item label="密码" name="password" :rules="[{ required: true, message: '请输入密码' }]">
      <a-input-password v-model:value="form.password" size="large" placeholder="请输入密码">
        <template #prefix><LockOutlined /></template>
      </a-input-password>
    </a-form-item>
    <a-button type="primary" size="large" block html-type="submit" :loading="loading">登 录</a-button>
  </a-form>
</template>

<script setup lang="ts">
import { reactive, ref } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { message } from 'ant-design-vue'
import { UserOutlined, LockOutlined } from '@ant-design/icons-vue'
import { userApi } from '../../api/user'
import { setToken, setUser, setPerms } from '../../api/request'

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
    if (!token) throw new Error('登录失败，请检查用户名或密码')
    setToken(token)
    setUser(String(data.username || form.username))
    setPerms(String(data.role || ''), Array.isArray(data.permissions) ? data.permissions : [])
    message.success('登录成功')
    router.push(String(route.query.redirect || '/dashboard'))
  } catch (error) {
    message.error(error instanceof Error ? error.message : String(error))
  } finally {
    loading.value = false
  }
}
</script>
