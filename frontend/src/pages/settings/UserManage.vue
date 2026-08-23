<template>
  <PageContainer title="用户管理" kicker="User & Role" description="创建用户、分配角色,管理角色权限。权限校验由后端统一拦截,前端菜单按权限显隐。">
    <a-tabs v-model:activeKey="tab">
      <!-- 用户 -->
      <a-tab-pane key="users" tab="用户">
        <div class="bar">
          <a-button @click="loadUsers">刷新</a-button>
          <a-button type="primary" @click="openAddUser">新建用户</a-button>
        </div>
        <a-table :columns="userCols" :data-source="users" :loading="loadingUsers" :pagination="false" row-key="username" size="middle" bordered>
          <template #bodyCell="{ column, record }">
            <template v-if="column.key === 'role'">
              <a-tag :color="record.is_manager ? 'red' : 'blue'">{{ roleTitle(record.role) }}</a-tag>
            </template>
            <template v-else-if="column.key === 'disabled'">
              <a-tag :color="record.disabled ? 'default' : 'green'">{{ record.disabled ? '已禁用' : '启用' }}</a-tag>
            </template>
            <template v-else-if="column.key === 'action'">
              <a-space>
                <a @click="openEditUser(record)">编辑</a>
                <a @click="toggleDisable(record)">{{ record.disabled ? '启用' : '禁用' }}</a>
                <ConfirmAction title="确认删除该用户?" danger @confirm="removeUser(record.username)">
                  <a class="danger-link">删除</a>
                </ConfirmAction>
              </a-space>
            </template>
          </template>
        </a-table>
      </a-tab-pane>

      <!-- 角色 -->
      <a-tab-pane key="roles" tab="角色">
        <div class="bar">
          <a-button @click="loadRoles">刷新</a-button>
          <a-button type="primary" @click="openAddRole">新建角色</a-button>
        </div>
        <a-table :columns="roleCols" :data-source="roles" :loading="loadingRoles" :pagination="false" row-key="name" size="middle" bordered>
          <template #bodyCell="{ column, record }">
            <template v-if="column.key === 'builtin'">
              <a-tag :color="record.builtin ? 'gold' : 'default'">{{ record.builtin ? '内置' : '自定义' }}</a-tag>
            </template>
            <template v-else-if="column.key === 'permissions'">
              <span v-if="record.permissions.includes('*') || record.permissions.length >= allPermCount">全部权限</span>
              <span v-else>{{ record.permissions.length }} 项</span>
            </template>
            <template v-else-if="column.key === 'action'">
              <a-space>
                <a v-if="!record.builtin" @click="openEditRole(record)">编辑</a>
                <a v-else @click="viewRole(record)">查看</a>
                <ConfirmAction v-if="!record.builtin" title="确认删除该角色?" danger @confirm="removeRole(record.name)">
                  <a class="danger-link">删除</a>
                </ConfirmAction>
              </a-space>
            </template>
          </template>
        </a-table>
      </a-tab-pane>
    </a-tabs>

    <!-- 用户弹窗 -->
    <a-modal v-model:open="userModal" :title="userForm.isEdit ? '编辑用户' : '新建用户'" @ok="saveUser" :confirm-loading="saving" width="460px">
      <a-form layout="vertical">
        <a-form-item label="用户名" required>
          <a-input v-model:value="userForm.username" :disabled="userForm.isEdit" placeholder="2-32 位,字母数字 _ . -" />
        </a-form-item>
        <a-form-item :label="userForm.isEdit ? '重置密码(留空不改)' : '密码'" :required="!userForm.isEdit">
          <a-input-password v-model:value="userForm.password" placeholder="至少 6 位" />
        </a-form-item>
        <a-form-item label="角色" required>
          <a-select v-model:value="userForm.role" :options="roleOptions" />
        </a-form-item>
      </a-form>
    </a-modal>

    <!-- 角色弹窗 -->
    <a-modal v-model:open="roleModal" :title="roleModalTitle" @ok="saveRole" :confirm-loading="saving" width="780px" :ok-button-props="{ disabled: roleForm.readonly }">
      <a-form layout="vertical">
        <a-row :gutter="16">
          <a-col :span="12">
            <a-form-item label="角色标识" required>
              <a-input v-model:value="roleForm.name" :disabled="roleForm.isEdit || roleForm.readonly" placeholder="英文标识,如 auditor" />
            </a-form-item>
          </a-col>
          <a-col :span="12">
            <a-form-item label="显示名">
              <a-input v-model:value="roleForm.title" :disabled="roleForm.readonly" placeholder="如 审计员" />
            </a-form-item>
          </a-col>
        </a-row>
        <a-form-item label="权限点" style="margin-bottom:0">
          <a-checkbox-group v-model:value="roleForm.permissions" :disabled="roleForm.readonly" class="perm-grid">
            <a-checkbox v-for="p in perms" :key="p.key" :value="p.key" class="perm-item">{{ p.desc }}</a-checkbox>
          </a-checkbox-group>
        </a-form-item>
      </a-form>
    </a-modal>
  </PageContainer>
</template>

<script setup lang="ts">
import { computed, onMounted, reactive, ref } from 'vue'
import { message } from 'ant-design-vue'
import PageContainer from '../../layouts/PageContainer.vue'
import ConfirmAction from '../../components/ConfirmAction.vue'
import { userApi, type UserItem, type RoleItem, type PermItem } from '../../api/user'

const tab = ref('users')
const saving = ref(false)

// —— 数据 ——
const users = ref<UserItem[]>([])
const roles = ref<RoleItem[]>([])
const perms = ref<PermItem[]>([])
const loadingUsers = ref(false)
const loadingRoles = ref(false)

const allPermCount = computed(() => perms.value.length)
const roleOptions = computed(() => roles.value.map(r => ({ label: `${r.title} (${r.name})`, value: r.name })))
function roleTitle(name: string) {
  return roles.value.find(r => r.name === name)?.title || name
}

const userCols = [
  { title: '用户名', dataIndex: 'username', key: 'username' },
  { title: '角色', key: 'role', width: 140 },
  { title: '状态', key: 'disabled', width: 100 },
  { title: '创建者', dataIndex: 'created_by', key: 'created_by', width: 120 },
  { title: '创建时间', dataIndex: 'create_date', key: 'create_date', width: 170 },
  { title: '操作', key: 'action', width: 180 },
]
const roleCols = [
  { title: '角色标识', dataIndex: 'name', key: 'name' },
  { title: '显示名', dataIndex: 'title', key: 'title' },
  { title: '类型', key: 'builtin', width: 100 },
  { title: '权限', key: 'permissions', width: 110 },
  { title: '说明', dataIndex: 'desc', key: 'desc' },
  { title: '操作', key: 'action', width: 140 },
]

async function loadUsers() {
  loadingUsers.value = true
  try { users.value = (await userApi.listUsers()).items } catch (e) { message.error(errMsg(e)) } finally { loadingUsers.value = false }
}
async function loadRoles() {
  loadingRoles.value = true
  try { roles.value = (await userApi.listRoles()).items } catch (e) { message.error(errMsg(e)) } finally { loadingRoles.value = false }
}
async function loadPerms() {
  try { perms.value = (await userApi.listPermissions()).items } catch { /* ignore */ }
}
function errMsg(e: unknown) { return e instanceof Error ? e.message : String(e) }

onMounted(() => { loadUsers(); loadRoles(); loadPerms() })

// —— 用户表单 ——
const userModal = ref(false)
const userForm = reactive({ isEdit: false, username: '', password: '', role: 'viewer' })
function openAddUser() {
  Object.assign(userForm, { isEdit: false, username: '', password: '', role: 'viewer' })
  userModal.value = true
}
function openEditUser(r: UserItem) {
  Object.assign(userForm, { isEdit: true, username: r.username, password: '', role: r.role })
  userModal.value = true
}
async function saveUser() {
  if (!userForm.username) return message.warning('请填写用户名')
  if (!userForm.isEdit && !userForm.password) return message.warning('请填写密码')
  saving.value = true
  try {
    if (userForm.isEdit) {
      await userApi.updateUser({ username: userForm.username, role: userForm.role, password: userForm.password || undefined })
    } else {
      await userApi.createUser(userForm.username, userForm.password, userForm.role)
    }
    message.success('已保存')
    userModal.value = false
    loadUsers()
  } catch (e) { message.error(errMsg(e)) } finally { saving.value = false }
}
async function toggleDisable(r: UserItem) {
  try {
    await userApi.updateUser({ username: r.username, disabled: !r.disabled })
    message.success(r.disabled ? '已启用' : '已禁用')
    loadUsers()
  } catch (e) { message.error(errMsg(e)) }
}
async function removeUser(username: string) {
  try { await userApi.deleteUser(username); message.success('已删除'); loadUsers() }
  catch (e) { message.error(errMsg(e)) }
}

// —— 角色表单 ——
const roleModal = ref(false)
const roleForm = reactive({ isEdit: false, readonly: false, name: '', title: '', permissions: [] as string[], desc: '' })
const roleModalTitle = computed(() => roleForm.readonly ? '查看角色' : (roleForm.isEdit ? '编辑角色' : '新建角色'))
function openAddRole() {
  Object.assign(roleForm, { isEdit: false, readonly: false, name: '', title: '', permissions: [], desc: '' })
  roleModal.value = true
}
function openEditRole(r: RoleItem) {
  Object.assign(roleForm, { isEdit: true, readonly: false, name: r.name, title: r.title, permissions: [...r.permissions], desc: r.desc || '' })
  roleModal.value = true
}
function viewRole(r: RoleItem) {
  const ps = r.permissions.includes('*') ? perms.value.map(p => p.key) : [...r.permissions]
  Object.assign(roleForm, { isEdit: true, readonly: true, name: r.name, title: r.title, permissions: ps, desc: r.desc || '' })
  roleModal.value = true
}
async function saveRole() {
  if (roleForm.readonly) { roleModal.value = false; return }
  if (!roleForm.name) return message.warning('请填写角色标识')
  saving.value = true
  try {
    await userApi.upsertRole({ name: roleForm.name, title: roleForm.title, permissions: roleForm.permissions, desc: roleForm.desc })
    message.success('已保存')
    roleModal.value = false
    loadRoles()
  } catch (e) { message.error(errMsg(e)) } finally { saving.value = false }
}
async function removeRole(name: string) {
  try { await userApi.deleteRole(name); message.success('已删除'); loadRoles() }
  catch (e) { message.error(errMsg(e)) }
}
</script>

<style scoped>
.bar { margin-bottom: 12px; display: flex; gap: 8px; }
.danger-link { color: #ff4d4f; }
code { background: #f5f5f5; padding: 0 4px; border-radius: 3px; font-size: 12px; }

/* 权限点勾选：CSS Grid 自适应两列，长短描述都整齐不溢出 */
.perm-grid {
  display: grid;
  grid-template-columns: repeat(2, minmax(0, 1fr));
  gap: 10px 16px;
  width: 100%;
}
/* 覆盖 antd checkbox 默认行内布局：方块顶对齐、文字换行不钻到方块下方、不撑破列宽 */
.perm-grid :deep(.ant-checkbox-wrapper) {
  display: flex;
  align-items: flex-start;
  margin-left: 0;
  min-width: 0;
}
.perm-grid :deep(.ant-checkbox) {
  margin-top: 2px;
  flex: 0 0 auto;
}
.perm-grid :deep(.ant-checkbox + span) {
  flex: 1 1 auto;
  min-width: 0;
  white-space: normal;
  word-break: break-word;
  line-height: 1.5;
}
@media (max-width: 640px) {
  .perm-grid { grid-template-columns: 1fr; }
}
</style>
