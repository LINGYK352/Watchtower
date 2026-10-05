<template>
  <PageContainer :title="translate('ui.m_fbf413d429bd')" kicker="User & Role" :description="translate('ui.m_d7fc78e962f3')">
    <a-tabs v-model:activeKey="tab">
      <!-- 用户 -->
      <a-tab-pane key="users" tab="用户">
        <div class="bar">
          <a-button @click="loadUsers">{{ translate('ui.m_aee887434131') }}</a-button>
          <a-button type="primary" @click="openAddUser">{{ translate('ui.m_3ae9a33489d7') }}</a-button>
        </div>
        <a-table :columns="userCols" :data-source="users" :loading="loadingUsers" :pagination="false" row-key="username" size="middle" bordered>
          <template #bodyCell="{ column, record }">
            <template v-if="column.key === 'role'">
              <a-tag :color="record.is_manager ? 'red' : 'blue'">{{ roleTitle(record.role) }}</a-tag>
            </template>
            <template v-else-if="column.key === 'disabled'">
              <a-tag :color="record.disabled ? 'default' : 'green'">{{ record.disabled ? translate('ui.m_bc5a87a757a5') : translate('ui.m_f4f0ead1116b') }}</a-tag>
            </template>
            <template v-else-if="column.key === 'action'">
              <a-space>
                <a @click="openEditUser(record)">{{ translate('ui.m_051836569928') }}</a>
                <a @click="toggleDisable(record)">{{ record.disabled ? translate('ui.m_f4f0ead1116b') : translate('ui.m_7df5c456c765') }}</a>
                <ConfirmAction :title="translate('ui.m_df407347ab01')" danger @confirm="removeUser(record.username)">
                  <a class="danger-link">{{ translate('ui.m_2f9daa828907') }}</a>
                </ConfirmAction>
              </a-space>
            </template>
          </template>
        </a-table>
      </a-tab-pane>

      <!-- 角色 -->
      <a-tab-pane key="roles" tab="角色">
        <div class="bar">
          <a-button @click="loadRoles">{{ translate('ui.m_aee887434131') }}</a-button>
          <a-button type="primary" @click="openAddRole">{{ translate('ui.m_7642dfca45b3') }}</a-button>
        </div>
        <a-table :columns="roleCols" :data-source="roles" :loading="loadingRoles" :pagination="false" row-key="name" size="middle" bordered>
          <template #bodyCell="{ column, record }">
            <template v-if="column.key === 'builtin'">
              <a-tag :color="record.builtin ? 'gold' : 'default'">{{ record.builtin ? translate('ui.m_95e35aabd9a9') : translate('ui.m_4eafa9e925b3') }}</a-tag>
            </template>
            <template v-else-if="column.key === 'permissions'">
              <span v-if="record.permissions.includes('*') || record.permissions.length >= allPermCount">{{ translate('ui.m_d80fd2cc445b') }}</span>
              <span v-else>{{ record.permissions.length }} {{ translate('ui.m_49ccde43a154') }}</span>
            </template>
            <template v-else-if="column.key === 'action'">
              <a-space>
                <a v-if="!record.builtin" @click="openEditRole(record)">{{ translate('ui.m_051836569928') }}</a>
                <a v-else @click="viewRole(record)">{{ translate('ui.m_db8db0530432') }}</a>
                <ConfirmAction v-if="!record.builtin" :title="translate('ui.m_fd1ef9cc3687')" danger @confirm="removeRole(record.name)">
                  <a class="danger-link">{{ translate('ui.m_2f9daa828907') }}</a>
                </ConfirmAction>
              </a-space>
            </template>
          </template>
        </a-table>
      </a-tab-pane>
    </a-tabs>

    <!-- 用户弹窗 -->
    <a-modal v-model:open="userModal" :title="userForm.isEdit ? translate('ui.m_fff6a05a26bc') : translate('ui.m_3ae9a33489d7')" @ok="saveUser" :confirm-loading="saving" width="460px">
      <a-form layout="vertical">
        <a-form-item :label="translate('ui.m_1a3f0617d6de')" required>
          <a-input v-model:value="userForm.username" :disabled="userForm.isEdit" :placeholder="translate('ui.m_c97d3a45b8b0')" />
        </a-form-item>
        <a-form-item :label="userForm.isEdit ? translate('ui.m_23ea6729ffde') : translate('ui.m_a621ab606db2')" :required="!userForm.isEdit">
          <a-input-password v-model:value="userForm.password" :placeholder="translate('ui.m_041568c2db7a')" />
        </a-form-item>
        <a-form-item :label="translate('ui.m_c47b54e84e79')" required>
          <a-select v-model:value="userForm.role" :options="roleOptions" />
        </a-form-item>
      </a-form>
    </a-modal>

    <!-- 角色弹窗 -->
    <a-modal v-model:open="roleModal" :title="roleModalTitle" @ok="saveRole" :confirm-loading="saving" width="780px" :ok-button-props="{ disabled: roleForm.readonly }">
      <a-form layout="vertical">
        <a-row :gutter="16">
          <a-col :span="12">
            <a-form-item :label="translate('ui.m_1bb6ba42be2d')" required>
              <a-input v-model:value="roleForm.name" :disabled="roleForm.isEdit || roleForm.readonly" :placeholder="translate('ui.m_399a167bc125')" />
            </a-form-item>
          </a-col>
          <a-col :span="12">
            <a-form-item :label="translate('ui.m_4587cc06a981')">
              <a-input v-model:value="roleForm.title" :disabled="roleForm.readonly" :placeholder="translate('ui.m_4aab5c3172c6')" />
            </a-form-item>
          </a-col>
        </a-row>
        <a-form-item :label="translate('ui.m_cc62491b9740')" style="margin-bottom:0">
          <a-checkbox-group v-model:value="roleForm.permissions" :disabled="roleForm.readonly" class="perm-grid">
            <a-checkbox v-for="p in perms" :key="p.key" :value="p.key" class="perm-item">{{ p.desc }}</a-checkbox>
          </a-checkbox-group>
        </a-form-item>
      </a-form>
    </a-modal>
  </PageContainer>
</template>

<script setup lang="ts">
import { t as translate } from '../../i18n'

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
  { get title() { return translate('ui.m_1a3f0617d6de') }, dataIndex: 'username', key: 'username' },
  { get title() { return translate('ui.m_c47b54e84e79') }, key: 'role', width: 140 },
  { get title() { return translate('ui.m_6320b4a8722a') }, key: 'disabled', width: 100 },
  { get title() { return translate('ui.m_f46c86c0286a') }, dataIndex: 'created_by', key: 'created_by', width: 120 },
  { get title() { return translate('ui.m_07ec86e0f1d4') }, dataIndex: 'create_date', key: 'create_date', width: 170 },
  { get title() { return translate('ui.m_ed31fbb483ee') }, key: 'action', width: 180 },
]
const roleCols = [
  { get title() { return translate('ui.m_1bb6ba42be2d') }, dataIndex: 'name', key: 'name' },
  { get title() { return translate('ui.m_4587cc06a981') }, dataIndex: 'title', key: 'title' },
  { get title() { return translate('ui.m_ba40014ff496') }, key: 'builtin', width: 100 },
  { get title() { return translate('ui.m_978cbca6265d') }, key: 'permissions', width: 110 },
  { get title() { return translate('ui.m_4262c45dc797') }, dataIndex: 'desc', key: 'desc' },
  { get title() { return translate('ui.m_ed31fbb483ee') }, key: 'action', width: 140 },
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
  if (!userForm.username) return message.warning(translate('ui.m_9b305ad90c54'))
  if (!userForm.isEdit && !userForm.password) return message.warning(translate('ui.m_3d1a8a4e75de'))
  saving.value = true
  try {
    if (userForm.isEdit) {
      await userApi.updateUser({ username: userForm.username, role: userForm.role, password: userForm.password || undefined })
    } else {
      await userApi.createUser(userForm.username, userForm.password, userForm.role)
    }
    message.success(translate('ui.m_1bd91a7d0c53'))
    userModal.value = false
    loadUsers()
  } catch (e) { message.error(errMsg(e)) } finally { saving.value = false }
}
async function toggleDisable(r: UserItem) {
  try {
    await userApi.updateUser({ username: r.username, disabled: !r.disabled })
    message.success(r.disabled ? translate('ui.m_dfb802238b38') : translate('ui.m_bc5a87a757a5'))
    loadUsers()
  } catch (e) { message.error(errMsg(e)) }
}
async function removeUser(username: string) {
  try { await userApi.deleteUser(username); message.success(translate('ui.m_077a6d37719a')); loadUsers() }
  catch (e) { message.error(errMsg(e)) }
}

// —— 角色表单 ——
const roleModal = ref(false)
const roleForm = reactive({ isEdit: false, readonly: false, name: '', title: '', permissions: [] as string[], desc: '' })
const roleModalTitle = computed(() => roleForm.readonly ? translate('ui.m_325c838e3219') : (roleForm.isEdit ? translate('ui.m_181ccc03f7d2') : translate('ui.m_7642dfca45b3')))
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
  if (!roleForm.name) return message.warning(translate('ui.m_ec12f09b231e'))
  saving.value = true
  try {
    await userApi.upsertRole({ name: roleForm.name, title: roleForm.title, permissions: roleForm.permissions, desc: roleForm.desc })
    message.success(translate('ui.m_1bd91a7d0c53'))
    roleModal.value = false
    loadRoles()
  } catch (e) { message.error(errMsg(e)) } finally { saving.value = false }
}
async function removeRole(name: string) {
  try { await userApi.deleteRole(name); message.success(translate('ui.m_077a6d37719a')); loadRoles() }
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
