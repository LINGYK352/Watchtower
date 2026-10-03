import { t as translate } from '../i18n'
// 未保存修改守卫（问题4）：整页内联编辑的配置页，改了没点保存就切走会静默丢设置。
// 用法：传入一个「当前状态序列化」函数，数据载入成功 / 保存成功后调 markSaved() 重置基线；
// dirty 供页面显示「有未保存修改」角标。路由切走弹确认框，刷新/关闭页触发浏览器原生拦截。
// 模态框式的新增/编辑（UserManage/Github 等）是离散提交点，不适用本守卫。
import { ref, computed, onMounted, onBeforeUnmount } from 'vue'
import { Modal } from 'ant-design-vue'
import { onBeforeRouteLeave } from 'vue-router'

export function useUnsavedGuard(serialize: () => string, opts?: { content?: string }) {
  // null = 基线未建立（数据尚未加载），此时不判脏，避免初始空态误报
  const baseline = ref<string | null>(null)
  const dirty = computed(() => baseline.value !== null && serialize() !== baseline.value)

  // 载入 / 保存成功后调用，把当前状态设为「已保存基线」，脏标记归零
  function markSaved() { baseline.value = serialize() }

  function onBeforeUnload(e: BeforeUnloadEvent) {
    if (dirty.value) { e.preventDefault(); e.returnValue = '' }
  }

  onBeforeRouteLeave((_to, _from, next) => {
    if (!dirty.value) return next()
    Modal.confirm({
      get title() { return translate('ui.m_c2277872cdce') },
      content: opts?.content || translate('ui.m_8c90fad4ed7a'),
      get okText() { return translate('ui.m_573c3f773c6e') }, okType: 'danger', get cancelText() { return translate('ui.m_120e7cea1231') },
      onOk: () => next(),
      onCancel: () => next(false),
    })
  })

  onMounted(() => window.addEventListener('beforeunload', onBeforeUnload))
  onBeforeUnmount(() => window.removeEventListener('beforeunload', onBeforeUnload))

  return { dirty, markSaved }
}
