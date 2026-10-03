import { computed } from 'vue'
import { t as translate } from '../i18n'
/**
 * 瞭望塔注册与使用协议（单一事实源）。
 * 首次登录强制弹窗（DisclaimerModal）与「使用手册 → 免责声明」共用同一份文本，避免两处漂移。
 * 修改法律条款只改这一处。
 *
 * v3（2026-09-30）：由单份笼统免责声明，替换为一套三份正式法律文本——
 *   一、注册用户协议与风险告知  二、隐私告知与个人信息处理规则  三、激活使用承诺书。
 * 平台首登为「整体阅读、一次同意」：三份文本一并呈现、一次勾选确认；条款实质变更时递增版本触发重签。
 * 服务提供者为个人开发者（公开署名 LINGYK），联系邮箱 lingyangkang352@163.com，官网 https://watchtowers.info/。
 */

export const DISCLAIMER_VERSION = 'v3'   // 条款版本：条款实质变更时递增（v3=替换为注册协议+隐私规则+激活承诺三份正式文本，旧 v2 签署失效需重签）

export const DISCLAIMER_TITLE = computed(() => translate('ui.m_82e60434b08f'))

/** 分段条款：每段一个小标题 + 若干条。手册与弹窗共用。三份文本以醒目小标题分隔。 */
export const DISCLAIMER_SECTIONS = computed<{ h: string; items: string[] }[]>(() => [
  {
    get h() { return translate('ui.m_8936cfd3ec96') },
    items: [
      translate('ui.m_547d3b6540cd'),
      translate('ui.m_09d0d41b5d81'),
    ],
  },
  {
    get h() { return translate('ui.m_6ffd5743c68d') },
    items: [
      translate('ui.m_bc6e17b891ca'),
      translate('ui.m_15a96838d6ac'),
      translate('ui.m_6d2d4143d2aa'),
      translate('ui.m_901f37da439a'),
    ],
  },
  {
    get h() { return translate('ui.m_3254953fec8f') },
    items: [
      translate('ui.m_02f4f9dfb68d'),
      translate('ui.m_6012cd1ff237'),
      translate('ui.m_2fadb9529f4c'),
    ],
  },
  {
    get h() { return translate('ui.m_7c81b69ddfec') },
    items: [
      translate('ui.m_315ce6f815f5'),
      translate('ui.m_50eee4bcb987'),
      translate('ui.m_8fac1125e5b0'),
    ],
  },
  {
    get h() { return translate('ui.m_4e9e6a518c32') },
    items: [
      translate('ui.m_64ce3fd33b55'),
      translate('ui.m_da2554fadb84'),
      translate('ui.m_70fd9ac59ee5'),
      translate('ui.m_d7ead82ed6aa'),
      translate('ui.m_1aa618f18338'),
    ],
  },
  {
    get h() { return translate('ui.m_4f2be8fd0021') },
    items: [
      translate('ui.m_cc5e52df6397'),
      translate('ui.m_631b52ebf035'),
      translate('ui.m_52fbc80535a7'),
      translate('ui.m_d07e3cb877eb'),
    ],
  },
  {
    get h() { return translate('ui.m_1ee716682a5e') },
    items: [
      translate('ui.m_124b5fe72b6d'),
      translate('ui.m_fa1666835eb1'),
      translate('ui.m_4e1ff34bd5ee'),
      translate('ui.m_debe3847f4fc'),
      translate('ui.m_f47dcc842c09'),
      translate('ui.m_0e465dc0b55f'),
    ],
  },
  {
    get h() { return translate('ui.m_792bb5fea949') },
    items: [
      translate('ui.m_3f284679a0fc'),
      translate('ui.m_7b14ea6f679d'),
      translate('ui.m_07ce2fb1b703'),
      translate('ui.m_8389dfe7aebf'),
    ],
  },
  {
    get h() { return translate('ui.m_f7ac40db43e7') },
    items: [
      translate('ui.m_6e270dd0c414'),
      translate('ui.m_5cb4c5e45f8e'),
      translate('ui.m_ebca0250fe3d'),
      translate('ui.m_9d59eeeaca66'),
    ],
  },
  {
    get h() { return translate('ui.m_d92df8b8532f') },
    items: [
      translate('ui.m_8450b5c91558'),
      translate('ui.m_bc0cb74d7b9e'),
      translate('ui.m_831391b3a289'),
      translate('ui.m_9a33f667ae34'),
    ],
  },
  {
    get h() { return translate('ui.m_ccd4278e7f57') },
    items: [
      translate('ui.m_136d94942fd1'),
      translate('ui.m_671d07370288'),
      translate('ui.m_d81929439525'),
      translate('ui.m_0f9dd75193c2'),
    ],
  },
])

/** 弹窗底部的一句话确认语（覆盖三份文本）。 */
export const DISCLAIMER_AGREE_TEXT = computed(() => translate('ui.m_16577f488597') +
  translate('ui.m_b67ac690b3c0'))
