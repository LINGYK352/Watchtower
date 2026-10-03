<template>
  <div>
    <a-alert
      class="page-alert"
      type="info"
      show-icon
      :message="translate('ui.m_dbeb89948740')"
    />

    <!-- ① 平台代理模式：4模式(直连/全局/规则/智能)×3源(自定义/机场/公共代理)。
         本区配「全局代理」和「智能代理」各绑哪个源(3选一)；策略页选 direct/global/smart 时套用。 -->
    <a-card class="page-card netmode-card" :title="translate('ui.m_4fa362683021')" size="small">
      <template #extra><a-button size="small" type="primary" :loading="modeSaving" @click="saveMode">{{ translate('ui.m_a3030bf8f16d') }}</a-button></template>
      <!-- 顶层总开关：直连（默认）/ 启用代理。直连时全局+智能配置禁用 -->
      <a-radio-group v-model:value="platformTop" button-style="solid" class="top-radios">
        <a-radio-button value="direct">{{ translate('ui.m_a2895bde5c79') }}</a-radio-button>
        <a-radio-button value="proxy">{{ translate('ui.m_36c4b473328f') }}</a-radio-button>
      </a-radio-group>
      <a-alert v-if="platformTop === 'direct'" type="success" show-icon banner class="mode-intro" style="margin-top:12px"
        :message="translate('ui.m_3e90e7c33eca')" />
      <template v-else>
        <a-alert type="info" show-icon banner class="mode-intro" style="margin-top:12px"
          :message="translate('ui.m_16215fdeb946')" />
        <a-row :gutter="16" style="margin-top:12px">
          <a-col :xs="24" :md="12">
            <div class="mode-block" :class="{ 'mode-on': globalForm.enabled }">
              <div class="mode-block-head">
                <span class="mode-name">{{ translate('ui.m_47a6434fe7b6') }} <a-tag color="blue">global</a-tag></span>
                <a-switch v-model:checked="globalForm.enabled" checked-children="开" un-checked-children="关" />
              </div>
              <SrcPicker v-if="globalForm.enabled" :src="globalForm.source" :customs="customs" @update="(s:ProxySource)=>globalForm.source=s" />
              <div class="hint">{{ translate('ui.m_c17ff8f56f02') }}</div>
            </div>
          </a-col>
          <a-col :xs="24" :md="12">
            <div class="mode-block mode-on">
              <div class="mode-block-head"><span class="mode-name">{{ translate('ui.m_7b026997bac4') }} <a-tag color="green">smart</a-tag></span></div>
              <SrcPicker :src="smartForm.source" :customs="customs" @update="(s:ProxySource)=>smartForm.source=s" />
              <div class="hint">{{ translate('ui.m_4737d54672e4') }}</div>
            </div>
          </a-col>
        </a-row>
      </template>
    </a-card>

    <!-- ② 运行状态 + 出口 IP（公共信息，突出不折叠） -->
    <a-card class="page-card status-card">
      <template #title>
        <a-space>
          <span>{{ translate('ui.m_e46b0272bd64') }}</span>
          <a-badge v-if="!status?.running" status="default" text="内核未运行" />
          <a-badge v-else-if="status?.last_health_ok" status="processing" text="运行中 · 代理可用" />
          <a-badge v-else status="error" text="运行中 · 代理不可用" />
        </a-space>
      </template>
      <template #extra><a-button size="small" @click="loadAll">{{ translate('ui.m_aee887434131') }}</a-button></template>
      <!-- 出口 IP 大字对比（最直观的"代理生不生效"）-->
      <a-row :gutter="16" class="exit-row">
        <a-col :xs="24" :sm="8">
          <div class="exit-box" :class="exitBoxClass">
            <div class="exit-k">{{ translate('ui.m_c2d411a98923') }}</div>
            <div class="exit-v">{{ status?.last_exit_ip || exitResult?.proxy_ip || exitResult?.direct_ip || '—' }}</div>
            <div class="exit-tag">
              <a-tag v-if="exitResult?.proxied" color="green">{{ translate('ui.m_00c682cdcc54') }}</a-tag>
              <a-tag v-else-if="exitProxyUnreachable" color="red">{{ translate('ui.m_2469998ac9e4') }}</a-tag>
              <a-tag v-else color="default">{{ translate('ui.m_6d7cb8fad1d2') }}</a-tag>
            </div>
          </div>
        </a-col>
        <a-col :xs="24" :sm="16">
          <a-descriptions :column="{ xs: 1, sm: 2 }" size="small" bordered>
            <a-descriptions-item :label="translate('ui.m_416baf7ad2a7')">
              <a-tag :color="status?.running ? 'success' : 'default'">{{ status?.running ? translate('ui.m_1f0eb99b7ed0') : translate('ui.m_62cdc8713bcf') }}</a-tag>
              <span class="muted" style="font-size:12px">{{ translate('ui.m_19fdba1f7361') }}</span>
            </a-descriptions-item>
            <a-descriptions-item :label="translate('ui.m_ccc148ea9788')">{{ status?.pid || '-' }}</a-descriptions-item>
            <a-descriptions-item :label="translate('ui.m_4696e67647af')">{{ status?.config?.active_profile_id || translate('ui.m_fdc1183b6810') }}</a-descriptions-item>
            <a-descriptions-item :label="translate('ui.m_c29326ab330d')"><a-typography-text :copyable="!!status?.proxy_url" :content="status?.proxy_url || '-'" /></a-descriptions-item>
            <a-descriptions-item :label="translate('ui.m_c9859a7f6cc3')" :span="2">
              <a-tag :color="status?.last_health_ok ? 'success' : 'error'">{{ status?.last_health_ok ? translate('ui.m_296de0e31f8c') : translate('ui.m_428fb8bfeecf') }}</a-tag>
              <span v-if="status?.last_health_check_time" style="color:#999;font-size:12px">{{ status?.last_health_check_time }}</span>
              <span v-if="!status?.last_health_ok && status?.last_health_error" style="color:#cf1322">（{{ status?.last_health_error }}）</span>
            </a-descriptions-item>
          </a-descriptions>
        </a-col>
      </a-row>
      <a-alert v-if="exitResult && !exitResult.proxied && exitProxyUnreachable" type="error" show-icon style="margin-top:12px"
        :message="translate('ui.m_31e376a1d0d6') + (exitResult.error || translate('ui.m_3a12fbef48fe')) + translate('ui.m_953efc17b560')" />
      <a-space class="card-actions" wrap style="margin-top: 14px">
        <!-- mihomo 独立容器由 compose 管生命周期(restart:unless-stopped 自愈)，无需手动启停内核，故删启动/停止/重启按钮。
             改配置(节点/订阅)经 controller 热 reload 生效。保留出口 IP 检测。 -->
        <a-button :loading="exitLoading" @click="checkExitIp">{{ translate('ui.m_3073bade4934') }}</a-button>
      </a-space>
    </a-card>
    <!-- ③ 流量消耗（公共信息，突出不折叠） -->
    <a-card class="page-card" size="small">
      <template #title>
        <a-space>
          <span>{{ translate('ui.m_effbbec31497') }}</span>
          <a-button type="link" size="small" @click="loadTraffic">{{ translate('ui.m_aee887434131') }}</a-button>
          <ConfirmAction danger size="small" type="link" :title="translate('ui.m_c80c340216bd')" @confirm="resetTrafficAll">{{ translate('ui.m_d75292a9941b') }}</ConfirmAction>
        </a-space>
      </template>
      <a-row :gutter="16">
        <a-col :span="6"><a-statistic :title="translate('ui.m_13839d7727ff')" :value="traffic?.total_up_h || '0B'" /></a-col>
        <a-col :span="6"><a-statistic :title="translate('ui.m_3c7acac1de25')" :value="traffic?.total_down_h || '0B'" /></a-col>
        <a-col :span="6"><a-statistic :title="translate('ui.m_042e5887ea1f')" :value="traffic?.connections ?? 0" /></a-col>
        <a-col :span="6"><a-statistic :title="translate('ui.m_416baf7ad2a7')" :value="traffic?.running ? '运行中' : '未运行'" :value-style="{ color: traffic?.running ? '#3f8600' : '#999' }" /></a-col>
      </a-row>
      <a-alert v-if="traffic && !traffic.running" type="info" show-icon style="margin-top:10px" :message="translate('ui.m_5c2b2f90c250')" />
      <a-tabs v-if="traffic && (traffic.by_profile?.length || traffic.by_node?.length)" size="small" style="margin-top:12px">
        <a-tab-pane key="profile" tab="按机场订阅">
          <a-table :columns="profileCols" :data-source="traffic.by_profile" row-key="key" size="small" :pagination="false">
            <template #bodyCell="{ column, record }">
              <template v-if="column.key === 'act'">
                <ConfirmAction danger size="small" type="link" :title="translate('ui.m_861e75417ee3')" @confirm="() => resetTraffic('profile', record.key)">{{ translate('ui.m_1ef3de06b32e') }}</ConfirmAction>
              </template>
            </template>
          </a-table>
        </a-tab-pane>
        <a-tab-pane key="node" tab="按节点">
          <a-table :columns="nodeCols" :data-source="traffic.by_node" row-key="key" size="small" :pagination="{ pageSize: 10 }">
            <template #bodyCell="{ column, record }">
              <template v-if="column.key === 'act'">
                <ConfirmAction danger size="small" type="link" :title="translate('ui.m_6252e9d65e53')" @confirm="() => resetTraffic('node', record.key)">{{ translate('ui.m_1ef3de06b32e') }}</ConfirmAction>
              </template>
            </template>
          </a-table>
        </a-tab-pane>
      </a-tabs>
    </a-card>

    <!-- ④ 代理源配置（全部折叠：自定义 / mihomo机场 / 公共代理 / 内核日志 / 基础配置） -->
    <a-collapse class="page-card src-collapse">
      <!-- 自定义代理 -->
      <a-collapse-panel key="custom">
        <template #header><span class="cp-h">{{ translate('ui.m_b5f943f6f042') }}</span><span class="cp-sub">{{ customs.length }} {{ translate('ui.m_0d9651ec92f7') }}</span></template>
        <template #extra><a-button size="small" type="primary" @click.stop="openCustom()">{{ translate('ui.m_0006d696d8e1') }}</a-button></template>
        <a-table :columns="customCols" :data-source="customs" :loading="customLoading" row-key="_id" :pagination="false" size="small">
          <template #bodyCell="{ column, record }">
            <template v-if="column.key === 'enabled'"><a-switch :checked="record.enabled" size="small" @change="(v: any) => toggleCustom(record, !!v)" /></template>
            <template v-else-if="column.key === 'health'">
              <a-tag v-if="record.last_health_ok === true" color="green">{{ translate('ui.m_53c67f0a00ba') }}</a-tag>
              <a-tag v-else-if="record.last_health_ok === false" color="red">{{ translate('ui.m_24c6481c0883') }}</a-tag>
              <a-tag v-else color="default">{{ translate('ui.m_c3eb5da0453e') }}</a-tag>
            </template>
            <template v-else-if="column.key === 'act'">
              <a-space>
                <a @click="testCustom(record)">{{ translate('ui.m_6aa8f49cc992') }}</a>
                <a @click="openCustom(record)">{{ translate('ui.m_051836569928') }}</a>
                <a-popconfirm :title="translate('ui.m_4f5e0eee1f3d')" @confirm="delCustom(record)"><a class="danger">{{ translate('ui.m_2f9daa828907') }}</a></a-popconfirm>
              </a-space>
            </template>
          </template>
        </a-table>
      </a-collapse-panel>

      <!-- 内核代理（mihomo）：订阅导入 + YAML 上传 + 配置列表 + 代理组节点 + 内核基础配置，全并入此折叠 -->
      <a-collapse-panel key="mihomo">
        <template #header><span class="cp-h">{{ translate('ui.m_7c140e4cb81e') }}</span><span class="cp-sub">{{ profiles.length }} {{ translate('ui.m_7dbe94dd5ac0') }}</span></template>
        <a-row :gutter="16">
          <a-col :xs="24" :lg="12">
            <div class="sub-block">
              <div class="sub-title">{{ translate('ui.m_25bcdf7f86c4') }}</div>
              <a-input v-model:value="importForm.name" :placeholder="translate('ui.m_9919db867bd4')" style="margin-bottom:8px" />
              <a-input v-model:value="importForm.url" :placeholder="translate('ui.m_24c5cddfb643')" style="margin-bottom:8px" />
              <a-button type="primary" size="small" :loading="loading" @click="importUrl">{{ translate('ui.m_a29a272c0e06') }}</a-button>
            </div>
          </a-col>
          <a-col :xs="24" :lg="12">
            <div class="sub-block">
              <div class="sub-title">{{ translate('ui.m_bfc0aa508798') }}</div>
              <a-input v-model:value="uploadForm.name" :placeholder="translate('ui.m_9919db867bd4')" style="margin-bottom:8px" />
              <a-upload :before-upload="beforeYamlUpload" :show-upload-list="false" accept=".yaml,.yml,.txt">
                <a-button size="small" style="margin-bottom:8px"><template #icon><UploadOutlined /></template>{{ translate('ui.m_822fb37dba29') }}</a-button>
              </a-upload>
              <a-textarea v-model:value="uploadForm.content" :rows="3" :placeholder="translate('ui.m_3d242483b53c')" style="margin-bottom:8px" />
              <a-button type="primary" size="small" :loading="loading" @click="uploadProfile">{{ translate('ui.m_c9e5e8908558') }}</a-button>
            </div>
          </a-col>
        </a-row>
        <div class="sub-title" style="margin-top:12px">{{ translate('ui.m_5305214750a5') }}</div>
        <a-table :columns="profileColumns" :data-source="profiles" row-key="_id" :pagination="false" size="small">
          <template #bodyCell="{ column, record }">
            <template v-if="column.key === 'action'"><a-button type="link" size="small" @click="activate(record._id)">{{ translate('ui.m_dd1286c29e9b') }}</a-button></template>
          </template>
        </a-table>
        <!-- 代理组/节点（内层折叠，节点多时收起） -->
        <a-collapse v-model:activeKey="groupsCardOpen" style="margin-top:12px">
          <a-collapse-panel key="groups">
            <template #header><span>{{ translate('ui.m_a82d0cca4b3f') }}</span><span class="cp-sub">{{ selectableGroups.length ? selectableGroups.length + translate('ui.m_a9f463237ae2') : translate('ui.m_5673b042ee1f') }}</span></template>
            <template #extra>
              <a-space @click.stop>
                <a-button size="small" @click="loadProxies">{{ translate('ui.m_778b04988d4f') }}</a-button>
                <a-button size="small" type="primary" @click="autoSelect">{{ translate('ui.m_1af4eae8c1a5') }}</a-button>
              </a-space>
            </template>
            <a-empty v-if="!selectableGroups.length" :description="translate('ui.m_32d4e91ed275')" />
            <a-collapse v-else v-model:activeKey="activeGroupKeys" class="proxy-collapse">
              <a-collapse-panel v-for="group in selectableGroups" :key="group.name">
                <template #header><span style="font-weight:500">{{ group.name }}</span><a-tag color="blue" style="margin-left:8px">{{ translate('ui.m_660648805666') }}{{ group.now || '-' }}</a-tag><span class="cp-sub">{{ group.all.length }} {{ translate('ui.m_2410d860f093') }}</span></template>
                <a-space wrap>
                  <a-button v-for="node in group.all" :key="node" size="small" :type="node === group.now ? 'primary' : 'default'" @click="selectProxy(group.name, node)">{{ node }}</a-button>
                </a-space>
              </a-collapse-panel>
            </a-collapse>
          </a-collapse-panel>
        </a-collapse>
        <!-- 内核基础配置（端口/熔断/DoH，属 mihomo 内核，并入本折叠） -->
        <a-divider orientation="left" style="margin-top:14px">{{ translate('ui.m_8a815f415b0b') }}</a-divider>
        <a-form layout="vertical" :model="form">
          <a-row :gutter="16">
            <!-- 删「启用代理」开关：mihomo 独立容器由 compose 常驻自愈，内核恒启用（是否真走代理由顶层「直连/启用代理」
                 总开关 + 各模式源绑定决定，不需内核级启用开关）。form.enabled 保存时恒置 true(见 saveConfig)。 -->
            <a-col :xs="24" :md="6"><a-form-item :label="translate('ui.m_dd7ae0b1e668')"><a-switch v-model:checked="form.auto_select" checked-children="启用" un-checked-children="关闭" /></a-form-item></a-col>
            <a-col :xs="24" :md="6"><a-form-item :label="translate('ui.m_1f8158d17dd9')"><a-input-number v-model:value="form.controller_port" :min="1" :max="65535" class="full" /></a-form-item></a-col>
            <a-col :xs="24" :md="6"><a-form-item :label="translate('ui.m_103215b7c2bb')"><a-input-number v-model:value="form.http_port" :min="1" :max="65535" class="full" /></a-form-item></a-col>
            <a-col :xs="24" :md="6"><a-form-item :label="translate('ui.m_cd476d2a8717')"><a-input-number v-model:value="form.socks_port" :min="1" :max="65535" class="full" /></a-form-item></a-col>
            <a-col :xs="24" :md="6"><a-form-item :label="translate('ui.m_3ba40d64a964')"><a-input-number v-model:value="form.mixed_port" :min="1" :max="65535" class="full" /></a-form-item></a-col>
            <a-col :xs="24" :md="12"><a-form-item :label="translate('ui.m_11c9b0f23db4')"><a-input v-model:value="form.test_url" /></a-form-item></a-col>
          </a-row>
          <a-divider orientation="left" style="margin-top: 4px">{{ translate('ui.m_6d825943bd10') }}</a-divider>
          <a-row :gutter="16">
            <a-col :xs="24" :md="12"><a-form-item :label="translate('ui.m_d90e44ea56d3')"><a-input v-model:value="form.health_check_url" placeholder="https://www.gstatic.com/generate_204" /></a-form-item></a-col>
            <a-col :xs="24" :md="6"><a-form-item :label="translate('ui.m_ca7ed1f3a74d')"><a-input-number v-model:value="form.health_check_interval" :min="10" class="full" /></a-form-item></a-col>
            <a-col :xs="24" :md="6"><a-form-item :label="translate('ui.m_74106a5df046')"><a-input-number v-model:value="form.health_fail_threshold" :min="1" :max="10" class="full" /></a-form-item></a-col>
          </a-row>
          <a-form-item :label="translate('ui.m_efdc92c8a66d')"><a-textarea v-model:value="dohText" :rows="2" placeholder="https://dns.alidns.com/resolve" /></a-form-item>
          <a-button type="primary" size="small" :loading="loading" @click="saveConfig">{{ translate('ui.m_d6039c4b243c') }}</a-button>
        </a-form>
      </a-collapse-panel>

      <!-- 公共代理（原公开抓取代理池） -->
      <a-collapse-panel key="pool">
        <template #header><span class="cp-h">{{ translate('ui.m_be7654e5e349') }}</span><span class="cp-sub">{{ poolStats?.alive ?? '-' }}/{{ poolStats?.total ?? '-' }} {{ translate('ui.m_3942cbf29122') }}</span></template>
        <template #extra>
          <a-space @click.stop>
            <a-button size="small" @click="loadPool">{{ translate('ui.m_aee887434131') }}</a-button>
            <a-button size="small" type="primary" :loading="poolCrawling" @click="crawlPool">{{ translate('ui.m_851758e4fb63') }}</a-button>
            <a-button size="small" :loading="poolVerifying" @click="verifyPool()">{{ translate('ui.m_e46320670dd8') }}</a-button>
          </a-space>
        </template>
        <a-alert type="warning" show-icon style="margin-bottom:12px"
          :message="translate('ui.m_44cbe86dbe6e')" />
        <a-descriptions :column="{ xs: 2, sm: 5 }" size="small" bordered style="margin-bottom:12px">
          <a-descriptions-item :label="translate('ui.m_5953fc09384f')">{{ poolStats?.total ?? '-' }}</a-descriptions-item>
          <a-descriptions-item :label="translate('ui.m_4d99c976beb8')">{{ poolStats?.alive ?? '-' }}</a-descriptions-item>
          <a-descriptions-item :label="translate('ui.m_1559a0a78fce')">{{ poolStats?.dead ?? '-' }}</a-descriptions-item>
          <a-descriptions-item :label="translate('ui.m_e5abf02cfe9e')">{{ poolStats?.unchecked ?? '-' }}</a-descriptions-item>
          <a-descriptions-item :label="translate('ui.m_f4f0ead1116b')">{{ poolStats?.enabled ?? '-' }}</a-descriptions-item>
        </a-descriptions>
        <a-collapse style="margin-bottom:12px">
          <a-collapse-panel key="cfg" header="抓取配置（查询语法 / 期望总量，0=不限）">
            <div v-for="(q, i) in poolCfg.queries" :key="i" style="display:flex;gap:8px;align-items:center;margin-bottom:8px;flex-wrap:wrap">
              <a-select v-model:value="q.source" style="width:90px" size="small" :options="[{value:'fofa',label:'FOFA'},{value:'hunter',label:'Hunter'}]" />
              <a-select v-model:value="q.type" style="width:90px" size="small" :options="[{value:'socks5',label:'socks5'},{value:'http',label:'http'}]" />
              <a-input v-model:value="q.q" size="small" style="flex:1;min-width:180px" :placeholder="translate('ui.m_0778983d2ceb')" />
              <a-switch v-model:checked="q.enabled" size="small" checked-children="启用" un-checked-children="停用" />
              <a-button size="small" danger type="link" @click="poolCfg.queries.splice(i,1)">{{ translate('ui.m_2f9daa828907') }}</a-button>
            </div>
            <a-space>
              <a-button size="small" @click="poolCfg.queries.push({source:'fofa',type:'socks5',q:'protocol=\'socks5\'',enabled:true})">{{ translate('ui.m_c06e7ce0f822') }}</a-button>
              <span>{{ translate('ui.m_6dffd126484f') }}</span>
              <a-input-number v-model:value="poolCfg.limit" :min="0" size="small" style="width:100px" />
              <a-button size="small" type="primary" @click="savePoolCfg">{{ translate('ui.m_6e584e3d5ce6') }}</a-button>
            </a-space>
          </a-collapse-panel>
        </a-collapse>
        <a-space style="margin-bottom:8px" wrap>
          <span>{{ translate('ui.m_4e1449e7d5e5') }}</span>
          <a-radio-group v-model:value="poolStatus" button-style="solid" size="small" @change="()=>{poolPage=1;loadPool()}">
            <a-radio-button value="alive">{{ translate('ui.m_b994669232e7') }}</a-radio-button>
            <a-radio-button value="">{{ translate('ui.m_5c55a67935af') }}</a-radio-button>
            <a-radio-button value="dead">{{ translate('ui.m_1559a0a78fce') }}</a-radio-button>
            <a-radio-button value="unchecked">{{ translate('ui.m_e5abf02cfe9e') }}</a-radio-button>
          </a-radio-group>
          <a-divider type="vertical" />
          <a-button size="small" :disabled="!poolSel.length" @click="verifyPool(poolSel)">{{ translate('ui.m_4d800c6416fd') }}</a-button>
          <a-button size="small" :disabled="!poolSel.length" @click="enablePool(poolSel, true)">{{ translate('ui.m_696025432811') }}</a-button>
          <a-button size="small" :disabled="!poolSel.length" @click="enablePool(poolSel, false)">{{ translate('ui.m_b07b51d47814') }}</a-button>
          <ConfirmAction danger size="small" :disabled="!poolSel.length" :title="translate('ui.m_0e8e67487022')" @confirm="() => deletePool(poolSel)">{{ translate('ui.m_469f67cf665e') }}</ConfirmAction>
        </a-space>
        <a-table :columns="poolColumns" :data-source="poolItems" row-key="_id" size="small"
          :row-selection="{ selectedRowKeys: poolSel, onChange: (k:any)=>poolSel=k }"
          :pagination="{ current: poolPage, pageSize: poolSize, total: poolTotal, onChange: (p:number)=>{poolPage=p;loadPool()} }">
          <template #bodyCell="{ column, record }">
            <template v-if="column.key === 'delay'">
              <a-tag v-if="record.delay === null" color="default">{{ translate('ui.m_e5abf02cfe9e') }}</a-tag>
              <a-tag v-else-if="record.delay < 0" color="error">{{ translate('ui.m_1559a0a78fce') }}</a-tag>
              <a-tag v-else :color="record.delay < 1500 ? 'success' : 'warning'">{{ record.delay }}ms</a-tag>
            </template>
            <template v-else-if="column.key === 'enabled'"><a-switch :checked="record.enabled" size="small" @change="(v:boolean)=>enablePool([record._id], v)" /></template>
            <template v-else-if="column.key === 'action'">
              <a-space>
                <a-button size="small" type="link" @click="verifyPool([record._id])">{{ translate('ui.m_687809210499') }}</a-button>
                <ConfirmAction danger size="small" type="link" :title="translate('ui.m_6c54d847bd5d')" @confirm="() => deletePool([record._id])">{{ translate('ui.m_2f9daa828907') }}</ConfirmAction>
              </a-space>
            </template>
          </template>
        </a-table>
      </a-collapse-panel>

      <!-- 内核日志 -->
      <a-collapse-panel key="logs">
        <template #header><span class="cp-h">{{ translate('ui.m_4fdb0cd045bf') }}</span></template>
        <template #extra><a-button size="small" @click.stop="loadLogs">{{ translate('ui.m_aee887434131') }}</a-button></template>
        <pre class="log-box">{{ logs || translate('ui.m_10fafbeaa7fd') }}</pre>
      </a-collapse-panel>

    </a-collapse>

    <!-- 自定义代理编辑弹窗 -->
    <a-modal v-model:open="customOpen" :title="customForm._id ? translate('ui.m_ca391aa29198') : translate('ui.m_f0b242d61d9f')"
      :confirm-loading="customSaving" @ok="saveCustom">
      <a-form layout="vertical">
        <a-form-item :label="translate('ui.m_d44e9b3d3b31')"><a-input v-model:value="customForm.name" :placeholder="translate('ui.m_a32346d4cf0a')" /></a-form-item>
        <a-form-item :label="translate('ui.m_bc95d6b6890e')">
          <a-input v-model:value="customForm.url" :placeholder="translate('ui.m_a9257f172186')" />
          <div class="hint">{{ translate('ui.m_641f1ae35157') }}</div>
        </a-form-item>
        <a-space><span>{{ translate('ui.m_f4f0ead1116b') }}</span><a-switch v-model:checked="customForm.enabled" /></a-space>
      </a-form>
    </a-modal>
  </div>
</template>
<script setup lang="ts">
import { t as translate } from '../../i18n'

import { computed, onMounted, reactive, ref, h } from 'vue'
import { message, Modal, RadioGroup, RadioButton, Select } from 'ant-design-vue'
import { UploadOutlined } from '@ant-design/icons-vue'
import { proxyApi, type ProxyConfig, type ProxyProfile, type ProxyStatus, type ExitIpResult, type ProxyTraffic, type PoolProxy, type PoolStats, type PoolConfig, type CustomProxy, type ProxySource } from '../../api/proxy'
import ConfirmAction from '../../components/ConfirmAction.vue'

const profileCols = [
  { get title() { return translate('ui.m_11f8f3d952a7') }, dataIndex: 'name', key: 'name', ellipsis: true },
  { get title() { return translate('ui.m_9043e17f4fbe') }, dataIndex: 'up_h', key: 'up_h', width: 110 },
  { get title() { return translate('ui.m_1cc22077b864') }, dataIndex: 'down_h', key: 'down_h', width: 110 },
  { get title() { return translate('ui.m_ed31fbb483ee') }, key: 'act', width: 70 }
]
const nodeCols = [
  { get title() { return translate('ui.m_2410d860f093') }, dataIndex: 'name', key: 'name', ellipsis: true },
  { get title() { return translate('ui.m_f0d0533e8d07') }, dataIndex: 'profile_name', key: 'profile_name', ellipsis: true },
  { get title() { return translate('ui.m_9043e17f4fbe') }, dataIndex: 'up_h', key: 'up_h', width: 110 },
  { get title() { return translate('ui.m_1cc22077b864') }, dataIndex: 'down_h', key: 'down_h', width: 110 },
  { get title() { return translate('ui.m_ed31fbb483ee') }, key: 'act', width: 70 }
]

const loading = ref(false)
const status = ref<ProxyStatus>()
const traffic = ref<ProxyTraffic>()
const profiles = ref<ProxyProfile[]>([])
const proxies = ref<Record<string, any>>({})
const logs = ref('')

// 公共代理（原公开抓取代理池）
const poolStats = ref<PoolStats>()
const poolItems = ref<PoolProxy[]>([])
const poolSel = ref<string[]>([])
const poolPage = ref(1)
const poolSize = ref(50)
const poolTotal = ref(0)
const poolCrawling = ref(false)
const poolVerifying = ref(false)
const poolStatus = ref('alive')
const poolCfg = reactive<PoolConfig>({ queries: [], limit: 100 })
const poolColumns = [
  { get title() { return translate('ui.m_ba40014ff496') }, dataIndex: 'type', key: 'type', width: 70 },
  { title: 'IP', dataIndex: 'host', key: 'host', ellipsis: true },
  { get title() { return translate('ui.m_e71ac32b544b') }, dataIndex: 'port', key: 'port', width: 70 },
  { get title() { return translate('ui.m_0cc659a9f57c') }, dataIndex: 'country', key: 'country', width: 90, ellipsis: true },
  { get title() { return translate('ui.m_ee3b1e6332b5') }, key: 'delay', width: 90 },
  { get title() { return translate('ui.m_a488e93d69cc') }, dataIndex: 'source', key: 'source', width: 70 },
  { get title() { return translate('ui.m_b8639bf714f7') }, dataIndex: 'last_check', key: 'last_check', width: 150, ellipsis: true },
  { get title() { return translate('ui.m_f4f0ead1116b') }, key: 'enabled', width: 60 },
  { get title() { return translate('ui.m_ed31fbb483ee') }, key: 'action', width: 110 }
]

const form = reactive<ProxyConfig>({
  enabled: false, mode: 'rule', http_port: 7890, socks_port: 7891, mixed_port: 7892,
  controller_port: 9090, auto_select: true, test_url: 'https://www.gstatic.com/generate_204',
  health_check_url: 'https://www.gstatic.com/generate_204', health_check_interval: 60, health_fail_threshold: 3
})
const importForm = reactive({ name: '', url: '' })
const uploadForm = reactive({ name: '', content: '' })
const dohText = ref('')
const exitResult = ref<ExitIpResult | null>(null)
// 代理不可达=网络异常：代理已启用(error 非"未启用")但探不到代理出口 IP
const exitProxyUnreachable = computed(() => {
  const r = exitResult.value; if (!r) return false
  const err = String((r as { error?: string }).error || '')
  return !r.proxied && !r.proxy_ip && err !== '' && err !== 'proxy not enabled'
})
const exitBoxClass = computed(() => exitResult.value?.proxied ? 'exit-ok' : (exitProxyUnreachable.value ? 'exit-err' : 'exit-direct'))
const exitLoading = ref(false)

const profileColumns = [
  { get title() { return translate('ui.m_d44e9b3d3b31') }, dataIndex: 'name' },
  { get title() { return translate('ui.m_a488e93d69cc') }, dataIndex: 'source' },
  { get title() { return translate('ui.m_2410d860f093') }, dataIndex: 'proxy_count' },
  { get title() { return translate('ui.m_d2fb017efc97') }, dataIndex: 'group_count' },
  { get title() { return translate('ui.m_ed31fbb483ee') }, key: 'action' }
]
const customCols = [
  { get title() { return translate('ui.m_d44e9b3d3b31') }, dataIndex: 'name', key: 'name', ellipsis: true },
  { title: 'URL', dataIndex: 'url', key: 'url', ellipsis: true },
  { get title() { return translate('ui.m_f4f0ead1116b') }, key: 'enabled', width: 70 },
  { get title() { return translate('ui.m_aa18b6dcd893') }, key: 'health', width: 90 },
  { get title() { return translate('ui.m_ed31fbb483ee') }, key: 'act', width: 150 }
]

// coreReady 已删：独立容器架构下 mihomo_bin(web容器内探二进制)恒空→误判"缺失"，内核状态改只看 controller 探活(status.running)
const selectableGroups = computed(() => Object.entries(proxies.value)
  .filter(([, info]) => Array.isArray(info?.all))
  .map(([name, info]) => ({ name, ...info })))
const activeGroupKeys = ref<string[]>([])
const groupsCardOpen = ref<string[]>([])

// —— 平台代理模式（4模式×3源，对齐设计）：本区配 global/smart 两个模式各绑哪个源 ——
// global_mode_enabled=全局开关；global_source/smart_source={type:custom/subscription/pool, ref_id}
const platformTop = ref<'direct' | 'proxy'>('direct')   // 顶层：直连(默认)/启用代理
const globalForm = reactive<{ enabled: boolean; source: ProxySource }>({ enabled: false, source: { type: 'subscription', ref_id: '' } })
const smartForm = reactive<{ source: ProxySource }>({ source: { type: 'subscription', ref_id: '' } })
const modeSaving = ref(false)
const customs = ref<CustomProxy[]>([])
const customLoading = ref(false)
// 内联「源选择器」：3源(自定义/机场/公共代理)单选 + 自定义时选具体条目
const SrcPicker = (props: { src: ProxySource; customs: CustomProxy[] }, ctx: any) => {
  const src = props.src || { type: 'subscription', ref_id: '' }
  const enabledCustoms = (props.customs || []).filter(c => c.enabled)
  const typeRadios = h(RadioGroup as any, {
    value: src.type, size: 'small', buttonStyle: 'solid',
    'onUpdate:value': (v: string) => ctx.emit('update', { type: v, ref_id: v === 'custom' ? (src.ref_id || (enabledCustoms[0]?._id || '')) : '' })
  }, () => [
    h(RadioButton as any, { value: 'custom' }, () => '🧩 自定义'),
    h(RadioButton as any, { value: 'subscription' }, () => '✈️ 内核代理'),
    h(RadioButton as any, { value: 'pool' }, () => '🌐 公共代理')
  ])
  const children: any[] = [typeRadios]
  if (src.type === 'custom') {
    children.push(h(Select as any, {
      value: src.ref_id || undefined, size: 'small', style: 'min-width:200px;margin-left:8px',
      get placeholder() { return translate('ui.m_7dc5dd5bdff1') },
      options: enabledCustoms.map(c => ({ label: c.name + ' (' + c.url + ')', value: c._id })),
      'onUpdate:value': (v: string) => ctx.emit('update', { type: 'custom', ref_id: v })
    }))
    if (!enabledCustoms.length) children.push(h('span', { class: 'hint', style: 'margin-left:8px' }, '无可用自定义代理，去下方新增'))
  }
  return h('div', { class: 'src-picker' }, children)
}
async function saveMode() {
  // 直连模式：全局关闭；智能源也置直连(subscription空占位，实际直连时策略选smart会降级)。
  if (platformTop.value === 'direct') {
    modeSaving.value = true
    try {
      await proxyApi.saveConfig({ global_mode_enabled: false, global_source: { type: 'subscription', ref_id: '' }, smart_source: { type: 'subscription', ref_id: '' } })
      message.success(translate('ui.m_1573747cb18b'))
    } catch (e) { message.error((e as Error).message) } finally { modeSaving.value = false }
    return
  }
  // 启用代理：先做前置结构性校验（即时提示，不必等后端往返）——只查源是否为空，不探可达性。
  const preErr = validateSourceLocal(globalForm.enabled ? globalForm.source : null, '全局代理')
    || (isSourceConfigured(smartForm.source) ? validateSourceLocal(smartForm.source, '智能代理') : '')
  if (preErr) { message.error(preErr); return }
  modeSaving.value = true
  try {
    const res: any = await proxyApi.saveConfig({
      global_mode_enabled: globalForm.enabled,
      global_source: globalForm.source,
      smart_source: smartForm.source
    })
    // 后端校验失败返回 {error}（HTTP 200，非异常），必须显式检查——否则空源会误报"已保存"
    if (res && res.error) { message.error(res.error); return }
    message.success(translate('ui.m_28b27652c0f3'))
    // 需求3：勾选启用代理后立即探测一次出口，失效则明确提示（不等定时的10分钟）
    verifyAfterSave()
  } catch (e) { message.error((e as Error).message) } finally { modeSaving.value = false }
}

// 与后端 _source_configured 逐字一致：subscription 空 ref_id=默认占位=未配置(直连)
function isSourceConfigured(src: ProxySource): boolean {
  if (!src || !src.type) return false
  if (src.type === 'subscription' && !src.ref_id) return false
  if (src.type === 'custom' && !src.ref_id) return false
  return true
}
// 前端源「结构性为空」前置校验（与后端 _validate_source_bound 对齐，只查空不探可达）。返回错误串（空=通过）。
function validateSourceLocal(src: ProxySource | null, label: string): string {
  if (!src || !src.type) return ''
  if (src.type === 'custom') {
    if (!src.ref_id) return translate('ui.m_883514a84b43', { p0: (label) })
    if (!customs.value.some(c => c._id === src.ref_id && c.enabled)) return translate('ui.m_d21bf721faea', { p0: (label) })
    return ''
  }
  if (src.type === 'pool') {
    const enabled = Number(poolStats.value?.enabled ?? 0), alive = Number(poolStats.value?.alive ?? 0)
    if (!(enabled > 0 && alive > 0)) return translate('ui.m_2536533d1eba', { p0: (label), p1: (enabled), p2: (alive) })
    return ''
  }
  if (src.type === 'subscription') {
    if (!(status.value?.config as any)?.active_profile_id) return translate('ui.m_d2ddec937f55', { p0: (label) })
    return ''
  }
  return ''
}

// 保存代理模式后主动探测出口可达性并提示（勾选时测失效）
async function verifyAfterSave() {
  try {
    const r = await proxyApi.exitIp()
    exitResult.value = r
    if (r.proxied) message.success(translate('ui.m_906deffe1d59', { p0: (r.proxy_ip) }))
    else if (r.error && r.error !== 'proxy not enabled' && !r.proxy_ip) message.warning(translate('ui.m_ab3ebd8b7e95'))
  } catch { /* 探测失败不阻断保存 */ }
}

function applyConfig(config: ProxyConfig) {
  Object.assign(form, config)
  const eps = config.doh_endpoints
  dohText.value = Array.isArray(eps) ? eps.join('\n') : (eps || '')
}
async function withLoading(fn: () => Promise<void>) {
  loading.value = true
  try { await fn() } catch (error) { message.error(error instanceof Error ? error.message : String(error)) } finally { loading.value = false }
}
async function loadStatus() { status.value = await proxyApi.status(); applyConfig(status.value.config) }
async function loadTraffic() { try { traffic.value = await proxyApi.traffic() } catch { /* 降级 */ } }
async function resetTraffic(scope: string, key: string) {
  try { traffic.value = await proxyApi.resetTraffic(scope, key); message.success(translate('ui.m_9790c6e72a16')) } catch (e) { message.error((e as Error).message || translate('ui.m_660fb1b057cd')) }
}
async function resetTrafficAll() {
  try { traffic.value = await proxyApi.resetTraffic(); message.success(translate('ui.m_ac1f7acd8cb3')) } catch (e) { message.error((e as Error).message || translate('ui.m_660fb1b057cd')) }
}
async function loadProfiles() { profiles.value = (await proxyApi.profiles()).items || [] }
async function loadProxies() { proxies.value = (await proxyApi.proxies()).proxies || {} }
async function loadLogs() { logs.value = (await proxyApi.logs()).logs || '' }
async function loadCustoms() {
  customLoading.value = true
  try { customs.value = (await proxyApi.customList()).items || [] } catch { /* 降级空 */ } finally { customLoading.value = false }
}
async function checkExitIp() {
  exitLoading.value = true
  try {
    exitResult.value = await proxyApi.exitIp()
    if (exitResult.value.proxied) message.success(translate('ui.m_906deffe1d59', { p0: (exitResult.value.proxy_ip) }))
    else message.warning(translate('ui.m_eb682235349c'))
    await loadStatus()
  } catch (error) { message.error(error instanceof Error ? error.message : String(error)) } finally { exitLoading.value = false }
}

// —— 自定义代理弹窗 ——
const customOpen = ref(false)
const customSaving = ref(false)
const customForm = reactive<Partial<CustomProxy>>({ _id: '', name: '', url: '', enabled: true })
function openCustom(rec?: CustomProxy) {
  Object.assign(customForm, rec ? { _id: rec._id, name: rec.name, url: rec.url, enabled: rec.enabled }
                                 : { _id: '', name: '', url: '', enabled: true })
  customOpen.value = true
}
async function saveCustom() {
  if (!customForm.name || !customForm.url) { message.warning(translate('ui.m_a5bf4f80e812')); return }
  customSaving.value = true
  try {
    const r = await proxyApi.customSave({ ...customForm })
    if (!r.ok) { message.error(translate('ui.m_6309a3bb5ba4')); return }
    message.success(translate('ui.m_1bd91a7d0c53')); customOpen.value = false; await loadCustoms()
  } catch (e) { message.error((e as Error).message) } finally { customSaving.value = false }
}
async function delCustom(rec: CustomProxy) {
  try { await proxyApi.customDelete(rec._id); message.success(translate('ui.m_077a6d37719a')); await loadCustoms() } catch (e) { message.error((e as Error).message) }
}
async function toggleCustom(rec: CustomProxy, v: boolean) {
  try { await proxyApi.customSave({ _id: rec._id, name: rec.name, url: rec.url, enabled: v }); await loadCustoms() } catch (e) { message.error((e as Error).message) }
}
async function testCustom(rec: CustomProxy) {
  message.loading({ get content() { return translate('ui.m_339da995c389') }, key: 'tc' })
  try {
    const r = await proxyApi.customTest(rec._id)
    message.success({ content: r.reachable ? translate('ui.m_3e0d24bc8b62') : translate('ui.m_1d56d9de7087'), key: 'tc' })
    await loadCustoms()
  } catch (e) { message.error({ content: (e as Error).message, key: 'tc' }) }
}

async function loadAll() {
  await withLoading(async () => {
    await loadStatus()
    await loadProfiles()
    await loadProxies().catch(() => { proxies.value = {} })
    await loadLogs()
    await loadTraffic()
    await loadPool().catch(() => { /* 代理池失败不影响主流程 */ })
    await loadCustoms()
    // 从 status.config 回填平台模式（global_mode_enabled + global_source/smart_source）
    const cfg = status.value?.config as any
    if (cfg) {
      globalForm.enabled = !!cfg.global_mode_enabled
      if (cfg.global_source && cfg.global_source.type) globalForm.source = { type: cfg.global_source.type, ref_id: cfg.global_source.ref_id || '' }
      if (cfg.smart_source && cfg.smart_source.type) smartForm.source = { type: cfg.smart_source.type, ref_id: cfg.smart_source.ref_id || '' }
      // 顶层：全局开 or 智能绑了非默认源 → 判定为"启用代理"；否则直连
      const smartConfigured = cfg.smart_source && cfg.smart_source.type && !(cfg.smart_source.type === 'subscription' && !cfg.smart_source.ref_id)
      platformTop.value = (cfg.global_mode_enabled || smartConfigured) ? 'proxy' : 'direct'
    }
  })
}

async function loadPool() {
  const [list, st, cfg] = await Promise.all([
    proxyApi.poolList(poolPage.value, poolSize.value, poolStatus.value),
    proxyApi.poolStats(),
    proxyApi.poolConfig()
  ])
  poolItems.value = list.items || []
  poolTotal.value = list.total || 0
  poolStats.value = st
  poolCfg.queries = cfg.queries || []
  poolCfg.limit = cfg.limit || 100
}
async function crawlPool() {
  poolCrawling.value = true
  try {
    const r = await proxyApi.poolCrawl()
    if (r.added > 0) message.success(translate('ui.m_78e257d62a43', { p0: (r.added) }))
    else message.info(translate('ui.m_2a92cee67280'))
    await loadPool()
  } catch (e) { message.error((e as Error).message || translate('ui.m_f522416a047e')) } finally { poolCrawling.value = false }
}
async function verifyPool(ids?: string[]) {
  poolVerifying.value = true
  try {
    const r = await proxyApi.poolVerify(ids)
    message.success(translate('ui.m_3254f812c831', { p0: (r.checked), p1: (r.alive), p2: (r.dropped) }))
    poolSel.value = []
    await loadPool()
  } catch (e) { message.error((e as Error).message || translate('ui.m_e3d65a6880d8')) } finally { poolVerifying.value = false }
}
async function enablePool(ids: string[], enabled: boolean) {
  try { await proxyApi.poolEnable(ids, enabled); await loadPool() } catch (e) { message.error((e as Error).message || translate('ui.m_0c3b4cf7aa25')) }
}
async function deletePool(ids: string[]) {
  try { await proxyApi.poolDelete(ids); poolSel.value = []; message.success(translate('ui.m_077a6d37719a')); await loadPool() } catch (e) { message.error((e as Error).message || translate('ui.m_c228558cf257')) }
}
async function savePoolCfg() {
  try { await proxyApi.poolSaveConfig({ queries: poolCfg.queries, limit: poolCfg.limit }); message.success(translate('ui.m_2b68cb9b659a')) } catch (e) { message.error((e as Error).message || translate('ui.m_6309a3bb5ba4')) }
}
async function saveConfig() {
  await withLoading(async () => {
    // enabled 恒 true：mihomo 独立容器常驻，内核级 enabled 开关已删（是否走代理由顶层总开关+源绑定决定）
    const payload = { ...form, enabled: true, doh_endpoints: dohText.value }
    applyConfig(await proxyApi.saveConfig(payload))
    message.success(translate('ui.m_985c5a8ccded'))
    await loadStatus()
  })
}
// runCore 已删：mihomo 独立容器由 compose 自愈，不再手动启停内核（见状态卡说明）
async function importUrl() {
  if (!importForm.url) return message.warning(translate('ui.m_6011ba08d5c2'))
  await withLoading(async () => {
    await proxyApi.importUrl(importForm.name, importForm.url)
    message.success(translate('ui.m_9aa5b676ae86')); importForm.url = ''; await loadProfiles()
  })
}
async function uploadProfile() {
  if (!uploadForm.content) return message.warning(translate('ui.m_f082c4f9e125'))
  await withLoading(async () => {
    await proxyApi.upload(uploadForm.name, uploadForm.content)
    message.success(translate('ui.m_3740b6bd4a5b')); uploadForm.content = ''; await loadProfiles()
  })
}
function beforeYamlUpload(file: File) {
  const reader = new FileReader()
  reader.onload = e => {
    uploadForm.content = String(e.target?.result || '')
    if (!uploadForm.name) uploadForm.name = file.name.replace(/\.(ya?ml|txt)$/i, '')
    message.success(translate('ui.m_854c598eee15'))
  }
  reader.onerror = () => message.error(translate('ui.m_3d943f807f07'))
  reader.readAsText(file)
  return false
}
async function activate(id: string) {
  await withLoading(async () => {
    applyConfig(await proxyApi.activate(id))
    message.success(translate('ui.m_192916153355')); await loadAll()
  })
}
async function selectProxy(group: string, name: string) {
  await withLoading(async () => {
    await proxyApi.select(group, name)
    message.success(translate('ui.m_15fd1fa3aa65', { p0: (group), p1: (name) })); await loadProxies()
  })
}
function autoSelect() {
  Modal.confirm({
    get title() { return translate('ui.m_d44da281bd11') },
    get content() { return translate('ui.m_4ddaaf35ae63') },
    onOk: async () => {
      await withLoading(async () => {
        const result = await proxyApi.autoSelect('PROXY')
        message.success(translate('ui.m_cac4ef79bf38', { p0: (result.selected.name), p1: (result.selected.delay) }))
        await loadProxies()
      })
    }
  })
}

onMounted(loadAll)
</script>

<style scoped>
.hint { color: #999; font-size: 12px; margin-top: 4px; line-height: 1.5; }
.danger { color: #ff4d4f; }
/* 平台模式区 */
.top-radios { display: flex; gap: 6px; }
.top-radios :deep(.ant-radio-button-wrapper) { font-size: 14px; }
.mode-block { border: 1px solid var(--dt-line, #f0f0f0); border-radius: 10px; padding: 14px; height: 100%; background: var(--dt-panel, #fafafa); }
.mode-block.mode-on { background: var(--dt-panel, #fff); border-color: var(--dt-accent, #d9e8ff); }
.mode-block-head { display: flex; align-items: center; justify-content: space-between; margin-bottom: 10px; }
.mode-name { font-weight: 600; }
.src-picker { display: flex; align-items: center; flex-wrap: wrap; gap: 4px; }
/* 出口 IP 大字盒 */
.exit-row { align-items: stretch; }
.exit-box { border-radius: 10px; padding: 14px 16px; height: 100%; border: 1px solid var(--dt-line, #eee); }
.exit-box.exit-ok { background: #f6ffed; border-color: #b7eb8f; }
.exit-box.exit-err { background: #fff1f0; border-color: #ffa39e; }
.exit-box.exit-direct { background: #fafafa; }
.exit-k { font-size: 12px; color: #888; }
.exit-v { font-size: 22px; font-weight: 700; font-family: 'Consolas','Monaco',monospace; margin: 4px 0; word-break: break-all; }
.exit-tag { margin-top: 2px; }
/* 折叠区 */
.src-collapse { margin-bottom: 16px; }
.cp-h { font-weight: 600; margin-right: 10px; }
.cp-sub { color: #999; font-size: 12px; margin-left: 6px; }
.sub-block { border: 1px solid var(--dt-line, #f0f0f0); border-radius: 8px; padding: 12px; }
.sub-title { font-weight: 500; margin-bottom: 8px; }
.log-box { background: #1e1e1e; color: #d4d4d4; border-radius: 8px; padding: 12px; max-height: 400px; overflow: auto; font-size: 12px; margin: 0; white-space: pre-wrap; word-break: break-all; }
.full { width: 100%; }
</style>


