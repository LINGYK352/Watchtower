<template>
  <div>
    <a-alert
      class="page-alert"
      type="info"
      show-icon
      message="代理出口 = 模式 × 源。顶层默认直连；启用代理后，「全局」「智能」两个模式各绑一个代理源（自定义 / 内核代理 / 公共代理）。模式在扫描策略里选，第三方情报固定智能出口，控制流量（LLM/更新/激活）永远直连。"
    />

    <!-- ① 平台代理模式：4模式(直连/全局/规则/智能)×3源(自定义/机场/公共代理)。
         本区配「全局代理」和「智能代理」各绑哪个源(3选一)；策略页选 direct/global/smart 时套用。 -->
    <a-card class="page-card netmode-card" title="平台代理模式" size="small">
      <template #extra><a-button size="small" type="primary" :loading="modeSaving" @click="saveMode">保存</a-button></template>
      <!-- 顶层总开关：直连（默认）/ 启用代理。直连时全局+智能配置禁用 -->
      <a-radio-group v-model:value="platformTop" button-style="solid" class="top-radios">
        <a-radio-button value="direct">🔗 直连（默认）</a-radio-button>
        <a-radio-button value="proxy">🛰️ 启用代理</a-radio-button>
      </a-radio-group>
      <a-alert v-if="platformTop === 'direct'" type="success" show-icon banner class="mode-intro" style="margin-top:12px"
        message="当前：直连模式。平台全局出口不走任何代理，下方代理源配置不生效。（这是默认，最快最稳）" />
      <template v-else>
        <a-alert type="info" show-icon banner class="mode-intro" style="margin-top:12px"
          message="代理出口 = 模式 × 源。模式(全局/智能)在扫描策略里选；本区配「全局」「智能」两个模式各绑哪个代理源(自定义/内核代理/公共代理)。控制流量(LLM/更新)永远直连。" />
        <a-row :gutter="16" style="margin-top:12px">
          <a-col :xs="24" :md="12">
            <div class="mode-block" :class="{ 'mode-on': globalForm.enabled }">
              <div class="mode-block-head">
                <span class="mode-name">🌍 全局代理 <a-tag color="blue">global</a-tag></span>
                <a-switch v-model:checked="globalForm.enabled" checked-children="开" un-checked-children="关" />
              </div>
              <SrcPicker v-if="globalForm.enabled" :src="globalForm.source" :customs="customs" @update="(s:ProxySource)=>globalForm.source=s" />
              <div class="hint">开启后，策略选「全局」的扫描/渗透出口走此源；关闭则「全局」等于直连。连不通不自动降级（明确报错）。</div>
            </div>
          </a-col>
          <a-col :xs="24" :md="12">
            <div class="mode-block mode-on">
              <div class="mode-block-head"><span class="mode-name">🧠 智能代理 <a-tag color="green">smart</a-tag></span></div>
              <SrcPicker :src="smartForm.source" :customs="customs" @update="(s:ProxySource)=>smartForm.source=s" />
              <div class="hint">智能模式：此源可达则走代理，不可达自动降级（→全局若开→直连）。第三方情报固定用它。</div>
            </div>
          </a-col>
        </a-row>
      </template>
    </a-card>

    <!-- ② 运行状态 + 出口 IP（公共信息，突出不折叠） -->
    <a-card class="page-card status-card">
      <template #title>
        <a-space>
          <span>运行状态</span>
          <a-badge v-if="!status?.running" status="default" text="内核未运行" />
          <a-badge v-else-if="status?.last_health_ok" status="processing" text="运行中 · 代理可用" />
          <a-badge v-else status="error" text="运行中 · 代理不可用" />
        </a-space>
      </template>
      <template #extra><a-button size="small" @click="loadAll">刷新</a-button></template>
      <!-- 出口 IP 大字对比（最直观的"代理生不生效"）-->
      <a-row :gutter="16" class="exit-row">
        <a-col :xs="24" :sm="8">
          <div class="exit-box" :class="exitBoxClass">
            <div class="exit-k">当前出口 IP</div>
            <div class="exit-v">{{ status?.last_exit_ip || exitResult?.proxy_ip || exitResult?.direct_ip || '—' }}</div>
            <div class="exit-tag">
              <a-tag v-if="exitResult?.proxied" color="green">代理生效</a-tag>
              <a-tag v-else-if="exitProxyUnreachable" color="red">代理不可用·网络异常</a-tag>
              <a-tag v-else color="default">直连出口</a-tag>
            </div>
          </div>
        </a-col>
        <a-col :xs="24" :sm="16">
          <a-descriptions :column="{ xs: 1, sm: 2 }" size="small" bordered>
            <a-descriptions-item label="内核">
              <a-tag :color="status?.running ? 'success' : 'default'">{{ status?.running ? '运行中' : '未运行' }}</a-tag>
              <span class="muted" style="font-size:12px">由容器编排自动托管（restart:unless-stopped 自愈）</span>
            </a-descriptions-item>
            <a-descriptions-item label="进程 PID">{{ status?.pid || '-' }}</a-descriptions-item>
            <a-descriptions-item label="活跃配置">{{ status?.config?.active_profile_id || '未激活' }}</a-descriptions-item>
            <a-descriptions-item label="代理出口地址"><a-typography-text :copyable="!!status?.proxy_url" :content="status?.proxy_url || '-'" /></a-descriptions-item>
            <a-descriptions-item label="健康检测" :span="2">
              <a-tag :color="status?.last_health_ok ? 'success' : 'error'">{{ status?.last_health_ok ? '正常' : '异常' }}</a-tag>
              <span v-if="status?.last_health_check_time" style="color:#999;font-size:12px">{{ status?.last_health_check_time }}</span>
              <span v-if="!status?.last_health_ok && status?.last_health_error" style="color:#cf1322">（{{ status?.last_health_error }}）</span>
            </a-descriptions-item>
          </a-descriptions>
        </a-col>
      </a-row>
      <a-alert v-if="exitResult && !exitResult.proxied && exitProxyUnreachable" type="error" show-icon style="margin-top:12px"
        :message="'⚠ 代理不可用·网络异常：代理已开启但无法连接（' + (exitResult.error || '经代理探出口失败') + '）。请检查代理源/节点是否可用。'" />
      <a-space class="card-actions" wrap style="margin-top: 14px">
        <!-- mihomo 独立容器由 compose 管生命周期(restart:unless-stopped 自愈)，无需手动启停内核，故删启动/停止/重启按钮。
             改配置(节点/订阅)经 controller 热 reload 生效。保留出口 IP 检测。 -->
        <a-button :loading="exitLoading" @click="checkExitIp">检测出口 IP</a-button>
      </a-space>
    </a-card>
    <!-- ③ 流量消耗（公共信息，突出不折叠） -->
    <a-card class="page-card" size="small">
      <template #title>
        <a-space>
          <span>流量消耗</span>
          <a-button type="link" size="small" @click="loadTraffic">刷新</a-button>
          <ConfirmAction danger size="small" type="link" title="确认清空全部流量统计？" @confirm="resetTrafficAll">清空统计</ConfirmAction>
        </a-space>
      </template>
      <a-row :gutter="16">
        <a-col :span="6"><a-statistic title="总上行" :value="traffic?.total_up_h || '0B'" /></a-col>
        <a-col :span="6"><a-statistic title="总下行" :value="traffic?.total_down_h || '0B'" /></a-col>
        <a-col :span="6"><a-statistic title="当前连接数" :value="traffic?.connections ?? 0" /></a-col>
        <a-col :span="6"><a-statistic title="内核" :value="traffic?.running ? '运行中' : '未运行'" :value-style="{ color: traffic?.running ? '#3f8600' : '#999' }" /></a-col>
      </a-row>
      <a-alert v-if="traffic && !traffic.running" type="info" show-icon style="margin-top:10px" message="代理内核未运行，无流量统计。启用代理并启动内核后自动统计。" />
      <a-tabs v-if="traffic && (traffic.by_profile?.length || traffic.by_node?.length)" size="small" style="margin-top:12px">
        <a-tab-pane key="profile" tab="按机场订阅">
          <a-table :columns="profileCols" :data-source="traffic.by_profile" row-key="key" size="small" :pagination="false">
            <template #bodyCell="{ column, record }">
              <template v-if="column.key === 'act'">
                <ConfirmAction danger size="small" type="link" title="清空该机场统计？" @confirm="() => resetTraffic('profile', record.key)">清空</ConfirmAction>
              </template>
            </template>
          </a-table>
        </a-tab-pane>
        <a-tab-pane key="node" tab="按节点">
          <a-table :columns="nodeCols" :data-source="traffic.by_node" row-key="key" size="small" :pagination="{ pageSize: 10 }">
            <template #bodyCell="{ column, record }">
              <template v-if="column.key === 'act'">
                <ConfirmAction danger size="small" type="link" title="清空该节点统计？" @confirm="() => resetTraffic('node', record.key)">清空</ConfirmAction>
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
        <template #header><span class="cp-h">🧩 自定义代理</span><span class="cp-sub">{{ customs.length }} 条 · 手填 URL（类 Proxifier）</span></template>
        <template #extra><a-button size="small" type="primary" @click.stop="openCustom()">新增</a-button></template>
        <a-table :columns="customCols" :data-source="customs" :loading="customLoading" row-key="_id" :pagination="false" size="small">
          <template #bodyCell="{ column, record }">
            <template v-if="column.key === 'enabled'"><a-switch :checked="record.enabled" size="small" @change="(v: any) => toggleCustom(record, !!v)" /></template>
            <template v-else-if="column.key === 'health'">
              <a-tag v-if="record.last_health_ok === true" color="green">✓ 可达</a-tag>
              <a-tag v-else-if="record.last_health_ok === false" color="red">✗ 不可达</a-tag>
              <a-tag v-else color="default">未测</a-tag>
            </template>
            <template v-else-if="column.key === 'act'">
              <a-space>
                <a @click="testCustom(record)">测试</a>
                <a @click="openCustom(record)">编辑</a>
                <a-popconfirm title="删除该自定义代理？" @confirm="delCustom(record)"><a class="danger">删除</a></a-popconfirm>
              </a-space>
            </template>
          </template>
        </a-table>
      </a-collapse-panel>

      <!-- 内核代理（mihomo）：订阅导入 + YAML 上传 + 配置列表 + 代理组节点 + 内核基础配置，全并入此折叠 -->
      <a-collapse-panel key="mihomo">
        <template #header><span class="cp-h">✈️ 内核代理</span><span class="cp-sub">{{ profiles.length }} 个订阅 · 订阅导入 / 节点管理 / 内核配置(mihomo)</span></template>
        <a-row :gutter="16">
          <a-col :xs="24" :lg="12">
            <div class="sub-block">
              <div class="sub-title">订阅导入</div>
              <a-input v-model:value="importForm.name" placeholder="配置名称" style="margin-bottom:8px" />
              <a-input v-model:value="importForm.url" placeholder="订阅 URL" style="margin-bottom:8px" />
              <a-button type="primary" size="small" :loading="loading" @click="importUrl">导入订阅</a-button>
            </div>
          </a-col>
          <a-col :xs="24" :lg="12">
            <div class="sub-block">
              <div class="sub-title">YAML 上传</div>
              <a-input v-model:value="uploadForm.name" placeholder="配置名称" style="margin-bottom:8px" />
              <a-upload :before-upload="beforeYamlUpload" :show-upload-list="false" accept=".yaml,.yml,.txt">
                <a-button size="small" style="margin-bottom:8px"><template #icon><UploadOutlined /></template>选择文件</a-button>
              </a-upload>
              <a-textarea v-model:value="uploadForm.content" :rows="3" placeholder="选 .yaml 自动读入，或粘贴 Clash/Mihomo 配置" style="margin-bottom:8px" />
              <a-button type="primary" size="small" :loading="loading" @click="uploadProfile">上传配置</a-button>
            </div>
          </a-col>
        </a-row>
        <div class="sub-title" style="margin-top:12px">配置列表</div>
        <a-table :columns="profileColumns" :data-source="profiles" row-key="_id" :pagination="false" size="small">
          <template #bodyCell="{ column, record }">
            <template v-if="column.key === 'action'"><a-button type="link" size="small" @click="activate(record._id)">激活</a-button></template>
          </template>
        </a-table>
        <!-- 代理组/节点（内层折叠，节点多时收起） -->
        <a-collapse v-model:activeKey="groupsCardOpen" style="margin-top:12px">
          <a-collapse-panel key="groups">
            <template #header><span>代理组 / 节点</span><span class="cp-sub">{{ selectableGroups.length ? selectableGroups.length + ' 个代理组' : '未加载（展开查看）' }}</span></template>
            <template #extra>
              <a-space @click.stop>
                <a-button size="small" @click="loadProxies">刷新节点</a-button>
                <a-button size="small" type="primary" @click="autoSelect">自动选优</a-button>
              </a-space>
            </template>
            <a-empty v-if="!selectableGroups.length" description="暂无可选择代理组，确认内核已启动且配置有效。" />
            <a-collapse v-else v-model:activeKey="activeGroupKeys" class="proxy-collapse">
              <a-collapse-panel v-for="group in selectableGroups" :key="group.name">
                <template #header><span style="font-weight:500">{{ group.name }}</span><a-tag color="blue" style="margin-left:8px">当前：{{ group.now || '-' }}</a-tag><span class="cp-sub">{{ group.all.length }} 节点</span></template>
                <a-space wrap>
                  <a-button v-for="node in group.all" :key="node" size="small" :type="node === group.now ? 'primary' : 'default'" @click="selectProxy(group.name, node)">{{ node }}</a-button>
                </a-space>
              </a-collapse-panel>
            </a-collapse>
          </a-collapse-panel>
        </a-collapse>
        <!-- 内核基础配置（端口/熔断/DoH，属 mihomo 内核，并入本折叠） -->
        <a-divider orientation="left" style="margin-top:14px">内核基础配置（端口 / 熔断检测 / DoH）</a-divider>
        <a-form layout="vertical" :model="form">
          <a-row :gutter="16">
            <!-- 删「启用代理」开关：mihomo 独立容器由 compose 常驻自愈，内核恒启用（是否真走代理由顶层「直连/启用代理」
                 总开关 + 各模式源绑定决定，不需内核级启用开关）。form.enabled 保存时恒置 true(见 saveConfig)。 -->
            <a-col :xs="24" :md="6"><a-form-item label="自动优选"><a-switch v-model:checked="form.auto_select" checked-children="启用" un-checked-children="关闭" /></a-form-item></a-col>
            <a-col :xs="24" :md="6"><a-form-item label="Controller端口"><a-input-number v-model:value="form.controller_port" :min="1" :max="65535" class="full" /></a-form-item></a-col>
            <a-col :xs="24" :md="6"><a-form-item label="HTTP端口"><a-input-number v-model:value="form.http_port" :min="1" :max="65535" class="full" /></a-form-item></a-col>
            <a-col :xs="24" :md="6"><a-form-item label="SOCKS端口"><a-input-number v-model:value="form.socks_port" :min="1" :max="65535" class="full" /></a-form-item></a-col>
            <a-col :xs="24" :md="6"><a-form-item label="Mixed端口"><a-input-number v-model:value="form.mixed_port" :min="1" :max="65535" class="full" /></a-form-item></a-col>
            <a-col :xs="24" :md="12"><a-form-item label="测速URL"><a-input v-model:value="form.test_url" /></a-form-item></a-col>
          </a-row>
          <a-divider orientation="left" style="margin-top: 4px">熔断检测参数</a-divider>
          <a-row :gutter="16">
            <a-col :xs="24" :md="12"><a-form-item label="健康检测URL"><a-input v-model:value="form.health_check_url" placeholder="https://www.gstatic.com/generate_204" /></a-form-item></a-col>
            <a-col :xs="24" :md="6"><a-form-item label="检测间隔(秒)"><a-input-number v-model:value="form.health_check_interval" :min="10" class="full" /></a-form-item></a-col>
            <a-col :xs="24" :md="6"><a-form-item label="失败阈值"><a-input-number v-model:value="form.health_fail_threshold" :min="1" :max="10" class="full" /></a-form-item></a-col>
          </a-row>
          <a-form-item label="DoH 端点"><a-textarea v-model:value="dohText" :rows="2" placeholder="https://dns.alidns.com/resolve" /></a-form-item>
          <a-button type="primary" size="small" :loading="loading" @click="saveConfig">保存内核配置</a-button>
        </a-form>
      </a-collapse-panel>

      <!-- 公共代理（原公开抓取代理池） -->
      <a-collapse-panel key="pool">
        <template #header><span class="cp-h">🌐 公共代理</span><span class="cp-sub">{{ poolStats?.alive ?? '-' }}/{{ poolStats?.total ?? '-' }} 可用 · FOFA/Hunter 抓取的免费代理</span></template>
        <template #extra>
          <a-space @click.stop>
            <a-button size="small" @click="loadPool">刷新</a-button>
            <a-button size="small" type="primary" :loading="poolCrawling" @click="crawlPool">立即抓取</a-button>
            <a-button size="small" :loading="poolVerifying" @click="verifyPool()">验活全部</a-button>
          </a-space>
        </template>
        <a-alert type="warning" show-icon style="margin-bottom:12px"
          message="公共代理来自 FOFA/Hunter 测绘的免费代理，属不可信中间人（可能蜜罐/嗅探），质量低、存活短。仅用于打目标的 HTTP 请求轮换 IP 防 WAF 封，绝不用于 LLM 访问。平台模式选「公共代理」即启用，池内自动选延时最低。" />
        <a-descriptions :column="{ xs: 2, sm: 5 }" size="small" bordered style="margin-bottom:12px">
          <a-descriptions-item label="总数">{{ poolStats?.total ?? '-' }}</a-descriptions-item>
          <a-descriptions-item label="可用">{{ poolStats?.alive ?? '-' }}</a-descriptions-item>
          <a-descriptions-item label="失效">{{ poolStats?.dead ?? '-' }}</a-descriptions-item>
          <a-descriptions-item label="未验活">{{ poolStats?.unchecked ?? '-' }}</a-descriptions-item>
          <a-descriptions-item label="启用">{{ poolStats?.enabled ?? '-' }}</a-descriptions-item>
        </a-descriptions>
        <a-collapse style="margin-bottom:12px">
          <a-collapse-panel key="cfg" header="抓取配置（查询语法 / 期望总量，0=不限）">
            <div v-for="(q, i) in poolCfg.queries" :key="i" style="display:flex;gap:8px;align-items:center;margin-bottom:8px;flex-wrap:wrap">
              <a-select v-model:value="q.source" style="width:90px" size="small" :options="[{value:'fofa',label:'FOFA'},{value:'hunter',label:'Hunter'}]" />
              <a-select v-model:value="q.type" style="width:90px" size="small" :options="[{value:'socks5',label:'socks5'},{value:'http',label:'http'}]" />
              <a-input v-model:value="q.q" size="small" style="flex:1;min-width:180px" placeholder="测绘语法" />
              <a-switch v-model:checked="q.enabled" size="small" checked-children="启用" un-checked-children="停用" />
              <a-button size="small" danger type="link" @click="poolCfg.queries.splice(i,1)">删除</a-button>
            </div>
            <a-space>
              <a-button size="small" @click="poolCfg.queries.push({source:'fofa',type:'socks5',q:'protocol=\'socks5\'',enabled:true})">+ 添加查询</a-button>
              <span>每条期望总量</span>
              <a-input-number v-model:value="poolCfg.limit" :min="0" size="small" style="width:100px" />
              <a-button size="small" type="primary" @click="savePoolCfg">保存配置</a-button>
            </a-space>
          </a-collapse-panel>
        </a-collapse>
        <a-space style="margin-bottom:8px" wrap>
          <span>显示</span>
          <a-radio-group v-model:value="poolStatus" button-style="solid" size="small" @change="()=>{poolPage=1;loadPool()}">
            <a-radio-button value="alive">存活</a-radio-button>
            <a-radio-button value="">全部</a-radio-button>
            <a-radio-button value="dead">失效</a-radio-button>
            <a-radio-button value="unchecked">未验活</a-radio-button>
          </a-radio-group>
          <a-divider type="vertical" />
          <a-button size="small" :disabled="!poolSel.length" @click="verifyPool(poolSel)">验活选中</a-button>
          <a-button size="small" :disabled="!poolSel.length" @click="enablePool(poolSel, true)">启用选中</a-button>
          <a-button size="small" :disabled="!poolSel.length" @click="enablePool(poolSel, false)">禁用选中</a-button>
          <ConfirmAction danger size="small" :disabled="!poolSel.length" title="删除选中代理?" @confirm="() => deletePool(poolSel)">删除选中</ConfirmAction>
        </a-space>
        <a-table :columns="poolColumns" :data-source="poolItems" row-key="_id" size="small"
          :row-selection="{ selectedRowKeys: poolSel, onChange: (k:any)=>poolSel=k }"
          :pagination="{ current: poolPage, pageSize: poolSize, total: poolTotal, onChange: (p:number)=>{poolPage=p;loadPool()} }">
          <template #bodyCell="{ column, record }">
            <template v-if="column.key === 'delay'">
              <a-tag v-if="record.delay === null" color="default">未验活</a-tag>
              <a-tag v-else-if="record.delay < 0" color="error">失效</a-tag>
              <a-tag v-else :color="record.delay < 1500 ? 'success' : 'warning'">{{ record.delay }}ms</a-tag>
            </template>
            <template v-else-if="column.key === 'enabled'"><a-switch :checked="record.enabled" size="small" @change="(v:boolean)=>enablePool([record._id], v)" /></template>
            <template v-else-if="column.key === 'action'">
              <a-space>
                <a-button size="small" type="link" @click="verifyPool([record._id])">验活</a-button>
                <ConfirmAction danger size="small" type="link" title="删除?" @confirm="() => deletePool([record._id])">删除</ConfirmAction>
              </a-space>
            </template>
          </template>
        </a-table>
      </a-collapse-panel>

      <!-- 内核日志 -->
      <a-collapse-panel key="logs">
        <template #header><span class="cp-h">📄 内核日志</span></template>
        <template #extra><a-button size="small" @click.stop="loadLogs">刷新</a-button></template>
        <pre class="log-box">{{ logs || '暂无日志' }}</pre>
      </a-collapse-panel>

    </a-collapse>

    <!-- 自定义代理编辑弹窗 -->
    <a-modal v-model:open="customOpen" :title="customForm._id ? '编辑自定义代理' : '新增自定义代理'"
      :confirm-loading="customSaving" @ok="saveCustom">
      <a-form layout="vertical">
        <a-form-item label="名称"><a-input v-model:value="customForm.name" placeholder="如 香港线路A" /></a-form-item>
        <a-form-item label="代理 URL">
          <a-input v-model:value="customForm.url" placeholder="http://user:pass@host:port 或 socks5://host:port" />
          <div class="hint">支持 http:// / https:// / socks5://（socks5 需服务端装 PySocks）。</div>
        </a-form-item>
        <a-space><span>启用</span><a-switch v-model:checked="customForm.enabled" /></a-space>
      </a-form>
    </a-modal>
  </div>
</template>
<script setup lang="ts">
import { computed, onMounted, reactive, ref, h } from 'vue'
import { message, Modal, RadioGroup, RadioButton, Select } from 'ant-design-vue'
import { UploadOutlined } from '@ant-design/icons-vue'
import { proxyApi, type ProxyConfig, type ProxyProfile, type ProxyStatus, type ExitIpResult, type ProxyTraffic, type PoolProxy, type PoolStats, type PoolConfig, type CustomProxy, type ProxySource } from '../../api/proxy'
import ConfirmAction from '../../components/ConfirmAction.vue'

const profileCols = [
  { title: '机场(订阅)', dataIndex: 'name', key: 'name', ellipsis: true },
  { title: '上行', dataIndex: 'up_h', key: 'up_h', width: 110 },
  { title: '下行', dataIndex: 'down_h', key: 'down_h', width: 110 },
  { title: '操作', key: 'act', width: 70 }
]
const nodeCols = [
  { title: '节点', dataIndex: 'name', key: 'name', ellipsis: true },
  { title: '所属机场', dataIndex: 'profile_name', key: 'profile_name', ellipsis: true },
  { title: '上行', dataIndex: 'up_h', key: 'up_h', width: 110 },
  { title: '下行', dataIndex: 'down_h', key: 'down_h', width: 110 },
  { title: '操作', key: 'act', width: 70 }
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
  { title: '类型', dataIndex: 'type', key: 'type', width: 70 },
  { title: 'IP', dataIndex: 'host', key: 'host', ellipsis: true },
  { title: '端口', dataIndex: 'port', key: 'port', width: 70 },
  { title: '国家', dataIndex: 'country', key: 'country', width: 90, ellipsis: true },
  { title: '延时', key: 'delay', width: 90 },
  { title: '来源', dataIndex: 'source', key: 'source', width: 70 },
  { title: '最后验活', dataIndex: 'last_check', key: 'last_check', width: 150, ellipsis: true },
  { title: '启用', key: 'enabled', width: 60 },
  { title: '操作', key: 'action', width: 110 }
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
  { title: '名称', dataIndex: 'name' },
  { title: '来源', dataIndex: 'source' },
  { title: '节点', dataIndex: 'proxy_count' },
  { title: '代理组', dataIndex: 'group_count' },
  { title: '操作', key: 'action' }
]
const customCols = [
  { title: '名称', dataIndex: 'name', key: 'name', ellipsis: true },
  { title: 'URL', dataIndex: 'url', key: 'url', ellipsis: true },
  { title: '启用', key: 'enabled', width: 70 },
  { title: '健康', key: 'health', width: 90 },
  { title: '操作', key: 'act', width: 150 }
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
      placeholder: '选一条自定义代理',
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
      message.success('已切换为直连模式，代理配置不生效')
    } catch (e) { message.error((e as Error).message) } finally { modeSaving.value = false }
    return
  }
  // 启用代理：按全局/智能表单存
  if (globalForm.enabled && globalForm.source.type === 'custom' && !globalForm.source.ref_id) { message.warning('全局代理选了自定义源，请选择一条自定义代理'); return }
  if (smartForm.source.type === 'custom' && !smartForm.source.ref_id) { message.warning('智能代理选了自定义源，请选择一条自定义代理'); return }
  modeSaving.value = true
  try {
    await proxyApi.saveConfig({
      global_mode_enabled: globalForm.enabled,
      global_source: globalForm.source,
      smart_source: smartForm.source
    })
    message.success('平台代理模式已保存')
    // 需求3：勾选启用代理后立即探测一次出口，失效则明确提示（不等定时的10分钟）
    verifyAfterSave()
  } catch (e) { message.error((e as Error).message) } finally { modeSaving.value = false }
}

// 保存代理模式后主动探测出口可达性并提示（勾选时测失效）
async function verifyAfterSave() {
  try {
    const r = await proxyApi.exitIp()
    exitResult.value = r
    if (r.proxied) message.success(`代理生效，出口 IP：${r.proxy_ip}`)
    else if (r.error && r.error !== 'proxy not enabled' && !r.proxy_ip) message.warning('⚠ 代理已启用但探不到出口，可能失效/节点不通，请检查代理源')
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
  try { traffic.value = await proxyApi.resetTraffic(scope, key); message.success('已清空') } catch (e) { message.error((e as Error).message || '清空失败') }
}
async function resetTrafficAll() {
  try { traffic.value = await proxyApi.resetTraffic(); message.success('已清空全部统计') } catch (e) { message.error((e as Error).message || '清空失败') }
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
    if (exitResult.value.proxied) message.success(`代理生效，出口 IP：${exitResult.value.proxy_ip}`)
    else message.warning('代理未生效或出口异常，详见提示')
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
  if (!customForm.name || !customForm.url) { message.warning('名称和 URL 必填'); return }
  customSaving.value = true
  try {
    const r = await proxyApi.customSave({ ...customForm })
    if (!r.ok) { message.error('保存失败'); return }
    message.success('已保存'); customOpen.value = false; await loadCustoms()
  } catch (e) { message.error((e as Error).message) } finally { customSaving.value = false }
}
async function delCustom(rec: CustomProxy) {
  try { await proxyApi.customDelete(rec._id); message.success('已删除'); await loadCustoms() } catch (e) { message.error((e as Error).message) }
}
async function toggleCustom(rec: CustomProxy, v: boolean) {
  try { await proxyApi.customSave({ _id: rec._id, name: rec.name, url: rec.url, enabled: v }); await loadCustoms() } catch (e) { message.error((e as Error).message) }
}
async function testCustom(rec: CustomProxy) {
  message.loading({ content: '探测中…', key: 'tc' })
  try {
    const r = await proxyApi.customTest(rec._id)
    message.success({ content: r.reachable ? '可达 ✓' : '不可达 ✗', key: 'tc' })
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
    if (r.added > 0) message.success(`抓取完成,新增 ${r.added} 条,正在后台验活,稍后刷新即只见存活`)
    else message.info('未抓到新代理(可能已存在或语法无结果)')
    await loadPool()
  } catch (e) { message.error((e as Error).message || '抓取失败') } finally { poolCrawling.value = false }
}
async function verifyPool(ids?: string[]) {
  poolVerifying.value = true
  try {
    const r = await proxyApi.poolVerify(ids)
    message.success(`验活完成:检测 ${r.checked},可用 ${r.alive},剔除 ${r.dropped}`)
    poolSel.value = []
    await loadPool()
  } catch (e) { message.error((e as Error).message || '验活失败') } finally { poolVerifying.value = false }
}
async function enablePool(ids: string[], enabled: boolean) {
  try { await proxyApi.poolEnable(ids, enabled); await loadPool() } catch (e) { message.error((e as Error).message || '操作失败') }
}
async function deletePool(ids: string[]) {
  try { await proxyApi.poolDelete(ids); poolSel.value = []; message.success('已删除'); await loadPool() } catch (e) { message.error((e as Error).message || '删除失败') }
}
async function savePoolCfg() {
  try { await proxyApi.poolSaveConfig({ queries: poolCfg.queries, limit: poolCfg.limit }); message.success('抓取配置已保存') } catch (e) { message.error((e as Error).message || '保存失败') }
}
async function saveConfig() {
  await withLoading(async () => {
    // enabled 恒 true：mihomo 独立容器常驻，内核级 enabled 开关已删（是否走代理由顶层总开关+源绑定决定）
    const payload = { ...form, enabled: true, doh_endpoints: dohText.value }
    applyConfig(await proxyApi.saveConfig(payload))
    message.success('配置已保存')
    await loadStatus()
  })
}
// runCore 已删：mihomo 独立容器由 compose 自愈，不再手动启停内核（见状态卡说明）
async function importUrl() {
  if (!importForm.url) return message.warning('请输入订阅 URL')
  await withLoading(async () => {
    await proxyApi.importUrl(importForm.name, importForm.url)
    message.success('订阅已导入'); importForm.url = ''; await loadProfiles()
  })
}
async function uploadProfile() {
  if (!uploadForm.content) return message.warning('请输入 YAML 内容')
  await withLoading(async () => {
    await proxyApi.upload(uploadForm.name, uploadForm.content)
    message.success('配置已上传'); uploadForm.content = ''; await loadProfiles()
  })
}
function beforeYamlUpload(file: File) {
  const reader = new FileReader()
  reader.onload = e => {
    uploadForm.content = String(e.target?.result || '')
    if (!uploadForm.name) uploadForm.name = file.name.replace(/\.(ya?ml|txt)$/i, '')
    message.success('已读取文件，点击「上传配置」确认')
  }
  reader.onerror = () => message.error('文件读取失败')
  reader.readAsText(file)
  return false
}
async function activate(id: string) {
  await withLoading(async () => {
    applyConfig(await proxyApi.activate(id))
    message.success('配置已激活'); await loadAll()
  })
}
async function selectProxy(group: string, name: string) {
  await withLoading(async () => {
    await proxyApi.select(group, name)
    message.success(`已切换 ${group} -> ${name}`); await loadProxies()
  })
}
function autoSelect() {
  Modal.confirm({
    title: '自动选择最优节点',
    content: '将对代理组 PROXY 执行延迟测试并切换到最低延迟节点。',
    onOk: async () => {
      await withLoading(async () => {
        const result = await proxyApi.autoSelect('PROXY')
        message.success(`已选择 ${result.selected.name}，延迟 ${result.selected.delay}ms`)
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


