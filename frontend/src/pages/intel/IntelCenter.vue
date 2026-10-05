<template>
  <PageContainer :title="translate('ui.m_71f13524f302')" kicker="Asset View" :description="translate('ui.m_bb7677cce316')">
    <template #extra>
      <a-space>
        <a-button @click="loadStat">{{ translate('ui.m_aee887434131') }}</a-button>
        <a-button @click="icpOpen = true">{{ translate('ui.m_fda1c81403fd') }}</a-button>
        <a-button type="primary" @click="collectOpen = true">{{ translate('ui.m_e4efd685efde') }}</a-button>
      </a-space>
    </template>

    <a-row :gutter="16" style="margin-bottom: 16px">
      <a-col :span="4"><a-card :bordered="false"><a-statistic :title="translate('ui.m_29ae9ac44b49')" :value="stat.asset_total" /></a-card></a-col>
      <a-col :span="4"><a-card :bordered="false"><a-statistic :title="translate('ui.m_38aa407393df')" :value="stat.system_total" /></a-card></a-col>
      <a-col :span="4"><a-card :bordered="false"><a-statistic :title="translate('ui.m_7ed61f4f27fc')" :value="stat.asset_with_vuln" :value-style="{ color: '#cf1322' }" /></a-card></a-col>
      <a-col :span="4"><a-card :bordered="false"><a-statistic :title="translate('ui.m_f0e83aad71c7')" :value="stat.asset_with_leak" :value-style="{ color: '#d46b08' }" /></a-card></a-col>
      <a-col :span="4"><a-card :bordered="false"><a-statistic :title="translate('ui.m_f4d8d39d3204')" :value="stat.asset_with_secret" :value-style="{ color: '#cf1322' }" /></a-card></a-col>
      <a-col :span="4"><a-card :bordered="false"><a-statistic :title="translate('ui.m_9f70256c2f4d')" :value="stat.asset_pentested" :value-style="{ color: '#3f8600' }" /></a-card></a-col>
    </a-row>

    <a-row :gutter="16" style="margin-bottom: 16px">
      <a-col :span="6"><a-card :bordered="false"><a-statistic :title="translate('ui.m_dad2903d50cb')" :value="stat.code_total" /></a-card></a-col>
      <a-col :span="6"><a-card :bordered="false"><a-statistic :title="translate('ui.m_3aa0781d6595')" :value="stat.code_audited" :value-style="{ color: '#3f8600' }" /></a-card></a-col>
      <a-col :span="6"><a-card :bordered="false"><a-statistic :title="translate('ui.m_285bc741cad0')" :value="stat.report_total" /></a-card></a-col>
    </a-row>

    <a-card :bordered="false">
      <a-tabs v-model:activeKey="activeTab" @change="onTabChange">
        <!-- 资产实例 -->
        <a-tab-pane key="asset" tab="资产实例">
          <SearchBar :model="assetQuery" @search="() => loadAsset(1)" @reset="resetAsset">
            <a-form-item :label="translate('ui.m_80b19d68b149')"><a-input v-model:value="assetQuery.unit" allow-clear :placeholder="translate('ui.m_63ff1732e396')" /></a-form-item>
            <a-form-item :label="translate('ui.m_a59fe62777ff')"><a-input v-model:value="assetQuery.site" allow-clear placeholder="URL" /></a-form-item>
            <a-form-item :label="translate('ui.m_8da7b84c6e67')"><a-input v-model:value="assetQuery.finger_names" allow-clear :placeholder="translate('ui.m_bf228fd890de')" /></a-form-item>
            <a-form-item :label="translate('ui.m_ec19a5e13344')">
              <a-select v-model:value="assetQuery.pentest_status" allow-clear style="width: 130px" :options="statusOptions" />
            </a-form-item>
          </SearchBar>
          <div style="margin-bottom:8px">
            <a-popconfirm :title="translate('ui.m_b3dce9fa21c7', { p0: (assetSelected.length) })" :disabled="!assetSelected.length" @confirm="batchDeleteAsset">
              <a-button danger :disabled="!assetSelected.length">{{ translate('ui.m_ddae7a0fc554') }}{{ assetSelected.length ? `(${assetSelected.length})` : '' }}</a-button>
            </a-popconfirm>
          </div>
          <AppTable :columns="assetColumns" :data="assetData.items" :loading="loading" selectable
            v-model:selectedRowKeys="assetSelected"
            :page="assetData.page" :size="assetData.size" :total="assetData.total" @change="(p, s) => loadAsset(p, s)">
            <template #bodyCell="{ column, record }">
              <template v-if="column.key === 'site'"><CopyText :text="String(record.site || '')" /></template>
              <template v-else-if="column.key === 'finger_names'">
                <a-tag v-for="f in (record.finger_names as string[] || [])" :key="f" color="blue">{{ f }}</a-tag>
                <span v-if="!(record.finger_names as string[] || []).length">-</span>
              </template>
              <template v-else-if="column.key === 'recon'">
                <a-space :size="4" wrap>
                  <a-tag v-if="reconSummary(record).vuln_cnt" :color="sevColor(reconSummary(record).max_severity)">🐛 {{ reconSummary(record).vuln_cnt }}</a-tag>
                  <a-tag v-if="reconSummary(record).leak_cnt" color="orange">🔓 {{ reconSummary(record).leak_cnt }}</a-tag>
                  <a-tag v-if="reconSummary(record).secret_cnt" color="red">🔑 {{ reconSummary(record).secret_cnt }}</a-tag>
                  <a-tag v-if="reconSummary(record).port_cnt" color="default">⚓ {{ reconSummary(record).port_cnt }}</a-tag>
                  <a-tag v-if="reconSummary(record).endpoint_cnt" color="default">🔗 {{ reconSummary(record).endpoint_cnt }}</a-tag>
                  <span v-if="!hasRecon(record)" style="color:#bbb">-</span>
                </a-space>
              </template>
              <template v-else-if="column.key === 'pentest_status'">
                <a-tag :color="statusColor(String(record.pentest_status))">{{ statusLabel(String(record.pentest_status)) }}</a-tag>
              </template>
              <template v-else-if="column.key === 'action'">
                <a-space>
                  <a-button type="link" size="small" @click="openContext(record)">{{ translate('ui.m_d6d4a20a30ea') }}</a-button>
                  <ConfirmAction danger type="link" size="small" :title="translate('ui.m_ff26f51a4ae3')" @confirm="removeRow('intel_asset', String(record._id), loadAsset)">{{ translate('ui.m_2f9daa828907') }}</ConfirmAction>
                </a-space>
              </template>
            </template>
          </AppTable>
        </a-tab-pane>

        <!-- 系统身份 -->
        <a-tab-pane key="system" tab="系统知识">
          <SearchBar :model="systemQuery" @search="() => loadSystem(1)" @reset="resetSystem">
            <a-form-item :label="translate('ui.m_8c3b91d03f51')"><a-input v-model:value="systemQuery.name" allow-clear :placeholder="translate('ui.m_29e7d0ffe833')" /></a-form-item>
            <a-form-item :label="translate('ui.m_5f76b2bf82dd')"><a-input v-model:value="systemQuery.version" allow-clear /></a-form-item>
          </SearchBar>
          <div style="margin-bottom:8px">
            <a-popconfirm :title="translate('ui.m_f242e36e1d45', { p0: (systemSelected.length) })" :disabled="!systemSelected.length" @confirm="batchDeleteSystem">
              <a-button danger :disabled="!systemSelected.length">{{ translate('ui.m_ddae7a0fc554') }}{{ systemSelected.length ? `(${systemSelected.length})` : '' }}</a-button>
            </a-popconfirm>
          </div>
          <AppTable :columns="systemColumns" :data="systemData.items" :loading="loading" selectable
            v-model:selectedRowKeys="systemSelected"
            :page="systemData.page" :size="systemData.size" :total="systemData.total" @change="(p, s) => loadSystem(p, s)">
            <template #bodyCell="{ column, record }">
              <template v-if="column.key === 'units'">
                <div class="tag-cell">
                  <a-tag v-for="u in (record.units as string[] || [])" :key="u">{{ u }}</a-tag>
                  <span v-if="!(record.units as string[] || []).length">-</span>
                </div>
              </template>
              <template v-else-if="column.key === 'instance_keys'">{{ (record.instance_keys as string[] || []).length }}</template>
              <template v-else-if="column.key === 'known_vulns'">
                <div class="tag-cell">
                  <template v-for="v in ((record.known_vulns as any[]) || []).slice(0, 4)" :key="v.name">
                    <a-tag :color="sevColor(String(v.severity))">{{ v.name }} ×{{ v.seen_count }}</a-tag>
                  </template>
                  <span v-if="!((record.known_vulns as any[]) || []).length" style="color:#bbb">-</span>
                </div>
              </template>
              <template v-else-if="column.key === 'common_leaks'">
                <div class="tag-cell">
                  <template v-for="l in ((record.common_leaks as any[]) || []).slice(0, 3)" :key="l.path">
                    <a-tag color="orange">{{ l.path }} ×{{ l.seen_count }}</a-tag>
                  </template>
                  <span v-if="!((record.common_leaks as any[]) || []).length" style="color:#bbb">-</span>
                </div>
              </template>
              <template v-else-if="column.key === 'success_paths'">
                <div class="tag-cell">
                  <template v-for="p in sortedPaths(record.success_paths)" :key="p.vuln_type + (p.entry || '')">
                    <a-tooltip :title="p.entry || p.vuln_type">
                      <a-tag :color="(p.useful_count || 0) > 0 ? 'green' : 'default'">
                        {{ p.vuln_type }} {{ translate('ui.m_f4c032d4aaaf') }}{{ p.useful_count || 0 }} {{ translate('ui.m_01ed1ef351c8') }}{{ p.seen_count || 0 }}
                      </a-tag>
                    </a-tooltip>
                  </template>
                  <span v-if="!((record.success_paths as any[]) || []).length" style="color:#bbb">-</span>
                </div>
              </template>
              <template v-else-if="column.key === 'action'">
                <ConfirmAction danger type="link" size="small" :title="translate('ui.m_55826b201cb1')" @confirm="removeRow('intel_system', String(record._id), loadSystem)">{{ translate('ui.m_2f9daa828907') }}</ConfirmAction>
              </template>
            </template>
          </AppTable>
        </a-tab-pane>

        <!-- 代码身份 -->
        <a-tab-pane key="code" tab="代码审计">
          <a-space style="margin-bottom: 12px">
            <a-button type="primary" @click="codeOpen = true">{{ translate('ui.m_7b4da3c6db3a') }}</a-button>
            <a-popconfirm :title="translate('ui.m_70a87cd73894', { p0: (codeSelected.length) })" :disabled="!codeSelected.length" @confirm="batchDeleteCode">
              <a-button danger :disabled="!codeSelected.length">{{ translate('ui.m_ddae7a0fc554') }}{{ codeSelected.length ? `(${codeSelected.length})` : '' }}</a-button>
            </a-popconfirm>
          </a-space>
          <AppTable :columns="codeColumns" :data="codeData.items" :loading="loading" selectable
            v-model:selectedRowKeys="codeSelected"
            :page="codeData.page" :size="codeData.size" :total="codeData.total" @change="(p, s) => loadCode(p, s)">
            <template #bodyCell="{ column, record }">
              <template v-if="column.key === 'repo_url'"><CopyText :text="String(record.repo_url || '')" /></template>
              <template v-else-if="column.key === 'audit_status'">
                <a-tag :color="auditColor(String(record.audit_status))">{{ auditLabel(String(record.audit_status)) }}</a-tag>
              </template>
              <template v-else-if="column.key === 'action'">
                <ConfirmAction danger type="link" size="small" :title="translate('ui.m_e19b44cb3d44')" @confirm="removeRow('intel_code', String(record._id), loadCode)">{{ translate('ui.m_2f9daa828907') }}</ConfirmAction>
              </template>
            </template>
          </AppTable>
        </a-tab-pane>

        <!-- 渗透报告 -->
        <a-tab-pane key="report" tab="渗透报告">
          <a-radio-group v-model:value="reportView" size="small" style="margin-bottom:12px" @change="onReportViewChange">
            <a-radio-button value="tree">{{ translate('ui.m_646dd7daa0ff') }}</a-radio-button>
            <a-radio-button value="list">{{ translate('ui.m_aedd6814ff8c') }}</a-radio-button>
          </a-radio-group>

          <div v-if="reportView === 'tree'">
            <a-empty v-if="!reportTree.length" :description="translate('ui.m_b3c99ba313bc')" />
            <a-collapse v-else accordion>
              <a-collapse-panel v-for="t in reportTree" :key="t.task_name">
                <template #header>
                  <a-space><a-tag color="blue">📋 {{ t.task_name }}</a-tag><span>{{ t.report_cnt }} {{ translate('ui.m_2933d4ab3491') }}</span></a-space>
                </template>
                <div v-for="u in t.units" :key="u.unit" style="margin-bottom:10px">
                  <div style="font-weight:600;margin:4px 0"><a-tag color="geekblue">🏢 {{ u.unit }}</a-tag><span style="color:#888">{{ u.report_cnt }} {{ translate('ui.m_0066134b36c4') }}</span></div>
                  <div v-for="a in u.assets" :key="a.asset" style="padding-left:16px;margin-bottom:4px">
                    <a-tag color="cyan">🌐 {{ a.asset }}</a-tag>
                    <a-button v-for="r in a.reports" :key="r._id" type="link" size="small" @click="showReportById(r._id)">
                      <a-tag v-if="r.system_name" color="purple" style="margin-right:4px">{{ r.system_name }}</a-tag>{{ translate('ui.m_5acb29ad2cb6') }}{{ r.save_date }})
                    </a-button>
                  </div>
                </div>
              </a-collapse-panel>
            </a-collapse>
          </div>

          <template v-else>
            <SearchBar :model="reportQuery" @search="() => loadReport(1)" @reset="resetReport">
              <a-form-item :label="translate('ui.m_80b19d68b149')"><a-input v-model:value="reportQuery.unit" allow-clear /></a-form-item>
              <a-form-item :label="translate('ui.m_5f45bb826b16')"><a-input v-model:value="reportQuery.asset_key" allow-clear :placeholder="translate('ui.m_c49a9c20184c')" /></a-form-item>
            </SearchBar>
            <div style="margin-bottom:8px">
              <a-popconfirm :title="translate('ui.m_a052d5160ce5', { p0: (reportSelected.length) })" :disabled="!reportSelected.length" @confirm="batchDeleteReport">
                <a-button danger :disabled="!reportSelected.length">{{ translate('ui.m_ddae7a0fc554') }}{{ reportSelected.length ? `(${reportSelected.length})` : '' }}</a-button>
              </a-popconfirm>
            </div>
            <AppTable :columns="reportColumns" :data="reportData.items" :loading="loading" selectable
              v-model:selectedRowKeys="reportSelected"
              :page="reportData.page" :size="reportData.size" :total="reportData.total" @change="(p, s) => loadReport(p, s)">
              <template #bodyCell="{ column, record }">
                <template v-if="column.key === 'action'">
                  <a-space>
                    <a-button type="link" size="small" @click="showReport(record)">{{ translate('ui.m_db8db0530432') }}</a-button>
                    <ConfirmAction danger type="link" size="small" :title="translate('ui.m_a00b1ca5af9f')" @confirm="removeRow('intel_report', String(record._id), loadReport)">{{ translate('ui.m_2f9daa828907') }}</ConfirmAction>
                  </a-space>
                </template>
              </template>
            </AppTable>
          </template>
        </a-tab-pane>

        <!-- #11 用户 2026-09-15：单位视图并入资产视图，作为一个 Tab（原独立菜单已下线） -->
        <a-tab-pane key="unit" tab="单位视图">
          <UnitView v-if="unitTabLoaded" embedded />
        </a-tab-pane>
      </a-tabs>
    </a-card>

    <!-- 从任务归集 -->
    <a-modal v-model:open="collectOpen" :title="translate('ui.m_825dd846eebf')" :confirm-loading="loading" @ok="doCollect">
      <a-alert type="info" show-icon style="margin-bottom: 12px"
        :message="translate('ui.m_ef77b8cc947c')" />
      <a-form layout="vertical">
        <a-form-item :label="translate('ui.m_a67aab1e472a')" required>
          <a-input v-model:value="collectTaskId" :placeholder="translate('ui.m_6ecc4e23ce73')" />
        </a-form-item>
      </a-form>
    </a-modal>

    <!-- 解析 ICP 备案单位 -->
    <a-modal v-model:open="icpOpen" :title="translate('ui.m_77184d6b3f86')" :confirm-loading="loading" @ok="doResolveIcp">
      <a-alert type="info" show-icon style="margin-bottom:12px"
        :message="translate('ui.m_525645c0a368')" />
      <a-form layout="vertical">
        <a-form-item :label="translate('ui.m_222952431147')" required>
          <a-input v-model:value="icpDomain" :placeholder="translate('ui.m_f51539de19d5')" />
        </a-form-item>
      </a-form>
      <a-descriptions v-if="icpResult" :column="1" size="small" bordered>
        <a-descriptions-item :label="translate('ui.m_23a30e02ebc3')">{{ icpResult.unit || translate('ui.m_4fc0d394be36') }}</a-descriptions-item>
        <a-descriptions-item :label="translate('ui.m_961c62c16230')">{{ icpResult.icp_no || '-' }}</a-descriptions-item>
        <a-descriptions-item :label="translate('ui.m_a488e93d69cc')">{{ icpResult.source }}</a-descriptions-item>
        <a-descriptions-item :label="translate('ui.m_f67a796567a5')">{{ icpResult.updated }}</a-descriptions-item>
      </a-descriptions>
    </a-modal>

    <!-- 登记代码身份 -->
    <a-modal v-model:open="codeOpen" :title="translate('ui.m_ff02570c9629')" :confirm-loading="loading" @ok="doAddCode">
      <a-form layout="vertical">
        <a-form-item :label="translate('ui.m_e6161ef37a62')" required><a-input v-model:value="codeForm.repo_url" placeholder="https://github.com/xxx/yyy" /></a-form-item>
        <a-form-item :label="translate('ui.m_b6df88d38b99')"><a-input v-model:value="codeForm.version" :placeholder="translate('ui.m_6f0318cda678')" /></a-form-item>
        <a-form-item :label="translate('ui.m_f258d24de968')"><a-input v-model:value="codeForm.system_id" :placeholder="translate('ui.m_4e18391e6997')" /></a-form-item>
        <a-form-item :label="translate('ui.m_f14353bc9ed9')"><a-input v-model:value="codeForm.local_path" :placeholder="translate('ui.m_f9578a5e8a7c')" /></a-form-item>
      </a-form>
    </a-modal>

    <!-- 报告详情 -->
    <a-drawer v-model:open="reportOpen" :title="translate('ui.m_285bc741cad0')" width="820">
      <template #extra>
        <a-space>
          <a-button size="small" @click="copyAllVulns">{{ translate('ui.m_1ee3552aea63') }}</a-button>
          <a-button size="small" type="primary" @click="exportReportMd">{{ translate('ui.m_ac8b027cc1e3') }}</a-button>
        </a-space>
      </template>
      <a-descriptions :column="2" size="small" bordered style="margin-bottom: 14px">
        <a-descriptions-item :label="translate('ui.m_5f45bb826b16')" :span="2">{{ currentReport?.asset_key || '-' }}</a-descriptions-item>
        <a-descriptions-item :label="translate('ui.m_80b19d68b149')">{{ currentReport?.unit || '-' }}</a-descriptions-item>
        <a-descriptions-item :label="translate('ui.m_5b50d7c4b595')">{{ currentReport?.system_name || '-' }}</a-descriptions-item>
        <a-descriptions-item :label="translate('ui.m_8b6ff498515b')">{{ currentReport?.save_date || '-' }}</a-descriptions-item>
        <a-descriptions-item :label="translate('ui.m_415760c06b97')">{{ reportVulns.length }}</a-descriptions-item>
      </a-descriptions>

      <a-tabs v-model:activeKey="reportTab">
        <a-tab-pane key="raw" tab="报告正文">
          <a-empty v-if="!reportContent" :description="translate('ui.m_f6bd7a2b54bc')" />
          <pre v-else class="report-content">{{ reportContent }}</pre>
        </a-tab-pane>
        <a-tab-pane key="vulns" :tab="translate('ui.m_1ffe7e6e3f85', { p0: (reportVulns.length) })">
          <a-empty v-if="!reportVulns.length" :description="translate('ui.m_fdeb6fc2cc04')" />
          <a-card v-for="v in reportVulns" :key="v.no" size="small" style="margin-bottom:10px"
            :title="`#${v.no} ${v.type}`">
            <template #extra><a-tag :color="sevColor(String(v.severity))">{{ String(v.severity || '').toUpperCase() }}</a-tag></template>
            <div class="vrow"><b>{{ translate('ui.m_1b451d4b169a') }}</b> <CopyText :text="String(v.target || '')" /></div>
            <div class="vrow" v-if="v.impact"><b>{{ translate('ui.m_eb8687470173') }}</b> {{ v.impact }}</div>
            <div class="vrow" v-if="v.poc">
              <b>PoC:</b> <a-button size="small" type="link" @click="copyText(String(v.poc))">{{ translate('ui.m_63d90d977348') }}</a-button>
              <pre class="report-content">{{ v.poc }}</pre>
            </div>
          </a-card>
        </a-tab-pane>
      </a-tabs>
    </a-drawer>

    <!-- 渗透档案(完整侦察情报装配) -->
    <a-drawer v-model:open="ctxOpen" :title="translate('ui.m_529d50a0d0b6')" width="860" :body-style="{ paddingTop: '8px' }">
      <a-spin :spinning="ctxLoading">
        <template v-if="ctx">
          <a-descriptions :title="translate('ui.m_f3e619f5e5f7')" :column="2" size="small" bordered style="margin-bottom:14px">
            <a-descriptions-item :label="translate('ui.m_a59fe62777ff')" :span="2">{{ ctx.identity.site }}</a-descriptions-item>
            <a-descriptions-item label="IP">{{ ctx.identity.ip || '-' }}</a-descriptions-item>
            <a-descriptions-item :label="translate('ui.m_80b19d68b149')">{{ ctx.identity.unit || '-' }}</a-descriptions-item>
            <a-descriptions-item :label="translate('ui.m_5b50d7c4b595')">{{ ctx.identity.system || '-' }}</a-descriptions-item>
            <a-descriptions-item :label="translate('ui.m_0d6a14a9ab25')">
              <a-tag v-for="f in (ctx.identity.fingerprints as string[] || [])" :key="f" color="blue">{{ f }}</a-tag>
              <span v-if="!(ctx.identity.fingerprints as string[] || []).length">-</span>
            </a-descriptions-item>
          </a-descriptions>

          <a-divider orientation="left" style="margin:10px 0">{{ translate('ui.m_ffd619daea29') }}</a-divider>
          <p style="margin:4px 0"><b>{{ translate('ui.m_dd78082c47cf') }}</b></p>
          <a-table v-if="knownVulns.length" :columns="vulnCols" :data-source="knownVulns" :pagination="false" size="small" row-key="target" bordered>
            <template #bodyCell="{ column, record }">
              <a-tag v-if="column.key==='severity'" :color="sevColor(String(record.severity))">{{ record.severity }}</a-tag>
            </template>
          </a-table>
          <a-empty v-else :image="false" :description="translate('ui.m_484d55613910')" style="margin:0" />
          <p style="margin:10px 0 4px"><b>{{ translate('ui.m_ddca902e3201') }}</b></p>
          <div v-if="fileLeaks.length">
            <a-tag v-for="(l,i) in fileLeaks" :key="i" color="orange" style="margin:2px">{{ l.url || l.site }} ({{ l.status_code }})</a-tag>
          </div>
          <a-empty v-else :image="false" :description="translate('ui.m_484d55613910')" style="margin:0" />
          <p style="margin:10px 0 4px"><b>{{ translate('ui.m_9c6a168830c5') }}</b></p>
          <div v-if="wihSamples.length">
            <div v-for="(s,i) in wihSamples" :key="i" class="secret-line">
              <a-tag color="red">{{ s.record_type }}</a-tag><span class="mono">{{ s.content }}</span>
            </div>
          </div>
          <a-empty v-else :image="false" :description="translate('ui.m_484d55613910')" style="margin:0" />

          <a-divider orientation="left" style="margin:14px 0 10px">{{ translate('ui.m_5aad54811bb4') }}</a-divider>
          <p style="margin:4px 0"><b>{{ translate('ui.m_01d64a3dcd2b') }}</b></p>
          <div v-if="asPorts.length">
            <a-tag v-for="(p,i) in asPorts" :key="i">{{ p.port }} {{ p.service }} {{ p.product }} {{ p.version }}</a-tag>
          </div>
          <a-empty v-else :image="false" :description="translate('ui.m_484d55613910')" style="margin:0" />
          <p style="margin:10px 0 4px"><b>{{ translate('ui.m_bbc1ed0bea05') }}</b></p>
          <div v-if="urlSamples.length">
            <div v-for="(e,i) in urlSamples" :key="i" class="mono">{{ e.url }} ({{ e.status_code }})</div>
          </div>
          <a-empty v-else :image="false" :description="translate('ui.m_484d55613910')" style="margin:0" />

          <a-divider orientation="left" style="margin:14px 0 10px">{{ translate('ui.m_1ad71a47649d') }}</a-divider>
          <div v-if="sysKnownVulns.length || sysCommonLeaks.length">
            <p style="margin:4px 0"><b>{{ translate('ui.m_55409bb6d6ae') }}</b></p>
            <a-tag v-for="(v,i) in sysKnownVulns" :key="i" :color="sevColor(String(v.severity))">{{ v.name }} ×{{ v.seen_count }} ({{ (v.units||[]).length }}{{ translate('ui.m_0ff3cb5fb171') }}</a-tag>
            <p style="margin:10px 0 4px"><b>{{ translate('ui.m_f80d18e79ffb') }}</b></p>
            <a-tag v-for="(l,i) in sysCommonLeaks" :key="i" color="orange">{{ l.path }} ×{{ l.seen_count }}</a-tag>
          </div>
          <a-empty v-else :image="false" :description="translate('ui.m_766402cf7043')" style="margin:0" />

          <a-divider orientation="left" style="margin:14px 0 10px">{{ translate('ui.m_3dad33aa3b74') }}</a-divider>
          <div v-if="codeAudit"><pre class="report-content">{{ codeAudit.audit_report }}</pre></div>
          <a-empty v-else :image="false" :description="translate('ui.m_d048c8d78030')" style="margin:0" />
        </template>
      </a-spin>
    </a-drawer>
  </PageContainer>
</template>

<script setup lang="ts">
import { t as translate } from '../../i18n'

import { onMounted, reactive, ref, computed } from 'vue'
import { message } from 'ant-design-vue'
import PageContainer from '../../layouts/PageContainer.vue'
import SearchBar from '../../components/SearchBar.vue'
import AppTable from '../../components/AppTable.vue'
import ConfirmAction from '../../components/ConfirmAction.vue'
import CopyText from '../../components/CopyText.vue'
import UnitView from './UnitView.vue'   // #11 单位视图作为 Tab 内嵌（embedded）
import { intelApi, type IntelStat, type IntelCollection, type PentestContext, type ReportTreeNode } from '../../api/intel'
import type { ListResult, RowRecord } from '../../api/types'

const loading = ref(false)
const activeTab = ref('asset')
const unitTabLoaded = ref(false)   // #11 单位视图 Tab 懒加载：首次切到才挂载 UnitView（其 onMounted 自拉数据）
const stat = ref<IntelStat>({ asset_total: 0, asset_pentested: 0, system_total: 0, code_total: 0, code_audited: 0, report_total: 0, asset_with_vuln: 0, asset_with_leak: 0, asset_with_secret: 0 })

const statusOptions = [
  { get label() { return translate('ui.m_ec1512e4b8dc') }, value: 'none' }, { get label() { return translate('ui.m_52dcb5fd61c8') }, value: 'pending' },
  { get label() { return translate('ui.m_dc9591e56d50') }, value: 'doing' }, { get label() { return translate('ui.m_9f70256c2f4d') }, value: 'done' }, { get label() { return translate('ui.m_71e95b289aad') }, value: 'skip' }
]
const statusLabelMap: Record<string, string> = { get none() { return translate('ui.m_ec1512e4b8dc') }, get pending() { return translate('ui.m_52dcb5fd61c8') }, get doing() { return translate('ui.m_dc9591e56d50') }, get done() { return translate('ui.m_9f70256c2f4d') }, get skip() { return translate('ui.m_71e95b289aad') } }
const statusColorMap: Record<string, string> = { none: 'default', pending: 'orange', doing: 'processing', done: 'green', skip: 'default' }
const statusLabel = (s: string) => statusLabelMap[s] || s || translate('ui.m_ec1512e4b8dc')
const statusColor = (s: string) => statusColorMap[s] || 'default'

// 侦察徽标
interface ReconSummary { port_cnt: number; leak_cnt: number; vuln_cnt: number; secret_cnt: number; endpoint_cnt: number; max_severity: string }
const emptySummary: ReconSummary = { port_cnt: 0, leak_cnt: 0, vuln_cnt: 0, secret_cnt: 0, endpoint_cnt: 0, max_severity: 'none' }
function reconSummary(record: Record<string, unknown>): ReconSummary {
  const r = record.recon as Record<string, unknown> | undefined
  return (r?.summary as ReconSummary) || emptySummary
}
function hasRecon(record: Record<string, unknown>): boolean {
  const s = reconSummary(record)
  return !!(s.port_cnt || s.leak_cnt || s.vuln_cnt || s.secret_cnt || s.endpoint_cnt)
}
const sevColorMap: Record<string, string> = { critical: 'red', high: 'volcano', medium: 'orange', low: 'gold', info: 'blue', unknown: 'default', none: 'default' }
const sevColor = (s: string) => sevColorMap[(s || '').toLowerCase()] || 'default'
const vulnCols = [
  { get title() { return translate('ui.m_b0475a364bcb') }, dataIndex: 'name', ellipsis: true },
  { get title() { return translate('ui.m_337717173807') }, key: 'severity', width: 100 },
  { get title() { return translate('ui.m_a488e93d69cc') }, dataIndex: 'source', width: 80 },
  { get title() { return translate('ui.m_57060c88a36b') }, dataIndex: 'target', ellipsis: true }
]
const auditLabelMap: Record<string, string> = { get none() { return translate('ui.m_108f47763695') }, get pending() { return translate('ui.m_f17e031d84f4') }, get done() { return translate('ui.m_3aa0781d6595') } }
const auditColorMap: Record<string, string> = { none: 'default', pending: 'orange', done: 'green' }
const auditLabel = (s: string) => auditLabelMap[s] || s || translate('ui.m_108f47763695')
const auditColor = (s: string) => auditColorMap[s] || 'default'

const empty: ListResult<RowRecord> = { page: 1, size: 10, total: 0, items: [] }
const assetData = ref<ListResult<RowRecord>>({ ...empty })
const assetSelected = ref<string[]>([])
const systemData = ref<ListResult<RowRecord>>({ ...empty })
const codeData = ref<ListResult<RowRecord>>({ ...empty })
const reportData = ref<ListResult<RowRecord>>({ ...empty })
const systemSelected = ref<string[]>([])
const codeSelected = ref<string[]>([])
const reportSelected = ref<string[]>([])

const assetQuery = reactive<Record<string, string>>({ unit: '', site: '', finger_names: '', pentest_status: '' })
const systemQuery = reactive<Record<string, string>>({ name: '', version: '' })
const reportQuery = reactive<Record<string, string>>({ unit: '', asset_key: '' })

const assetColumns = [
  { get title() { return translate('ui.m_a59fe62777ff') }, key: 'site', dataIndex: 'site', ellipsis: true },
  { get title() { return translate('ui.m_c3405f8c7d9d') }, dataIndex: 'title', ellipsis: true },
  { get title() { return translate('ui.m_0d6a14a9ab25') }, key: 'finger_names' },
  { get title() { return translate('ui.m_b7585d36c8fc') }, key: 'recon', width: 230 },
  { get title() { return translate('ui.m_80b19d68b149') }, dataIndex: 'unit', ellipsis: true },
  { get title() { return translate('ui.m_ec19a5e13344') }, key: 'pentest_status' },
  { get title() { return translate('ui.m_ed31fbb483ee') }, key: 'action', width: 150 }
]
const systemColumns = [
  { get title() { return translate('ui.m_8c3b91d03f51') }, dataIndex: 'name', width: 160, ellipsis: true },
  { get title() { return translate('ui.m_5f76b2bf82dd') }, dataIndex: 'version', width: 90 },
  { get title() { return translate('ui.m_0a9efd2f4309') }, key: 'units', width: 160 },
  { get title() { return translate('ui.m_cc43dc69ae08') }, key: 'instance_keys', width: 60 },
  { get title() { return translate('ui.m_9b42cb291e51') }, key: 'known_vulns', width: 220 },
  { get title() { return translate('ui.m_0de7cdcb77d4') }, key: 'common_leaks', width: 200 },
  { get title() { return translate('ui.m_b4cba457aa21') }, key: 'success_paths', width: 300 },
  { get title() { return translate('ui.m_ed31fbb483ee') }, key: 'action', width: 80 }
]
// 打法按 有用值(被借鉴后真打成)> 出现次数 降序,与后端 read_system_playbook 排序一致;限前 6 条防列溢出
function sortedPaths(paths: unknown): Array<Record<string, any>> {
  const arr = (paths as Array<Record<string, any>>) || []
  return [...arr].sort((a, b) =>
    (b.useful_count || 0) - (a.useful_count || 0) || (b.seen_count || 0) - (a.seen_count || 0)
  ).slice(0, 6)
}
const codeColumns = [
  { get title() { return translate('ui.m_89b2ecbe1f09') }, key: 'repo_url', dataIndex: 'repo_url', ellipsis: true },
  { get title() { return translate('ui.m_1ebda8b43508') }, dataIndex: 'version', width: 160 },
  { get title() { return translate('ui.m_26d5f382b4b2') }, key: 'audit_status', width: 110 },
  { get title() { return translate('ui.m_ef6e45755779') }, dataIndex: 'local_path', ellipsis: true },
  { get title() { return translate('ui.m_ed31fbb483ee') }, key: 'action', width: 90 }
]
const reportColumns = [
  { get title() { return translate('ui.m_5f45bb826b16') }, dataIndex: 'asset_key', ellipsis: true },
  { get title() { return translate('ui.m_80b19d68b149') }, dataIndex: 'unit', ellipsis: true },
  { get title() { return translate('ui.m_8b6ff498515b') }, dataIndex: 'save_date', width: 170 },
  { get title() { return translate('ui.m_ed31fbb483ee') }, key: 'action', width: 120 }
]

async function loadStat() {
  try { stat.value = await intelApi.stat() } catch (e) { message.error((e as Error).message) }
}
async function loadAsset(page = 1, size = assetData.value.size) {
  loading.value = true
  try { assetData.value = await intelApi.assets({ page, size, ...cleanQuery(assetQuery) }); assetSelected.value = [] }
  catch (e) { message.error((e as Error).message) } finally { loading.value = false }
}
async function batchDeleteAsset() {
  if (!assetSelected.value.length) return
  try {
    await intelApi.remove('intel_asset', assetSelected.value)
    message.success(translate('ui.m_1facce16efa9', { p0: (assetSelected.value.length) }))
    loadAsset(1); loadStat()
  } catch (e) { message.error((e as Error).message) }
}
async function loadSystem(page = 1, size = systemData.value.size) {
  loading.value = true
  try { systemData.value = await intelApi.systems({ page, size, ...cleanQuery(systemQuery) }); systemSelected.value = [] }
  catch (e) { message.error((e as Error).message) } finally { loading.value = false }
}
async function loadCode(page = 1, size = codeData.value.size) {
  loading.value = true
  try { codeData.value = await intelApi.codes({ page, size }); codeSelected.value = [] }
  catch (e) { message.error((e as Error).message) } finally { loading.value = false }
}
async function loadReport(page = 1, size = reportData.value.size) {
  loading.value = true
  try { reportData.value = await intelApi.reports({ page, size, ...cleanQuery(reportQuery) }); reportSelected.value = [] }
  catch (e) { message.error((e as Error).message) } finally { loading.value = false }
}
async function batchDeleteSystem() {
  if (!systemSelected.value.length) return
  try { await intelApi.remove('intel_system', systemSelected.value); message.success(translate('ui.m_925464646d44', { p0: (systemSelected.value.length) })); loadSystem(1); loadStat() }
  catch (e) { message.error((e as Error).message) }
}
async function batchDeleteCode() {
  if (!codeSelected.value.length) return
  try { await intelApi.remove('intel_code', codeSelected.value); message.success(translate('ui.m_925464646d44', { p0: (codeSelected.value.length) })); loadCode(1); loadStat() }
  catch (e) { message.error((e as Error).message) }
}
async function batchDeleteReport() {
  if (!reportSelected.value.length) return
  try { await intelApi.remove('intel_report', reportSelected.value); message.success(translate('ui.m_15d28ba48370', { p0: (reportSelected.value.length) })); loadReport(1); loadStat() }
  catch (e) { message.error((e as Error).message) }
}
function cleanQuery(q: Record<string, string>) {
  const out: Record<string, string> = {}
  Object.entries(q).forEach(([k, v]) => { if (v) out[k] = v })
  return out
}
function resetAsset() { assetQuery.unit = ''; assetQuery.site = ''; assetQuery.finger_names = ''; assetQuery.pentest_status = ''; loadAsset(1) }
function resetSystem() { systemQuery.name = ''; systemQuery.version = ''; loadSystem(1) }
function resetReport() { reportQuery.unit = ''; reportQuery.asset_key = ''; loadReport(1) }

function onTabChange(key: string) {
  if (key === 'asset') loadAsset(1)
  else if (key === 'system') loadSystem(1)
  else if (key === 'code') loadCode(1)
  else if (key === 'report') { reportView.value === 'tree' ? loadReportTree() : loadReport(1) }
  else if (key === 'unit') { unitTabLoaded.value = true }   // #11 首次进单位视图 Tab 挂载 UnitView（内部自拉数据）
}

async function removeRow(collection: IntelCollection, id: string, reload: (p?: number) => void) {
  try { await intelApi.remove(collection, [id]); message.success(translate('ui.m_077a6d37719a')); reload(1); loadStat() }
  catch (e) { message.error((e as Error).message) }
}

// 从任务归集
const collectOpen = ref(false)
const collectTaskId = ref('')
async function doCollect() {
  if (!collectTaskId.value.trim()) return message.warning(translate('ui.m_ebec9110521f'))
  loading.value = true
  try {
    const ret = await intelApi.collect(collectTaskId.value.trim())
    message.success(translate('ui.m_262c98b43f60', { p0: (ret.site_total), p1: (ret.new_asset), p2: (ret.system_cnt) }))
    collectOpen.value = false; collectTaskId.value = ''
    loadStat(); loadAsset(1)
  } catch (e) { message.error((e as Error).message) } finally { loading.value = false }
}

// 登记代码身份
const codeOpen = ref(false)
const codeForm = reactive({ repo_url: '', version: '', system_id: '', local_path: '' })
async function doAddCode() {
  if (!codeForm.repo_url.trim()) return message.warning(translate('ui.m_4c2bebd5b1c1'))
  loading.value = true
  try {
    await intelApi.addCode({ ...codeForm })
    message.success(translate('ui.m_5f2f3886f1b2'))
    codeOpen.value = false
    codeForm.repo_url = ''; codeForm.version = ''; codeForm.system_id = ''; codeForm.local_path = ''
    loadCode(1); loadStat()
  } catch (e) { message.error((e as Error).message) } finally { loading.value = false }
}

// 报告详情
const reportOpen = ref(false)
const currentReport = ref<RowRecord | null>(null)
const reportContent = ref('')
const reportTab = ref('raw')
interface ReportVuln { no: string; type: string; severity: string; target: string; impact?: string; poc?: string }
const reportVulns = ref<ReportVuln[]>([])
function copyText(t: string) {
  navigator.clipboard?.writeText(t).then(() => message.success(translate('ui.m_8f6f8d979c98'))).catch(() => message.error(translate('ui.m_753d8bb0da99')))
}
function showReport(record: RowRecord) {
  currentReport.value = record
  const c = record.content
  reportContent.value = typeof c === 'string' ? c : JSON.stringify(c, null, 2)
  // 结构化漏洞:优先用 vulns(含 poc/impact),回退 vuln_index
  const vulns = record.vulns as Record<string, ReportVuln> | undefined
  const vidx = record.vuln_index as Array<{ no: string; type: string; severity: string; entry: string }> | undefined
  if (vulns && Object.keys(vulns).length) {
    reportVulns.value = Object.entries(vulns).map(([no, v]) => ({ ...v, no }))
      .sort((a, b) => Number(a.no) - Number(b.no))
  } else if (vidx && vidx.length) {
    reportVulns.value = vidx.map(v => ({ no: v.no, type: v.type, severity: v.severity, target: v.entry }))
  } else {
    reportVulns.value = []
  }
  reportTab.value = 'raw'   // 默认显示报告正文(看报告即看正文)
  reportOpen.value = true
}
function vulnToMd(v: ReportVuln) {
  return translate('ui.m_73aebb566b42', { p0: (v.no), p1: (v.type), p2: (String(v.severity || '').toUpperCase()), p3: (v.target) })
    + (v.impact ? translate('ui.m_e2c9a6361a9d', { p0: (v.impact) }) : '') + (v.poc ? `\n\`\`\`bash\n${v.poc}\n\`\`\`\n` : '')
}
function copyAllVulns() {
  if (!reportVulns.value.length) return message.warning(translate('ui.m_f22224474a9b'))
  copyText(reportVulns.value.map(vulnToMd).join('\n'))
}
function exportReportMd() {
  const r = currentReport.value || {}
  const head = `# ${r.title || '渗透报告'}\n\n- 资产: ${r.asset_key || '-'}\n- 单位: ${r.unit || '-'}\n- 系统: ${r.system_name || '-'}\n- 时间: ${r.save_date || '-'}\n\n## 漏洞清单(${reportVulns.value.length})\n\n`
  const body = reportVulns.value.map(vulnToMd).join('\n') || '(无结构化漏洞)\n'
  const full = head + body + `\n\n---\n## 报告正文\n\n${reportContent.value}`
  const blob = new Blob([full], { type: 'text/markdown;charset=utf-8' })
  const a = document.createElement('a')
  a.href = URL.createObjectURL(blob)
  a.download = `report_${String(r.asset_key || 'pentest').replace(/[^\w.-]/g, '_')}.md`
  a.click()
  URL.revokeObjectURL(a.href)
}


// 渗透情报档案抽屉
const ctxOpen = ref(false)
const ctxLoading = ref(false)
const ctx = ref<PentestContext | null>(null)
// BUG-013：渗透档案抽屉曾因 ctx 某嵌套数组字段为 undefined 直接读 .length 抛异常→body 全空白。
// 在此归一化：所有模板会深读的嵌套结构补默认空值，模板即可安全渲染（一处兜底 > 十几处可选链）。
// 对齐后端 asset_intel._context 真实结构归一化（原按错误 schema 归一→把后端真实数据抹成空，
// 是"攻击面/漏洞数据不对"的真根因：known_findings 本是数组却被当对象补 .vulns=[]，恒空）。
function _normalizeContext(raw: any): PentestContext {
  const c = raw || {}
  c.identity = c.identity || {}
  c.known_findings = Array.isArray(c.known_findings) ? c.known_findings : []   // 已确认漏洞数组
  c.attack_surface = c.attack_surface || {}
  c.attack_surface.ports = c.attack_surface.ports || []
  c.attack_surface.url_samples = c.attack_surface.url_samples || []
  c.attack_surface.wih_samples = c.attack_surface.wih_samples || []
  c.attack_surface.fileleak_samples = c.attack_surface.fileleak_samples || []
  c.history = c.history || {}
  c.pointers = c.pointers || {}
  return c as PentestContext
}

// 渗透档案抽屉的派生视图（对齐后端真实字段；system_intel/code_audit 后端 _context 暂不返回→安全兜底空）
const knownVulns = computed<any[]>(() => (ctx.value?.known_findings as any[]) || [])
const fileLeaks = computed<any[]>(() => (ctx.value?.attack_surface?.fileleak_samples as any[]) || [])
const wihSamples = computed<any[]>(() => (ctx.value?.attack_surface?.wih_samples as any[]) || [])
const asPorts = computed<any[]>(() => (ctx.value?.attack_surface?.ports as any[]) || [])
const urlSamples = computed<any[]>(() => (ctx.value?.attack_surface?.url_samples as any[]) || [])
const sysKnownVulns = computed<any[]>(() => ((ctx.value as any)?.system_intel?.known_vulns as any[]) || [])
const sysCommonLeaks = computed<any[]>(() => ((ctx.value as any)?.system_intel?.common_leaks as any[]) || [])
const codeAudit = computed<any>(() => (ctx.value as any)?.code_audit || null)

async function openContext(record: RowRecord) {
  ctxOpen.value = true
  ctxLoading.value = true
  ctx.value = null
  try {
    ctx.value = _normalizeContext(await intelApi.context(String(record.key || '')))
  } catch (e) { message.error((e as Error).message) } finally { ctxLoading.value = false }
}

// 报告三级目录树
const reportView = ref<'tree' | 'list'>('tree')
const reportTree = ref<ReportTreeNode[]>([])
async function loadReportTree() {
  try { reportTree.value = (await intelApi.reportTree()).tree } catch (e) { message.error((e as Error).message) }
}
function onReportViewChange() {
  if (reportView.value === 'tree') loadReportTree()
  else loadReport(1)
}
async function showReportById(id: string) {
  // 树里点报告:从已加载列表找,没有就按 _id 精确拉单篇(列表接口不支持 _id 过滤)
  const found = reportData.value.items.find(r => String(r._id) === id)
  if (found) { showReport(found); return }
  try {
    const doc = await intelApi.reportDetail(id)
    if (doc && doc._id) showReport(doc)
    else message.error(translate('ui.m_a81da756dd01'))
  } catch (e) { message.error((e as Error).message) }
}

// ICP 备案解析
const icpOpen = ref(false)
const icpDomain = ref('')
const icpResult = ref<{ unit: string; icp_no: string; source: string; updated: number } | null>(null)
async function doResolveIcp() {
  if (!icpDomain.value.trim()) return message.warning(translate('ui.m_b6e3c2e08699'))
  loading.value = true
  try {
    const r = await intelApi.resolveIcp(icpDomain.value.trim())
    icpResult.value = r
    message.success(r.unit ? translate('ui.m_fc3095d46ae6', { p0: (r.unit), p1: (r.updated) }) : translate('ui.m_50db027e3a65'))
    if (r.unit) loadAsset(1)
  } catch (e) { message.error((e as Error).message) } finally { loading.value = false }
}

onMounted(() => { loadStat(); loadAsset(1) })
</script>

<style scoped>
.report-content { white-space: pre-wrap; word-break: break-all; font-family: 'Consolas', 'Monaco', monospace; font-size: 13px; line-height: 1.6; }
.vrow { margin-bottom: 6px; line-height: 1.6; }
/* 标签密集列:在固定列宽内自动换行,防标签横向溢出列边界 */
.tag-cell { display: flex; flex-wrap: wrap; gap: 4px; }
.tag-cell :deep(.ant-tag) { margin: 0; white-space: normal; height: auto; line-height: 1.4; }
</style>
