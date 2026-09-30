<template>
  <PageContainer title="资产视图" kicker="Asset View" description="扫描资产归集成三层身份(资产实例/系统/代码)+单位视图,服务渗透去重、同系统借鉴、代码审计复用。">
    <template #extra>
      <a-space>
        <a-button @click="loadStat">刷新</a-button>
        <a-button @click="icpOpen = true">解析备案单位</a-button>
        <a-button type="primary" @click="collectOpen = true">从任务归集</a-button>
      </a-space>
    </template>

    <a-row :gutter="16" style="margin-bottom: 16px">
      <a-col :span="4"><a-card :bordered="false"><a-statistic title="资产实例" :value="stat.asset_total" /></a-card></a-col>
      <a-col :span="4"><a-card :bordered="false"><a-statistic title="系统身份" :value="stat.system_total" /></a-card></a-col>
      <a-col :span="4"><a-card :bordered="false"><a-statistic title="含漏洞资产" :value="stat.asset_with_vuln" :value-style="{ color: '#cf1322' }" /></a-card></a-col>
      <a-col :span="4"><a-card :bordered="false"><a-statistic title="含泄露资产" :value="stat.asset_with_leak" :value-style="{ color: '#d46b08' }" /></a-card></a-col>
      <a-col :span="4"><a-card :bordered="false"><a-statistic title="含密钥资产" :value="stat.asset_with_secret" :value-style="{ color: '#cf1322' }" /></a-card></a-col>
      <a-col :span="4"><a-card :bordered="false"><a-statistic title="已渗透" :value="stat.asset_pentested" :value-style="{ color: '#3f8600' }" /></a-card></a-col>
    </a-row>

    <a-row :gutter="16" style="margin-bottom: 16px">
      <a-col :span="6"><a-card :bordered="false"><a-statistic title="代码身份" :value="stat.code_total" /></a-card></a-col>
      <a-col :span="6"><a-card :bordered="false"><a-statistic title="已审计" :value="stat.code_audited" :value-style="{ color: '#3f8600' }" /></a-card></a-col>
      <a-col :span="6"><a-card :bordered="false"><a-statistic title="渗透报告" :value="stat.report_total" /></a-card></a-col>
    </a-row>

    <a-card :bordered="false">
      <a-tabs v-model:activeKey="activeTab" @change="onTabChange">
        <!-- 资产实例 -->
        <a-tab-pane key="asset" tab="资产实例">
          <SearchBar :model="assetQuery" @search="() => loadAsset(1)" @reset="resetAsset">
            <a-form-item label="单位"><a-input v-model:value="assetQuery.unit" allow-clear placeholder="所属单位" /></a-form-item>
            <a-form-item label="站点"><a-input v-model:value="assetQuery.site" allow-clear placeholder="URL" /></a-form-item>
            <a-form-item label="指纹/系统"><a-input v-model:value="assetQuery.finger_names" allow-clear placeholder="如 帆软/致远/泛微/Shiro" /></a-form-item>
            <a-form-item label="渗透状态">
              <a-select v-model:value="assetQuery.pentest_status" allow-clear style="width: 130px" :options="statusOptions" />
            </a-form-item>
          </SearchBar>
          <div style="margin-bottom:8px">
            <a-popconfirm :title="`确认删除选中的 ${assetSelected.length} 条资产情报？`" :disabled="!assetSelected.length" @confirm="batchDeleteAsset">
              <a-button danger :disabled="!assetSelected.length">批量删除{{ assetSelected.length ? `(${assetSelected.length})` : '' }}</a-button>
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
                  <a-button type="link" size="small" @click="openContext(record)">渗透档案</a-button>
                  <ConfirmAction danger type="link" size="small" title="确认删除该资产实例？" @confirm="removeRow('intel_asset', String(record._id), loadAsset)">删除</ConfirmAction>
                </a-space>
              </template>
            </template>
          </AppTable>
        </a-tab-pane>

        <!-- 系统身份 -->
        <a-tab-pane key="system" tab="系统知识">
          <SearchBar :model="systemQuery" @search="() => loadSystem(1)" @reset="resetSystem">
            <a-form-item label="系统名"><a-input v-model:value="systemQuery.name" allow-clear placeholder="如 泛微OA" /></a-form-item>
            <a-form-item label="版本"><a-input v-model:value="systemQuery.version" allow-clear /></a-form-item>
          </SearchBar>
          <div style="margin-bottom:8px">
            <a-popconfirm :title="`确认删除选中的 ${systemSelected.length} 条系统知识？`" :disabled="!systemSelected.length" @confirm="batchDeleteSystem">
              <a-button danger :disabled="!systemSelected.length">批量删除{{ systemSelected.length ? `(${systemSelected.length})` : '' }}</a-button>
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
                        {{ p.vuln_type }} · 有用×{{ p.useful_count || 0 }} · 见过×{{ p.seen_count || 0 }}
                      </a-tag>
                    </a-tooltip>
                  </template>
                  <span v-if="!((record.success_paths as any[]) || []).length" style="color:#bbb">-</span>
                </div>
              </template>
              <template v-else-if="column.key === 'action'">
                <ConfirmAction danger type="link" size="small" title="确认删除该系统身份？" @confirm="removeRow('intel_system', String(record._id), loadSystem)">删除</ConfirmAction>
              </template>
            </template>
          </AppTable>
        </a-tab-pane>

        <!-- 代码身份 -->
        <a-tab-pane key="code" tab="代码审计">
          <a-space style="margin-bottom: 12px">
            <a-button type="primary" @click="codeOpen = true">登记待审代码</a-button>
            <a-popconfirm :title="`确认删除选中的 ${codeSelected.length} 条代码身份？`" :disabled="!codeSelected.length" @confirm="batchDeleteCode">
              <a-button danger :disabled="!codeSelected.length">批量删除{{ codeSelected.length ? `(${codeSelected.length})` : '' }}</a-button>
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
                <ConfirmAction danger type="link" size="small" title="确认删除该代码身份？" @confirm="removeRow('intel_code', String(record._id), loadCode)">删除</ConfirmAction>
              </template>
            </template>
          </AppTable>
        </a-tab-pane>

        <!-- 渗透报告 -->
        <a-tab-pane key="report" tab="渗透报告">
          <a-radio-group v-model:value="reportView" size="small" style="margin-bottom:12px" @change="onReportViewChange">
            <a-radio-button value="tree">三级目录</a-radio-button>
            <a-radio-button value="list">列表</a-radio-button>
          </a-radio-group>

          <div v-if="reportView === 'tree'">
            <a-empty v-if="!reportTree.length" description="暂无报告。AI 引擎渗透后报告按 任务&gt;单位&gt;资产 自动归档于此。" />
            <a-collapse v-else accordion>
              <a-collapse-panel v-for="t in reportTree" :key="t.task_name">
                <template #header>
                  <a-space><a-tag color="blue">📋 {{ t.task_name }}</a-tag><span>{{ t.report_cnt }} 份报告</span></a-space>
                </template>
                <div v-for="u in t.units" :key="u.unit" style="margin-bottom:10px">
                  <div style="font-weight:600;margin:4px 0"><a-tag color="geekblue">🏢 {{ u.unit }}</a-tag><span style="color:#888">{{ u.report_cnt }} 份</span></div>
                  <div v-for="a in u.assets" :key="a.asset" style="padding-left:16px;margin-bottom:4px">
                    <a-tag color="cyan">🌐 {{ a.asset }}</a-tag>
                    <a-button v-for="r in a.reports" :key="r._id" type="link" size="small" @click="showReportById(r._id)">
                      <a-tag v-if="r.system_name" color="purple" style="margin-right:4px">{{ r.system_name }}</a-tag>查看报告({{ r.save_date }})
                    </a-button>
                  </div>
                </div>
              </a-collapse-panel>
            </a-collapse>
          </div>

          <template v-else>
            <SearchBar :model="reportQuery" @search="() => loadReport(1)" @reset="resetReport">
              <a-form-item label="单位"><a-input v-model:value="reportQuery.unit" allow-clear /></a-form-item>
              <a-form-item label="资产"><a-input v-model:value="reportQuery.asset_key" allow-clear placeholder="资产 key" /></a-form-item>
            </SearchBar>
            <div style="margin-bottom:8px">
              <a-popconfirm :title="`确认删除选中的 ${reportSelected.length} 份报告？`" :disabled="!reportSelected.length" @confirm="batchDeleteReport">
                <a-button danger :disabled="!reportSelected.length">批量删除{{ reportSelected.length ? `(${reportSelected.length})` : '' }}</a-button>
              </a-popconfirm>
            </div>
            <AppTable :columns="reportColumns" :data="reportData.items" :loading="loading" selectable
              v-model:selectedRowKeys="reportSelected"
              :page="reportData.page" :size="reportData.size" :total="reportData.total" @change="(p, s) => loadReport(p, s)">
              <template #bodyCell="{ column, record }">
                <template v-if="column.key === 'action'">
                  <a-space>
                    <a-button type="link" size="small" @click="showReport(record)">查看</a-button>
                    <ConfirmAction danger type="link" size="small" title="确认删除该报告？" @confirm="removeRow('intel_report', String(record._id), loadReport)">删除</ConfirmAction>
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
    <a-modal v-model:open="collectOpen" title="从扫描任务归集情报资产" :confirm-loading="loading" @ok="doCollect">
      <a-alert type="info" show-icon style="margin-bottom: 12px"
        message="读取该任务的 site 站点结果,归一化成资产实例并按指纹聚合系统身份。重复归集幂等,不会产生重复资产。" />
      <a-form layout="vertical">
        <a-form-item label="扫描任务 ID" required>
          <a-input v-model:value="collectTaskId" placeholder="task 集合的 _id" />
        </a-form-item>
      </a-form>
    </a-modal>

    <!-- 解析 ICP 备案单位 -->
    <a-modal v-model:open="icpOpen" title="解析 ICP 备案单位" :confirm-loading="loading" @ok="doResolveIcp">
      <a-alert type="info" show-icon style="margin-bottom:12px"
        message="通过鹰图/FOFA 查域名备案单位,并回填该主域下所有资产的单位字段(报告三级目录第一级)。需在 config.yaml 配置 HUNTER.KEY。" />
      <a-form layout="vertical">
        <a-form-item label="域名" required>
          <a-input v-model:value="icpDomain" placeholder="如 example.com" />
        </a-form-item>
      </a-form>
      <a-descriptions v-if="icpResult" :column="1" size="small" bordered>
        <a-descriptions-item label="备案单位">{{ icpResult.unit || '(未查到)' }}</a-descriptions-item>
        <a-descriptions-item label="备案号">{{ icpResult.icp_no || '-' }}</a-descriptions-item>
        <a-descriptions-item label="来源">{{ icpResult.source }}</a-descriptions-item>
        <a-descriptions-item label="回填资产数">{{ icpResult.updated }}</a-descriptions-item>
      </a-descriptions>
    </a-modal>

    <!-- 登记代码身份 -->
    <a-modal v-model:open="codeOpen" title="登记待审计代码身份" :confirm-loading="loading" @ok="doAddCode">
      <a-form layout="vertical">
        <a-form-item label="仓库地址" required><a-input v-model:value="codeForm.repo_url" placeholder="https://github.com/xxx/yyy" /></a-form-item>
        <a-form-item label="版本 / commit"><a-input v-model:value="codeForm.version" placeholder="可空" /></a-form-item>
        <a-form-item label="关联系统身份 ID"><a-input v-model:value="codeForm.system_id" placeholder="可空,system 表 _id" /></a-form-item>
        <a-form-item label="源码落地目录"><a-input v-model:value="codeForm.local_path" placeholder="可空,服务器路径" /></a-form-item>
      </a-form>
    </a-modal>

    <!-- 报告详情 -->
    <a-drawer v-model:open="reportOpen" title="渗透报告" width="820">
      <template #extra>
        <a-space>
          <a-button size="small" @click="copyAllVulns">复制全部漏洞</a-button>
          <a-button size="small" type="primary" @click="exportReportMd">导出 Markdown</a-button>
        </a-space>
      </template>
      <a-descriptions :column="2" size="small" bordered style="margin-bottom: 14px">
        <a-descriptions-item label="资产" :span="2">{{ currentReport?.asset_key || '-' }}</a-descriptions-item>
        <a-descriptions-item label="单位">{{ currentReport?.unit || '-' }}</a-descriptions-item>
        <a-descriptions-item label="系统">{{ currentReport?.system_name || '-' }}</a-descriptions-item>
        <a-descriptions-item label="时间">{{ currentReport?.save_date || '-' }}</a-descriptions-item>
        <a-descriptions-item label="漏洞数">{{ reportVulns.length }}</a-descriptions-item>
      </a-descriptions>

      <a-tabs v-model:activeKey="reportTab">
        <a-tab-pane key="raw" tab="报告正文">
          <a-empty v-if="!reportContent" description="报告正文为空" />
          <pre v-else class="report-content">{{ reportContent }}</pre>
        </a-tab-pane>
        <a-tab-pane key="vulns" :tab="`漏洞清单(${reportVulns.length})`">
          <a-empty v-if="!reportVulns.length" description="本报告无结构化漏洞条目" />
          <a-card v-for="v in reportVulns" :key="v.no" size="small" style="margin-bottom:10px"
            :title="`#${v.no} ${v.type}`">
            <template #extra><a-tag :color="sevColor(String(v.severity))">{{ String(v.severity || '').toUpperCase() }}</a-tag></template>
            <div class="vrow"><b>目标:</b> <CopyText :text="String(v.target || '')" /></div>
            <div class="vrow" v-if="v.impact"><b>危害:</b> {{ v.impact }}</div>
            <div class="vrow" v-if="v.poc">
              <b>PoC:</b> <a-button size="small" type="link" @click="copyText(String(v.poc))">复制</a-button>
              <pre class="report-content">{{ v.poc }}</pre>
            </div>
          </a-card>
        </a-tab-pane>
      </a-tabs>
    </a-drawer>

    <!-- 渗透档案(完整侦察情报装配) -->
    <a-drawer v-model:open="ctxOpen" title="AI 渗透情报档案" width="860" :body-style="{ paddingTop: '8px' }">
      <a-spin :spinning="ctxLoading">
        <template v-if="ctx">
          <a-descriptions title="资产身份" :column="2" size="small" bordered style="margin-bottom:14px">
            <a-descriptions-item label="站点" :span="2">{{ ctx.identity.site }}</a-descriptions-item>
            <a-descriptions-item label="IP">{{ ctx.identity.ip || '-' }}</a-descriptions-item>
            <a-descriptions-item label="单位">{{ ctx.identity.unit || '-' }}</a-descriptions-item>
            <a-descriptions-item label="系统">{{ ctx.identity.system || '-' }}</a-descriptions-item>
            <a-descriptions-item label="指纹">
              <a-tag v-for="f in (ctx.identity.fingerprints as string[] || [])" :key="f" color="blue">{{ f }}</a-tag>
              <span v-if="!(ctx.identity.fingerprints as string[] || []).length">-</span>
            </a-descriptions-item>
          </a-descriptions>

          <a-divider orientation="left" style="margin:10px 0">已知弱点(已发现，无需重复挖)</a-divider>
          <p style="margin:4px 0"><b>已确认漏洞</b></p>
          <a-table v-if="knownVulns.length" :columns="vulnCols" :data-source="knownVulns" :pagination="false" size="small" row-key="target" bordered>
            <template #bodyCell="{ column, record }">
              <a-tag v-if="column.key==='severity'" :color="sevColor(String(record.severity))">{{ record.severity }}</a-tag>
            </template>
          </a-table>
          <a-empty v-else :image="false" description="无" style="margin:0" />
          <p style="margin:10px 0 4px"><b>文件泄露</b></p>
          <div v-if="fileLeaks.length">
            <a-tag v-for="(l,i) in fileLeaks" :key="i" color="orange" style="margin:2px">{{ l.url || l.site }} ({{ l.status_code }})</a-tag>
          </div>
          <a-empty v-else :image="false" description="无" style="margin:0" />
          <p style="margin:10px 0 4px"><b>JS 情报(WebInfoHunter)</b></p>
          <div v-if="wihSamples.length">
            <div v-for="(s,i) in wihSamples" :key="i" class="secret-line">
              <a-tag color="red">{{ s.record_type }}</a-tag><span class="mono">{{ s.content }}</span>
            </div>
          </div>
          <a-empty v-else :image="false" description="无" style="margin:0" />

          <a-divider orientation="left" style="margin:14px 0 10px">攻击面</a-divider>
          <p style="margin:4px 0"><b>开放端口/服务</b></p>
          <div v-if="asPorts.length">
            <a-tag v-for="(p,i) in asPorts" :key="i">{{ p.port }} {{ p.service }} {{ p.product }} {{ p.version }}</a-tag>
          </div>
          <a-empty v-else :image="false" description="无" style="margin:0" />
          <p style="margin:10px 0 4px"><b>关键端点(URL 样本)</b></p>
          <div v-if="urlSamples.length">
            <div v-for="(e,i) in urlSamples" :key="i" class="mono">{{ e.url }} ({{ e.status_code }})</div>
          </div>
          <a-empty v-else :image="false" description="无" style="margin:0" />

          <a-divider orientation="left" style="margin:14px 0 10px">同系统借鉴(这套系统在别处怎么被打下来)</a-divider>
          <div v-if="sysKnownVulns.length || sysCommonLeaks.length">
            <p style="margin:4px 0"><b>同系统历史漏洞</b></p>
            <a-tag v-for="(v,i) in sysKnownVulns" :key="i" :color="sevColor(String(v.severity))">{{ v.name }} ×{{ v.seen_count }} ({{ (v.units||[]).length }}单位)</a-tag>
            <p style="margin:10px 0 4px"><b>共性泄露路径</b></p>
            <a-tag v-for="(l,i) in sysCommonLeaks" :key="i" color="orange">{{ l.path }} ×{{ l.seen_count }}</a-tag>
          </div>
          <a-empty v-else :image="false" description="暂无同系统历史情报(首次遇到该系统)" style="margin:0" />

          <a-divider orientation="left" style="margin:14px 0 10px">代码审计</a-divider>
          <div v-if="codeAudit"><pre class="report-content">{{ codeAudit.audit_report }}</pre></div>
          <a-empty v-else :image="false" description="该系统未关联开源代码审计" style="margin:0" />
        </template>
      </a-spin>
    </a-drawer>
  </PageContainer>
</template>

<script setup lang="ts">
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
  { label: '未渗透', value: 'none' }, { label: '待渗透', value: 'pending' },
  { label: '进行中', value: 'doing' }, { label: '已渗透', value: 'done' }, { label: '已跳过', value: 'skip' }
]
const statusLabelMap: Record<string, string> = { none: '未渗透', pending: '待渗透', doing: '进行中', done: '已渗透', skip: '已跳过' }
const statusColorMap: Record<string, string> = { none: 'default', pending: 'orange', doing: 'processing', done: 'green', skip: 'default' }
const statusLabel = (s: string) => statusLabelMap[s] || s || '未渗透'
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
  { title: '漏洞', dataIndex: 'name', ellipsis: true },
  { title: '等级', key: 'severity', width: 100 },
  { title: '来源', dataIndex: 'source', width: 80 },
  { title: '目标', dataIndex: 'target', ellipsis: true }
]
const auditLabelMap: Record<string, string> = { none: '未审计', pending: '待审计', done: '已审计' }
const auditColorMap: Record<string, string> = { none: 'default', pending: 'orange', done: 'green' }
const auditLabel = (s: string) => auditLabelMap[s] || s || '未审计'
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
  { title: '站点', key: 'site', dataIndex: 'site', ellipsis: true },
  { title: '标题', dataIndex: 'title', ellipsis: true },
  { title: '指纹', key: 'finger_names' },
  { title: '侦察', key: 'recon', width: 230 },
  { title: '单位', dataIndex: 'unit', ellipsis: true },
  { title: '渗透状态', key: 'pentest_status' },
  { title: '操作', key: 'action', width: 150 }
]
const systemColumns = [
  { title: '系统名', dataIndex: 'name', width: 160, ellipsis: true },
  { title: '版本', dataIndex: 'version', width: 90 },
  { title: '涉及单位', key: 'units', width: 160 },
  { title: '实例', key: 'instance_keys', width: 60 },
  { title: '同系统已知漏洞', key: 'known_vulns', width: 220 },
  { title: '共性泄露', key: 'common_leaks', width: 200 },
  { title: '打法', key: 'success_paths', width: 300 },
  { title: '操作', key: 'action', width: 80 }
]
// 打法按 有用值(被借鉴后真打成)> 出现次数 降序,与后端 read_system_playbook 排序一致;限前 6 条防列溢出
function sortedPaths(paths: unknown): Array<Record<string, any>> {
  const arr = (paths as Array<Record<string, any>>) || []
  return [...arr].sort((a, b) =>
    (b.useful_count || 0) - (a.useful_count || 0) || (b.seen_count || 0) - (a.seen_count || 0)
  ).slice(0, 6)
}
const codeColumns = [
  { title: '仓库', key: 'repo_url', dataIndex: 'repo_url', ellipsis: true },
  { title: '版本/commit', dataIndex: 'version', width: 160 },
  { title: '审计状态', key: 'audit_status', width: 110 },
  { title: '落地目录', dataIndex: 'local_path', ellipsis: true },
  { title: '操作', key: 'action', width: 90 }
]
const reportColumns = [
  { title: '资产', dataIndex: 'asset_key', ellipsis: true },
  { title: '单位', dataIndex: 'unit', ellipsis: true },
  { title: '时间', dataIndex: 'save_date', width: 170 },
  { title: '操作', key: 'action', width: 120 }
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
    message.success(`已删除 ${assetSelected.value.length} 条资产情报`)
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
  try { await intelApi.remove('intel_system', systemSelected.value); message.success(`已删除 ${systemSelected.value.length} 条`); loadSystem(1); loadStat() }
  catch (e) { message.error((e as Error).message) }
}
async function batchDeleteCode() {
  if (!codeSelected.value.length) return
  try { await intelApi.remove('intel_code', codeSelected.value); message.success(`已删除 ${codeSelected.value.length} 条`); loadCode(1); loadStat() }
  catch (e) { message.error((e as Error).message) }
}
async function batchDeleteReport() {
  if (!reportSelected.value.length) return
  try { await intelApi.remove('intel_report', reportSelected.value); message.success(`已删除 ${reportSelected.value.length} 份`); loadReport(1); loadStat() }
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
  try { await intelApi.remove(collection, [id]); message.success('已删除'); reload(1); loadStat() }
  catch (e) { message.error((e as Error).message) }
}

// 从任务归集
const collectOpen = ref(false)
const collectTaskId = ref('')
async function doCollect() {
  if (!collectTaskId.value.trim()) return message.warning('请输入任务 ID')
  loading.value = true
  try {
    const ret = await intelApi.collect(collectTaskId.value.trim())
    message.success(`归集完成:站点 ${ret.site_total},新增资产 ${ret.new_asset},系统 ${ret.system_cnt}`)
    collectOpen.value = false; collectTaskId.value = ''
    loadStat(); loadAsset(1)
  } catch (e) { message.error((e as Error).message) } finally { loading.value = false }
}

// 登记代码身份
const codeOpen = ref(false)
const codeForm = reactive({ repo_url: '', version: '', system_id: '', local_path: '' })
async function doAddCode() {
  if (!codeForm.repo_url.trim()) return message.warning('请输入仓库地址')
  loading.value = true
  try {
    await intelApi.addCode({ ...codeForm })
    message.success('已登记')
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
  navigator.clipboard?.writeText(t).then(() => message.success('已复制')).catch(() => message.error('复制失败'))
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
  return `### #${v.no} ${v.type}\n- 等级: ${String(v.severity || '').toUpperCase()}\n- 目标: ${v.target}\n`
    + (v.impact ? `- 危害: ${v.impact}\n` : '') + (v.poc ? `\n\`\`\`bash\n${v.poc}\n\`\`\`\n` : '')
}
function copyAllVulns() {
  if (!reportVulns.value.length) return message.warning('无结构化漏洞')
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
    else message.error('报告不存在')
  } catch (e) { message.error((e as Error).message) }
}

// ICP 备案解析
const icpOpen = ref(false)
const icpDomain = ref('')
const icpResult = ref<{ unit: string; icp_no: string; source: string; updated: number } | null>(null)
async function doResolveIcp() {
  if (!icpDomain.value.trim()) return message.warning('请输入域名')
  loading.value = true
  try {
    const r = await intelApi.resolveIcp(icpDomain.value.trim())
    icpResult.value = r
    message.success(r.unit ? `备案单位:${r.unit},回填 ${r.updated} 个资产` : '未查到备案单位')
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
