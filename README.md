# 瞭望塔 Watchtower

Web与Windows当前正式版本：**v1.21.178**。原创代码GPL-3.0-only。

[官网与下载](https://watchtowers.info/) · [English](README.en.md) · [178更新与修复安装](docs/release178.md)

178合并177全部已发布补丁与本轮修复：Windows下载统一另存为、证书与更新兼容、首次协议签署保持；配对确认/撤销清理、增量同步业务身份合并、内置环节仅覆盖同步及重复清理；旧/迁移会话受闸刀监管的挂机模式与入口；工作区多进程收信租约和独立临时目录修复并发503，后台重连保留消息和草稿；修复重启遮罩鉴权和页面不可点击、Windows99%状态与更新恢复互斥，完整安装器新增保留账号配置/业务资料的修复安装；新建会话模式选中态、多目录ZIP解压后由用户选入口（本地和云端）、未填目标显示未知且继续待命；专有SKILL在同步/流式/后台会话中沿实际模型及环节传给工具，兼容显式备用、网络重试及绑定撤销。

178为双端新安装基板及回退下限。177、177B-1、177B-2直接升级178，保留账号、配置、任务、会话与证据；旧175/176沿既有签名功能链升级。安装包统一由官网分发，Windows支持修复现有安装。Windows10未完成实机验收。


<!-- watchtower-ui-gallery:start -->
## 功能界面 · 示例数据

以下为177实际界面与隔离示例数据，不对应真实客户、真实设备连接或实际评估结果。安装包和补丁统一在[分发系统](https://watchtowers.info/)下载。

### 01 · 跨端协作

Linux与Windows在独立工作区交接会话、证据与附件。

![Watchtower 跨端协作 · sample data](assets/screenshots/177/collaboration.png)

### 02 · 漏洞中心

统一查看AI渗透、内核扫描与工作组发现，关联验证状态与证据。

![Watchtower 漏洞中心 · sample data](assets/screenshots/177/findings.png)

### 03 · 公开情报

查看情报来源、风险等级、组件与同步状态，快速筛选相关线索。

![Watchtower 公开情报 · sample data](assets/screenshots/177/public-intelligence.png)

### 04 · APP渗透

管理有线与无线设备，连接移动端评估与平台会话。

![Watchtower APP渗透 · sample data](assets/screenshots/177/app-pentest.png)

### 05 · APP流量

按设备查看HTTPS、WebSocket与TCP/TLS流量及请求响应。

![Watchtower APP流量 · sample data](assets/screenshots/177/app-traffic.png)

### 06 · 报告编辑

直接编辑报告内容并实时预览，整理证据、风险与修复建议。

![Watchtower 报告编辑 · sample data](assets/screenshots/177/report-editor.png)

### 07 · 报告生成

按任务、会话或单个漏洞选择来源，使用Word模板生成交付报告。

![Watchtower 报告生成 · sample data](assets/screenshots/177/report-generation.png)

### 08 · AI会话台

在同一会话查看上下文、工具调用、关联漏洞与协作接续结果。

![Watchtower AI会话台 · sample data](assets/screenshots/177/ai-console.png)

### 09 · Burps历史记录

在AI会话台内查看HTTP/HTTPS历史、HaE标记与原始报文。

![Watchtower Burps历史记录 · sample data](assets/screenshots/177/burps-history.png)

### 10 · Burps重放

将历史请求送入Repeater，在同一窗口对照请求与响应。

![Watchtower Burps重放 · sample data](assets/screenshots/177/burps-repeater.png)

<!-- watchtower-ui-gallery:end -->


## 联系作者

遇到问题可扫码添加我的微信，请附版本号、操作步骤和报错信息。

<img src="assets/contact/wechat.png" alt="WeChat QR code" width="300">
