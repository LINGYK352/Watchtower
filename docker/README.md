# Docker 部署说明

用户安装与更新请阅读 [部署与更新](../docs/installation.md)。本目录保存安装脚本、Dockerfile、Compose 和 Nginx 配置；它不包含运营方独立分发系统的源码或注册数据库。

## 当前运行结构

Compose 运行 Web、Worker、Scheduler、MongoDB、RabbitMQ、Mihomo 和 Nginx。默认网页入口为主机的 `5555` 端口，Web API 容器监听 `5013`。

预构建应用镜像包含平台运行代码、依赖及所需工具。安装脚本将代码导出到主机，Compose 再挂载主机目录；因此代码和前端产物更新可以在挂载目录中生效。配置和数据按实际卷设置保存，更新前仍应自行备份。

## 获取完整运行环境

```bash
curl -fL https://watchtowers.info/dist/install.sh -o install.sh
# 检查内容后执行，并按提示选择安装方式
sudo bash install.sh
```

全新安装和卸载包含数据清理步骤。已有部署不要把全新安装当作日常更新；先备份，再按完整部署说明操作。

## 源码构建的前提

源码仓库不包含完整外部二进制和离线依赖。构建前需准备 Dockerfile 要求的 `external/`、`vendor/wheels/` 等材料，并先构建 `frontend/` 生成 `docker/frontend/`。

在文件齐备且确认各组件许可后，从仓库根目录构建：

```bash
docker build -f docker/Dockerfile --build-arg BASE_VERSION="$(cat version.txt)" -t sentinel:base .
```

实际第三方依赖及所需权限以 Dockerfile 和 Compose 为准。不得将密钥、数据库、日志、客户资料或内部运维脚本加入构建上下文和发布物。

## 更新与进程

- 前端产物由 Nginx 从挂载目录读取。
- Web 使用 Gunicorn 的 reload 机制加载相应后端改动。
- Worker 和 Scheduler 的代码更新需要由更新流程完成相应进程重启，不能假定它们也会自动跟随 Web 重载。
- 系统依赖或镜像构建内容变更需要重新准备对应镜像。

官网分发服务独立运行，主平台 Compose 不应再按旧文档增加 `update-server` 服务。旧 `updates/` 路径及旧服务器示例已从本说明移除，以免使用者照搬过期运维命令。

更多开发与验证说明见 [开发指南](../docs/development.md) 和 [架构说明](../docs/architecture.md)。
