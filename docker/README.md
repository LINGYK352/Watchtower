# 哨兵 Sentinel · Docker 分发与增量热更

## 一句话架构

**自包含镜像（代码+依赖+外部工具+前端全烘焙），pull/load 即跑；config 挂载、数据独立卷。**
- `sentinel:vX` 镜像 = 应用代码 + Python 依赖 + external 侦察工具 + 前端产物（`docker/Dockerfile` 烘焙）。
- MongoDB/RabbitMQ/Nginx = compose 里独立官方镜像；数据在独立卷 `sentinel_mongo`（镜像不含数据/密钥）。
- config.yaml 挂载只读进容器（不入镜像，数据清洗）。
- **可选热更**：把 `sentinel_platform`/`docker/frontend` 挂成卷覆盖镜像内路径，则热更补丁卷文件 + reload 即生效，不重建镜像（见 docker-compose.yml 文末注释）。

## 分发给别人（推荐：一条命令）

对方（有无 docker、有无外网都可）：
```bash
curl -fsSLk https://124.222.145.172:5555/dist/install.sh | bash
```
`install.sh` 自动：检测/装 docker（没有才装 + 配国内加速器）→ 下载全量包（含 4 镜像+部署文件）→
`docker load` → `docker compose up -d` → 打印访问地址。**装完直接可登录**：

    访问 http://<对方IP>:5555    账号 admin    密码 sentinel@2026

> 全量包 `sentinel-full-vX.tar.gz` 托管在 `124:/opt/sentinel/current/docker/frontend/dist/`（nginx 静态服务，自签名 https 故用 `curl -k`）。
> **开箱即用**：首次启动 user 集合为空时 `seed_default_admin()` 自动建默认管理员（幂等，有用户不覆盖），账号密码可经 config `SENTINEL.DEFAULT_ADMIN_USER/PASS` 覆盖。
> ⚠️ 上线前务必：改管理员密码 + config 里 `SENTINEL.API_KEY`/`SALT`（默认值公开，仅供首启）。

## 自己构建镜像（在有 docker+外网的机器/虚拟机）

生产 124 无 docker 且外网受限 → 在构建虚拟机（如 192.168.128.129，Ubuntu 同版 + docker + 国内加速器）：
```bash
# 构建上下文 = 项目根；Dockerfile 白名单式精确 COPY 只烘焙主平台运行所需
# （sentinel_platform/external/dicts/docker/frontend/vendor/version.txt）。
# 分发系统(云端/distribution)、文档(云端/docs)、注册库(*.db)、密钥经 .dockerignore + 精确 COPY 双层挡在镜像外。
# --build-arg BASE_VERSION 注入镜像 LABEL sentinel.base.version，install.sh 靠它判断本地镜像是否已是
# 云端最新基板→是则复用不重下 1.1G（不传则 LABEL=unknown，install.sh 回退 .base_version 旁标记）。
docker build -f docker/Dockerfile --build-arg BASE_VERSION="$(cat version.txt)" -t sentinel:base .   # 从加速器拉 python:3.8-slim
docker save sentinel:base | gzip > sentinel-image-$(cat version.txt).tar.gz   # 完整镜像基板（install.sh image 模式 docker load）
# 部署包（compose/nginx/config 样例，镜像不含）：
tar czf sentinel-deploy-$(cat version.txt).tar.gz -C docker docker-compose.yml nginx.conf -C ../config config.yaml.example
# 两个 tar.gz 传 124 的 /opt/sentinel-cloud/dist/ 托管（/dist/latest 自动按版本号取最新）
```

## 首次部署（手动，不用一键脚本时）

```bash
docker load -i sentinel-images.tar                            # 或已 build 好镜像
cp docker/config/config.yaml.example docker/config/config.yaml   # 已有默认可跑的 config.yaml 则跳过
docker compose -f docker/docker-compose.yml up -d             # web/worker/scheduler/mongo/rabbitmq/nginx
# 访问 http://<host>:5555   账号 admin/sentinel@2026
# 注：分发系统(update-server/:5080)已独立，不在本栈内——由运营方在 /opt/sentinel-cloud/ 单独部署（见 云端/distribution/DESIGN.md）
```

## 后续增量热更（两种，都不重建镜像）

**方式 A：拉取式（推荐给分发的其他实例）**——实例定期向更新源比对版本号自动拉：
```bash
# 部署实例内起客户端常驻（每 1h 检查一次你的服务器更新源）
python updates/update_client.py \
    --source http://124.222.145.172:5080 \
    --current /opt/sentinel/current --interval 3600 --daemon \
    --reload-cmd "docker compose -f docker/docker-compose.yml restart worker scheduler"
# web 用 gunicorn --reload 自动重载，无需 restart；worker/scheduler 需 restart
```
更新源（你的服务器）已在 compose 里跑 `update-server`（5080 端口），**发布物已数据清洗**（不外发 config.yaml/密钥/运行时）。

**方式 B：推送式（dev 从本地推生产）**：
```bash
python updates/hot_update.py --mode remote --host <host> --user root \
    --current /opt/sentinel/current \
    --worker-restart "docker compose -f docker/docker-compose.yml restart worker" \
    --scheduler-restart "docker compose -f docker/docker-compose.yml restart scheduler"
```

## 为什么能共存（原理）

Docker 镜像是不可变层——若把代码烘焙进镜像，改代码=重建+重拉（重）。
本方案把代码放**挂载卷**：容器只是「带依赖的运行环境」，代码在宿主机。
热更改的是宿主机文件 → 容器透过卷立即看到 → `gunicorn --reload`（web）或 `docker restart`（worker/scheduler，秒级）加载新代码。
**依赖变了才需重建镜像**（requirements.txt 变化，热更工具会拦截提示）——日常代码/前端热更永不重建。

## 数据/配置安全（热更绝不碰）

- `config/config.yaml`：挂载只读，热更发布物已清洗剔除，绝不覆盖
- MongoDB 数据：独立命名卷 `sentinel_mongo`
- 日志/运行时/备份：`logs/`/`shared/`/`.update_backup/` 均在清洗排除名单
