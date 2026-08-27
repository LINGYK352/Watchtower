# 瞭望塔 Watchtower 自包含系统镜像 —— **代码+依赖+外部工具+前端全烘焙进镜像，pull 即跑**。
# 别人 docker load/pull 后仅需填 config.yaml + compose up 即全栈运行；config 挂载不入镜像。
# 增量热更（可选）：把 sentinel_platform/docker/frontend 挂成卷覆盖镜像内路径即可（见 compose 文末）。
#
# 构建（在构建上下文根，含 sentinel_platform/external/docker/vendor）：
#   docker build -f docker/Dockerfile -t sentinel:v1.21.24 .
# 打包边界铁律（2026-08-06 用户明令）：镜像**只含主平台运行所需**——用精确 COPY 白名单。
# 绝不打进：分发系统(云端/distribution)、文档(云端/docs)、注册库/密钥(*.db/*.key/update_keys.json)、
# 真实配置(config.yaml)、系统数据。分发系统是独立系统(运营方 /opt/sentinel-cloud/ 独立部署)。
FROM python:3.8-slim

# 系统工具：侦察外部工具在 external/ 走 PATH 调用；build-essential 供 C 扩展编译
# （psutil/cryptography 等，仅 gcc 缺 libc6-dev 头文件会编译失败 limits.h not found）。
# **先把 Debian apt 源换国内镜像**（容器内默认 deb.debian.org 国内慢/超时→卡构建；
# python:3.8-slim=bookworm，新格式源在 sources.list.d/debian.sources，换清华源）。pip 配阿里源避免 PyPI 慢。
RUN sed -i 's|deb.debian.org|mirrors.tuna.tsinghua.edu.cn|g; s|security.debian.org|mirrors.tuna.tsinghua.edu.cn|g' \
        /etc/apt/sources.list /etc/apt/sources.list.d/debian.sources 2>/dev/null; \
    apt-get update && apt-get install -y --no-install-recommends \
        nmap proxychains4 curl ca-certificates build-essential docker.io \
        fontconfig libfreetype6 fonts-liberation \
    && rm -rf /var/lib/apt/lists/*
# fontconfig/libfreetype6/fonts-liberation = PhantomJS 运行时依赖（SPA 渲染截图 + collect_js 抓活接口 apis）；
# 缺则 phantomjs exec 失败 → DynamicResources.available()=False → apis 恒空 → AI 抓不到接口挖不到洞。
# sentinel-ext 低权限用户（AI扩展沙盒执行）：slim 镜像自带 useradd，无需额外装包
RUN useradd --system --create-home --home-dir /var/lib/sentinel-ext --shell /usr/sbin/nologin sentinel-ext 2>/dev/null || true
RUN pip config set global.index-url https://mirrors.aliyun.com/pypi/simple/ \
    && pip config set global.trusted-host mirrors.aliyun.com

WORKDIR /opt/sentinel/current

# 依赖单独一层（利用 docker 层缓存：仅 requirements 变才重装）
COPY requirements.txt /tmp/requirements.txt
COPY vendor/wheels /tmp/wheels
# 优先离线 vendor wheel，缺失回退在线（celery 5.1.2 需 pip<24.1）
RUN pip install --no-cache-dir "pip<24.1" "setuptools<70" \
    && (pip install --no-cache-dir --no-index --find-links /tmp/wheels -r /tmp/requirements.txt \
        || pip install --no-cache-dir -r /tmp/requirements.txt) \
    && rm -rf /tmp/wheels

# —— AI 渗透真浏览器（Playwright Chromium）——
# 设计分工：扫描内核截图/collect_js=PhantomJS 轻量全量；AI 渗透 browser_navigate/browser_login=
# Playwright Chromium（按需启停/单实例/低频，只点重点 SPA 站点，不进扫描并发，无 OOM）。
# 装到默认路径 /root/.cache/ms-playwright（与运行时 _browser 默认查找路径一致，不设自定义 env
# 避免路径不一致；容器以 root 跑，HOME=/root）。Chromium 二进制(~150M)+系统依赖 build 时联网拉取。
# playwright 未装/装失败时 _browser.available()=False，工具自动降级 requests（不阻断构建）。
# **三类进程镜像同基（web/worker/scheduler 都用 sentinel:base），故都含 chromium**——
# 会话不论落 celery worker 还是 scheduler 线程执行器都能真渲染,不降级(实测教训:只装部分容器→落到没装的就 fallback)。
RUN apt-get update \
    && playwright install-deps chromium \
    && playwright install chromium \
    && rm -rf /var/lib/apt/lists/* \
    || echo "WARN: playwright chromium 安装失败，browser_navigate/login 将降级 requests"

# 应用代码 + 外部工具 + 前端产物烘焙进镜像（自包含）——数据清洗已在暂存阶段完成（无真 config/密钥）
COPY sentinel_platform ./sentinel_platform
COPY external ./external
COPY dicts ./dicts
COPY docker/frontend ./docker/frontend
# 分发系统(云端/distribution)**不烘焙进主平台镜像**——它是独立系统，运营方在 /opt/sentinel-cloud/
# 独立部署（2026-08-06 生产已改造）。主平台镜像与分发系统彻底分离，见打包边界铁律（文件头）。
COPY version.txt ./version.txt
# 镜像基板版本身份：构建时 --build-arg BASE_VERSION="$(cat version.txt)" 注入，install.sh 靠此 LABEL
# 判断"本地镜像是否已是云端最新基板"→ 是则复用不重下 1.1G（不传则为 unknown，install.sh 回退旁标记文件）。
ARG BASE_VERSION=unknown
LABEL sentinel.base.version=$BASE_VERSION
RUN chmod -R +x external 2>/dev/null || true       # 外部工具二进制（Go 工具经 PATH 调用）加执行权限
# 侦察外部工具上 PATH（recon 对接模块用 shutil.which(bare-name) 解析）：
#   external/bin/* = PD 全家桶(subfinder/dnsx/naabu/httpx/katana) + massdns；nuclei/phantomjs 各自归档目录。
#   缺失的工具对应阶段 available()=False 自动降级（honest degrade），不阻断构建。
RUN set -e; \
    for b in subfinder dnsx naabu httpx katana massdns; do \
        [ -f "external/bin/$b" ] && ln -sf "/opt/sentinel/current/external/bin/$b" "/usr/local/bin/$b" || true; \
    done; \
    [ -f external/nuclei/nuclei_3.3.9_linux_amd64/nuclei ] && ln -sf /opt/sentinel/current/external/nuclei/nuclei_3.3.9_linux_amd64/nuclei /usr/local/bin/nuclei || true; \
    [ -f external/phantomjs/phantomjs ] && ln -sf /opt/sentinel/current/external/phantomjs/phantomjs /usr/local/bin/phantomjs || true; \
    chmod -R +x external/bin 2>/dev/null || true; \
    true

ENV PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1
# config.yaml 不烘焙（挂载只读提供）；只暴露主平台端口（5080 是独立分发系统端口，不属本镜像）。command 由 compose 覆盖
EXPOSE 5013
# gthread 线程模型：SSE 长连接(会话实时观察)占线程不占 worker，防 sync worker 被长连接占满。compose 会覆盖此 command。
CMD ["gunicorn", "-b", "0.0.0.0:5013", "sentinel_platform.wsgi:application", "-w", "3", "--threads", "8", "-k", "gthread", "--timeout", "0"]
