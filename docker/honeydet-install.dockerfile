# honeydet 安装脚本
# 用于在 Docker 镜像构建时安装 honeydet

# 下载并安装 honeydet
RUN set -ex && \
    # 安装 Go 编译环境（如果需要从源码编译）
    # 或者直接下载预编译二进制
    cd /tmp && \
    wget https://github.com/referefref/honeydet/releases/latest/download/honeydet-linux-amd64 -O honeydet && \
    chmod +x honeydet && \
    mv honeydet /usr/local/bin/honeydet && \
    # 验证安装
    honeydet -version || true

# 设置环境变量
ENV HONEYDET_PATH=/usr/local/bin/honeydet
