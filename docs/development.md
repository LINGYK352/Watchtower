# 开发指南

## 运行环境

前端使用 Vue 3、TypeScript 和 Vite 5。后端依赖清单以 Python 3.8 的 Linux 运行环境为历史基线；部分锁定依赖对安装器版本有要求。其他 Python 版本需要自行验证，不能仅因模块可以导入就认为完整运行兼容。

完整功能还依赖 MongoDB、RabbitMQ、浏览器运行环境及按需准备的外部工具。公开仓库只提供源码、配置样例、字典和模板，不包含完整离线发行依赖。

## 前端

```bash
cd frontend
npm ci
npm run build
```

构建会执行 TypeScript 检查，并将产物写入 `docker/frontend/`。该目录由 Nginx 提供服务，产物不纳入 Git。

```bash
npm run dev
```

开发服务器默认监听所有网络接口，请控制开发网络暴露范围。当前 Vite 配置没有自动配置后端 API 代理；需要根据开发环境设置反向代理或访问路径，不应假定启动前端即具备完整后端。

## 后端

使用隔离的 Python 环境，先阅读 `requirements.txt` 对平台、版本和离线安装的说明。历史 Celery 版本的安装可能需要 `pip<24.1`，不要修改系统 Python 来满足项目要求。

将配置样例复制到实际开发配置位置并填写本地服务连接信息。配置、凭据、数据库和运行标记不得提交。

```bash
# 从仓库根目录启动开发服务器
python -m sentinel_platform
```

此入口默认监听 `127.0.0.1:5003`，可由 `SENTINEL_HOST` 和 `SENTINEL_PORT` 调整。它仅用于开发；Compose 中的生产 Web 入口使用 Gunicorn，监听容器内 `5013`。

Worker 和调度器入口分别为：

```bash
celery -A sentinel_platform.celery_app:celery_app worker -l info
python -m sentinel_platform.scheduler
```

启动前确认数据库、消息队列和配置指向开发环境。任务执行可能产生真实网络请求，不要把开发配置指向未授权目标或生产数据源。

## 验证

确定性回归层不联网、不调用模型，也不依赖生产数据库：

```bash
python -m sentinel_platform.tests.regression
```

该入口只选择 `test_reg_*.py`，不会自动执行 `live_fire` 实验。完整说明见[回归测试说明](../sentinel_platform/tests/regression/README.md)。

按修改的模块选择单测。部分扩展、集成和端到端测试需要额外依赖或隔离服务，不应把未完成的全量测试报告为通过。涉及页面交互、Worker、Scheduler 或多进程状态时，还需在隔离环境做真实链路验证。

## 修改边界

- HTTP 路由放在 `router/endpoints/`，业务能力放在对应模块。
- 跨模块优先使用 `contracts` 和 Registry；统一装配入口是 `bootstrap.py`。
- 外部工具通过适配器调用和解析；原始输出不要直接成为平台数据契约。
- JSON API 沿用 `code`、`message`、`data` 信封；二进制下载等端点按各自约定处理。
- 多 Worker 状态不能依赖某个 Web 进程的内存值；共享状态及幂等条件需明确。
- 应用行为改动需遵守项目的版本、构建、变更记录和发布流程；纯文档整理不冒充新的正式软件版本。

## 准备 Pull Request

阅读[贡献指南](../CONTRIBUTING.md)，说明问题、改动范围、验证结果及限制。不要提交测试账号凭据、运行日志、客户截图、数据库或大体积第三方二进制。
