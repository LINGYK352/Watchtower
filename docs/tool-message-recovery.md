# 工具消息历史恢复（v1.21.167）

DeepSeek 或中转站有时返回 DSML/XML/JSON 文本工具调用。旧实现解析并执行后，优先保存未经补齐的 raw_message，再追加原生工具结果。这会形成没有 preceding tool_calls 的 tool 消息，下一次请求返回 HTTP 400。

原始消息仍是正文与推理的来源，但不再无条件优先于已执行调用结构。`_llm._assistant_tool_message` 保留原生 reasoning_content 或 Claude thinking/signature，只有工具 ID/名称与执行调用一致时才原样回填；文本调用则补齐原生调用。引擎验证唯一非空 ID 和结果数量，拒绝半批追加；原生 JSON 参数不完整时不执行空参数工具。

所有 OpenAI/Claude 出站请求统一读取当前历史，不依赖进程内缓存。旧 DSML 历史只有相邻结果的数量、唯一 ID 及名称匹配时才还原调用。无法准确还原的结果转为标注的历史资料，保留原 ID、名称及已保存内容。原生调用缺失的结果明确记录为历史中断（Claude is_error=true），不虚构成功、不重新执行工具。重复结果保留为资料。原始数据库记录不被覆盖，实际证据仍受原有报送校验约束。

兼容 OpenAI 原生调用和 Claude 原生内容块；不改变模型隔离、预算、工具权限或错误分类。真实参数/schema 400 不会被通用重试掩盖。热更新分发 _llm.py/_engine.py 后，Worker 按既有更新器刷新，Web 按 reload 加载；存量用户更新后显式恢复会话即生效，不需改配置或清空历史，也不会自动重启所有作战会话。

验证：25 项解析/回填/历史边界检查；VM 上针对引擎、会话、SSE、模型隔离的有效回归；自有严格 HTTP 上游检验双协议的多轮和旧 checkpoint 恢复，不访问用户目标、不调用收费模型。扩大回归发现的五项原有失败另行记录，未通过改变当前工具权限或会话展示契约来掩盖。

参考契约：[DeepSeek Tool Calls](https://api-docs.deepseek.com/guides/tool_calls/)、[DeepSeek Thinking Mode](https://api-docs.deepseek.com/guides/thinking_mode/)、[Claude Tool Results](https://platform.claude.com/docs/en/agents-and-tools/tool-use/handle-tool-calls)。
