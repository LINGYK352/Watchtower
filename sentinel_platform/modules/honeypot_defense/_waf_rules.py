"""honeypot_defense/_waf_rules —— Web 攻击检测规则集（OWASP CRS 衍生的成熟正则）。

**来源与设计**：手写零散正则漏检严重（如经典 `or '1'='1'` 变体），本模块移植 OWASP Core Rule Set
(CRS) 的核心检测正则思想（SQLi/XSS/RCE/LFI/RFI），纯 Python 正则实现——无需编译、无新依赖、纯热更。
非 libinjection(C库)级别 100% 覆盖，但覆盖常见变体远优于手写，配合行为层漏桶足够告警用途。

规则按攻击族组织，每条 (compiled_regex, 说明)。检测方 attack_alert.AttackDetector 逐族匹配计分。
更新规则：直接加/改本文件的正则条目，走热更新即到达存量实例（对齐 CRS 可持续更新的思路）。
"""
from __future__ import annotations

import re

# ── SQL 注入（CRS 942xxx 衍生：经典布尔/联合/时间盲注/堆叠/注释/编码变体）──
# 覆盖手写版漏掉的引号变体 'x'='x'、数字比较、常见函数、information_schema 等。
SQLI_PATTERNS = [
    # 布尔盲注：or/and + 比较（含引号变体 '1'='1'、"a"="a"、1=1、1 like 1）
    re.compile(r"(?i)(?:'|\"|`|\s)(?:or|and)\s+(?:'?[\w]+'?|\d+)\s*(?:=|!=|<>|like|>|<)\s*(?:'?[\w]+'?|\d+)"),
    re.compile(r"(?i)\b(?:or|and)\b\s+\d+\s*=\s*\d+"),                       # or 1=1 / and 2=2
    re.compile(r"(?i)['\"`]\s*(?:or|and)\s+['\"`]?\s*\d"),                   # ' or '1 / " or 1
    # 联合查询注入
    re.compile(r"(?i)\bunion\b(?:\s+all)?\s+\bselect\b"),
    re.compile(r"(?i)\bselect\b.{1,100}?\bfrom\b"),
    re.compile(r"(?i)\b(?:insert\s+into|delete\s+from|update\s+\w+\s+set|drop\s+(?:table|database)|truncate\s+table|alter\s+table)\b"),
    # 时间/条件盲注 + 危险函数
    re.compile(r"(?i)\b(?:sleep|benchmark|pg_sleep|waitfor\s+delay|dbms_pipe\.receive_message)\s*\("),
    re.compile(r"(?i)\b(?:load_file|into\s+(?:out|dump)file|extractvalue|updatexml|floor\s*\(\s*rand)\b"),
    re.compile(r"(?i)\b(?:exec(?:ute)?|sp_executesql|xp_cmdshell)\b\s*[\(@]"),
    # 元数据探测 / 注释截断
    re.compile(r"(?i)\b(?:information_schema|table_schema|table_name|column_name|version\s*\(\s*\)|@@version|database\s*\(\s*\))\b"),
    re.compile(r"(?:--\s|#|/\*.*?\*/|;\s*--)"),                              # SQL 注释符
    re.compile(r"(?i)['\"`]\s*;\s*(?:select|insert|update|delete|drop|exec)"),  # 堆叠查询
]

# ── XSS（CRS 941xxx 衍生：脚本标签/事件处理器/协议/编码/DOM 汇聚点）──
XSS_PATTERNS = [
    re.compile(r"(?i)<\s*script[\s/>]"),
    re.compile(r"(?i)</\s*script\s*>"),
    re.compile(r"(?i)<\s*(?:img|svg|iframe|body|input|video|audio|object|embed|marquee|details)[^>]*\bon\w+\s*="),
    re.compile(r"(?i)\bon(?:error|load|click|mouseover|focus|toggle|animationstart|beforescriptexecute)\s*="),
    re.compile(r"(?i)javascript\s*:"),
    re.compile(r"(?i)\b(?:alert|prompt|confirm|eval|atob|String\.fromCharCode)\s*\("),
    re.compile(r"(?i)<\s*(?:iframe|frame|embed|object)[^>]*\bsrc\s*="),
    re.compile(r"(?i)(?:document\.(?:cookie|domain|location|write)|window\.(?:location|name)|\.innerHTML)"),
    re.compile(r"(?i)(?:expression\s*\(|url\s*\(\s*javascript|vbscript\s*:)"),
    re.compile(r"(?i)&#x?[0-9a-f]{2,};.*(?:script|alert|onerror)"),          # HTML 实体编码绕过
]

# ── 命令注入 / RCE（CRS 932xxx 衍生：shell 元字符 + 命令、反引号、$()、管道）──
RCE_PATTERNS = [
    re.compile(r"(?i)[;|&`]\s*(?:whoami|id|uname|cat|ls|dir|pwd|wget|curl|nc|ncat|bash|sh|python|perl|ping|nslookup|ifconfig|ipconfig|net\s+user|type\s)"),
    re.compile(r"(?i)\|\s*(?:whoami|id|cat|ls|nc|bash|sh|curl|wget)"),
    re.compile(r"\$\((?:[^)]{1,80})\)"),                                     # $(cmd)
    re.compile(r"`[^`]{1,80}`"),                                            # `cmd`
    re.compile(r"(?i)(?:;|\|\||&&)\s*(?:rm\s+-rf|chmod\s|chown\s|kill\s|reboot|shutdown)"),
    re.compile(r"(?i)\b(?:/bin/(?:ba)?sh|/etc/passwd|/etc/shadow|cmd\.exe|powershell(?:\.exe)?)\b"),
    re.compile(r"(?i)\b(?:system|exec|passthru|shell_exec|popen|proc_open|assert)\s*\("),   # PHP RCE 函数
    re.compile(r"(?i)(?:\$\{jndi:|%24%7bjndi)"),                            # Log4Shell
]

# ── 目录遍历 / LFI（CRS 930xxx 衍生：../ 及各种编码变体、绝对路径、null 字节）──
TRAVERSAL_PATTERNS = [
    re.compile(r"(?:\.\./|\.\.\\){1,}"),                                    # ../ 或 ..\
    re.compile(r"(?i)(?:%2e%2e[/\\]|%2e%2e%2f|%2e%2e%5c)"),                 # URL 编码
    re.compile(r"(?i)(?:\.\.%2f|\.\.%5c|%252e%252e)"),                     # 双重编码
    re.compile(r"(?i)(?:/etc/(?:passwd|shadow|hosts|group)|/proc/self/environ|c:\\windows\\|boot\.ini)"),
    re.compile(r"(?i)(?:file|php|zip|phar|data|expect)://"),                # PHP 封装协议 LFI/RFI
    re.compile(r"%00"),                                                     # null 字节截断
]

# ── 敏感路径 / 探测（平台不存在的敏感文件/后台/元文件；仅 4xx 时计分，见检测器）──
SENSITIVE_PATH_PATTERNS = [
    re.compile(r"(?i)/\.git(?:/|$)"),
    re.compile(r"(?i)/\.svn(?:/|$)"),
    re.compile(r"(?i)/\.env(?:\.|$|/)"),
    re.compile(r"(?i)/\.(?:aws|ssh|docker|vscode|idea)(?:/|$)"),
    re.compile(r"(?i)/(?:backup|bak|dump|db|database|www|web|site|old|test)\.(?:zip|tar|gz|sql|rar|7z|bak)$"),
    re.compile(r"(?i)/(?:phpmyadmin|pma|adminer|myadmin)(?:/|$)"),
    re.compile(r"(?i)/(?:wp-admin|wp-login|wp-config|wp-content)"),
    re.compile(r"(?i)/(?:config|configuration|settings|setup|install)\.(?:php|inc|bak|old|txt|yml|yaml)$"),
    re.compile(r"(?i)/(?:actuator|phpinfo|info\.php|test\.php|shell\.php|console/text)(?:/|$)"),
    re.compile(r"(?i)/(?:shell|cmd|webshell|c99|r57|b374k|wso|backdoor)\.(?:php|jsp|asp|aspx|war)"),
    re.compile(r"(?i)\.(?:bak|old|swp|orig|save|~|inc|log)$"),
    re.compile(r"(?i)/(?:\.htaccess|\.htpasswd|web\.config|composer\.(?:json|lock)|\.DS_Store|Dockerfile|docker-compose)"),
]

# ── 扫描器 / 恶意 UA（弱信号）──
SCANNER_UA_KEYWORDS = [
    "sqlmap", "nikto", "nmap", "masscan", "nessus", "openvas", "burp", "acunetix",
    "appscan", "metasploit", "dirsearch", "nuclei", "gobuster", "ffuf", "wfuzz",
    "feroxbuster", "dirbuster", "hydra", "zgrab", "httpx", "xray", "goby",
    "python-requests", "python-urllib", "go-http-client", "curl/", "wget/",
    "libwww-perl", "scrapy", "zmeu", "netsparker",
]

# ── Webshell 上传文件名特征 ──
WEBSHELL_PATTERNS = [
    re.compile(r"(?i)(?:shell|cmd|backdoor|c99|r57|b374k|wso|antsword|godzilla|behinder)\.(?:php|jsp|asp|aspx)"),
    re.compile(r"(?i)\.(?:php[3457]?|phtml|jsp|jspx|asp|aspx|ashx)(?:\.|$|;)"),
    re.compile(r"(?i)(?:eval|assert|system|exec|base64_decode)\s*\("),
]
