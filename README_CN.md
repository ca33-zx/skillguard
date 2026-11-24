<div align="center">

# `skillguard`

**零依赖 AI Coding Agent 安全静态审计工具：专扫 Skills (`SKILL.md`)、MCP 配置、指令文件 (`CLAUDE.md` / `AGENTS.md` / `.cursorrules`) 与 Agent Hooks**

[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/downloads/)
[![Zero Dependencies](https://img.shields.io/badge/dependencies-0%20(stdlib%20only)-blueviolet.svg)](pyproject.toml)
[![Tests](https://img.shields.io/badge/tests-13%20passed-brightgreen.svg)](tests/)
[![SARIF 2.1.0](https://img.shields.io/badge/SARIF-2.1.0-orange.svg)](src/skillguard/reporters.py)
[![License](https://img.shields.io/badge/license-Apache%202.0-green.svg)](LICENSE)

[English](README.md) | 简体中文

</div>

---

越来越多开发者在本地使用 **Claude Code、OpenCode、OpenClaw、Cursor、Codex、Windsurf、Cline、Antigravity**，并直接从社区安装各种 **`SKILL.md` 技能包、`.mcp.json` 服务配置、`CLAUDE.md` 规则文件与 `settings.json` 钩子（Hooks）**。

这些文件直接拥有你本机的 Shell 权限、文件系统与 API Key 访问权——只要在看似无害的 Markdown 里藏一行**肉眼完全不可见的 Unicode Tag 字符（`U+E0000–U+E007F`）**、一个隐藏的 `<!-- HTML 注释 -->`、一个未锁版本的 `npx -y` MCP 服务，或者一条 `SessionStart` Hook，就能在后台静默窃取 `~/.ssh`、`~/.aws` 和 `$ANTHROPIC_API_KEY`。

**`skillguard`** 完全基于 **Python 标准库（零第三方运行时依赖）**，毫秒级扫描全套 AI Agent 扩展面，**自动解码隐藏的 Unicode 与 Base64 载荷**，支持 **彩色终端、JSON、SARIF 2.1.0（直连 GitHub Code Scanning）与暗黑交互式 HTML 审计仪表盘**。

![skillguard 肉眼所见 vs 毫秒级安全审计对比图](assets/skillguard_hero.png)

---

## 六大静态安全检测引擎（内置 22 条规则）

| 检测引擎 | 规则编号 | 核心覆盖威胁 |
|---|---|---|
| **1. 不可见 Unicode 隐写引擎** | `SG001`–`SG004` | **Unicode Tag Block（`U+E0000–U+E007F`）隐形 ASCII 注入**（*自动解码还原明文！*）、Trojan Source 双向字符欺骗（`U+202E`）、零宽字符簇、隐藏 HTML 注释注入 |
| **2. 提示词注入与持久化引擎** | `SG010`–`SG013` | 越权指令覆盖、隐瞒用户指令（`never tell the user`）、Markdown 外链图片数据外泄、`--dangerously-skip-permissions` / 自我修改 `CLAUDE.md` 蠕虫指令、`~/.zshrc` 与 `.git/hooks` 投毒 |
| **3. 密钥窃取与硬编码泄露引擎** | `SG020`–`SG022` | 读取 `~/.ssh/id_*`、`~/.aws/credentials`、`~/.kube/config`、Keychain/DPAPI，外传 `$ANTHROPIC_API_KEY`/`$GITHUB_TOKEN`，配置文件误提交真实 API Key（*自动脱敏展示*） |
| **4. 危险 Shell 与混淆执行引擎** | `SG030`–`SG033` | `curl \| sh` / PowerShell `iex (irm ...)` 远程执行、`base64 -d \| sh`（*自动解码还原！*）、`/dev/tcp` 反弹 Shell、`crontab`/`LaunchAgents` 持久化、高危 `rm -rf` |
| **5. MCP 与 Agent Hook 供应链审计** | `SG040`–`SG044` | 未锁定版本的 `npx -y` / `uvx` 动态包执行（防投毒/Rug-pull）、恶意 `SessionStart`/`PreToolUse`/`PostToolUse` Hook、通配符 `Bash(*)` / `autoApprove: ["*"]`、非本地明文 `http://` MCP 端点、MCP `env` 明文密钥 |
| **6. 技能脚本 Python AST 深度分析** | `SG050`–`SG051` | 对 `skills/*/scripts/*.py` 做抽象语法树（AST）分析，检出 `eval`/`exec`/`shell=True` 与敏感文件外传——**即便路径被字符串拼接拆分（如 `".aws" + "/credentials"`）也能精准还原捕获** |

---

## 快速体验

```bash
# 安装（零第三方依赖）
pip install -e .

# 1. 扫描内置红队演示靶场（毫秒级揪出隐形 Unicode 注入、MCP 供应链风险、恶意 Hook 与 AST 密钥外传）
skillguard scan examples/vulnerable_workspace

# 2. 验证干净工作区零误报（Risk 0/100, Grade A+）
skillguard scan examples/safe_workspace

# 3. 扫描当前项目 + 本机全局 Agent 配置目录（~/.claude、~/.cursor、~/.codex 等）
skillguard scan . --include-home

# 4. 导出暗黑模式交互式 HTML 审计报告 或 GitHub SARIF 2.1.0 报告
skillguard scan examples/vulnerable_workspace --format html --out report.html --fail-on none
skillguard scan . --format sarif --out skillguard.sarif --fail-on high

# 5. 查看全部 22 条内置规则与 CWE 映射
skillguard rules
```

---

## 抑制误报（行内注释 & `.skillguardignore`）

```markdown
<!-- skillguard:ignore SG013 -->
说明文档中正常提及用户手动配置 ~/.bashrc。
```

或在仓库根目录添加 `.skillguardignore` 排除指定路径。

## 开源协议

本项目基于 [Apache-2.0](LICENSE) 协议开源。
