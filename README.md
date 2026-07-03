<div align="center">

# AIta — AI 情感智能聊天助手

**让每一次心动都不再错过**

一个基于纯前端单文件架构的 AI 情感智能聊天分析工具，帮助你读懂对方、说对话、找准时机。

[功能特性](#-功能特性) ·
[快速开始](#-快速开始) ·
[使用指南](#-使用指南) ·
[技术架构](#-技术架构) ·
[配置说明](#-配置说明) ·
[部署方式](#-部署方式)

</div>

---

## 背景

社交场景中，"看不懂对方在想什么""不知道该说什么"是高频痛点。市面上的 AI 聊天工具大多只看最后一条消息就给建议，缺乏对完整对话上下文的理解，容易给出脱离语境甚至翻车的回复。

AIta 把聊天记录分析做成一个完整的工程问题：从角色识别、人格画像、情绪轨迹到接话建议，全链路打通，并且**所有数据只在用户浏览器本地处理**，不上传不收集。

## 核心特性

- **单文件零部署**：核心功能全部集成在一个 `index.html` 中（约 530KB），双击即用，无需后端服务器
- **本地引擎优先**：内置完整的本地分析引擎，开箱即用；可选配置 AI 大模型增强分析深度
- **全上下文理解**：分析全量对话而非只看最后一条，识别关系阶段、情绪走势、对话热度
- **语气模仿**：学习用户的说话风格（用词、语气词、表情符号习惯），生成贴合用户人设的回复建议
- **安全设计**：反讽检测、严肃场景保护、危机干预短路、Prompt 注入防护等多层安全机制
- **隐私保护**：所有数据仅在浏览器本地处理，不向任何服务器上传聊天内容

## 功能概览

### 聊天记录智能分析

粘贴聊天文本或上传聊天截图（OCR 自动识别），系统会：

- 自动识别"我"与"对方"角色（支持时间戳前缀剥离、系统消息过滤）
- 生成对方的人格画像、MBTI 性格类型分析
- 输出沟通风格仪表盘（主动性/亲密度/直接度/情绪基调/节奏感 5 维）
- 渲染 5D 雷达图（带扫描激活动画）
- 判断关系阶段（初识期/试探期/稳定期等）
- 分析情绪轨迹（对方情绪是上扬还是走低）

### AI 接话建议

基于全量对话上下文，给出 3 条贴合用户语气风格的回复建议：

- 支持"换一批"获取更多方案
- 区分催问型/求意见型等不同问题类型
- 反讽检测避免"低情商翻车"（识别"你可真行""呵呵加油哦"等被动攻击）
- 严肃场景自动切换陪伴模式（失恋/被骂/失业等不接梗）
- 危机信号短路干预（自伤倾向触发安全引导与热线）

### 攻略策略生成

诊断当前关系卡点，围绕"卡点—根因—突破—规避"输出策略：

- 7 类卡点诊断（回避型/简短回复/反讽/内敛/浅层外向/亲密/普通）
- 线上沟通策略 + 线下行动建议 + 时间线推进
- 质量优先于数量，禁止通用废话建议

## 快速开始

### 方式一：直接打开（推荐）

```bash
# 下载或克隆仓库
git clone https://github.com/your-username/aita-chat-assistant.git
cd aita-chat-assistant

# 直接用浏览器打开 index.html 即可
# Windows
start index.html
# macOS
open index.html
# Linux
xdg-open index.html
```

无需安装任何依赖，无需后端服务，开箱即用。

### 方式二：本地服务器（可选）

```bash
# 使用 Python
python -m http.server 8080

# 或使用 Node.js
npx serve -l 8080

# 然后访问 http://localhost:8080
```

### 方式三：Node.js 后端部署（可选）

如果需要使用服务端代理 AI API（避免浏览器跨域），可以启动内置的 Node.js 服务器：

```bash
npm install
npm start
# 服务启动在 http://localhost:3001
```

## 使用指南

### 基本流程

1. **粘贴聊天记录**：在聊天记录输入框粘贴文本（支持 `我：xxx` / `对方：xxx` 或 `【我】xxx` / `【对方】xxx` 等常见格式）
2. **填写基本信息**（可选）：对方昵称、认识时长、关系状态等
3. **点击分析**：等待几秒钟，获得完整分析报告
4. **查看接话建议**：在建议区查看 3 条回复建议，可点击"换一批"刷新
5. **可选：上传截图**：支持拖拽上传聊天截图，OCR 自动识别文字

### 配置 AI 增强（可选）

本地引擎已经可以独立工作。如果想获得更深度的分析，可以配置 AI 大模型：

1. 点击右上角齿轮图标进入设置
2. 选择 AI 服务商（支持 DeepSeek / 智谱 GLM / 月之暗面 Kimi / 通义千问 / OpenAI / 硅基流动）
3. 填入 API Key 和模型名称
4. 保存后所有分析将由 AI 生成，本地引擎仅在 AI 字段缺失时兜底

### 隐私清除

如果想清除本地保存的所有配置（API Key、模型等），可在设置页面点击"清除所有本地配置"按钮，一键清除所有 localStorage 数据。

## 技术架构

### 整体设计

```
┌─────────────────────────────────────────┐
│              index.html (单文件)          │
│  ┌─────────────────────────────────────┐ │
│  │         前端 UI (玻璃拟态深色)        │ │
│  │   Aurora 流光 + 雷达图 + 仪表盘      │ │
│  └──────────────┬──────────────────────┘ │
│  ┌──────────────▼──────────────────────┐ │
│  │          本地分析引擎                │ │
│  │  角色识别 → 风格分析 → 意图识别      │ │
│  │  → 情绪轨迹 → 建议生成 → 安全审查    │ │
│  └──────────────┬──────────────────────┘ │
│  ┌──────────────▼──────────────────────┐ │
│  │       AI 增强（可选，用户自配）       │ │
│  │  6 厂商适配 + 归一化层 + JSON mode   │ │
│  └─────────────────────────────────────┘ │
└─────────────────────────────────────────┘
```

### 核心模块

| 模块 | 职责 | 关键函数 |
|---|---|---|
| 角色识别 | 区分"我"与"对方"消息 | `parseChatMessages` |
| 风格分析 | 15 维用户/对方风格画像 | `analyzeUserStyle` / `analyzeSpeaker` |
| 意图识别 | 8 大意图分支 + 语境消解 | `detectIntent` / `detectSarcasm` |
| 情绪分析 | 情感深度分析 + 情绪轨迹 | `analyzeSentimentDeep` / `emotionShift` |
| 建议生成 | 语气模仿 + 上下文调整 | `generateLocalSuggestion` / `styleMessage` |
| 安全保护 | 反讽/严肃/危机/Prompt 注入 | `detectCrisis` / `critiqueSuggestion` |
| AI 归一化 | AI 返回结果字段修复与兜底 | `normalizeAIAnalysis` / `normalizeAISuggestion` |
| 梗识别 | 网络梗 + 多语言谐音梗 | `detectMeme` / `detectHomophone` |

### 安全机制

- **危机干预短路**：检测到自伤/自杀信号时，跳过所有正常建议，返回安全引导与心理援助热线
- **反讽检测**：识别"你可真行""呵呵加油哦"等被动攻击，避免顺着夸回去的翻车
- **严肃场景保护**：失恋/被骂/失业等场景禁用幽默和表情符号，切换陪伴模式
- **关系阶段感知**：初识期阻止暧昧建议，避免越界
- **Prompt 注入防护**：所有用户输入在 AI Prompt 中以 XML 标签隔离，防止指令注入
- **自我审查机制**：每条建议生成后经过 `critiqueSuggestion` 审查，发现重复/越界/语气不符等问题自动替换

## 配置说明

### 本地引擎（默认）

无需任何配置，直接打开 `index.html` 即可使用。

### AI 增强（可选）

支持 6 大 AI 服务商，任选其一：

| 服务商 | Endpoint | 推荐模型 | 获取 Key |
|---|---|---|---|
| DeepSeek | `https://api.deepseek.com/v1` | `deepseek-chat` | [platform.deepseek.com](https://platform.deepseek.com) |
| 智谱 AI | `https://open.bigmodel.cn/api/paas/v4` | `glm-4-flash` | [open.bigmodel.cn](https://open.bigmodel.cn) |
| 月之暗面 | `https://api.moonshot.cn/v1` | `moonshot-v1-8k` | [platform.moonshot.cn](https://platform.moonshot.cn) |
| 通义千问 | `https://dashscope.aliyuncs.com/compatible-mode/v1` | `qwen-turbo` | [dashscope.console.aliyun.com](https://dashscope.console.aliyun.com) |
| OpenAI | `https://api.openai.com/v1` | `gpt-4o-mini` | [platform.openai.com](https://platform.openai.com) |
| 硅基流动 | `https://api.siliconflow.cn/v1` | `deepseek-ai/DeepSeek-V3` | [cloud.siliconflow.cn](https://cloud.siliconflow.cn) |

**说明**：
- 智谱 AI 的 Key 格式为 `xxx.xxx`，会自动切换到 `glm-4v-plus` 视觉模型
- 文本模型不支持图片输入，上传截图时会自动降级为 OCR 文字分析
- API Key 仅保存在浏览器 localStorage，不会上传到任何服务器

### 环境变量（仅 Node.js 后端模式）

```env
LLM_API_KEY=your-api-key
LLM_BASE_URL=https://open.bigmodel.cn/api/paas/v4
LLM_MODEL=glm-4-flash
LLM_VISION_MODEL=glm-4v-plus
PORT=3001
```

## 部署方式

### 静态托管

`index.html` 是纯前端单文件，可直接部署到任何静态托管平台：

- **GitHub Pages**：推送代码后在仓库 Settings → Pages 开启
- **Vercel / Netlify**：连接仓库，构建命令留空，输出目录为根目录
- **Cloudflare Pages**：同上
- **自有服务器**：将 `index.html` 上传到任意 Web 服务器静态目录

### Docker

```dockerfile
FROM nginx:alpine
COPY index.html /usr/share/nginx/html/
EXPOSE 80
CMD ["nginx", "-g", "daemon off;"]
```

```bash
docker build -t aita .
docker run -p 8080:80 aita
```

## 项目结构

```
.
├── index.html              # 主应用（单文件，包含前端+本地引擎+AI集成）
├── server.js               # Node.js 后端（可选，用于 AI API 代理）
├── package.json            # 项目配置与依赖
├── README.md               # 项目说明
├── LICENSE                 # MIT 许可证
├── CONTRIBUTING.md         # 贡献指南
└── .gitignore              # Git 忽略规则
```

## 技术栈

| 类别 | 技术 |
|---|---|
| 前端 | 原生 HTML / CSS / JavaScript（无框架依赖） |
| 视觉 | 玻璃拟态、CSS 变量、Canvas 雷达图、Aurora 流光 |
| OCR | Tesseract.js（懒加载） |
| AI | OpenAI 兼容协议（支持 6 大厂商） |
| 后端 | Node.js + Express（可选） |
| 存储 | 浏览器 localStorage |

## 兼容性

- ✅ Chrome 90+（推荐）
- ✅ Edge 90+（推荐）
- ✅ Firefox 90+
- ✅ 支持 `file://` 协议直接打开
- ✅ 响应式布局，支持移动端
- ✅ 支持 `prefers-reduced-motion` 无障碍设置

## 性能

- 本地引擎响应时间：0.15–0.59ms
- 单文件体积：约 530KB（无外部依赖）
- 首屏加载：Tesseract.js 懒加载，不阻塞首屏渲染
- 正则表达式预编译，避免高频编译开销

## 常见问题

<details>
<summary>打开后提示"无法连接服务器"？</summary>

这是本地服务器模式的提示。直接打开 `index.html` 不需要后端服务器，本地引擎会自动接管所有分析。如果要用 AI 增强功能，可以在设置中配置 API Key（前端直连模式）。
</details>

<details>
<summary>API Key 会泄露吗？</summary>

不会。API Key 仅保存在你浏览器的 localStorage 中，不会上传到任何服务器。前端直连 AI API 时，Key 直接从浏览器发送到 AI 服务商，不经过任何中间服务器。
</details>

<details>
<summary>聊天记录会被上传吗？</summary>

本地引擎模式下，所有数据只在浏览器本地处理。AI 增强模式下，聊天内容会发送到你配置的 AI 服务商进行分析，但不会经过任何其他服务器。
</details>

<details>
<summary>支持哪些聊天格式？</summary>

支持常见格式：`我：xxx` / `对方：xxx`、`【我】xxx` / `【对方】xxx`、`A: xxx` / `B: xxx`，并自动剥离 `[14:30]` `(14:30)` `2024-01-01 14:30` 等时间戳前缀，过滤"撤回/已读/正在输入"等系统消息。
</details>

## 贡献

欢迎提交 Issue 和 Pull Request。请阅读 [贡献指南](./CONTRIBUTING.md) 了解开发约定。

## 许可证

[MIT License](./LICENSE) — 自由使用、修改、分发。
