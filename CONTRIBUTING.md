# 贡献指南

感谢你对 AIta 项目的关注！欢迎通过以下方式参与贡献。

## 行为准则

请保持友善、尊重的交流态度，共同维护开放包容的社区氛围。

## 如何贡献

### 报告问题

- 在 [Issues](../../issues) 中搜索是否已有相同问题
- 提交新 Issue 时请包含：复现步骤、预期行为、实际行为、环境信息（浏览器/操作系统）

### 提交代码

1. Fork 本仓库
2. 创建特性分支：`git checkout -b feature/your-feature-name`
3. 提交更改：`git commit -m 'feat: 添加 XXX 功能'`
4. 推送分支：`git push origin feature/your-feature-name`
5. 提交 Pull Request 并描述改动内容

### 提交信息规范

采用 [Conventional Commits](https://www.conventionalcommits.org/) 规范：

| 前缀 | 用途 | 示例 |
|---|---|---|
| `feat` | 新功能 | `feat: 新增谐音梗检测` |
| `fix` | 修复 Bug | `fix: 修复雷达图不显示问题` |
| `docs` | 文档更新 | `docs: 更新 README` |
| `style` | 代码格式 | `style: 统一缩进` |
| `refactor` | 重构 | `refactor: 抽离意图识别模块` |
| `perf` | 性能优化 | `perf: 预编译正则表达式` |
| `test` | 测试 | `test: 补充反讽检测用例` |
| `chore` | 构建/工具 | `chore: 更新依赖版本` |

## 开发约定

- 单文件架构：核心功能全部集成在 `index.html` 中，保持零部署门槛
- 安全优先：处理聊天数据时注意隐私保护，不收集不上传任何用户数据
- 本地优先：默认使用本地分析引擎，AI 增强为可选项
- 兼容性：支持 Chrome / Edge / Firefox 现代浏览器，支持 `file://` 协议直接打开

## 本地开发

```bash
# 克隆仓库
git clone https://github.com/your-username/aita-chat-assistant.git
cd aita-chat-assistant

# 直接打开 index.html 即可使用
# 或启动本地服务器（可选）
python -m http.server 8080
# 访问 http://localhost:8080
```

## 许可证

提交的代码将遵循 [MIT License](./LICENSE)。
