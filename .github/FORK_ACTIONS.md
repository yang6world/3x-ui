# Fork 自动构建说明

当前 Fork 使用三个主要构建工作流：

- `CI`：提交到 `main` 或创建 Pull Request 时运行测试、静态检查和前端构建；也支持手动运行。
- `Release 3X-UI`：提交到 `main` 时构建 Linux 多架构及 Windows 安装包，并更新 `dev-latest` 预发布版本；推送 `v*.*.*` 标签时创建对应版本构建。
- `Release 3X-UI for Docker`：提交到 `main` 时构建并推送 `latest`、`main` 和 `sha-*` 镜像；推送版本标签时发布版本镜像。

Docker 镜像发布到当前 Fork 自己的 GHCR 地址：

```text
ghcr.io/<当前仓库所有者>/<当前仓库名>
```

不需要配置 Docker Hub 密钥，工作流使用仓库自动提供的 `GITHUB_TOKEN`。

## 首次启用

1. 打开 Fork 仓库的 **Actions** 页面，点击 **I understand my workflows, go ahead and enable them**。
2. 在 **Settings → Actions → General** 中允许仓库使用工作流所需的 Actions。
3. 确认工作流可以申请 `contents: write` 和 `packages: write` 权限。权限已经在工作流内按任务声明。
4. 提交一次影响 Go、前端或 Docker 构建文件的改动到 `main`，或在 Actions 页面手动运行工作流。
5. 第一次推送完成后，在仓库的 **Packages** 页面把容器包可见性调整为所需的 Public 或 Private。

## 可选工作流

- Claude Issue/PR 工作流需要仓库 Secret `CLAUDE_CODE_OAUTH_TOKEN`。没有该 Secret 时，建议在 Actions 页面禁用这两个工作流。
- Docs Deploy 需要在 **Settings → Pages** 中选择 GitHub Actions，并建议设置仓库变量 `NEXT_PUBLIC_SITE_URL`。
- 定时 Mutation testing 和 Cleanup Caches 会消耗 Actions 分钟；Fork 不需要时可以在 Actions 页面禁用。

## 当前仍沿用上游的部分

安装和面板自更新脚本仍从 `MHSanaei/3x-ui` 获取正式版本。因此 Fork 已关闭“发布后安装”冒烟任务，避免它错误地测试上游同名版本。CI、本仓库 Release 构建产物以及 GHCR Docker 镜像不受影响。如果需要让安装、自更新也完整跟随 Fork，需要另行修改 `install.sh`、`update.sh` 和 `x-ui.sh` 中的仓库来源。
