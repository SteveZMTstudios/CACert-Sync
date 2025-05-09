# CA证书同步

定期从多个权威来源收集CA根证书，并将它们保存在标准格式中。通过GitHub Actions自动化运行，每年更新一次，确保证书库保持更新。访问 [ca-update.stevezmt.top](https://ca-update.stevezmt.top) 查看并下载CA证书。

> [!CAUTION]
> 该项目仅收集和存储来自网络上公开的CA证书，不对其即时性和真实性做出保证。<br>
> 导入未知来源的CA证书可能会使您的设备陷入风险，包括但不限于网络流量被监视等。<br>

## 功能

- 从多个权威来源收集CA根证书：
  - Ubuntu ca-certificates
  - Firefox的PEM证书链
  - Microsoft Windows证书更新
  - python-certifi库

- 自动处理已撤销的证书
- 提供可兼容所有浏览器的下载界面
- 自动创建GitHub Releases归档
- 通过GitHub Pages提供在线访问

## 目录结构

- `/scripts`: 证书收集和处理脚本
- `/certs`: 最终的证书存储目录
- `/templates`: 网站模板
- `/.github/workflows`: GitHub Actions工作流配置

## 快速开始

### 在线访问
访问 [ca-update.stevezmt.top](https://ca-update.stevezmt.top) 查看并下载CA证书。

### 本地再部署（作为服务器）

1. 克隆仓库：
   ```bash
   git clone https://github.com/yourusername/cacert-sync.git
   cd cacert-sync
   ```

2. 运行安装脚本：
   ```bash
   ./install.sh
   ```

3. 使用命令行工具：
   ```bash
   # 激活虚拟环境
   source venv/bin/activate
   
   # 运行测试
   python scripts/cacert-cli.py test
   
   # 同步证书
   python scripts/cacert-cli.py sync
   ```

   因为会需要从系统的`ca-certificates`中读取证书，所以需要作为root运行。

### 使用GitHub Actions自动化

1. Fork这个仓库
2. 启用GitHub Actions
3. 启用GitHub Pages，使用`gh-pages`分支或`/docs`目录
4. 证书将自动每年更新一次

## 手动触发更新

可以通过GitHub Actions页面手动触发更新流程。

## 证书撤销处理

系统会自动处理已撤销的证书，将它们从证书库中移除。已撤销的证书列表来源于Mozilla、Microsoft和其他可信来源。

## 浏览器兼容性

生成的网页设计兼容所有浏览器，包括：
- 现代浏览器 (Chrome, Firefox, Edge, Safari)
- 旧版浏览器 (IE5/6, Netscape)
- 文本浏览器 (w3m, lynx)




