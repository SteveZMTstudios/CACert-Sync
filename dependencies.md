# 依赖说明

本项目依赖以下Python库:

## 核心依赖
- **beautifulsoup4**: 用于解析HTML页面，在`sync_certificates.py`中用来解析证书网页内容
- **bs4**: BeautifulSoup的包装器，为了兼容性
- **requests**: 用于发起HTTP请求，下载证书和从在线源获取信息
- **certifi**: 提供了Mozilla的CA证书集合，作为证书收集的一个来源
- **pyopenssl**: OpenSSL的Python封装，用于证书操作
- **cryptography**: 加密库，pyOpenSSL的依赖

## 安装方法

可以使用pip直接安装所有依赖:

```bash
pip install -r requirements.txt
```

## 可选依赖
- **lxml**: 作为beautifulsoup4的解析器，可提供更快的HTML解析速度
  ```bash
  pip install lxml
  ```

## 系统要求
本项目依赖于以下系统命令:
- wget: 用于下载证书
- openssl: 用于证书操作和验证
- ca-certificates: 系统CA证书
- libnss3-tools: NSS工具，处理证书
- cabextract: 提取Windows CAB文件

在Ubuntu/Debian系统上，可以使用以下命令安装系统依赖:

```bash
sudo apt-get update
sudo apt-get install -y ca-certificates libnss3-tools openssl cabextract wget
```

## GitHub Actions运行说明

如果在GitHub Actions上运行时遇到依赖问题，请确保：
1. `requirements.txt` 文件中包含了所有需要的Python依赖
2. 工作流文件中正确安装了所有系统依赖
3. 使用`-r requirements.txt`而不是手动列出依赖，以确保一致性
