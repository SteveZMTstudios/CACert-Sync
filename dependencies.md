# 依赖说明

本项目依赖以下Python库:

## 核心依赖
- **beautifulsoup4**: 用于解析HTML页面，在`sync_certificates.py`中用来解析证书网页内容
- **requests**: 用于发起HTTP请求，下载证书和从在线源获取信息
- **certifi**: 提供了Mozilla的CA证书集合，作为证书收集的一个来源

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
