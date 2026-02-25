# 证书收集系统的主要配置和设置

# 证书来源配置
SOURCES = [
    "ubuntu",    # Ubuntu ca-certificates
    "firefox",   # Firefox的证书链
    "windows",   # Microsoft Windows的证书更新
    "certifi"    # Python certifi库
]

# 更新频率设置 (GitHub Actions中使用)
UPDATE_FREQUENCY = "yearly"  # 每年更新一次

# 证书黑名单更新源
BLACKLIST_SOURCES = [
    "https://wiki.mozilla.org/CA/Revoked_Certificates",
    "https://ccadb.org/resources"
]

# HTML模板设置
TEMPLATE_DIR = "templates"
INDEX_TEMPLATE = "index.html"

# 证书存储设置
CERTS_DIR = "certs"

# 项目元数据
METADATA = {
    "title": "CA证书库",
    "description": "提供最新的可信CA根证书的收集库",
    "github": "https://github.com/stevezmtstudios/cacert-sync",
    "version": "1.0.0"
}

# 修复导航上下文 (用于相对路径)
SITE_CONTEXT = {
    "assets_path": "assets",  # 资源路径
    "certs_path": "certs"      # 证书路径
}
