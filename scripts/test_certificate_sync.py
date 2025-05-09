#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
测试证书收集和页面生成
脚本仅用于本地测试，而不是GitHub Actions
"""

import os
import sys
import logging
import shutil
import subprocess
from pathlib import Path
import datetime

# 配置日志
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)]
)
logger = logging.getLogger("ca-cert-test")

# 定义常量
SCRIPT_DIR = Path(__file__).parent.absolute()
ROOT_DIR = SCRIPT_DIR.parent
CERTS_DIR = ROOT_DIR / "certs"
TEST_CERTS_DIR = ROOT_DIR / "test-certs"
TEMP_DIR = ROOT_DIR / "temp"


def setup_test_environment():
    """设置测试环境"""
    logger.info("设置测试环境...")
    
    # 创建测试证书目录
    if TEST_CERTS_DIR.exists():
        shutil.rmtree(TEST_CERTS_DIR)
    TEST_CERTS_DIR.mkdir(exist_ok=True, parents=True)
    
    # 确保证书目录存在
    if CERTS_DIR.exists():
        shutil.rmtree(CERTS_DIR)
    CERTS_DIR.mkdir(exist_ok=True, parents=True)
    
    # 创建临时目录
    if TEMP_DIR.exists():
        shutil.rmtree(TEMP_DIR)
    TEMP_DIR.mkdir(exist_ok=True, parents=True)
    
    # 创建示例证书
    logger.info("创建示例证书...")
    # 创建一个简单的示例证书
    sample_cert = """-----BEGIN CERTIFICATE-----
MIIFazCCA1OgAwIBAgIRAIIQz7DSQONZRGPgu2OCiwAwDQYJKoZIhvcNAQELBQAw
TzELMAkGA1UEBhMCVVMxKTAnBgNVBAoTIEludGVybmV0IFNlY3VyaXR5IFJlc2Vh
cmNoIEdyb3VwMRUwEwYDVQQDEwxJU1JHIFJvb3QgWDEwHhcNMTUwNjA0MTEwNDM4
WhcNMzUwNjA0MTEwNDM4WjBPMQswCQYDVQQGEwJVUzEpMCcGA1UEChMgSW50ZXJu
ZXQgU2VjdXJpdHkgUmVzZWFyY2ggR3JvdXAxFTATBgNVBAMTDElTUkcgUm9vdCBY
MTCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAK3oJHP0FDfzm54rVygc
h77ct984kIxuPOZXoHj3dcKi/vVqbvYATyjb3miGbESTtrFj/RQSa78f0uoxmyF+
0TM8ukj13Xnfs7j/EvEhmkvBioZxaUpmZmyPfjxwv60pIgbz5MDmgK7iS4+3mX6U
A5/TR5d8mUgjU+g4rk8Kb4Mu0UlXjIB0ttov0DiNewNwIRt18jA8+o+u3dpjq+sW
T8KOEUt+zwvo/7V3LvSye0rgTBIlDHCNAymg4VMk7BPZ7hm/ELNKjD+Jo2FR3qyH
B5T0Y3HsLuJvW5iB4YlcNHlsdu87kGJ55tukmi8mxdAQ4Q7e2RCOFvu396j3x+UC
B5iPNgiV5+I3lg02dZ77DnKxHZu8A/lJBdiB3QW0KtZB6awBdpUKD9jf1b0SHzUv
KBds0pjBqAlkd25HN7rOrFleaJ1/ctaJxQZBKT5ZPt0m9STJEadao0xAH0ahmbWn
OlFuhjuefXKnEgV4We0+UXgVCwOPjdAvBbI+e0ocS3MFEvzG6uBQE3xDk3SzynTn
jh8BCNAw1FtxNrQHusEwMFxIt4I7mKZ9YIqioymCzLq9gwQbooMDQaHWBfEbwrbw
qHyGO0aoSCqI3Haadr8faqU9GY/rOPNk3sgrDQoo//fb4hVC1CLQJ13hef4Y53CI
rU7m2Ys6xt0nUW7/vGT1M0NPAgMBAAGjQjBAMA4GA1UdDwEB/wQEAwIBBjAPBgNV
HRMBAf8EBTADAQH/MB0GA1UdDgQWBBR5tFnme7bl5AFzgAiIyBpY9umbbjANBgkq
hkiG9w0BAQsFAAOCAgEAVR9YqbyyqFDQDLHYGmkgJykIrGF1XIpu+ILlaS/V9lZL
ubhzEFnTIZd+50xx+7LSYK05qAvqFyFWhfFQDlnrzuBZ6brJFe+GnY+EgPbk6ZGQ
3BebYhtF8GaV0nxvwuo77x/Py9auJ/GpsMiu/X1+mvoiBOv/2X/qkSsisRcOj/KK
NFtY2PwByVS5uCbMiogziUwthDyC3+6WVwW6LLv3xLfHTjuCvjHIInNzktHCgKQ5
ORAzI4JMPJ+GslWYHb4phowim57iaztXOoJwTdwJx4nLCgdNbOhdjsnvzqvHu7Ur
TkXWStAmzOVyyghqpZXjFaH3pO3JLF+l+/+sKAIuvtd7u+Nxe5AW0wdeRlN8NwdC
jNPElpzVmbUq4JUagEiuTDkHzsxHpFKVK7q4+63SM1N95R1NbdWhscdCb+ZAJzVc
oyi3B43njTOQ5yOf+1CceWxG1bQVs5ZufpsMljq4Ui0/1lvh+wjChP4kqKOJ2qxq
4RgqsahDYVvTH9w7jXbyLeiNdd8XM2w9U/t7y0Ff/9yi0GE44Za4rF2LN9d11TPA
mRGunUHBcnWEvgJBQl9nJEiU0Zsnvgc/ubhPgXRR4Xq37Z0j4r7g1SgEEzwxA57d
emyPxgcYxn/eR44/KJ4EBs+lVDR3veyJm+kXQ99b21/+jh5Xos1AnX5iItreGCc=
-----END CERTIFICATE-----"""
    
    # 创建不同颁发者和过期日期的证书变种
    sample_certs = [
        {"name": "Internet Security Research Group Root X1", "expiry": "Jun  4 11:04:38 2035 GMT"},
        {"name": "DigiCert Global Root CA", "expiry": "Nov 10 00:00:00 2031 GMT"},
        {"name": "GlobalSign Root CA", "expiry": "Jan 28 12:00:00 2028 GMT"},
        {"name": "GeoTrust Global CA", "expiry": "May 21 04:00:00 2022 GMT"},
        {"name": "Baltimore CyberTrust Root", "expiry": "May 12 23:59:00 2025 GMT"}
    ]
    
    for i, cert_data in enumerate(sample_certs):
        test_cert_path = TEST_CERTS_DIR / f"test-cert-{i}.crt"
        with open(test_cert_path, 'w', encoding='utf-8') as f:
            f.write(sample_cert)
        logger.info(f"创建了示例证书: {test_cert_path}")


def create_cert_info(cert_name, expiry_date):
    """创建模拟证书信息"""
    return {
        "subject_cn": cert_name,
        "subject_o": "Example CA Organization",
        "issuer_cn": cert_name,
        "issuer_o": "Example CA Organization",
        "not_before": "Jan 1 00:00:00 2020 GMT",
        "not_after": expiry_date,
        "fingerprint": f"{hash(cert_name)}".replace("-", "")[:40]
    }


def create_cert_info_map():
    """创建一个证书信息映射用于测试"""
    sample_certs = [
        {"name": "Internet Security Research Group Root X1", "expiry": "Jun  4 11:04:38 2035 GMT"},
        {"name": "DigiCert Global Root CA", "expiry": "Nov 10 00:00:00 2031 GMT"},
        {"name": "GlobalSign Root CA", "expiry": "Jan 28 12:00:00 2028 GMT"},
        {"name": "GeoTrust Global CA", "expiry": "May 21 04:00:00 2022 GMT"},
        {"name": "Baltimore CyberTrust Root", "expiry": "May 12 23:59:00 2025 GMT"}
    ]
    
    cert_info_map = {}
    for i, cert_data in enumerate(sample_certs):
        cert_name = f"test_cert_{i}"
        cert_info_map[cert_name] = create_cert_info(cert_data["name"], cert_data["expiry"])
        
        # 复制证书到目标目录
        source_path = TEST_CERTS_DIR / f"test-cert-{i}.crt"
        dest_path = CERTS_DIR / f"{cert_name}.crt"
        shutil.copy(source_path, dest_path)
        logger.info(f"复制证书到CERTS_DIR: {dest_path}")
    
    return cert_info_map


def generate_html_page(cert_info_map, output_path):
    """生成HTML页面展示证书列表"""
    logger.info("生成HTML页面...")
    
    # 读取模板
    template_path = ROOT_DIR / "templates" / "index.html"
    with open(template_path, 'r', encoding='utf-8') as f:
        template = f.read()
    
    # 当前日期
    current_date = datetime.datetime.now().strftime("%Y-%m-%d")
    
    # 生成证书列表HTML
    cert_list_html = []
    
    for cert_name, info in cert_info_map.items():
        issuer = info.get("subject_cn", "未知")
        valid_until = info.get("not_after", "未知")
        
        cert_list_html.append(f"""
        <tr>
          <td>{issuer}</td>
          <td>{valid_until}</td>
          <td><a href="certs/{cert_name}.crt" class="download-link" title="下载 {cert_name}.crt"><button class="download-button"><img src="assets/download@32x32.png" alt="下载" width="18" height="18"></button></a></td>
        </tr>
        """)
    
    # 替换模板中的占位符
    html_content = template.replace("{{LAST_UPDATED}}", current_date)
    html_content = html_content.replace("{{CERTIFICATE_COUNT}}", str(len(cert_info_map)))
    html_content = html_content.replace("{{CERTIFICATE_LIST_REPLACED}}", "\n".join(cert_list_html))
    
    # 修复资源路径 - 将templates/assets/替换为assets/
    html_content = html_content.replace('templates/assets/', 'assets/')
    
    # 写入输出文件
    with open(output_path, 'w', encoding='utf-8') as f:
        f.write(html_content)
    
    logger.info(f"HTML页面已生成: {output_path}")


def create_assets_dir():
    """确保assets目录存在并包含必要文件"""
    assets_dir = ROOT_DIR / "assets"
    template_assets_dir = ROOT_DIR / "templates" / "assets"
    
    if template_assets_dir.exists():
        if assets_dir.exists():
            shutil.rmtree(assets_dir)
        
        # 创建assets目录
        assets_dir.mkdir(exist_ok=True, parents=True)
        
        # 复制所有资源文件
        for asset_file in template_assets_dir.glob("*"):
            shutil.copy(asset_file, assets_dir / asset_file.name)
        
        logger.info("复制资源文件到assets目录")


def run_test():
    """运行测试"""
    logger.info("运行证书同步测试...")
    
    # 创建证书信息映射
    cert_info_map = create_cert_info_map()
    
    # 确保assets目录存在
    create_assets_dir()
    
    # 生成HTML页面
    index_path = ROOT_DIR / "index.html"
    generate_html_page(cert_info_map, index_path)
    
    logger.info(f"测试完成，生成了HTML页面: {index_path}")
    logger.info(f"处理了 {len(cert_info_map)} 个证书")


def cleanup():
    """清理测试文件"""
    logger.info("清理测试文件...")
    
    if TEMP_DIR.exists():
        shutil.rmtree(TEMP_DIR)
        logger.info(f"删除了临时目录: {TEMP_DIR}")


def main():
    """主函数"""
    try:
        # 设置测试环境
        setup_test_environment()
        
        # 运行测试
        run_test()
        
        # 清理 (可选)
        cleanup()
        
        logger.info("测试成功完成！")
        return 0
    
    except Exception as e:
        logger.error(f"测试失败: {e}")
        import traceback
        traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())
