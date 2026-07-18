#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
主证书收集脚本 - 从多个来源收集CA根证书
"""

import os
import sys
import shutil
import logging
import argparse
import datetime
import subprocess
import re
from pathlib import Path
from typing import List, Dict, Optional
from bs4 import BeautifulSoup

# 新的Mozilla证书源：直接解析NSS的certdata.txt，避免大量访问crt.sh导致429
MOZILLA_CERTDATA_URL = "https://hg-edge.mozilla.org/releases/mozilla-release/raw-file/default/security/nss/lib/ckfw/builtins/certdata.txt"

# 配置日志
logging.basicConfig(
    level=logging.INFO,
    # level=logging.DEBUG,
    format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)]
)
logger = logging.getLogger("ca-cert-sync")

# 定义常量
SCRIPT_DIR = Path(__file__).parent.absolute()
ROOT_DIR = SCRIPT_DIR.parent
CERTS_DIR = ROOT_DIR / "certs"
TEMP_DIR = ROOT_DIR / "temp"
BLACKLIST_FILE = ROOT_DIR / "blacklist.txt"
SOURCES_DIR = {
    "ubuntu": TEMP_DIR / "ubuntu",
    "firefox": TEMP_DIR / "firefox",
    "windows": TEMP_DIR / "windows",
    "certifi": TEMP_DIR / "certifi",
    "curl": TEMP_DIR / "curl"
}

AUTHROOT_STL_CAB_URL = "https://ctldl.windowsupdate.com/msdownload/update/v3/static/trustedr/en/authrootstl.cab"


def setup_directories() -> None:
    """设置所需的目录结构"""
    logger.info("设置目录结构...")
    
    # 创建证书目录
    CERTS_DIR.mkdir(exist_ok=True, parents=True)
    
    # 创建临时目录
    TEMP_DIR.mkdir(exist_ok=True, parents=True)
    
    # 创建各个源的临时目录
    for source_dir in SOURCES_DIR.values():
        source_dir.mkdir(exist_ok=True, parents=True)


def run_command(command: List[str], cwd: Optional[Path] = None, verbose: bool = True) -> str:
    """执行shell命令并返回输出
    
    Args:
        command: 要执行的命令列表
        cwd: 执行命令的工作目录
        verbose: 是否显示详细输出
    
    Returns:
        命令的输出
    """
    cmd_str = ' '.join(command)
    logger.debug(f"执行命令: {cmd_str}")
    
    if verbose:
        # 在详细模式下，直接显示命令输出
        logger.debug(f"正在执行命令: {cmd_str}")
        process = subprocess.Popen(
            command,
            cwd=cwd.as_posix() if cwd else None,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
            universal_newlines=True
        )
        
        output_lines = []
        # 实时输出命令结果
        for line in iter(process.stdout.readline, ''):
            line = line.rstrip()
            logger.debug(f"  {line}")
            output_lines.append(line)
        
        process.wait()
        output = '\n'.join(output_lines)
        
        if process.returncode != 0:
            logger.error(f"命令执行失败: {cmd_str}")
            raise subprocess.CalledProcessError(process.returncode, cmd_str, output=output)
        return output
    else:
        # 在非详细模式下，静默执行命令
        result = subprocess.run(
            command,
            cwd=cwd.as_posix() if cwd else None,
            capture_output=True,
            text=True,
            check=True
        )
        
        return result.stdout


def download_file(url: str, dest_path: Path, verbose: bool = True) -> bool:
    """下载文件到指定路径，使用自定义 User-Agent 并带重试和 shell 命令备份"""
    logger.debug(f"正在下载: {url} -> {dest_path}")
    import urllib.request
    headers = {
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
    }
    req = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=30) as response:
            with open(dest_path, 'wb') as f:
                f.write(response.read())
        return True
    except Exception as e:
        logger.warning(f"Python 下载失败: {url}, 错误: {e}。尝试使用 shell 命令...")
        try:
            cmd = ["wget", "-U", headers['User-Agent'], "-O", dest_path.as_posix(), url]
            run_command(cmd, verbose=verbose)
            return True
        except Exception as e2:
            logger.warning(f"wget 下载失败: {e2}")
            try:
                cmd = ["curl", "-H", f"User-Agent: {headers['User-Agent']}", "-L", "-o", dest_path.as_posix(), url]
                run_command(cmd, verbose=verbose)
                return True
            except Exception as e3:
                logger.error(f"所有下载方式均失败: {url}, 错误: {e3}")
                return False


def extract_cab(cab_path: Path, dest_dir: Path, verbose: bool = True) -> None:
    """解压 CAB 压缩包到目标目录"""
    if dest_dir.exists():
        shutil.rmtree(dest_dir)
    dest_dir.mkdir(exist_ok=True, parents=True)
    
    if os.name == 'nt':
        run_command(["extrac32", "/E", "/Y", "/L", dest_dir.as_posix(), cab_path.as_posix()], verbose=verbose)
    else:
        run_command(["cabextract", "-d", dest_dir.as_posix(), cab_path.as_posix()], verbose=verbose)


def collect_ubuntu_certs(verbose: bool = True) -> List[Path]:
    """从Ubuntu ca-certificates收集证书"""
    logger.info("从Ubuntu ca-certificates收集证书...")
    
    source_dir = SOURCES_DIR["ubuntu"]
    # 清空源目录
    if source_dir.exists():
        shutil.rmtree(source_dir)
    source_dir.mkdir(exist_ok=True, parents=True)
    
    try:
        # 安装ca-certificates包
        run_command(["apt-get", "update", "-y"], verbose=verbose)
        run_command(["apt-get", "install", "-y", "ca-certificates"], verbose=verbose)
        
        # 复制证书
        ubuntu_certs_dir = Path("/usr/share/ca-certificates/mozilla")
        if ubuntu_certs_dir.exists():
            for cert_file in ubuntu_certs_dir.glob("*.crt"):
                shutil.copy(cert_file, source_dir)
        
        # 如果Mozilla目录不存在，尝试/etc/ssl/certs
        else:
            ubuntu_certs_dir = Path("/etc/ssl/certs")
            for cert_file in ubuntu_certs_dir.glob("*.pem"):
                # 将.pem转换为.crt (实际上格式相同，只是扩展名不同)
                dest_file = source_dir / f"{cert_file.stem}.crt"
                shutil.copy(cert_file, dest_file)
        
        return list(source_dir.glob("*.crt"))
    
    except Exception as e:
        logger.error(f"从Ubuntu收集证书时出错: {e}")
        return []


def collect_firefox_certs(verbose: bool = True) -> List[Path]:
    """从Mozilla收集证书 - 直接从Mozilla CCADB获取"""
    logger.info("从Mozilla CCADB收集证书...")
    
    source_dir = SOURCES_DIR["firefox"]
    # 清空源目录
    if source_dir.exists():
        shutil.rmtree(source_dir)
    source_dir.mkdir(exist_ok=True, parents=True)
    
    try:
        # 安装必要的工具
        run_command(["apt-get", "install", "-y", "wget", "curl"], verbose=verbose)
        
        # 直接从Mozilla CCADB获取当前信任的CA证书列表
        mozilla_ca_url = "https://ccadb.my.salesforce-sites.com/mozilla/IncludedCACertificateReport"
        
        # 下载HTML页面
        temp_html = TEMP_DIR / "mozilla_ca_list.html"
        run_command(["wget", "-O", temp_html.as_posix(), mozilla_ca_url], verbose=verbose)
        
        # 解析HTML获取证书链接
        cert_links = []
        with open(temp_html, 'r', encoding='utf-8') as f:
            content = f.read()
            soup = BeautifulSoup(content, 'html.parser')
            
            # 调试信息：打印页面结构
            logger.debug("开始分析HTML页面结构...")
            
            # 查找表格
            tables = soup.find_all('table')
            logger.debug(f"页面中找到{len(tables)}个表格")
            
            if tables:
                # 遍历每个表格的行
                for table in tables:
                    rows = table.find_all('tr')
                    logger.debug(f"表格中找到{len(rows)}行")
                    
                    # 检查表头，确定PEM证书所在的列索引
                    headers = rows[0].find_all('th') if rows else []
                    pem_col_idx = None
                    
                    for idx, header in enumerate(headers):
                        header_text = header.get_text().strip().lower()
                        if "download" in header_text or ".crt" in header_text:
                            pem_col_idx = idx
                            logger.debug(f"找到证书列，索引为: {pem_col_idx}, 标题为: {header_text}")
                            break
                    
                    # 如果找不到明确的证书列，尝试使用最后一列
                    if pem_col_idx is None and headers:
                        pem_col_idx = len(headers) - 1
                        logger.debug(f"未找到明确的证书列，使用最后一列: {pem_col_idx}")
                    
                    # 遍历每一行查找证书链接
                    for row in rows[1:]:  # 跳过表头
                        cells = row.find_all('td')
                        
                        # 检查是否有足够的单元格
                        if cells and pem_col_idx is not None and pem_col_idx < len(cells):
                            link_cell = cells[pem_col_idx]
                            
                            # 在单元格中查找所有链接
                            links = link_cell.find_all('a')
                            for link in links:
                                href = link.get('href')
                                link_text = link.get_text().strip().lower()
                                
                                # 使用更宽松的条件检查链接
                                # 可能是直接的证书链接，或指向crt.sh的链接，或包含关键词的链接
                                if href:
                                    if (href.endswith('.crt') or href.endswith('.cer') or 
                                        "crt.sh" in href  or "?d=" in href or
                                        "download" in link_text):
                                        logger.debug(f"找到证书链接: {href}")
                                        cert_links.append(href)
            
            # 如果以上方法没有找到链接，尝试查找页面中所有可能的证书链接
            if not cert_links:
                logger.debug("未在表格中找到证书链接，尝试在整个页面中查找...")
                all_links = soup.find_all('a')
                for link in all_links:
                    href = link.get('href')
                    if href:
                        # 使用宽松的条件匹配可能的证书链接
                        if (href.endswith('.crt') or href.endswith('.cer') or 
                            "crt.sh" in href or "?id=" in href or "?d=" in href):
                            cert_links.append(href)
                            logger.debug(f"在页面中找到可能的证书链接: {href}")
        
        logger.info(f"从Mozilla CCADB页面找到 {len(cert_links)} 个证书链接")
        
        # 下载每个证书
        for idx, cert_url in enumerate(cert_links):
            try:
                cert_file = source_dir / f"mozilla-{idx:03d}.crt"
                logger.debug(f"处理证书链接 {idx}: {cert_url}")
                
                # 判断链接类型并相应处理
                if cert_url.endswith('.crt') or cert_url.endswith('.cer') or cert_url.endswith('.pem'):
                    # 直接下载证书文件
                    logger.debug(f"直接下载证书文件: {cert_url}")
                    run_command(["wget", "-O", cert_file.as_posix(), cert_url], verbose=verbose)
                
                else:
                    # 对于其他类型的链接，先下载HTML页面然后提取证书
                    temp_cert_html = TEMP_DIR / f"temp_cert_{idx}.html"
                    run_command(["wget", "--timeout=30", "--tries=3", "-O", temp_cert_html.as_posix(), cert_url], verbose=verbose)
                    
                    # 检查下载是否成功
                    if not temp_cert_html.exists() or temp_cert_html.stat().st_size == 0:
                        logger.warning(f"下载证书页面失败: {cert_url}")
                        continue
                    
                    try:
                        # 读取HTML内容
                        with open(temp_cert_html, 'r', encoding='utf-8', errors='ignore') as f:
                            cert_html = f.read()
                        
                        # 使用BeautifulSoup解析HTML
                        cert_soup = BeautifulSoup(cert_html, 'html.parser')
                        
                        # 处理crt.sh链接 - 尝试不同方法
                        cert_content = None
                        
                        # 方法1：查找pre标签中的证书
                        pre_tags = cert_soup.find_all('pre')
                        for pre in pre_tags:
                            content = pre.get_text()
                            if ("-----BEGIN CERTIFICATE-----" in content and 
                                "-----END CERTIFICATE-----" in content):
                                cert_content = content
                                logger.debug(f"在pre标签中找到证书内容")
                                break
                        
                        # 方法2：查找textarea中的证书
                        if not cert_content:
                            textareas = cert_soup.find_all('textarea')
                            for textarea in textareas:
                                content = textarea.get_text()
                                if ("-----BEGIN CERTIFICATE-----" in content and 
                                    "-----END CERTIFICATE-----" in content):
                                    cert_content = content
                                    logger.debug(f"在textarea标签中找到证书内容")
                                    break
                        
                        # 方法3：查找页面中任何包含证书格式的文本
                        if not cert_content:
                            page_text = cert_soup.get_text()
                            start_idx = page_text.find("-----BEGIN CERTIFICATE-----")
                            end_idx = page_text.find("-----END CERTIFICATE-----")
                            
                            if start_idx >= 0 and end_idx >= 0:
                                cert_content = page_text[start_idx:end_idx + 25]  # +25 to include "-----END CERTIFICATE-----"
                                logger.debug(f"在页面文本中找到证书内容")
                        
                        # 如果找到了证书内容，保存它
                        if cert_content:
                            with open(cert_file, 'w', encoding='utf-8') as f:
                                f.write(cert_content)
                                logger.debug(f"证书内容已保存到文件: {cert_file}")
                        else:
                            # 如果找不到证书内容，尝试直接从crt.sh下载PEM格式
                            if "crt.sh" in cert_url and "?d=" in cert_url:
                                cert_id = cert_url.split("?d=")[-1].split("&")[0]
                                direct_pem_url = f"https://crt.sh/?d={cert_id}&pem=1"
                                logger.debug(f"尝试直接下载PEM格式: {direct_pem_url}")
                                
                                run_command(["wget", "-O", cert_file.as_posix(), direct_pem_url], verbose=verbose)
                            else:
                                logger.warning(f"在HTML页面中找不到有效的证书内容: {cert_url}")
                                continue
                    
                    except Exception as e:
                        logger.warning(f"处理证书HTML时出错: {e}")
                        continue
                    
                    finally:
                        # 清理临时文件
                        if temp_cert_html.exists():
                            temp_cert_html.unlink()
                
                # 无论采用哪种方法，都验证下载的证书是否有效
                try:
                    # 使用openssl验证证书格式
                    if cert_file.exists():
                        run_command([
                            "openssl", "x509", "-in", cert_file.as_posix(),
                            "-noout", "-text"
                        ], verbose=False)
                        logger.debug(f"验证证书成功: {cert_file}")
                    else:
                        logger.warning(f"证书文件不存在: {cert_file}")
                        continue
                except Exception as e:
                    logger.warning(f"下载的文件不是有效的X.509证书: {cert_url}, 错误: {e}")
                    # 删除无效的证书文件
                    if cert_file.exists():
                        cert_file.unlink()
                    continue
                
                # 验证下载的是否为有效的证书
                try:
                    # 使用openssl验证证书格式
                    run_command([
                        "openssl", "x509", "-in", cert_file.as_posix(),
                        "-noout", "-text"
                    ], verbose=False)
                except Exception:
                    logger.warning(f"下载的文件不是有效的X.509证书: {cert_url}")
                    # 删除无效的证书文件
                    if cert_file.exists():
                        cert_file.unlink()
                    continue
                    
                logger.debug(f"下载证书: {cert_url} -> {cert_file}")
            except Exception as e:
                logger.warning(f"下载证书时出错 {cert_url}: {e}")
        
        # 更新黑名单
        update_revoked_certificates(verbose=verbose)
        
        return list(source_dir.glob("*.crt"))
    
    except Exception as e:
        logger.error(f"从Mozilla收集证书时出错: {e}")
        return []


def collect_mozilla_certdata_certs(verbose: bool = True) -> List[Path]:
    """通过下载并解析Mozilla NSS certdata.txt获取根证书

    优点：
    - 单一文件下载，避免对CCADB及crt.sh的大量请求触发速率限制(429)
    - 与curl / certifi来源一致性高
    缺点：
    - certdata.txt 可能偶尔结构调整，需要维护解析脚本
    """
    logger.info("使用Mozilla certdata.txt获取证书...")
    source_dir = SOURCES_DIR["firefox"]  # 复用firefox目录以保持下游逻辑不变
    if source_dir.exists():
        shutil.rmtree(source_dir)
    source_dir.mkdir(exist_ok=True, parents=True)

    try:
        # 下载certdata.txt
        certdata_path = TEMP_DIR / "mozilla-certdata.txt"
        run_command(["wget", "-O", certdata_path.as_posix(), MOZILLA_CERTDATA_URL], verbose=verbose)
        if not certdata_path.exists() or certdata_path.stat().st_size == 0:
            logger.warning("下载的certdata.txt为空或不存在")
            return []

        # 调用现有的解析脚本
        extract_script = SCRIPT_DIR / "extract_mozilla_certdata.py"
        if not extract_script.exists():
            logger.error("缺少解析脚本 extract_mozilla_certdata.py")
            return []

        run_command([
            sys.executable,
            extract_script.as_posix(),
            "--source", certdata_path.as_posix(),
            "--destination", source_dir.as_posix()
        ], verbose=verbose)

        certs = list(source_dir.glob("mozilla-*.crt"))
        logger.info(f"通过certdata.txt解析得到 {len(certs)} 个证书")
        return certs
    except Exception as e:
        logger.error(f"解析Mozilla certdata.txt时出错: {e}")
        return []


def update_revoked_certificates(verbose: bool = True) -> None:
    """从Mozilla CCADB和其他来源更新已撤销证书列表"""
    logger.info("更新已撤销证书列表...")
    
    # 存储所有撤销的指纹
    revoked_fingerprints = []
    
    try:
        # 1. 从Mozilla CCADB获取已撤销 of the certificates
        removed_ca_url = "https://ccadb.my.salesforce-sites.com/mozilla/RemovedCACertificateReport"
        
        # 下载HTML页面
        temp_html = TEMP_DIR / "mozilla_removed_ca_list.html"
        download_file(removed_ca_url, temp_html, verbose=verbose)
        
        # 解析HTML获取已撤销证书的SHA-256指纹（第9列）
        with open(temp_html, 'r', encoding='utf-8') as f:
            soup = BeautifulSoup(f.read(), 'html.parser')
            for row in soup.find_all('tr'):
                cells = row.find_all('td')
                if cells and len(cells) >= 9:  # SHA-256指纹在第9列
                    sha256_cell = cells[8]  # 索引为8的单元格
                    sha256_fp = sha256_cell.text.strip().lower().replace(':', '')
                    if sha256_fp and len(sha256_fp) == 64:  # SHA-256指纹应该是64个字符
                        revoked_fingerprints.append(("sha256", sha256_fp))
                    
                    # 同时也可以收集SHA-1指纹（第8列）作为备份
                    if len(cells) >= 8:
                        sha1_cell = cells[7]  # 索引为7的单元格
                        sha1_fp = sha1_cell.text.strip().lower().replace(':', '')
                        if sha1_fp and len(sha1_fp) == 40:  # SHA-1指纹应该是40个字符
                            revoked_fingerprints.append(("sha1", sha1_fp))
        
        logger.info(f"从Mozilla CCADB找到 {len(revoked_fingerprints)} 个已撤销的证书指纹")
        
        # 2. 从Windows CRL获取已撤销证书（可选）
        try:
            # 首先检查工作区中是否已有disallowedcert.stl文件
            local_stl_path = ROOT_DIR / "disallowedcert.stl"
            stl_file_path = None
            
            if local_stl_path.exists():
                logger.info(f"使用本地STL文件: {local_stl_path}")
                stl_file_path = local_stl_path
            else:
                # 如果本地不存在，从Microsoft下载
                windows_untrusted_url = "http://ctldl.windowsupdate.com/msdownload/update/v3/static/trustedr/en/disallowedcertstl.cab"
                cab_file = TEMP_DIR / "windows_untrusted.cab"
                extract_dir = TEMP_DIR / "windows_untrusted"
                
                # 下载并解压CAB文件
                if download_file(windows_untrusted_url, cab_file, verbose=verbose):
                    extract_cab(cab_file, extract_dir, verbose=verbose)
                    
                    # 查找STL文件
                    stl_files = list(extract_dir.glob("*.stl"))
                    if stl_files:
                        stl_file_path = stl_files[0]
                        logger.info(f"从CAB文件中提取到STL文件: {stl_file_path}")
            
            # 如果找到了STL文件，使用 asn1crypto 处理它
            if stl_file_path:
                try:
                    from asn1crypto import cms, core
                    with open(stl_file_path, "rb") as f:
                        data = f.read()
                    
                    content_info = cms.ContentInfo.load(data)
                    signed_data = content_info['content']
                    encap_content_info = signed_data['encap_content_info']
                    ctl_content = encap_content_info['content'].parsed
                    
                    # Force child parsing
                    len(ctl_content)
                    
                    class TrustedSubject(core.Sequence):
                        _fields = [
                            ('subject_identifier', core.OctetString),
                            ('subject_attributes', core.SetOf, {'optional': True}),
                        ]
                        
                    class TrustedSubjects(core.SequenceOf):
                        _child_spec = TrustedSubject

                    trusted_subjects_node = None
                    for child in reversed(ctl_content.children):
                        if child[2] == 16:
                            try:
                                der_bytes = child[3] + child[4] + child[5]
                                subjects = TrustedSubjects.load(der_bytes)
                                if len(subjects) > 0 and isinstance(subjects[0]['subject_identifier'], core.OctetString):
                                    trusted_subjects_node = child
                                    break
                            except Exception:
                                continue
                                
                    if trusted_subjects_node:
                        der_bytes = trusted_subjects_node[3] + trusted_subjects_node[4] + trusted_subjects_node[5]
                        subjects = TrustedSubjects.load(der_bytes)
                        logger.info(f"从 Windows STL 中解析到 {len(subjects)} 个已撤销的证书项")
                        for s in subjects:
                            raw_hash = s['subject_identifier'].native
                            if len(raw_hash) == 16:
                                revoked_fingerprints.append(("md5", raw_hash.hex().lower()))
                            elif len(raw_hash) == 20:
                                revoked_fingerprints.append(("sha1", raw_hash.hex().lower()))
                            elif len(raw_hash) == 48:
                                md5_part = raw_hash[:16].hex().lower()
                                sha256_part = raw_hash[16:].hex().lower()
                                revoked_fingerprints.append(("md5", md5_part))
                                revoked_fingerprints.append(("sha256", sha256_part))
                            else:
                                revoked_fingerprints.append(("sha1", raw_hash.hex().lower()))
                    else:
                        logger.warning("在 Windows STL 中未找到 trustedSubjects")
                except Exception as e:
                    logger.warning(f"解析 Windows STL 时出错: {e}")
            
            logger.info(f"从Windows CRL找到可能的指纹，现在共有 {len(revoked_fingerprints)} 个指纹")
        except Exception as e:
            logger.warning(f"从Windows获取已撤销证书时出错: {e}")
        
        # 3. 从Google CRLSets获取已撤销证书（可选）
        try:
            google_crlset_url = "https://storage.googleapis.com/chrome-component-crl-set/latest.crx"
            crlset_file = TEMP_DIR / "google_crlset.crx"
            
            # 下载CRLSet
            run_command(["wget", "-O", crlset_file.as_posix(), google_crlset_url], verbose=verbose)
            
            # 尝试提取和解析CRLSet（简化处理，实际上需要专门的解析器）
            # 这里只提取明显的SHA-1和SHA-256指纹模式
            if crlset_file.exists():
                with open(crlset_file, 'rb') as f:
                    content = f.read()
                    text_content = content.decode('utf-8', errors='ignore')
                    
                    # 使用正则表达式查找可能的SHA-1指纹
                    import re
                    sha1_pattern = re.compile(r'[0-9a-f]{40}', re.IGNORECASE)
                    for match in sha1_pattern.finditer(text_content):
                        revoked_fingerprints.append(("sha1", match.group(0).lower()))
                    
                    # 使用正则表达式查找可能的SHA-256指纹
                    sha256_pattern = re.compile(r'[0-9a-f]{64}', re.IGNORECASE)
                    for match in sha256_pattern.finditer(text_content):
                        revoked_fingerprints.append(("sha256", match.group(0).lower()))
            
            logger.info(f"从Google CRLSet找到可能的指纹，现在共有 {len(revoked_fingerprints)} 个指纹")
        except Exception as e:
            logger.warning(f"从Google获取已撤销证书时出错: {e}")
        
        # 移除重复项
        unique_fingerprints = list(set(revoked_fingerprints))
        logger.info(f"合并后共有 {len(unique_fingerprints)} 个唯一的已撤销证书指纹")
        
        # 更新黑名单文件
        with open(BLACKLIST_FILE, 'w') as f:
            for fp_type, fingerprint in unique_fingerprints:
                f.write(f"{fp_type}:{fingerprint}\n")
        
        logger.info(f"已更新黑名单文件: {BLACKLIST_FILE}")
    
    except Exception as e:
        logger.error(f"更新已撤销证书列表时出错: {e}")


def collect_windows_certs(verbose: bool = True) -> List[Path]:
    """从Microsoft Windows证书更新收集证书"""
    logger.info("从Microsoft Windows证书更新收集证书...")
    
    source_dir = SOURCES_DIR["windows"]
    # 清空源目录
    if source_dir.exists():
        shutil.rmtree(source_dir)
    source_dir.mkdir(exist_ok=True, parents=True)
    
    try:
        # 安装必要的工具
        try:
            run_command(["apt-get", "install", "-y", "wget", "cabextract", "openssl"], verbose=verbose)
        except Exception as e:
            logger.warning(f"安装系统依赖失败 (可能不是 Ubuntu/Debian 环境): {e}")

        # 下载Windows根证书计划
        authroot_url = "http://ctldl.windowsupdate.com/msdownload/update/v3/static/trustedr/en/authrootstl.cab"
        authroot_cab = TEMP_DIR / "authroot.cab"
        if not download_file(authroot_url, authroot_cab, verbose=verbose):
            logger.error("下载 authrootstl.cab 失败")
            return []
        
        # 解压cab文件到临时目录
        extract_dir = TEMP_DIR / "authroot-extract"
        extract_cab(authroot_cab, extract_dir, verbose=verbose)
        
        # 提取 STL 中的证书 hashes
        stl_file = extract_dir / "authroot.stl"
        hashes = []
        if stl_file.exists():
            try:
                from asn1crypto import cms, core
                with open(stl_file, "rb") as f:
                    data = f.read()
                
                content_info = cms.ContentInfo.load(data)
                signed_data = content_info['content']
                encap_content_info = signed_data['encap_content_info']
                ctl_content = encap_content_info['content'].parsed
                
                # Force parsing of children
                len(ctl_content)
                
                class TrustedSubject(core.Sequence):
                    _fields = [
                        ('subject_identifier', core.OctetString),
                        ('subject_attributes', core.SetOf, {'optional': True}),
                    ]
                    
                class TrustedSubjects(core.SequenceOf):
                    _child_spec = TrustedSubject

                trusted_subjects_node = None
                for child in reversed(ctl_content.children):
                    if child[2] == 16:
                        try:
                            der_bytes = child[3] + child[4] + child[5]
                            subjects = TrustedSubjects.load(der_bytes)
                            if len(subjects) > 0 and isinstance(subjects[0]['subject_identifier'], core.OctetString):
                                trusted_subjects_node = child
                                break
                        except Exception:
                            continue
                
                if trusted_subjects_node:
                    der_bytes = trusted_subjects_node[3] + trusted_subjects_node[4] + trusted_subjects_node[5]
                    subjects = TrustedSubjects.load(der_bytes)
                    for s in subjects:
                        sha1_hex = s['subject_identifier'].native.hex().lower()
                        hashes.append(sha1_hex)
                    logger.info(f"从 Windows STL 中成功解析到 {len(hashes)} 个根证书哈希")
                else:
                    logger.error("在 Windows STL 中未找到 trustedSubjects 字段")
            except Exception as e:
                logger.error(f"解析 Windows STL 时出错: {e}")
        
        # 并行下载并转换证书
        if hashes:
            import concurrent.futures
            from cryptography import x509
            from cryptography.hazmat.primitives import serialization
            
            # 使用 ThreadPoolExecutor 并行下载
            max_workers = 30
            logger.info(f"使用 {max_workers} 个线程并行下载 {len(hashes)} 个证书...")
            
            def download_and_convert(sha1_hash: str, index: int) -> bool:
                url = f"http://ctldl.windowsupdate.com/msdownload/update/v3/static/trustedr/en/{sha1_hash}.crt"
                der_path = TEMP_DIR / f"{sha1_hash}.der"
                output_file = source_dir / f"windows-stl-{index:03d}.crt"
                
                if download_file(url, der_path, verbose=False):
                    try:
                        with open(der_path, "rb") as f:
                            der_bytes = f.read()
                        
                        # 转换 DER 为 PEM
                        cert = x509.load_der_x509_certificate(der_bytes)
                        pem_bytes = cert.public_bytes(serialization.Encoding.PEM)
                        
                        with open(output_file, "wb") as f:
                            f.write(pem_bytes)
                        
                        if der_path.exists():
                            der_path.unlink()
                        return True
                    except Exception as e:
                        logger.warning(f"转换证书 {sha1_hash} 失败: {e}")
                        if der_path.exists():
                            der_path.unlink()
                return False

            success_count = 0
            with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
                future_to_hash = {
                    executor.submit(download_and_convert, sha1, idx): sha1 
                    for idx, sha1 in enumerate(hashes)
                }
                for future in concurrent.futures.as_completed(future_to_hash):
                    sha1 = future_to_hash[future]
                    try:
                        if future.result():
                            success_count += 1
                    except Exception as e:
                        logger.warning(f"下载/转换任务异常 ({sha1}): {e}")
            logger.info(f"下载完成：成功获取并转换了 {success_count}/{len(hashes)} 个 Windows 根证书")

        # 下载补充的根证书
        supplemental_urls = [
            "https://www.microsoft.com/pki/certs/MicrosoftRootCert.crt",
            "https://www.microsoft.com/pki/mscorp/msitwww2.crt"
        ]
        
        from cryptography import x509
        from cryptography.hazmat.primitives import serialization
        
        cert_index = len(hashes) + 1
        for url in supplemental_urls:
            try:
                cert_file = TEMP_DIR / f"windows-supp-{cert_index}.crt"
                output_file = source_dir / f"windows-supp-{cert_index:03d}.crt"
                
                if download_file(url, cert_file, verbose=verbose):
                    with open(cert_file, "rb") as f:
                        der_bytes = f.read()
                    
                    # 转换 DER 为 PEM
                    cert = x509.load_der_x509_certificate(der_bytes)
                    pem_bytes = cert.public_bytes(serialization.Encoding.PEM)
                    
                    with open(output_file, "wb") as f:
                        f.write(pem_bytes)
                    cert_index += 1
                    logger.info(f"成功收集补充证书: {url}")
            except Exception as e:
                logger.warning(f"处理补充证书 {url} 时出错: {e}")
                continue
        
        return list(source_dir.glob("*.crt"))
    
    except Exception as e:
        logger.error(f"从Windows收集证书时出错: {e}")
        return []


def collect_certifi_certs(verbose: bool = True) -> List[Path]:
    """从python-certifi库收集证书"""
    logger.info("从python-certifi库收集证书...")
    
    source_dir = SOURCES_DIR["certifi"]
    # 清空源目录
    if source_dir.exists():
        shutil.rmtree(source_dir)
    source_dir.mkdir(exist_ok=True, parents=True)
    
    try:
        # 安装certifi
        run_command(["pip3", "install", "--upgrade", "certifi", "--break-system-packages"], verbose=verbose)
        
        # 运行Python脚本获取certifi证书路径
        certifi_script = f"""
import certifi
import sys
sys.stdout.write(certifi.where())
"""
        certifi_path = run_command(["python3", "-c", certifi_script], verbose=verbose).strip()
        
        if not certifi_path or not os.path.exists(certifi_path):
            raise FileNotFoundError(f"找不到certifi证书文件: {certifi_path}")
        
        # 分割并提取单个证书
        cert_index = 0
        with open(certifi_path, 'r', encoding='utf-8') as f:
            cert_data = []
            in_cert = False
            
            for line in f:
                if "-----BEGIN CERTIFICATE-----" in line:
                    in_cert = True
                    cert_data = [line]
                elif "-----END CERTIFICATE-----" in line:
                    cert_data.append(line)
                    # 保存证书
                    cert_file = source_dir / f"certifi-{cert_index:03d}.crt"
                    with open(cert_file, 'w', encoding='utf-8') as cert_out:
                        cert_out.write("".join(cert_data))
                    cert_index += 1
                    in_cert = False
                elif in_cert:
                    cert_data.append(line)
        
        return list(source_dir.glob("*.crt"))
    
    except Exception as e:
        logger.error(f"从certifi收集证书时出错: {e}")
        return []


def collect_curl_certs(verbose: bool = True) -> List[Path]:
    """从cURL官方提供的 CA bundle 收集根证书

    下载 https://curl.se/ca/cacert.pem 并拆分成单独证书文件。
    与 certifi 处理方式类似，以便后续统一去重 / 解析。
    """
    logger.info("从cURL CA bundle收集证书...")

    source_dir = SOURCES_DIR["curl"]
    if source_dir.exists():
        shutil.rmtree(source_dir)
    source_dir.mkdir(exist_ok=True, parents=True)

    bundle_url = "https://curl.se/ca/cacert.pem"
    bundle_path = TEMP_DIR / "curl-cacert.pem"

    try:
        # 确保有下载工具
        try:
            run_command(["wget", "--version"], verbose=False)
            downloader = ["wget", "-O", bundle_path.as_posix(), bundle_url]
        except Exception:
            # wget 不可用时尝试 curl
            downloader = ["curl", "-fsSL", bundle_url, "-o", bundle_path.as_posix()]

        run_command(downloader, verbose=verbose)

        if not bundle_path.exists() or bundle_path.stat().st_size == 0:
            logger.warning("cURL bundle 下载失败或为空")
            return []

        cert_index = 0
        with open(bundle_path, "r", encoding="utf-8", errors="ignore") as f:
            current = []
            in_cert = False
            for line in f:
                if "-----BEGIN CERTIFICATE-----" in line:
                    in_cert = True
                    current = [line]
                elif "-----END CERTIFICATE-----" in line and in_cert:
                    current.append(line)
                    cert_file = source_dir / f"curl-{cert_index:03d}.crt"
                    with open(cert_file, "w", encoding="utf-8") as out:
                        out.write("".join(current))
                    cert_index += 1
                    in_cert = False
                elif in_cert:
                    current.append(line)

        logger.info(f"从cURL bundle拆分得到 {cert_index} 个证书")
        return list(source_dir.glob("*.crt"))
    except Exception as e:
        logger.error(f"从cURL收集证书时出错: {e}")
        return []


def normalize_cert_filename(cert_path: Path, cert_info: Dict) -> Path:
    """标准化证书文件名，使用证书属性生成唯一名称"""
    # 使用CN和O创建一个安全的文件名
    cn = cert_info.get("subject_cn", "")
    o = cert_info.get("subject_o", "")
    
    # 创建基本名称
    if cn:
        base_name = cn
    elif o:
        base_name = o
    else:
        # 如果没有可用的名称，使用原始文件名（不包含路径）
        base_name = cert_path.name.replace('.crt', '')
    
    # 清理名称，移除非法字符
    safe_name = "".join(c if c.isalnum() else "_" for c in base_name)
    # 截断过长的名称
    safe_name = safe_name[:50]
    # 添加后缀避免潜在的重复
    fingerprint_suffix = cert_info.get("fingerprint", "")[:8]
    
    # 最终文件名
    final_name = f"{safe_name}_{fingerprint_suffix}.crt"
    logger.debug(f"标准化证书文件名: {final_name}")
    
    return Path(final_name)  # 仅返回文件名，不包含路径


def get_cert_info(cert_path: Path, verbose: bool = True) -> Dict:
    """获取证书信息"""
    logger.debug(f"获取证书信息: {cert_path.name}")
    try:
        # 使用openssl获取证书信息
        output = run_command([
            "openssl", "x509", "-in", cert_path.as_posix(),
            "-noout", "-subject", "-issuer", "-dates", "-fingerprint"
        ], verbose=verbose)
        
        info = {}
        
        def extract_field(part: str, field: str) -> str:
            """提取字段值，处理带空格和不带空格的格式，并处理引号问题"""
            # 处理常见的格式变体
            patterns = [
                f"{field}=",      # CN=Value
                f"{field} =",     # CN =Value
                f"{field}= ",     # CN= Value
                f"{field} = "     # CN = Value
            ]
            for pattern in patterns:
                if pattern in part:
                    value = part.split(pattern)[1].strip()
                    # 移除引号 (如果存在)
                    if value.startswith('"') and value.endswith('"'):
                        value = value[1:-1]
                    return value
            return ""

        # 智能解析带引号的字段
        def parse_dn_string(dn_string: str) -> Dict[str, str]:
            """解析带引号的DN字符串，返回字段映射"""
            result = {}
            # 处理引号内的内容
            in_quotes = False
            field_parts = []
            current_part = ""
            
            for char in dn_string:
                if char == '"':
                    in_quotes = not in_quotes
                    current_part += char
                elif char == ',' and not in_quotes:
                    field_parts.append(current_part.strip())
                    current_part = ""
                else:
                    current_part += char
            
            # 添加最后一部分
            if current_part:
                field_parts.append(current_part.strip())
            
            # 解析每个部分
            for part in field_parts:
                for field in ["CN", "O"]:
                    value = extract_field(part, field)
                    if value:
                        result[field] = value
            
            return result

        # 解析主题
        if "subject=" in output:
            subject_line = next((l for l in output.split("\n") if l.startswith("subject=")), "")
            # 去除subject=前缀
            subject_content = subject_line.replace("subject=", "").strip()
            
            # 使用智能解析处理带引号的内容
            fields = parse_dn_string(subject_content)
            
            if "CN" in fields:
                info["subject_cn"] = fields["CN"]
            if "O" in fields:
                info["subject_o"] = fields["O"]
        
        # 解析颁发者
        if "issuer=" in output:
            issuer_line = next((l for l in output.split("\n") if l.startswith("issuer=")), "")
            # 去除issuer=前缀
            issuer_content = issuer_line.replace("issuer=", "").strip()
            
            # 使用智能解析处理带引号的内容
            fields = parse_dn_string(issuer_content)
            
            if "CN" in fields:
                info["issuer_cn"] = fields["CN"]
            if "O" in fields:
                info["issuer_o"] = fields["O"]
        
        if "notBefore=" in output:
            not_before_line = next((l for l in output.split("\n") if l.startswith("notBefore=")), "")
            info["not_before"] = not_before_line.replace("notBefore=", "").strip()
        
        if "notAfter=" in output:
            not_after_line = next((l for l in output.split("\n") if l.startswith("notAfter=")), "")
            info["not_after"] = not_after_line.replace("notAfter=", "").strip()
        
        if "SHA1 Fingerprint=" in output:
            fingerprint_line = next((l for l in output.split("\n") if "SHA1 Fingerprint=" in l), "")
            info["fingerprint"] = fingerprint_line.split("=")[1].strip().replace(":", "").lower()
            info["fingerprint_type"] = "sha1"
            
        # 尝试获取SHA-256指纹
        try:
            sha256_output = run_command([
                "openssl", "x509", "-in", cert_path.as_posix(),
                "-noout", "-fingerprint", "-sha256"
            ], verbose=False)
            
            if "SHA256 Fingerprint=" in sha256_output:
                sha256_line = next((l for l in sha256_output.split("\n") if "SHA256 Fingerprint=" in l), "")
                info["sha256_fingerprint"] = sha256_line.split("=")[1].strip().replace(":", "").lower()
        except Exception as e:
            logger.debug(f"获取SHA-256指纹时出错: {e}")
            # 如果SHA-256获取失败，继续使用SHA-1
        
        # 尝试获取MD5指纹
        try:
            md5_output = run_command([
                "openssl", "x509", "-in", cert_path.as_posix(),
                "-noout", "-fingerprint", "-md5"
            ], verbose=False)
            
            if "MD5 Fingerprint=" in md5_output:
                md5_line = next((l for l in md5_output.split("\n") if "MD5 Fingerprint=" in l), "")
                info["md5_fingerprint"] = md5_line.split("=")[1].strip().replace(":", "").lower()
        except Exception as e:
            logger.debug(f"获取MD5指纹时出错: {e}")
        
        return info
    
    except Exception as e:
        logger.error(f"获取证书信息时出错 {cert_path.name}: {e}")
        return {}


def is_self_signed(cert_path: Path, verbose: bool = True) -> bool:
    """检查证书是否为自签名"""
    try:
        # 使用openssl验证证书是否自签名
        output = run_command([
            "openssl", "verify", "-CAfile", cert_path.as_posix(), cert_path.as_posix()
        ], verbose=verbose)
        return ": OK" in output
    except Exception:
        return False


def is_certificate_revoked(cert_info: Dict) -> bool:
    """检查证书是否已撤销"""
    # 从黑名单文件中读取撤销的证书指纹
    if not BLACKLIST_FILE.exists():
        logger.debug(f"黑名单文件不存在: {BLACKLIST_FILE}")
        return False
    
    # 获取证书的SHA-1、SHA-256和MD5指纹
    sha1_fingerprint = cert_info.get("fingerprint", "").lower()
    sha256_fingerprint = cert_info.get("sha256_fingerprint", "").lower()
    md5_fingerprint = cert_info.get("md5_fingerprint", "").lower()
    
    if not sha1_fingerprint and not sha256_fingerprint and not md5_fingerprint:
        return False
    
    logger.debug(f"检查证书指纹是否在黑名单中 - SHA-1: {sha1_fingerprint}, SHA-256: {sha256_fingerprint}, MD5: {md5_fingerprint}")
    
    # 从黑名单文件中读取和解析指纹
    with open(BLACKLIST_FILE, 'r') as f:
        lines = [line.strip().lower() for line in f if line.strip()]
    
    # 构建指纹和类型的映射，处理不同的格式
    blacklist_fps = set()
    blacklist_with_type = {}
    
    for line in lines:
        # 处理格式: "类型:指纹"，例如 "sha1:123456..."
        if ":" in line and line.count(":") == 1:
            fp_type, fp = line.split(":")
            blacklist_with_type[(fp_type, fp)] = True
            blacklist_fps.add(fp)
        else:
            # 没有类型前缀的老格式，直接加入指纹集合
            blacklist_fps.add(line)
    
    # 检查SHA-1指纹
    if sha1_fingerprint:
        # 检查带类型的格式
        if ("sha1", sha1_fingerprint) in blacklist_with_type:
            logger.info(f"证书SHA-1指纹在黑名单中（带类型格式）: {sha1_fingerprint}")
            return True
        
        # 检查不带类型的格式（向后兼容）
        if sha1_fingerprint in blacklist_fps:
            logger.info(f"证书SHA-1指纹在黑名单中（无类型格式）: {sha1_fingerprint}")
            return True
    
    # 检查SHA-256指纹
    if sha256_fingerprint:
        # 检查带类型的格式
        if ("sha256", sha256_fingerprint) in blacklist_with_type:
            logger.info(f"证书SHA-256指纹在黑名单中（带类型格式）: {sha256_fingerprint}")
            return True
        
        # 检查不带类型的格式（向后兼容）
        if sha256_fingerprint in blacklist_fps:
            logger.info(f"证书SHA-256指纹在黑名单中（无类型格式）: {sha256_fingerprint}")
            return True
            
    # 检查MD5指纹
    if md5_fingerprint:
        # 检查带类型的格式
        if ("md5", md5_fingerprint) in blacklist_with_type:
            logger.info(f"证书MD5指纹在黑名单中（带类型格式）: {md5_fingerprint}")
            return True
        
        # 检查不带类型的格式（向后兼容）
        if md5_fingerprint in blacklist_fps:
            logger.info(f"证书MD5指纹在黑名单中（无类型格式）: {md5_fingerprint}")
            return True
    
    return False


def process_and_store_certs(collected_certs: List[Path], verbose: bool = True) -> Dict[str, Dict]:
    """处理和存储收集到的证书"""
    logger.debug("处理和存储收集到的证书...")
    logger.debug(f"脚本目录: {SCRIPT_DIR}")
    logger.debug(f"根目录: {ROOT_DIR}")
    logger.debug(f"证书目录: {CERTS_DIR}")
    logger.debug(f"临时目录: {TEMP_DIR}")
    logger.debug(f"黑名单文件: {BLACKLIST_FILE}")
    logger.debug(f"源目录: {SOURCES_DIR}")
    logger.info(f"处理 {len(collected_certs)} 个收集到的证书...")
    
    # 存储证书信息的字典
    cert_info_map = {}
    # 用于跟踪重复证书的集合
    fingerprints = set()
    
    # 创建临时处理目录
    temp_proc_dir = TEMP_DIR / "processing"
    if temp_proc_dir.exists():
        shutil.rmtree(temp_proc_dir)
    temp_proc_dir.mkdir(exist_ok=True, parents=True)
    
    # 将所有输入证书路径转换为绝对路径
    collected_certs = [Path(cert).resolve() for cert in collected_certs]
    
    # 确保CERTS_DIR存在
    CERTS_DIR.mkdir(exist_ok=True, parents=True)
    
    for cert_path in collected_certs:
        try:
            logger.debug(f"处理证书: {cert_path}")
            
            # 首先复制证书到临时处理目录
            temp_cert = temp_proc_dir / f"temp_{cert_path.name}"
            shutil.copy2(cert_path, temp_cert)
            
            # 获取证书信息
            cert_info = get_cert_info(temp_cert, verbose=verbose)
            
            # 跳过没有足够信息的证书
            if not cert_info or "fingerprint" not in cert_info:
                logger.warning(f"跳过不完整的证书: {cert_path.name}")
                continue
            
            # 检查是否是重复证书
            fingerprint = cert_info["fingerprint"]
            if fingerprint in fingerprints:
                logger.debug(f"跳过重复证书: {cert_path.name}")
                continue
            
            # 检查证书是否已撤销
            if is_certificate_revoked(cert_info):
                logger.info(f"跳过已撤销的证书: {cert_path.name}")
                continue
            
            # 检查是否为自签名根证书
            if not is_self_signed(temp_cert, verbose=verbose):
                logger.debug(f"跳过非自签名证书: {cert_path.name}")
                continue
            
            # 标准化文件名（仅获取文件名，不包含路径）
            dest_filename = normalize_cert_filename(cert_path, cert_info)
            # 构建目标路径（在CERTS_DIR下）
            dest_path = CERTS_DIR / dest_filename
            
            logger.debug(f"目标证书完整路径: {dest_path}")
            
            try:
                # 移动到最终目标目录（如果已存在则替换）
                if dest_path.exists():
                    dest_path.unlink()
                shutil.copy2(temp_cert, dest_path)
                logger.debug(f"成功存储证书到: {dest_path}")
            except Exception as e:
                logger.error(f"存储证书失败 {dest_filename}: {e}")
                continue
            
            # 添加到信息映射
            cert_info_map[dest_filename.stem] = cert_info
            # 添加指纹到集合
            fingerprints.add(fingerprint)
            
        except Exception as e:
            logger.error(f"处理证书时出错 {cert_path.name}: {e}")
            continue
    
    # 清理临时目录
    shutil.rmtree(temp_proc_dir)
    
    # 验证证书是否都被正确存储
    stored_certs = list(CERTS_DIR.glob("*.crt"))
    if not stored_certs:
        logger.fatal("!!!=======在certs目录中没有找到任何证书========!!!")
    else:
        logger.info(f"在certs目录中找到 {len(stored_certs)} 个证书文件")
    
    logger.info(f"成功处理并存储了 {len(cert_info_map)} 个唯一证书")
    return cert_info_map


def build_aggregate_cert_bundle(verbose: bool = True) -> None:
    """聚合根证书并生成一键更新文件到 certs/all 目录"""
    logger.info("生成聚合证书包 certs/all ...")

    aggregate_dir = CERTS_DIR / "all"
    if aggregate_dir.exists():
        shutil.rmtree(aggregate_dir)
    aggregate_dir.mkdir(exist_ok=True, parents=True)

    cert_files = sorted(CERTS_DIR.glob("*.crt"))
    if not cert_files:
        logger.warning("certs目录中没有可聚合的证书，跳过生成 certs/all")
        return

    cacerts_pem = aggregate_dir / "cacerts.pem"
    cacerts_crt = aggregate_dir / "cacerts.crt"
    cacerts_p12 = aggregate_dir / "cacerts.p12"
    cacert_der = aggregate_dir / "cacert.der"
    authroot_cab = aggregate_dir / "authrootstl.cab"

    with open(cacerts_pem, "w", encoding="utf-8") as pem_out:
        for cert_file in cert_files:
            with open(cert_file, "r", encoding="utf-8", errors="ignore") as cert_in:
                content = cert_in.read().strip()
                if not content:
                    continue
                pem_out.write(content)
                pem_out.write("\n\n")

    shutil.copy2(cacerts_pem, cacerts_crt)

    try:
        run_command([
            "openssl", "pkcs12", "-export", "-nokeys",
            "-in", cacerts_pem.as_posix(),
            "-out", cacerts_p12.as_posix(),
            "-passout", "pass:",
            "-name", "CACert-Sync Root CAs"
        ], verbose=verbose)
    except Exception as e:
        logger.warning(f"生成 cacerts.p12 失败: {e}")

    try:
        run_command([
            "openssl", "crl2pkcs7", "-nocrl",
            "-certfile", cacerts_pem.as_posix(),
            "-outform", "DER",
            "-out", cacert_der.as_posix()
        ], verbose=verbose)
    except Exception as e:
        logger.warning(f"使用PKCS7方式生成 cacert.der 失败: {e}")
        try:
            run_command([
                "openssl", "x509",
                "-in", cert_files[0].as_posix(),
                "-outform", "DER",
                "-out", cacert_der.as_posix()
            ], verbose=verbose)
        except Exception as e2:
            logger.warning(f"回退方式生成 cacert.der 失败: {e2}")

    try:
        run_command(["wget", "-O", authroot_cab.as_posix(), AUTHROOT_STL_CAB_URL], verbose=verbose)
    except Exception as e:
        logger.warning(f"wget 下载 authrootstl.cab 失败，尝试 curl: {e}")
        try:
            run_command(["curl", "-L", "-o", authroot_cab.as_posix(), AUTHROOT_STL_CAB_URL], verbose=verbose)
        except Exception as e2:
            logger.warning(f"curl 下载 authrootstl.cab 失败: {e2}")

    logger.info("聚合证书包生成完成")


def generate_html_page(cert_info_map: Dict[str, Dict], output_path: Path) -> None:
    """生成HTML页面展示证书列表"""
    logger.info("生成HTML页面...")
    
    # 读取模板
    template_path = ROOT_DIR / "templates" / "index.html"
    with open(template_path, 'r', encoding='utf-8') as f:
        template = f.read()
    
    # 当前日期
    current_date = datetime.datetime.now().strftime("%Y-%m-%d")
    
    # 生成证书列表HTML - 按照字母顺序排序
    cert_list_html = []
    
    # 将证书信息按照证书名称排序
    sorted_certs = []
    for cert_name, info in cert_info_map.items():
        # 获取证书显示名称：优先CN，其次组织名O
        cert_display_name = info.get("subject_cn", "") or info.get("subject_o", "")
        if not cert_display_name:
            # 如果没有可用主题字段，则使用文件名并仅去掉末尾的指纹后缀
            cert_name_without_suffix = cert_name.rsplit('_', 1)[0] if '_' in cert_name else cert_name
            cert_display_name = cert_name_without_suffix.replace('_', ' ')
            
        issuer = info.get("subject_o", "") or info.get("subject_cn", "未知")
        valid_until = info.get("not_after", "未知")
        sorted_certs.append((cert_name, cert_display_name, issuer, valid_until))
    
    # 按证书名称排序（使用证书名称的小写形式进行排序）
    sorted_certs.sort(key=lambda x: x[1].lower())
    
    # 生成HTML
    for idx, (cert_name, cert_display_name, issuer, valid_until) in enumerate(sorted_certs):
        cert_id = f"cert_{idx}"
        cert_list_html.append(f"""
        <div class="ios-list-item-container" id="container_{cert_id}" data-name="{cert_display_name}" data-issuer="{issuer}" data-valid="{valid_until}">
          <a href="certs/{cert_name}.crt" class="ios-list-item-link" onclick="return handleItemClick(event, '{cert_id}')">
            <div class="ios-list-item">
              <img class="ios-list-item-icon" src="assets/settings@96x96.png" width="30" height="30" alt="">
              <div class="ios-list-item-text">
                <div class="ios-list-item-title">{cert_display_name}</div>
                <div class="ios-list-item-subtitle">{issuer}</div>
              </div>
              <div class="ios-list-arrow"></div>
            </div>
          </a>
          <div class="cert-card" id="card_{cert_id}" style="display: none;">
            <div class="cert-card-row1">
              <div class="cert-card-col-left">
                <img class="cert-card-img" src="assets/settings@128x128.png" width="128" height="128" alt="">
              </div>
              <div class="cert-card-col-right">
                <h2 class="cert-card-title">{cert_display_name}</h2>
                <p class="cert-card-subtitle">{issuer}</p>
                <div class="cert-card-status">
                  <span class="trusted-icon">&#10003;</span>
                  <span class="trusted-text">可信</span>
                </div>
                <a href="certs/{cert_name}.crt" class="cert-card-btn-link" target="_blank">
                  <button type="button" class="cert-card-btn" id="btn_{cert_id}">下载</button>
                </a>
              </div>
            </div>
            <div class="cert-card-row2">
              <div class="cert-metadata-row">
                <span class="meta-label">包含</span>
                <span class="meta-value">根证书</span>
              </div>
              <div class="cert-metadata-row">
                <span class="meta-label">有效期至</span>
                <span class="meta-value">{valid_until}</span>
              </div>
              <div class="cert-metadata-row">
                <span class="meta-label">文件名</span>
                <span class="meta-value">{cert_name}.crt</span>
              </div>
            </div>
          </div>
        </div>
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


def sync_template_assets() -> None:
    """同步模板静态资源到发布目录assets"""
    template_assets_dir = ROOT_DIR / "templates" / "assets"
    assets_dir = ROOT_DIR / "assets"

    if not template_assets_dir.exists():
        logger.warning("模板资源目录不存在，跳过资源同步")
        return

    assets_dir.mkdir(exist_ok=True, parents=True)

    for asset_file in template_assets_dir.glob("*"):
        if asset_file.is_file():
            shutil.copy(asset_file, assets_dir / asset_file.name)

    logger.info("已同步模板资源到assets目录")


def main():
    """主函数"""
    parser = argparse.ArgumentParser(description="收集和同步CA根证书")
    parser.add_argument("--clean", action="store_true", help="清理所有现有证书后再收集")
    parser.add_argument("--noverbose", action="store_true", help="减少输出详细信息")
    parser.add_argument("-v", "--verbose", action="store_true", help="显示详细输出")
    args = parser.parse_args()
    
    # 设置是否详细输出
    verbose = not args.noverbose or args.verbose
    logger.setLevel(logging.DEBUG if verbose else logging.INFO)
    
    # 打印常量
    logger.debug(f"脚本目录: {SCRIPT_DIR}")
    logger.debug(f"根目录: {ROOT_DIR}")
    logger.debug(f"证书目录: {CERTS_DIR}")
    logger.debug(f"临时目录: {TEMP_DIR}")
    logger.debug(f"黑名单文件: {BLACKLIST_FILE}")
    logger.debug(f"源目录: {SOURCES_DIR}")
    
    logger.info("CA证书同步开始...")
    
    # 设置目录
    setup_directories()
    
    # 如果指定了清理，则删除现有证书
    if args.clean and CERTS_DIR.exists():
        logger.info("清理现有证书...")
        shutil.rmtree(CERTS_DIR)
        CERTS_DIR.mkdir(exist_ok=True)
    
    # 收集证书
    collected_certs = []
    
    # 从Ubuntu收集
    ubuntu_certs = collect_ubuntu_certs(verbose=verbose)
    collected_certs.extend(ubuntu_certs)
    logger.info(f"从Ubuntu收集了 {len(ubuntu_certs)} 个证书")
    
    # 优先使用Mozilla certdata.txt方式获取，避免CCADB速率限制
    firefox_certs = collect_mozilla_certdata_certs(verbose=verbose)
    if not firefox_certs:
        logger.warning("certdata.txt方式未获取到证书，回退到CCADB抓取方式")
        firefox_certs = collect_firefox_certs(verbose=verbose)
    collected_certs.extend(firefox_certs)
    logger.info(f"从Mozilla源收集了 {len(firefox_certs)} 个证书")
    
    # 从Windows收集
    windows_certs = collect_windows_certs(verbose=verbose)
    collected_certs.extend(windows_certs)
    logger.info(f"从Windows收集了 {len(windows_certs)} 个证书")
    
    # 从certifi收集
    certifi_certs = collect_certifi_certs(verbose=verbose)
    collected_certs.extend(certifi_certs)
    logger.info(f"从certifi收集了 {len(certifi_certs)} 个证书")

    # 从cURL CA bundle收集
    curl_certs = collect_curl_certs(verbose=verbose)
    collected_certs.extend(curl_certs)
    logger.info(f"从cURL收集了 {len(curl_certs)} 个证书")
    
    # 处理和存储证书
    cert_info_map = process_and_store_certs(collected_certs, verbose=verbose)

    # 生成聚合证书包，便于设备一键更新
    build_aggregate_cert_bundle(verbose=verbose)
    
    # 生成HTML页面
    sync_template_assets()
    index_path = ROOT_DIR / "index.html"
    generate_html_page(cert_info_map, index_path)
    
    # 清理临时文件
    if TEMP_DIR.exists():
        logger.info("清理临时文件...")
        shutil.rmtree(TEMP_DIR)
    
    logger.info("CA证书同步完成")


if __name__ == "__main__":
    main()
