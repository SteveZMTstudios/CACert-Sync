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
from pathlib import Path
from typing import List, Dict, Set, Optional

# 配置日志
logging.basicConfig(
    level=logging.INFO,
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
    "certifi": TEMP_DIR / "certifi"
}


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
        logger.info(f"正在执行命令: {cmd_str}")
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
            logger.info(f"  {line}")
            output_lines.append(line)
        
        process.wait()
        output = '\n'.join(output_lines)
        
        if process.returncode != 0:
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
    """从Firefox收集证书"""
    logger.info("从Firefox收集证书...")
    
    source_dir = SOURCES_DIR["firefox"]
    # 清空源目录
    if source_dir.exists():
        shutil.rmtree(source_dir)
    source_dir.mkdir(exist_ok=True, parents=True)
    
    try:
        # 安装必要的工具
        run_command(["apt-get", "install", "-y", "wget", "unzip"], verbose=verbose)
        
        # 下载最新的Firefox ESR
        firefox_url = "https://download.mozilla.org/?product=firefox-esr-latest-ssl&os=linux64&lang=en-US"
        firefox_zip = TEMP_DIR / "firefox.tar.bz2"
        run_command(["wget", "-O", firefox_zip.as_posix(), firefox_url], verbose=verbose)
        
        # 解压Firefox
        firefox_dir = TEMP_DIR / "firefox-extract"
        if firefox_dir.exists():
            shutil.rmtree(firefox_dir)
        firefox_dir.mkdir(exist_ok=True, parents=True)
        run_command(["tar", "-xf", firefox_zip.as_posix(), "-C", firefox_dir.as_posix()], verbose=verbose)
        
        # 提取证书
        cert_db_path = firefox_dir / "firefox" / "browser" / "features" / "@ADDONID@" / "cert_storage.sqlite"
        
        if not cert_db_path.exists():
            # 尝试其他可能的路径
            possible_paths = list(firefox_dir.glob("**/cert*.sqlite"))
            if possible_paths:
                cert_db_path = possible_paths[0]
            else:
                # 如果找不到证书数据库，使用NSS工具导出内置证书
                # 安装NSS工具
                run_command(["apt-get", "install", "-y", "libnss3-tools"], verbose=verbose)
                
                # 找到NSS数据库目录
                nss_dir = firefox_dir / "firefox" / "browser"
                if not nss_dir.exists():
                    nss_dir = firefox_dir / "firefox"
                
                # 导出证书
                cert_index = 0
                
                certutil_output = run_command(["certutil", "-L", "-d", "sql:" + nss_dir.as_posix()], verbose=verbose)
                for line in certutil_output.strip().split("\n"):
                    if "CT,C,C" in line or ",,," in line:  # CA证书标记
                        cert_name = line.split()[0].strip()
                        if cert_name:
                            output_file = source_dir / f"firefox-{cert_index:03d}.crt"
                            try:
                                run_command([
                                    "certutil", "-L", "-d", f"sql:{nss_dir.as_posix()}",
                                    "-n", cert_name, "-a", "-o", output_file.as_posix()
                                ], verbose=verbose)
                                cert_index += 1
                            except Exception as e:
                                logger.warning(f"导出证书 {cert_name} 时出错: {e}")
                
                return list(source_dir.glob("*.crt"))
        
        # 如果以上方法都失败，尝试从Mozilla的证书数据中获取
        fallback_url = "https://hg.mozilla.org/mozilla-central/raw-file/tip/security/nss/lib/ckfw/builtins/certdata.txt"
        certdata_file = TEMP_DIR / "certdata.txt"
        run_command(["wget", "-O", certdata_file.as_posix(), fallback_url], verbose=verbose)
        
        # 转换certdata.txt为证书
        run_command([
            "python3", (SCRIPT_DIR / "extract_mozilla_certdata.py").as_posix(),
            "--source", certdata_file.as_posix(),
            "--destination", source_dir.as_posix()
        ], verbose=verbose)
        
        return list(source_dir.glob("*.crt"))
    
    except Exception as e:
        logger.error(f"从Firefox收集证书时出错: {e}")
        return []


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
        run_command(["apt-get", "install", "-y", "wget", "cabextract"], verbose=verbose)
        
        # 下载Windows根证书计划
        authroot_url = "http://ctldl.windowsupdate.com/msdownload/update/v3/static/trustedr/en/authrootstl.cab"
        authroot_cab = TEMP_DIR / "authroot.cab"
        run_command(["wget", "-O", authroot_cab.as_posix(), authroot_url], verbose=verbose)
        
        # 解压cab文件到临时目录
        extract_dir = TEMP_DIR / "authroot-extract"
        if extract_dir.exists():
            shutil.rmtree(extract_dir)
        extract_dir.mkdir(exist_ok=True, parents=True)
        
        run_command(["cabextract", "-d", extract_dir.as_posix(), authroot_cab.as_posix()], verbose=verbose)
        
        # 安装证书转换工具
        run_command(["apt-get", "install", "-y", "openssl"], verbose=verbose)
        
        # 转换STL文件为PEM格式
        stl_files = list(extract_dir.glob("*.stl"))
        cert_index = 0
        
        for stl_file in stl_files:
            output_file = source_dir / f"windows-{cert_index:03d}.crt"
            try:
                run_command([
                    "openssl", "x509", "-inform", "DER", "-in", stl_file.as_posix(),
                    "-out", output_file.as_posix()
                ], verbose=verbose)
                cert_index += 1
            except Exception as e:
                logger.warning(f"转换证书 {stl_file.name} 时出错: {e}")
        
        # 如果以上方法失败，尝试从其他来源获取Windows证书
        if cert_index == 0:
            ms_cert_url = "http://www.download.windowsupdate.com/msdownload/update/v3/static/trustedr/en/rootsupd.exe"
            rootsupd_exe = TEMP_DIR / "rootsupd.exe"
            run_command(["wget", "-O", rootsupd_exe.as_posix(), ms_cert_url], verbose=verbose)
            
            # 使用cabextract提取exe中的证书
            run_command(["cabextract", "-d", extract_dir.as_posix(), rootsupd_exe.as_posix()], verbose=verbose)
            
            # 寻找证书文件并转换
            cert_files = list(extract_dir.glob("*.cer")) + list(extract_dir.glob("*.crt"))
            for cert_file in cert_files:
                output_file = source_dir / f"windows-{cert_index:03d}.crt"
                try:
                    run_command([
                        "openssl", "x509", "-inform", "DER", "-in", cert_file.as_posix(),
                        "-out", output_file.as_posix()
                    ], verbose=verbose)
                    cert_index += 1
                except Exception:
                    # 尝试以PEM格式读取
                    try:
                        shutil.copy(cert_file, output_file)
                        cert_index += 1
                    except Exception as e:
                        logger.warning(f"处理证书 {cert_file.name} 时出错: {e}")
        
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
        run_command(["pip3", "install", "--upgrade", "certifi"], verbose=verbose)
        
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
        # 如果没有可用的名称，使用原始文件名
        return cert_path
    
    # 清理名称，移除非法字符
    safe_name = "".join(c if c.isalnum() else "_" for c in base_name)
    # 截断过长的名称
    safe_name = safe_name[:50]
    # 添加后缀避免潜在的重复
    fingerprint_suffix = cert_info.get("fingerprint", "")[:8]
    
    # 最终文件名
    return Path(f"{safe_name}_{fingerprint_suffix}.crt")


def get_cert_info(cert_path: Path, verbose: bool = True) -> Dict:
    """获取证书信息"""
    try:
        # 使用openssl获取证书信息
        output = run_command([
            "openssl", "x509", "-in", cert_path.as_posix(),
            "-noout", "-subject", "-issuer", "-dates", "-fingerprint"
        ], verbose=verbose)
        
        info = {}
        
        # 解析主题
        if "subject=" in output:
            subject_line = next((l for l in output.split("\n") if l.startswith("subject=")), "")
            subject_parts = subject_line.replace("subject=", "").split(",")
            
            for part in subject_parts:
                if "CN=" in part:
                    info["subject_cn"] = part.split("CN=")[1].strip()
                if "O=" in part:
                    info["subject_o"] = part.split("O=")[1].strip()
        
        # 解析颁发者
        if "issuer=" in output:
            issuer_line = next((l for l in output.split("\n") if l.startswith("issuer=")), "")
            issuer_parts = issuer_line.replace("issuer=", "").split(",")
            
            for part in issuer_parts:
                if "CN=" in part:
                    info["issuer_cn"] = part.split("CN=")[1].strip()
                if "O=" in part:
                    info["issuer_o"] = part.split("O=")[1].strip()
        
        # 解析有效期
        if "notBefore=" in output:
            not_before_line = next((l for l in output.split("\n") if l.startswith("notBefore=")), "")
            info["not_before"] = not_before_line.replace("notBefore=", "").strip()
        
        if "notAfter=" in output:
            not_after_line = next((l for l in output.split("\n") if l.startswith("notAfter=")), "")
            info["not_after"] = not_after_line.replace("notAfter=", "").strip()
        
        # 解析指纹
        if "SHA1 Fingerprint=" in output:
            fingerprint_line = next((l for l in output.split("\n") if "SHA1 Fingerprint=" in l), "")
            info["fingerprint"] = fingerprint_line.split("=")[1].strip().replace(":", "").lower()
        
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
        return False
    
    with open(BLACKLIST_FILE, 'r') as f:
        blacklist = [line.strip().lower() for line in f if line.strip()]
    
    fingerprint = cert_info.get("fingerprint", "").lower()
    return fingerprint in blacklist


def process_and_store_certs(collected_certs: List[Path], verbose: bool = True) -> Dict[str, Dict]:
    """处理和存储收集到的证书"""
    logger.info(f"处理 {len(collected_certs)} 个收集到的证书...")
    
    # 存储证书信息的字典
    cert_info_map = {}
    # 用于跟踪重复证书的集合
    fingerprints = set()
    
    # 创建临时处理目录
    temp_proc_dir = ROOT_DIR / "temp-processing"
    if temp_proc_dir.exists():
        shutil.rmtree(temp_proc_dir)
    temp_proc_dir.mkdir(exist_ok=True, parents=True)
    
    for cert_path in collected_certs:
        try:
            # 获取证书信息
            cert_info = get_cert_info(cert_path, verbose=verbose)
            
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
            if not is_self_signed(cert_path, verbose=verbose):
                logger.debug(f"跳过非自签名证书: {cert_path.name}")
                continue
            
            # 标准化文件名
            normalized_name = normalize_cert_filename(cert_path, cert_info)
            
            # 首先复制到临时目录，然后再移动到最终目标
            # 这样可以避免源文件和目标文件相同的问题
            temp_path = temp_proc_dir / normalized_name
            dest_path = CERTS_DIR / normalized_name
            
            # 复制证书到临时目录
            shutil.copy(cert_path, temp_path)
            
            # 然后移动到目标目录（如果已存在则替换）
            if dest_path.exists():
                dest_path.unlink()
            shutil.move(temp_path, dest_path)
            
            logger.debug(f"已存储证书: {normalized_name}")
            
            # 添加到信息映射
            cert_info_map[normalized_name.stem] = cert_info
            # 添加指纹到集合
            fingerprints.add(fingerprint)
            
        except Exception as e:
            logger.error(f"处理证书时出错 {cert_path.name}: {e}")
    
    # 清理临时目录
    if temp_proc_dir.exists():
        shutil.rmtree(temp_proc_dir)
    
    logger.info(f"成功处理并存储了 {len(cert_info_map)} 个唯一证书")
    return cert_info_map


def generate_html_page(cert_info_map: Dict[str, Dict], output_path: Path) -> None:
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
        issuer = info.get("subject_o", "") or info.get("subject_cn", "未知")
        valid_until = info.get("not_after", "未知")
        
        cert_list_html.append(f"""
        <tr>
          <td>{issuer}</td>
          <td>{valid_until}</td>
          <td><a href="certs/{cert_name}.crt" class="download-link"><button class="download-button"><img src="assets/download@32x32.png" alt="下载" width="16" height="16"></button></a></td>
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
    
    # 确保assets目录存在并包含必要文件
    assets_dir = ROOT_DIR / "assets"
    template_assets_dir = ROOT_DIR / "templates" / "assets"
    
    if template_assets_dir.exists() and not assets_dir.exists():
        # 创建assets目录
        assets_dir.mkdir(exist_ok=True, parents=True)
        
        # 复制所有资源文件
        for asset_file in template_assets_dir.glob("*"):
            shutil.copy(asset_file, assets_dir / asset_file.name)
        
        logger.info("复制资源文件到assets目录")


def main():
    """主函数"""
    parser = argparse.ArgumentParser(description="收集和同步CA根证书")
    parser.add_argument("--clean", action="store_true", help="清理所有现有证书后再收集")
    parser.add_argument("--noverbose", action="store_true", help="减少输出详细信息")
    args = parser.parse_args()
    
    # 设置是否详细输出
    verbose = not args.noverbose
    
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
    
    # 从Firefox收集
    firefox_certs = collect_firefox_certs(verbose=verbose)
    collected_certs.extend(firefox_certs)
    logger.info(f"从Firefox收集了 {len(firefox_certs)} 个证书")
    
    # 从Windows收集
    windows_certs = collect_windows_certs(verbose=verbose)
    collected_certs.extend(windows_certs)
    logger.info(f"从Windows收集了 {len(windows_certs)} 个证书")
    
    # 从certifi收集
    certifi_certs = collect_certifi_certs(verbose=verbose)
    collected_certs.extend(certifi_certs)
    logger.info(f"从certifi收集了 {len(certifi_certs)} 个证书")
    
    # 处理和存储证书
    cert_info_map = process_and_store_certs(collected_certs, verbose=verbose)
    
    # 生成HTML页面
    index_path = ROOT_DIR / "index.html"
    generate_html_page(cert_info_map, index_path)
    
    # 清理临时文件
    if TEMP_DIR.exists():
        logger.info("清理临时文件...")
        shutil.rmtree(TEMP_DIR)
    
    logger.info("CA证书同步完成")


if __name__ == "__main__":
    main()
