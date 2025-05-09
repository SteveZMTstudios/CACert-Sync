#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
从Mozilla certdata.txt文件中提取证书
"""

import os
import sys
import base64
import argparse
from pathlib import Path
from typing import List, Dict, Optional


def parse_args():
    """解析命令行参数"""
    parser = argparse.ArgumentParser(description="从Mozilla certdata.txt提取证书")
    parser.add_argument("--source", type=str, required=True, help="certdata.txt文件的路径")
    parser.add_argument("--destination", type=str, required=True, help="保存证书的目录")
    return parser.parse_args()


def read_certdata(certdata_path: str) -> List[str]:
    """读取certdata.txt文件内容"""
    with open(certdata_path, 'r', encoding='utf-8', errors='replace') as f:
        return f.readlines()


def extract_certs(certdata_lines: List[str]) -> List[Dict[str, str]]:
    """从certdata.txt行中提取证书"""
    certs = []
    current_cert = None
    in_cert = False
    in_label = False
    label = ""
    cert_data = []
    
    for line in certdata_lines:
        line = line.strip()
        
        # 开始一个新证书
        if line.startswith("CKA_LABEL") and "UTF8" in line:
            in_label = True
            continue
        
        # 获取证书标签
        if in_label and line.startswith('"'):
            label = line.strip('"\\')
            in_label = False
            current_cert = {"label": label, "data": []}
        
        # 开始证书数据
        if line.startswith("CKA_VALUE MULTILINE_OCTAL"):
            in_cert = True
            cert_data = []
            continue
        
        # 结束证书数据
        if in_cert and line == "END":
            in_cert = False
            if current_cert:
                current_cert["data"] = cert_data
                certs.append(current_cert)
                current_cert = None
            continue
        
        # 收集证书数据
        if in_cert and line:
            # 处理八进制格式
            oct_values = line.split("\\")
            for oct_value in oct_values:
                if oct_value:
                    try:
                        byte_value = int(oct_value, 8) & 0xFF
                        cert_data.append(byte_value)
                    except ValueError:
                        pass
    
    return certs


def cert_data_to_pem(cert_data: List[int]) -> str:
    """将证书数据转换为PEM格式"""
    der_bytes = bytes(cert_data)
    b64_data = base64.b64encode(der_bytes).decode('ascii')
    
    # 按64字符宽度格式化
    formatted_data = []
    for i in range(0, len(b64_data), 64):
        formatted_data.append(b64_data[i:i+64])
    
    return "-----BEGIN CERTIFICATE-----\n" + "\n".join(formatted_data) + "\n-----END CERTIFICATE-----\n"


def save_cert(cert: Dict[str, str], index: int, destination: str) -> Optional[str]:
    """保存证书到文件"""
    try:
        # 创建安全的文件名
        safe_label = "".join(c if c.isalnum() else "_" for c in cert["label"])
        safe_label = safe_label[:50]  # 限制长度
        filename = f"mozilla-{index:03d}-{safe_label}.crt"
        filepath = os.path.join(destination, filename)
        
        # 转换为PEM格式并保存
        pem_data = cert_data_to_pem(cert["data"])
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(pem_data)
        
        return filepath
    except Exception as e:
        print(f"保存证书时出错: {e}", file=sys.stderr)
        return None


def main():
    """主函数"""
    args = parse_args()
    
    # 确保目标目录存在
    os.makedirs(args.destination, exist_ok=True)
    
    # 读取certdata.txt
    certdata_lines = read_certdata(args.source)
    
    # 提取证书
    certs = extract_certs(certdata_lines)
    
    # 保存证书
    success_count = 0
    for i, cert in enumerate(certs):
        if save_cert(cert, i, args.destination):
            success_count += 1
    
    print(f"成功提取并保存了 {success_count} 个证书到 {args.destination}")


if __name__ == "__main__":
    main()
