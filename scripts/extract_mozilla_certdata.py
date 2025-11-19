#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
从Mozilla certdata.txt文件中提取证书
"""

import os
import sys
import re
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
    """从certdata.txt行中提取证书

    兼容NSS certdata格式：
    - 标签在同一行：CKA_LABEL UTF8 "..."
    - 证书值：CKA_VALUE MULTILINE_OCTAL 之后若干行以 \ooo 八进制转义表示，直至单独一行 END
    - 忽略注释行和非证书对象中的值
    """
    certs: List[Dict[str, str]] = []
    current_label: Optional[str] = None
    in_value: bool = False
    data_bytes: List[int] = []

    label_re = re.compile(r'^CKA_LABEL\s+UTF8\s+"(.*)"\s*$')
    value_begin_re = re.compile(r'^CKA_VALUE\s+MULTILINE_OCTAL\s*$')
    end_re = re.compile(r'^END\s*$')
    # 匹配所有 \ooo 八进制转义（1-3位八进制）
    octet_re = re.compile(r'\\([0-7]{1,3})')

    for raw in certdata_lines:
        line = raw.rstrip("\n")
        stripped = line.strip()

        # 跳过注释与空行
        if not stripped or stripped.startswith('#'):
            continue

        # 解析标签（同一行）
        m_label = label_re.match(stripped)
        if m_label:
            # 保留原始标签内容（支持包含逗号或引号的情况）
            current_label = m_label.group(1)
            continue

        # 检测值开始
        if value_begin_re.match(stripped):
            in_value = True
            data_bytes = []
            continue

        # 收集值直到 END
        if in_value:
            if end_re.match(stripped):
                in_value = False
                if data_bytes:
                    label = current_label if current_label else f"mozilla_cert_{len(certs):03d}"
                    certs.append({
                        "label": label,
                        "data": data_bytes[:]
                    })
                # 一个对象结束后，不强制清除label，因为同一对象顺序通常是先label后value
                # 但为避免跨对象污染，若后续对象未设置新label，将自动使用默认名
                current_label = None
                data_bytes = []
            else:
                # 从当前行提取所有八进制转义
                for m in octet_re.finditer(stripped):
                    try:
                        data_bytes.append(int(m.group(1), 8) & 0xFF)
                    except Exception:
                        # 忽略异常字节
                        continue

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
