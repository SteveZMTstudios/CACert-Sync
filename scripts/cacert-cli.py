#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
证书收集系统命令行工具
"""

import sys
import argparse
import subprocess
from pathlib import Path

# 定义常量
SCRIPT_DIR = Path(__file__).parent.absolute()
ROOT_DIR = SCRIPT_DIR.parent
SYNC_SCRIPT = SCRIPT_DIR / "sync_certificates.py"
TEST_SCRIPT = SCRIPT_DIR / "test_certificate_sync.py"


def run_command(cmd, explanation=None):
    """运行命令并显示输出"""
    if explanation:
        print(f"\n>>> {explanation}")
    
    print(f"$ {' '.join(cmd)}")
    result = subprocess.run(cmd, check=True)
    return result.returncode == 0


def sync_certs(args):
    """同步证书"""
    cmd = [sys.executable, str(SYNC_SCRIPT)]
    
    if args.clean:
        cmd.append("--clean")
    
    if args.noverbose:
        cmd.append("--noverbose")
    
    return run_command(cmd, "正在同步证书...")


def test_sync(args):
    """测试同步功能"""
    cmd = [sys.executable, str(TEST_SCRIPT)]
    return run_command(cmd, "正在运行测试...")


def setup_env(args):
    """设置环境"""
    # 创建必要的目录
    dirs = [
        ROOT_DIR / "certs",
        ROOT_DIR / "assets"
    ]
    
    for dir_path in dirs:
        dir_path.mkdir(exist_ok=True, parents=True)
        print(f"已创建目录: {dir_path}")
    
    # 复制模板资源
    template_assets = ROOT_DIR / "templates" / "assets"
    assets_dir = ROOT_DIR / "assets"
    
    if template_assets.exists():
        for asset_file in template_assets.glob("*"):
            target_file = assets_dir / asset_file.name
            if not target_file.exists() or args.force:
                import shutil
                shutil.copy(asset_file, target_file)
                print(f"已复制资源: {asset_file.name}")
    
    print("\n环境设置完成！")
    return True


def main():
    """主函数"""
    parser = argparse.ArgumentParser(description="CA证书收集系统命令行工具")
    subparsers = parser.add_subparsers(dest="command", help="可用命令")
    
    # 同步命令
    sync_parser = subparsers.add_parser("sync", help="同步证书")
    sync_parser.add_argument("--clean", action="store_true", help="清理现有证书")
    sync_parser.add_argument("--noverbose", action="store_true", help="减少输出详细信息")
    sync_parser.add_argument("-v","--verbose", action="store_true", help="输出详细信息和调试")
    
    
    # 测试命令
    test_parser = subparsers.add_parser("test", help="运行测试")
    
    # 设置环境命令
    setup_parser = subparsers.add_parser("setup", help="设置环境")
    setup_parser.add_argument("--force", action="store_true", help="强制覆盖现有文件")
    
    args = parser.parse_args()
    
    if args.command == "sync":
        return 0 if sync_certs(args) else 1
    elif args.command == "test":
        return 0 if test_sync(args) else 1
    elif args.command == "setup":
        return 0 if setup_env(args) else 1
    else:
        parser.print_help()
        return 0


if __name__ == "__main__":
    sys.exit(main())
