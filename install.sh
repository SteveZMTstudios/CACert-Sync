#!/bin/bash
# CA证书收集系统安装脚本

set -e

# 设置颜色
GREEN='\033[0;32m'
BLUE='\033[0;34m'
RED='\033[0;31m'
NC='\033[0m' # No Color

echo -e "${BLUE}开始安装CA证书收集系统...${NC}"

# 检查Python版本
python3 --version || {
    echo -e "${RED}请先安装Python3${NC}"
    exit 1
}

# 检查必要的命令
for cmd in openssl wget git; do
    which $cmd > /dev/null || {
        echo -e "${RED}请先安装 $cmd${NC}"
        exit 1
    }
done

# 创建虚拟环境
if [ ! -d "venv" ]; then
    echo -e "${BLUE}创建Python虚拟环境...${NC}"
    python3 -m venv venv
fi

# 激活虚拟环境
source venv/bin/activate

# 安装依赖
echo -e "${BLUE}安装依赖...${NC}"
pip install --upgrade pip
pip install requests certifi

# 设置环境
echo -e "${BLUE}设置环境...${NC}"
python scripts/cacert-cli.py setup --force

echo -e "${GREEN}安装完成！${NC}"
echo ""
echo -e "使用以下命令运行系统："
echo -e "${BLUE}source venv/bin/activate  # 激活虚拟环境${NC}"
echo -e "${BLUE}python scripts/cacert-cli.py sync  # 同步证书${NC}"
echo -e "${BLUE}python scripts/cacert-cli.py test  # 运行测试${NC}"
echo ""
echo -e "或者使用GitHub Actions自动化运行"
echo ""
