"""
生成恶意xlsx文件用于XXE漏洞测试
这个脚本会创建一个包含外部实体注入的xlsx文件
"""

import sys
import os

# 添加父目录到路径以便导入模块
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from vuln.xxe import XXEVulnerabilityTool


def main():
    """生成测试文件"""
    print("=" * 60)
    print("XXE漏洞测试文件生成器")
    print("=" * 60)
    print()
    
    # 使用模块生成测试文件
    tool = XXEVulnerabilityTool()
    output_path = tool.generate_test_file()
    
    print()
    print("=" * 60)
    print("测试文件已准备就绪！")
    print("启动Flask应用后，访问 http://localhost:5000 进行上传测试")
    print("=" * 60)


if __name__ == '__main__':
    main()
