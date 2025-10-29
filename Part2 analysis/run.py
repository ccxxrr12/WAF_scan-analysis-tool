#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
简化的WAF规则分析工具启动脚本
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from flask_cors import CORS

try:
    from backend.app import app

    # 启用 CORS 支持
    CORS(app)

    if __name__ == '__main__':
        print("=" * 60)
        print("WAF规则智能识别与分析工具")
        print("=" * 60)
        print("核心功能：")
        print("1. URL智能分析 - 识别网站使用的WAF类型")
        print("2. 规则文件分析 - 解析ModSecurity规则文件")
        print("3. 语义分析 - 识别攻击模式和安全策略")
        print("4. 依赖分析 - 分析规则间的依赖关系")
        print("5. 冲突检测 - 检测规则冲突和优化建议")
        print("6. 可视化展示 - 图表和AST可视化")
        print("=" * 60)

        # 启动Flask应用
        app.run(host='0.0.0.0', port=5000, debug=True)

except Exception as e:
    print(f"启动失败: {str(e)}")
    print("正在使用备用模式启动...")

    # 备用模式：直接启动简化版Web界面
    from flask import Flask, render_template

    app = Flask(__name__, template_folder='../UI_2.0_frontend/templates')
    CORS(app)

    @app.route('/')
    def index():
        return render_template('index.html')

    app.run(host='0.0.0.0', port=5000, debug=True)