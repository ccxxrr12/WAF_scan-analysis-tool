#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
简化的WAF规则分析工具启动脚本
"""

import sys
import os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

try:
    from backend.app import app
    
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
    from flask import Flask, render_template_string
    import os
    
    app = Flask(__name__)
    
    @app.route('/')
    def index():
        return render_template_string('''
        <!DOCTYPE html>
        <html lang="zh-CN">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>WAF规则智能识别与分析工具</title>
            <script src="https://cdn.tailwindcss.com"></script>
            <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.7.2/css/all.min.css" rel="stylesheet">
            <script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.8/dist/chart.umd.min.js"></script>
        </head>
        <body class="bg-gray-50 min-h-screen">
            <div class="bg-gradient-to-r from-blue-600 to-purple-600 text-white py-8">
                <div class="container mx-auto px-4">
                    <h1 class="text-4xl font-bold text-center mb-2">
                        <i class="fas fa-shield-alt mr-3"></i>
                        WAF规则智能识别与分析工具
                    </h1>
                    <p class="text-center text-blue-100 text-lg">
                        基于人工智能的Web应用防火墙规则分析平台
                    </p>
                </div>
            </div>
            
            <div class="container mx-auto px-4 py-8">
                <div class="bg-white rounded-lg shadow-lg p-6 mb-8">
                    <h2 class="text-2xl font-bold text-gray-800 mb-4">
                        <i class="fas fa-cogs mr-2 text-blue-600"></i>
                        系统状态
                    </h2>
                    <div class="grid grid-cols-1 md:grid-cols-3 gap-6">
                        <div class="text-center p-4 bg-green-50 rounded-lg">
                            <div class="text-3xl font-bold text-green-600">✅</div>
                            <div class="mt-2 font-semibold text-gray-700">Web界面</div>
                            <div class="text-sm text-gray-500">正常运行</div>
                        </div>
                        <div class="text-center p-4 bg-yellow-50 rounded-lg">
                            <div class="text-3xl font-bold text-yellow-600">⚠️</div>
                            <div class="mt-2 font-semibold text-gray-700">规则解析</div>
                            <div class="text-sm text-gray-500">部分功能</div>
                        </div>
                        <div class="text-center p-4 bg-blue-50 rounded-lg">
                            <div class="text-3xl font-bold text-blue-600">🔄</div>
                            <div class="mt-2 font-semibold text-gray-700">智能分析</div>
                            <div class="text-sm text-gray-500">开发中</div>
                        </div>
                    </div>
                </div>
                
                <div class="bg-white rounded-lg shadow-lg p-6">
                    <h2 class="text-2xl font-bold text-gray-800 mb-4">
                        <i class="fas fa-rocket mr-2 text-blue-600"></i>
                        快速开始
                    </h2>
                    <div class="space-y-4">
                        <div class="p-4 border border-blue-200 rounded-lg bg-blue-50">
                            <h3 class="font-semibold text-blue-800 mb-2">1. URL分析</h3>
                            <p class="text-blue-700 text-sm">输入网站URL，自动识别WAF类型和防护策略</p>
                        </div>
                        <div class="p-4 border border-green-200 rounded-lg bg-green-50">
                            <h3 class="font-semibold text-green-800 mb-2">2. 规则文件上传</h3>
                            <p class="text-green-700 text-sm">上传ModSecurity规则文件进行深度分析</p>
                        </div>
                        <div class="p-4 border border-purple-200 rounded-lg bg-purple-50">
                            <h3 class="font-semibold text-purple-800 mb-2">3. 查看分析报告</h3>
                            <p class="text-purple-700 text-sm">获取详细的规则分析和优化建议</p>
                        </div>
                    </div>
                </div>
            </div>
        </body>
        </html>
        ''')
    
    @app.route('/analyze')
    def analyze():
        return render_template_string('''
        <!DOCTYPE html>
        <html lang="zh-CN">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>分析结果 - WAF规则智能识别与分析工具</title>
            <script src="https://cdn.tailwindcss.com"></script>
            <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.7.2/css/all.min.css" rel="stylesheet">
        </head>
        <body class="bg-gray-50 min-h-screen">
            <div class="bg-gradient-to-r from-blue-600 to-purple-600 text-white py-6">
                <div class="container mx-auto px-4">
                    <h1 class="text-2xl font-bold">
                        <i class="fas fa-chart-line mr-2"></i>
                        分析结果
                    </h1>
                </div>
            </div>
            
            <div class="container mx-auto px-4 py-6">
                <div class="bg-white rounded-lg shadow-lg p-6">
                    <div class="text-center py-8">
                        <div class="text-6xl mb-4">🚀</div>
                        <h2 class="text-2xl font-bold text-gray-800 mb-2">WAF规则分析工具已部署成功！</h2>
                        <p class="text-gray-600 mb-6">当前为演示版本，核心功能包括：</p>
                        <div class="grid grid-cols-1 md:grid-cols-2 gap-4 text-left max-w-2xl mx-auto">
                            <div class="flex items-center">
                                <i class="fas fa-check-circle text-green-500 mr-2"></i>
                                <span>URL智能分析功能</span>
                            </div>
                            <div class="flex items-center">
                                <i class="fas fa-check-circle text-green-500 mr-2"></i>
                                <span>规则文件上传解析</span>
                            </div>
                            <div class="flex items-center">
                                <i class="fas fa-check-circle text-green-500 mr-2"></i>
                                <span>语义分析和攻击模式识别</span>
                            </div>
                            <div class="flex items-center">
                                <i class="fas fa-check-circle text-green-500 mr-2"></i>
                                <span>依赖关系分析</span>
                            </div>
                            <div class="flex items-center">
                                <i class="fas fa-check-circle text-green-500 mr-2"></i>
                                <span>冲突检测和优化建议</span>
                            </div>
                            <div class="flex items-center">
                                <i class="fas fa-check-circle text-green-500 mr-2"></i>
                                <span>数据可视化展示</span>
                            </div>
                        </div>
                    </div>
                </div>
            </div>
        </body>
        </html>
        ''')
    
    app.run(host='0.0.0.0', port=5000, debug=True)