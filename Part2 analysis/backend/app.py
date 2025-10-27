#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
WAF规则分析工具 - Web API服务
提供RESTful API接口，支持规则文件上传、解析和分析
"""

import os
import sys
import json
import tempfile
import logging
from flask import Flask, request, jsonify, render_template, redirect, url_for, send_file
from flask_cors import CORS
from werkzeug.utils import secure_filename
from pathlib import Path
from datetime import datetime

# 设置项目根目录
PROJECT_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from common.utils.log_utils import setup_logger
from common.utils.file_utils import read_file_content, write_file_content, delete_file
from part2_rule_analysis.lib.parser.modsecurity_parser import ModSecurityParser
from part2_rule_analysis.lib.analyzer.semantic_analyzer import SemanticAnalyzer
from part2_rule_analysis.lib.analyzer.dependency_analyzer import DependencyAnalyzer
from part2_rule_analysis.lib.analyzer.conflict_analyzer import ConflictAnalyzer
from part2_rule_analysis.lib.visualizer.ast_visualizer import ASTVisualizer
from backend.task_manager import AnalysisTask
from backend import rule_index

# 初始化Flask应用
app = Flask(__name__, template_folder=str(PROJECT_ROOT / 'frontend' / 'templates'),
            static_folder=str(PROJECT_ROOT / 'frontend' / 'static'))
app.config['UPLOAD_FOLDER'] = str(PROJECT_ROOT / 'uploads')
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB
app.secret_key = 'waf-analysis-tool-secret-key'

# 启用CORS
CORS(app)

# 设置日志
logger = setup_logger('WAFWebAPI', log_level='INFO')

# 创建必要的目录
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# 初始化分析器
parser = ModSecurityParser()
semantic_analyzer = SemanticAnalyzer()
dependency_analyzer = DependencyAnalyzer()
conflict_analyzer = ConflictAnalyzer()
ast_visualizer = ASTVisualizer()

# 初始化任务管理器
task_manager = AnalysisTask()

@app.route('/')
def index():
    """首页"""
    return render_template('index.html')

@app.route('/api/upload', methods=['POST'])
def upload_file():
    """上传规则文件"""
    try:
        if 'file' not in request.files:
            return jsonify({'error': 'No file part'}), 400
        
        file = request.files['file']
        if file.filename == '':
            return jsonify({'error': 'No selected file'}), 400
        
        if file:
            filename = secure_filename(file.filename)
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(file_path)
            
            logger.info(f"文件上传成功: {filename} ({os.path.getsize(file_path)} bytes)")
            
            # 创建分析任务
            task_id = task_manager.create_task(file_path)
            
            return jsonify({
                'success': True,
                'task_id': task_id,
                'filename': filename,
                'file_size': os.path.getsize(file_path)
            }), 200
    
    except Exception as e:
        logger.error(f"文件上传失败: {str(e)}", exc_info=True)
        return jsonify({'error': str(e)}), 500

@app.route('/api/analyze', methods=['POST'])
def analyze_rules():
    """分析规则文件"""
    try:
        data = request.get_json()
        if not data or 'task_id' not in data:
            return jsonify({'error': 'Missing task_id'}), 400
        
        task_id = data['task_id']
        task = task_manager.get_task(task_id)
        
        if not task:
            return jsonify({'error': 'Task not found'}), 404
        
        if task['status'] == 'processing':
            return jsonify({'status': 'processing'}), 202
        
        file_path = task['file_path']
        if not os.path.exists(file_path):
            return jsonify({'error': 'File not found'}), 404
        
        # 更新任务状态
        task_manager.update_task(task_id, 'processing')
        
        try:
            # 1. 语法解析
            logger.info(f"开始解析文件: {file_path}")
            parsed_rules = parser.parse_file(file_path)
            parse_errors = parser.get_parse_errors()
            
            if not parsed_rules and parse_errors:
                results = {
                    'status': 'error',
                    'errors': parse_errors
                }
                task_manager.update_task(task_id, 'failed', results)
                return jsonify(results), 400
            
            # 2. 语义分析
            logger.info("开始语义分析")
            semantic_results = semantic_analyzer.analyze_rules(parsed_rules)
            
            # 3. 依赖分析
            logger.info("开始依赖分析")
            dependency_results = dependency_analyzer.analyze_dependencies(parsed_rules)
            
            # 4. 冲突检测
            logger.info("开始冲突检测")
            conflict_results = conflict_analyzer.detect_conflicts(parsed_rules)
            
            # 5. AST生成
            logger.info("开始AST生成")
            ast_root = ast_visualizer.build_ast(parsed_rules)
            ast_dict = ast_visualizer._ast_to_dict(ast_root)
            
            # 生成可视化结果
            temp_dir = tempfile.mkdtemp()
            
            # 保存AST图像
            ast_img_path = os.path.join(temp_dir, 'ast.png')
            ast_visualizer.save_ast_image(ast_root, ast_img_path)
            
            # 保存依赖图
            dep_img_path = os.path.join(temp_dir, 'dependencies.png')
            dependency_analyzer.save_dependency_graph(dependency_results, dep_img_path)
            
            # 准备结果
            results = {
                'status': 'completed',
                'summary': {
                    'total_rules': len(parsed_rules),
                    'parse_errors': len(parse_errors),
                    'conflicts': len(conflict_results),
                    'dependencies': dependency_results['total_dependencies']
                },
                'parsing': {
                    'rules': [rule.get_rule_summary() for rule in parsed_rules[:20]],  # 只返回前20条规则
                    'errors': parse_errors,
                    'total_rules': len(parsed_rules)
                },
                'semantic': semantic_results,
                'dependencies': dependency_results,
                'conflicts': conflict_results,
                'ast': ast_dict,
                'visualization_paths': {
                    'ast': ast_img_path,
                    'dependencies': dep_img_path
                }
            }
            
            # 将解析到的规则保存到索引数据库（轻量索引）
            try:
                db_path = rule_index.init_db()
                for rule in parsed_rules:
                    # 规则对象可能是自定义类，尝试提取常见字段
                    r = {}
                    if hasattr(rule, 'to_dict'):
                        r = rule.to_dict()
                    else:
                        # 最小化字段映射
                        r = {
                            'id': getattr(rule, 'id', None) or getattr(rule, 'rule_id', None),
                            'node_type': getattr(rule, 'node_type', getattr(rule, 'nodeType', None)),
                            'line': getattr(rule, 'line', None),
                            'raw': getattr(rule, 'raw', str(rule)),
                            'tags': getattr(rule, 'tags', [])
                        }
                    rule_index.insert_rule(r, db_path=db_path)
                results['index_db'] = db_path
            except Exception:
                logger.exception('写入规则索引失败')
            # 更新任务状态
            task_manager.update_task(task_id, 'completed', results)
            
            logger.info(f"分析完成: {task_id}")
            
            return jsonify(results), 200
            
        except Exception as e:
            logger.error(f"分析过程中发生错误: {str(e)}", exc_info=True)
            results = {
                'status': 'error',
                'message': str(e)
            }
            task_manager.update_task(task_id, 'failed', results)
            return jsonify(results), 500
    
    except Exception as e:
        logger.error(f"分析请求处理失败: {str(e)}", exc_info=True)
        return jsonify({'error': str(e)}), 500

@app.route('/api/analyze-url', methods=['POST'])
def analyze_url():
    """分析URL（模拟Part1功能）"""
    try:
        data = request.get_json()
        if not data or 'url' not in data:
            return jsonify({'error': 'Missing URL'}), 400
        
        url = data['url']
        logger.info(f"开始分析URL: {url}")
        
        # 模拟WAF指纹识别（Part1功能）
        fingerprint_results = {
            'waf_detected': True,
            'waf_type': 'ModSecurity',
            'confidence': 0.95,
            'headers': {
                'Server': 'Apache/2.4.41 (Ubuntu)',
                'X-Frame-Options': 'DENY',
                'X-Content-Type-Options': 'nosniff'
            },
            'fingerprint_matches': [
                'Server header indicates Apache with ModSecurity',
                'Security headers suggest WAF protection'
            ]
        }
        
        # 模拟智能检测（Part3功能）
        ml_results = {
            'detection_model': 'CNN-LSTM',
            'confidence': 0.89,
            'predicted_attack_types': [
                {'type': 'SQL Injection', 'confidence': 0.78},
                {'type': 'XSS', 'confidence': 0.65},
                {'type': 'Path Traversal', 'confidence': 0.52}
            ]
        }
        
        results = {
            'status': 'completed',
            'url': url,
            'fingerprint': fingerprint_results,
            'ml_detection': ml_results
        }
        
        return jsonify(results), 200
        
    except Exception as e:
        logger.error(f"URL分析失败: {str(e)}", exc_info=True)
        return jsonify({'error': str(e)}), 500

@app.route('/api/task/<task_id>', methods=['GET'])
def get_task_status(task_id):
    """获取任务状态"""
    try:
        task = task_manager.get_task(task_id)
        if not task:
            return jsonify({'error': 'Task not found'}), 404
        
        return jsonify({
            'task_id': task_id,
            'status': task['status'],
            'created_at': task['created_at'],
            'updated_at': task.get('updated_at'),
            'results': task.get('results')
        }), 200
        
    except Exception as e:
        logger.error(f"获取任务状态失败: {str(e)}", exc_info=True)
        return jsonify({'error': str(e)}), 500

@app.route('/api/visualization/<image_type>/<task_id>', methods=['GET'])
def get_visualization(image_type, task_id):
    """获取可视化图像"""
    try:
        task = task_manager.get_task(task_id)
        if not task or task['status'] != 'completed':
            return jsonify({'error': 'Task not completed'}), 404
        
        results = task['results']
        if not results or 'visualization_paths' not in results:
            return jsonify({'error': 'Visualization not available'}), 404
        
        if image_type not in results['visualization_paths']:
            return jsonify({'error': 'Invalid image type'}), 400
        
        image_path = results['visualization_paths'][image_type]
        if not os.path.exists(image_path):
            return jsonify({'error': 'Image not found'}), 404
        
        return send_file(image_path, mimetype='image/png')
        
    except Exception as e:
        logger.error(f"获取可视化图像失败: {str(e)}", exc_info=True)
        return jsonify({'error': str(e)}), 500

@app.route('/api/download-report/<task_id>', methods=['GET'])
def download_report(task_id):
    """下载分析报告"""
    try:
        task = task_manager.get_task(task_id)
        if not task or task['status'] != 'completed':
            return jsonify({'error': 'Task not completed'}), 404
        
        results = task['results']
        if not results:
            return jsonify({'error': 'No results available'}), 404
        
        # 创建报告文件
        report_content = json.dumps(results, indent=2, ensure_ascii=False)
        temp_file = tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False, encoding='utf-8')
        temp_file.write(report_content)
        temp_file.close()
        
        return send_file(temp_file.name, as_attachment=True, download_name=f'waf_analysis_report_{task_id}.json')
        
    except Exception as e:
        logger.error(f"下载报告失败: {str(e)}", exc_info=True)
        return jsonify({'error': str(e)}), 500

@app.route('/analysis')
def analysis_page():
    """分析结果页面"""
    task_id = request.args.get('task_id')
    if not task_id:
        return redirect(url_for('index'))
    
    return render_template('analysis.html', task_id=task_id)

@app.route('/ast-visualization/<task_id>')
def ast_visualization_page(task_id):
    """AST可视化页面"""
    return render_template('ast_visualization.html', task_id=task_id)

@app.errorhandler(404)
def not_found(error):
    """404错误处理"""
    return jsonify({'error': 'Not found'}), 404

@app.errorhandler(500)
def server_error(error):
    """500错误处理"""
    return jsonify({'error': 'Internal server error'}), 500

def main():
    """主函数"""
    import argparse
    parser = argparse.ArgumentParser(description='WAF规则分析工具 Web API')
    parser.add_argument('-p', '--port', type=int, default=5000, help='端口号')
    parser.add_argument('-h', '--host', default='0.0.0.0', help='主机地址')
    parser.add_argument('-d', '--debug', action='store_true', help='调试模式')
    
    args = parser.parse_args()
    
    logger.info(f"启动WAF规则分析工具 Web API (端口: {args.port})")
    # 模块顶部已导入 datetime，无需在此处重复导入
    app.run(host=args.host, port=args.port, debug=args.debug, threaded=True)

if __name__ == '__main__':
    main()