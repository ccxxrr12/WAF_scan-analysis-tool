#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
WAF规则智能识别与分析工具 - Part2: 规则解析与语法分析
主程序入口
"""

import os
import sys
import logging
import argparse
from pathlib import Path

# 设置项目根目录
PROJECT_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from common.utils.log_utils import setup_logger
from part2_rule_analysis.lib.parser.modsecurity_parser import ModSecurityParser
from part2_rule_analysis.lib.analyzer.semantic_analyzer import SemanticAnalyzer
from part2_rule_analysis.lib.analyzer.dependency_analyzer import DependencyAnalyzer
from part2_rule_analysis.lib.analyzer.conflict_analyzer import ConflictAnalyzer
from part2_rule_analysis.lib.visualizer.ast_visualizer import ASTVisualizer

class WAFRuleAnalyzer:
    """WAF规则分析器主类"""
    
    def __init__(self, config=None):
        """初始化分析器"""
        self.config = config or {}
        self.logger = setup_logger('WAFRuleAnalyzer', log_level=self.config.get('log_level', 'INFO'))
        
        # 初始化各个组件
        self.parser = ModSecurityParser()
        self.semantic_analyzer = SemanticAnalyzer()
        self.dependency_analyzer = DependencyAnalyzer()
        self.conflict_analyzer = ConflictAnalyzer()
        self.ast_visualizer = ASTVisualizer()
        
        self.analysis_results = {
            'parsed_rules': [],
            'semantic_analysis': {},
            'dependencies': [],
            'conflicts': [],
            'ast': None
        }
    
    def analyze_file(self, file_path):
        """分析单个规则文件"""
        try:
            self.logger.info(f"开始分析规则文件: {file_path}")
            
            # 1. 语法解析
            self.logger.info("正在进行语法解析...")
            parsed_rules = self.parser.parse_file(file_path)
            self.analysis_results['parsed_rules'] = parsed_rules
            
            if not parsed_rules:
                self.logger.warning("未解析到任何规则")
                return self.analysis_results
            
            # 2. 语义分析
            self.logger.info("正在进行语义分析...")
            semantic_result = self.semantic_analyzer.analyze_rules(parsed_rules)
            self.analysis_results['semantic_analysis'] = semantic_result
            
            # 3. 依赖关系分析
            self.logger.info("正在分析规则依赖关系...")
            dependencies = self.dependency_analyzer.analyze_dependencies(parsed_rules)
            self.analysis_results['dependencies'] = dependencies
            
            # 4. 冲突检测
            self.logger.info("正在检测规则冲突...")
            conflicts = self.conflict_analyzer.detect_conflicts(parsed_rules)
            self.analysis_results['conflicts'] = conflicts
            
            # 5. 生成AST
            self.logger.info("正在生成抽象语法树...")
            ast_root = self.ast_visualizer.build_ast(parsed_rules)
            self.analysis_results['ast'] = ast_root
            
            self.logger.info("规则分析完成")
            return self.analysis_results
            
        except Exception as e:
            self.logger.error(f"规则分析失败: {str(e)}", exc_info=True)
            raise
    
    def analyze_content(self, content):
        """分析规则内容"""
        try:
            self.logger.info("开始分析规则内容")
            
            # 1. 语法解析
            parsed_rules = self.parser.parse_content(content)
            self.analysis_results['parsed_rules'] = parsed_rules
            
            if not parsed_rules:
                self.logger.warning("未解析到任何规则")
                return self.analysis_results
            
            # 2. 语义分析
            semantic_result = self.semantic_analyzer.analyze_rules(parsed_rules)
            self.analysis_results['semantic_analysis'] = semantic_result
            
            # 3. 依赖关系分析
            dependencies = self.dependency_analyzer.analyze_dependencies(parsed_rules)
            self.analysis_results['dependencies'] = dependencies
            
            # 4. 冲突检测
            conflicts = self.conflict_analyzer.detect_conflicts(parsed_rules)
            self.analysis_results['conflicts'] = conflicts
            
            # 5. 生成AST
            ast_root = self.ast_visualizer.build_ast(parsed_rules)
            self.analysis_results['ast'] = ast_root
            
            self.logger.info("规则内容分析完成")
            return self.analysis_results
            
        except Exception as e:
            self.logger.error(f"规则内容分析失败: {str(e)}", exc_info=True)
            raise
    
    def save_visualization(self, output_dir):
        """保存可视化结果"""
        try:
            os.makedirs(output_dir, exist_ok=True)
            
            # 保存AST可视化
            if self.analysis_results['ast']:
                ast_path = os.path.join(output_dir, 'ast.png')
                self.ast_visualizer.save_ast_image(self.analysis_results['ast'], ast_path)
                self.logger.info(f"AST可视化已保存到: {ast_path}")
            
            # 保存依赖关系图
            if self.analysis_results['dependencies']:
                dep_path = os.path.join(output_dir, 'dependencies.png')
                self.dependency_analyzer.save_dependency_graph(
                    self.analysis_results['dependencies'], dep_path)
                self.logger.info(f"依赖关系图已保存到: {dep_path}")
            
            return output_dir
            
        except Exception as e:
            self.logger.error(f"保存可视化结果失败: {str(e)}", exc_info=True)
            raise

def main():
    """主函数"""
    parser = argparse.ArgumentParser(description='WAF规则解析与语法分析工具')
    parser.add_argument('input', help='输入文件路径或URL')
    parser.add_argument('-o', '--output', help='输出目录', default='./output')
    parser.add_argument('-l', '--log-level', help='日志级别', choices=['DEBUG', 'INFO', 'WARNING', 'ERROR'], default='INFO')
    
    args = parser.parse_args()
    
    try:
        # 初始化分析器
        analyzer = WAFRuleAnalyzer({
            'log_level': args.log_level
        })
        
        # 分析文件
        results = analyzer.analyze_file(args.input)
        
        # 保存结果
        analyzer.save_visualization(args.output)
        
        # 输出摘要信息
        print(f"\n=== 分析结果摘要 ===")
        print(f"解析规则数量: {len(results['parsed_rules'])}")
        print(f"语义分析警告: {len(results['semantic_analysis'].get('warnings', []))}")
        print(f"依赖关系数量: {len(results['dependencies'])}")
        print(f"冲突规则数量: {len(results['conflicts'])}")
        
        if results['conflicts']:
            print(f"\n发现冲突规则:")
            for conflict in results['conflicts'][:5]:  # 只显示前5个
                print(f"  - {conflict['type']}: {conflict['description']}")
        
        print(f"\n详细结果已保存到: {args.output}")
        
    except KeyboardInterrupt:
        print("\n程序被用户中断")
    except Exception as e:
        print(f"程序执行失败: {str(e)}")
        sys.exit(1)

if __name__ == '__main__':
    main()