#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
语义分析器
对解析后的WAF规则进行语义分析，提取业务意图和安全策略
"""

import re
import logging
import json
from collections import defaultdict

class SemanticAnalyzer:
    """语义分析器"""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.attack_patterns = self._load_attack_patterns()
        self.rule_classification = {
            'sql_injection': [],
            'xss': [],
            'path_traversal': [],
            'command_injection': [],
            'file_upload': [],
            'authentication': [],
            'authorization': [],
            'information_disclosure': [],
            'rate_limiting': [],
            'other': []
        }
    
    def _load_attack_patterns(self):
        """加载攻击模式特征库"""
        return {
            # SQL注入模式
            'sql_injection': {
                'patterns': [
                    r'select.*from',
                    r'insert.*into',
                    r'update.*set',
                    r'delete.*from',
                    r'drop.*table',
                    r'alter.*table',
                    r'create.*table',
                    r'union.*select',
                    r'--',
                    r'#',
                    r';',
                    r'or.*=',
                    r'and.*=',
                    r'exec\(',
                    r'sp_executesql',
                    r'xp_cmdshell',
                    r'@@version',
                    r'db_name\('
                ],
                'variables': ['ARGS', 'ARGS_GET', 'ARGS_POST', 'REQUEST_URI'],
                'confidence': 0.8
            },
            
            # XSS模式
            'xss': {
                'patterns': [
                    r'<script',
                    r'>script<',
                    r'javascript:',
                    r'vbscript:',
                    r'onload=',
                    r'onerror=',
                    r'onclick=',
                    r'<iframe',
                    r'<img.*src=',
                    r'<svg.*onload=',
                    r'data:text/html',
                    r'eval\(',
                    r'alert\(',
                    r'document\.write'
                ],
                'variables': ['ARGS', 'ARGS_GET', 'ARGS_POST', 'REQUEST_URI', 'REQUEST_HEADERS'],
                'confidence': 0.7
            },
            
            # 路径遍历模式
            'path_traversal': {
                'patterns': [
                    r'\.\.',
                    r'\/etc\/passwd',
                    r'\/etc\/shadow',
                    r'\/proc\/',
                    r'c:\\windows\\',
                    r'c:\\winnt\\',
                    r'c:\\inetpub\\',
                    r'\/var\/www\/',
                    r'web\.config',
                    r'app\.config'
                ],
                'variables': ['ARGS', 'REQUEST_URI', 'REQUEST_FILENAME'],
                'confidence': 0.9
            },
            
            # 命令注入模式
            'command_injection': {
                'patterns': [
                    r'\|',
                    r'&',
                    r';',
                    r'&&',
                    r'||',
                    r'`',
                    r'\$\(',
                    r'ping',
                    r'cmd\.exe',
                    r'bash',
                    r'sh',
                    r'cat',
                    r'ls',
                    r'dir',
                    r'rm',
                    r'del',
                    r'mkdir',
                    r'rmdir'
                ],
                'variables': ['ARGS', 'REQUEST_URI'],
                'confidence': 0.7
            }
        }
    
    def analyze_rules(self, parsed_rules):
        """分析规则列表"""
        try:
            self.logger.info(f"开始语义分析，共 {len(parsed_rules)} 条规则")
            
            analysis_results = {
                'rule_count': len(parsed_rules),
                'rule_types': defaultdict(int),
                'attack_types': defaultdict(int),
                'phases_distribution': defaultdict(int),
                'severity_distribution': defaultdict(int),
                'warnings': [],
                'rule_classification': self.rule_classification.copy(),
                'action_summary': defaultdict(int),
                'variable_usage': defaultdict(int)
            }
            
            # 分析每条规则
            for rule in parsed_rules:
                self._analyze_single_rule(rule, analysis_results)
            
            # 生成统计信息
            self._generate_statistics(analysis_results)
            
            self.logger.info("语义分析完成")
            return analysis_results
            
        except Exception as e:
            self.logger.error(f"语义分析失败: {str(e)}", exc_info=True)
            raise
    
    def _analyze_single_rule(self, rule, analysis_results):
        """分析单条规则"""
        # 提取规则信息
        rule.extract_rule_info()
        
        # 更新规则类型统计
        analysis_results['rule_types'][rule.node_type] += 1
        
        # 更新动作统计
        for action in rule.actions:
            analysis_results['action_summary'][action] += 1
        
        # 更新变量使用统计
        for var in rule.variables:
            analysis_results['variable_usage'][var] += 1
        
        # 更新阶段分布
        if rule.phase:
            analysis_results['phases_distribution'][rule.phase] += 1
        
        # 更新严重级别分布
        if rule.severity:
            analysis_results['severity_distribution'][rule.severity] += 1
        
        # 规则分类
        self._classify_rule(rule, analysis_results)
        
        # 安全检查
        self._security_checks(rule, analysis_results)
    
    def _classify_rule(self, rule, analysis_results):
        """规则分类"""
        if rule.node_type != "SecRule":
            return
        
        # 基于模式匹配进行分类
        classified = False
        
        # 检查攻击模式
        for attack_type, pattern_info in self.attack_patterns.items():
            if self._matches_attack_pattern(rule, pattern_info):
                analysis_results['rule_classification'][attack_type].append(rule.get_rule_summary())
                analysis_results['attack_types'][attack_type] += 1
                classified = True
        
        # 如果没有匹配到特定攻击类型，进行其他分类
        if not classified:
            # 基于变量和动作进行分类
            if any(var in ['REMOTE_ADDR', 'REMOTE_PORT'] for var in rule.variables):
                if any(action.startswith('ipMatch') or action.startswith('geo') for action in rule.actions):
                    analysis_results['rule_classification']['authentication'].append(rule.get_rule_summary())
                elif any(action.startswith('setvar:IP.') for action in rule.actions):
                    analysis_results['rule_classification']['rate_limiting'].append(rule.get_rule_summary())
            elif any(var in ['REQUEST_HEADERS:Authorization', 'REQUEST_HEADERS:Cookie'] for var in rule.variables):
                analysis_results['rule_classification']['authentication'].append(rule.get_rule_summary())
            elif any(action.startswith('drop') or action.startswith('deny') for action in rule.actions):
                analysis_results['rule_classification']['authorization'].append(rule.get_rule_summary())
            elif any(var in ['RESPONSE_BODY', 'RESPONSE_HEADERS'] for var in rule.variables):
                analysis_results['rule_classification']['information_disclosure'].append(rule.get_rule_summary())
            elif any(var in ['FILES', 'FILES_NAMES', 'FILES_SIZES'] for var in rule.variables):
                analysis_results['rule_classification']['file_upload'].append(rule.get_rule_summary())
            else:
                analysis_results['rule_classification']['other'].append(rule.get_rule_summary())
    
    def _matches_attack_pattern(self, rule, pattern_info):
        """匹配攻击模式"""
        if not rule.pattern:
            return False
        
        # 检查变量是否在关注的变量列表中
        if pattern_info.get('variables'):
            if not any(var in pattern_info['variables'] for var in rule.variables):
                return False
        
        # 检查模式是否匹配
        pattern_text = rule.pattern.lower()
        for pattern in pattern_info['patterns']:
            if re.search(pattern, pattern_text, re.IGNORECASE):
                return True
        
        return False
    
    def _security_checks(self, rule, analysis_results):
        """安全检查"""
        warnings = []
        
        # 检查规则ID是否存在
        if rule.node_type == "SecRule" and not rule.rule_id:
            warnings.append({
                'type': 'missing_rule_id',
                'severity': 'warning',
                'message': f"规则缺少ID标识 (第{rule.line_num}行)",
                'rule': rule.get_rule_summary()
            })
        
        # 检查链式规则是否正确配置
        if rule.is_chain and not rule.rule_id:
            warnings.append({
                'type': 'chain_rule_without_id',
                'severity': 'error',
                'message': f"链式规则缺少ID标识 (第{rule.line_num}行)",
                'rule': rule.get_rule_summary()
            })
        
        # 检查是否有冲突的动作
        if 'deny' in rule.actions and 'pass' in rule.actions:
            warnings.append({
                'type': 'conflicting_actions',
                'severity': 'error',
                'message': f"规则同时包含deny和pass动作 (第{rule.line_num}行)",
                'rule': rule.get_rule_summary()
            })
        
        # 检查是否缺少日志动作
        if ('deny' in rule.actions or 'drop' in rule.actions) and 'log' not in rule.actions:
            warnings.append({
                'type': 'missing_log_action',
                'severity': 'warning',
                'message': f"阻断规则缺少log动作 (第{rule.line_num}行)",
                'rule': rule.get_rule_summary()
            })
        
        # 检查是否使用了危险的正则表达式
        if rule.pattern and ('(.*)' in rule.pattern or '(.+)' in rule.pattern):
            if any(var in ['ARGS', 'REQUEST_URI'] for var in rule.variables):
                warnings.append({
                    'type': 'dangerous_regex',
                    'severity': 'warning',
                    'message': f"规则使用了贪婪匹配的正则表达式 (第{rule.line_num}行)",
                    'rule': rule.get_rule_summary()
                })
        
        # 添加警告信息
        if warnings:
            analysis_results['warnings'].extend(warnings)
            for warning in warnings:
                self.logger.warning(f"安全检查警告: {warning['message']}")
    
    def _generate_statistics(self, analysis_results):
        """生成统计信息"""
        # 计算各类规则的百分比
        total_rules = analysis_results['rule_count']
        if total_rules > 0:
            for attack_type in analysis_results['attack_types']:
                count = analysis_results['attack_types'][attack_type]
                percentage = (count / total_rules) * 100
                analysis_results['attack_types'][f"{attack_type}_percentage"] = round(percentage, 2)
    
    def generate_report(self, analysis_results, output_path):
        """生成语义分析报告"""
        try:
            report = {
                'semantic_analysis_report': {
                    'summary': {
                        'total_rules': analysis_results['rule_count'],
                        'rule_types': dict(analysis_results['rule_types']),
                        'attack_types': dict(analysis_results['attack_types']),
                        'top_variables': dict(sorted(analysis_results['variable_usage'].items(), 
                                                  key=lambda x: x[1], reverse=True)[:5]),
                        'top_actions': dict(sorted(analysis_results['action_summary'].items(), 
                                                 key=lambda x: x[1], reverse=True)[:5])
                    },
                    'rule_classification': {
                        attack_type: len(rules) for attack_type, rules in 
                        analysis_results['rule_classification'].items()
                    },
                    'warnings': analysis_results['warnings'],
                    'details': analysis_results
                }
            }
            
            with open(output_path, 'w', encoding='utf-8') as f:
                json.dump(report, f, indent=2, ensure_ascii=False)
            
            self.logger.info(f"语义分析报告已保存到: {output_path}")
            return output_path
            
        except Exception as e:
            self.logger.error(f"生成报告失败: {str(e)}", exc_info=True)
            raise

def main():
    """测试主函数"""
    import argparse
    from part2_rule_analysis.lib.parser.modsecurity_parser import ModSecurityParser
    
    parser = argparse.ArgumentParser(description='语义分析器测试')
    parser.add_argument('file', help='ModSecurity规则文件路径')
    
    args = parser.parse_args()
    
    # 设置日志
    logging.basicConfig(level=logging.INFO)
    
    try:
        # 解析规则文件
        parser = ModSecurityParser()
        rules = parser.parse_file(args.file)
        
        if not rules:
            print("没有解析到任何规则")
            return
        
        # 进行语义分析
        analyzer = SemanticAnalyzer()
        results = analyzer.analyze_rules(rules)
        
        # 显示结果摘要
        print(f"\n=== 语义分析结果摘要 ===")
        print(f"总规则数量: {results['rule_count']}")
        print(f"规则类型分布: {dict(results['rule_types'])}")
        print(f"攻击类型分布: {dict(results['attack_types'])}")
        print(f"警告数量: {len(results['warnings'])}")
        
        # 保存详细报告
        analyzer.generate_report(results, 'semantic_analysis_report.json')
        print(f"\n详细报告已保存到: semantic_analysis_report.json")
        
    except Exception as e:
        print(f"分析失败: {str(e)}")

if __name__ == '__main__':
    main()