"""
规则分析模块实现
实现RuleAnalysisInterface接口，封装Part2 analysis的功能
"""

import os
import sys
import json
from typing import Dict, List, Optional, Any, Tuple

# 添加Part2 analysis 2.0到Python路径
sys.path.append(os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 
                            'Part2 analysis', 'part2_rule_analysis', '2.0'))

try:
    from backend.rule_parser import RuleParser
    from backend.semantic_analyzer import SemanticAnalyzer
    from backend.dependency_analyzer import DependencyAnalyzer
    from backend.conflict_analyzer import ConflictAnalyzer
    from backend.database import RuleDatabase
    HAS_PART2_BACKEND = True
except ImportError as e:
    print(f"无法导入Part2 analysis 2.0后端模块: {e}")
    HAS_PART2_BACKEND = False

from backend.api_interface import RuleAnalysisInterface


class RuleAnalysisImplementation(RuleAnalysisInterface):
    """规则分析模块的具体实现"""
    
    def __init__(self):
        self.config = {
            'rules_dir': os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 
                                    'Part2 analysis', 'coreruleset-main', 'rules'),
            'db_path': os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 
                                  'Part2 analysis', 'part2_rule_analysis', '2.0', 'rules.db')
        }
        self.initialized = False
        self.rules = []  # 存储规则信息
        self.rules_count = 0
        self.rules_by_file = {}
        
        # 初始化Part2 analysis 2.0组件
        if HAS_PART2_BACKEND:
            try:
                self.rule_parser = RuleParser()
                self.semantic_analyzer = SemanticAnalyzer()
                self.dependency_analyzer = DependencyAnalyzer()
                self.conflict_analyzer = ConflictAnalyzer()
                self.database = RuleDatabase(self.config['db_path'])
                self.part2_available = True
            except Exception as e:
                print(f"初始化Part2 analysis 2.0组件失败: {e}")
                self.part2_available = False
        else:
            self.part2_available = False
    
    def initialize(self, config: Dict[str, Any] = None) -> bool:
        """初始化分析模块
        
        Args:
            config: 配置参数
            
        Returns:
            bool: 初始化是否成功
        """
        try:
            # 更新配置
            if config:
                self.config.update(config)
            
            # 验证规则目录是否存在
            if not os.path.exists(self.config['rules_dir']):
                print(f"规则目录不存在: {self.config['rules_dir']}")
                return False
            
            # 加载规则文件
            self.load_rules()
            
            self.initialized = True
            return True
            
        except Exception as e:
            print(f"初始化分析模块失败: {e}")
            self.initialized = False
            return False
    
    def load_rules(self, rules_dir: str = None) -> int:
        """加载规则文件并使用Part2 analysis 2.0进行分析
        
        Args:
            rules_dir: 规则目录路径
            
        Returns:
            int: 成功加载的规则数量
        """
        rules_dir = rules_dir or self.config['rules_dir']
        
        # 重置规则计数器
        self.rules = []
        self.rules_count = 0
        self.rules_by_file = {}
        
        try:
            # 如果Part2 analysis 2.0可用，使用它来解析规则
            if self.part2_available:
                # 遍历规则目录中的所有.conf和.conf.example文件
                for filename in os.listdir(rules_dir):
                    if filename.endswith('.conf') or filename.endswith('.conf.example'):
                        file_path = os.path.join(rules_dir, filename)
                        
                        try:
                            # 读取文件内容
                            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                                content = f.read()
                            
                            # 使用Part2 analysis 2.0解析规则
                            parse_result = self.rule_parser.parse_content(content)
                            
                            # 进行语义分析
                            rules = parse_result.get('rules', [])
                            rules = self.semantic_analyzer.batch_analyze(rules)
                            
                            # 进行依赖分析
                            rules = self.dependency_analyzer.batch_analyze(rules)
                            
                            # 进行冲突分析
                            conflicts = self.conflict_analyzer.batch_analyze(rules)
                            
                            # 将规则插入数据库
                            self.database.batch_insert(rules, parse_result.get('parse_status', ''), [content])
                            
                            # 统计每个文件的规则数
                            self.rules_by_file[filename] = {
                                'total': len(rules),
                                'conflicts': len(conflicts),
                                'parse_status': parse_result.get('parse_status', '')
                            }
                            
                            # 添加规则到内部存储
                            for rule in rules:
                                self.rules.append({
                                    'id': rule.get('rule_info', {}).get('id', ''),
                                    'type': rule.get('rule_info', {}).get('type', ''),
                                    'file': filename,
                                    'content': rule.get('rule_info', {}).get('raw_rule', ''),
                                    'rule_data': rule
                                })
                                
                        except Exception as e:
                            print(f"处理规则文件失败 {filename}: {e}")
                            # 即使某个文件处理失败，也继续处理其他文件
                            continue
            else:
                # 如果Part2 analysis 2.0不可用，使用原有方法
                # 遍历规则目录中的所有.conf和.conf.example文件
                for filename in os.listdir(rules_dir):
                    if filename.endswith('.conf') or filename.endswith('.conf.example'):
                        file_path = os.path.join(rules_dir, filename)
                        file_rules = []
                        
                        try:
                            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                                content = f.read()
                                
                                # 解析文件中的规则
                                rule_lines = content.split('\n')
                                for line_num, line in enumerate(rule_lines, 1):
                                    line = line.strip()
                                    if line.startswith('SecRule') or line.startswith('SecAction'):
                                        rule_info = {
                                            'id': f"{filename}:{line_num}",
                                            'type': 'SecRule' if 'SecRule' in line else 'SecAction',
                                            'file': filename,
                                            'content': line,
                                            'line_number': line_num
                                        }
                                        
                                        # 尝试提取规则ID（如果存在）
                                        rule_id_match = None
                                        if 'id:' in line:
                                            # 更准确地提取ID
                                            import re
                                            id_pattern = r'id\s*:\s*["\']?(\d+)["\']?'
                                            match = re.search(id_pattern, line)
                                            if match:
                                                rule_id_match = match.group(1)
                                                rule_info['rule_id'] = rule_id_match
                                        
                                        file_rules.append(rule_info)
                                        self.rules.append(rule_info)
                        
                        except Exception as e:
                            print(f"读取规则文件失败 {filename}: {e}")
                        
                        # 统计每个文件的规则数
                        self.rules_by_file[filename] = {
                            'total': len(file_rules),
                            'secrule': len([r for r in file_rules if r['type'] == 'SecRule']),
                            'secaction': len([r for r in file_rules if r['type'] == 'SecAction'])
                        }
            
            self.rules_count = len(self.rules)
            return self.rules_count
            
        except Exception as e:
            print(f"加载规则失败: {e}")
            return 0
    
    def analyze_request(self, request_data: Dict[str, Any]) -> Dict[str, Any]:
        """分析HTTP请求是否符合规则
        
        Args:
            request_data: HTTP请求数据，包含method, url, headers, body等
            
        Returns:
            Dict[str, Any]: 分析结果
        """
        if not self.initialized:
            return {'error': '模块未初始化'}
        
        try:
            # 如果Part2 analysis 2.0可用，使用数据库中的规则进行分析
            if self.part2_available:
                # 获取所有规则
                all_rules = self.database.get_all_rules()
                
                # 这里应该实现更复杂的规则匹配逻辑
                # 目前简化处理，仅返回规则统计信息
                matched_rules = []
                for rule in all_rules:
                    # 示例匹配逻辑
                    rule_info = rule.get('rule_info', {})
                    rule_id = rule_info.get('id', '')
                    if rule_id:
                        matched_rules.append({
                            'rule_id': rule_id,
                            'severity': rule_info.get('severity', 'unknown'),
                            'phase': rule_info.get('phase', 'unknown'),
                            'message': rule_info.get('msg', '')
                        })
                
                # 确定风险级别
                risk_level = 'Low'
                if len(matched_rules) > 0:
                    risk_level = 'Medium'
                
                return {
                    'matched_rules': matched_rules[:10],  # 限制返回数量
                    'matched_count': len(matched_rules),
                    'risk_level': risk_level,
                    'analysis_completed': True
                }
            else:
                # 使用原有的简化分析逻辑
                matched_rules = []
                
                # 获取请求信息
                method = request_data.get('method', 'GET').upper()
                url = request_data.get('url', '')
                headers = request_data.get('headers', {})
                body = request_data.get('body', '')
                
                # 检查常见的安全问题（简化示例）
                request_text = f"{method} {url} {body}"
                
                # 检查SQL注入特征
                sql_patterns = ['select.*from', 'insert.*into', 'update.*set', 'delete.*from', 
                              'drop table', 'union select', "' or '1'='1"]
                for pattern in sql_patterns:
                    if pattern in request_text.lower():
                        matched_rules.append({
                            'category': 'SQL Injection',
                            'severity': 'High',
                            'matched_text': pattern
                        })
                
                # 检查XSS特征
                xss_patterns = ['<script', 'javascript:', 'onerror=', 'onload=', 'onclick=']
                for pattern in xss_patterns:
                    if pattern in request_text.lower():
                        matched_rules.append({
                            'category': 'XSS',
                            'severity': 'High',
                            'matched_text': pattern
                        })
                
                # 确定风险级别
                risk_level = 'Low'
                if len(matched_rules) > 0:
                    high_severity_count = sum(1 for r in matched_rules if r['severity'] == 'High')
                    if high_severity_count > 0:
                        risk_level = 'High'
                    else:
                        risk_level = 'Medium'
                
                return {
                    'matched_rules': matched_rules,
                    'matched_count': len(matched_rules),
                    'risk_level': risk_level,
                    'analysis_completed': True
                }
            
        except Exception as e:
            return {'error': str(e), 'matched_rules': []}
    
    def get_rule_statistics(self) -> Dict[str, int]:
        """获取规则统计信息
        
        Returns:
            Dict[str, int]: 规则统计数据
        """
        if not self.initialized:
            return {'error': '模块未初始化'}
        
        try:
            if self.part2_available:
                # 使用Part2 analysis 2.0数据库获取统计信息
                all_rules = self.database.get_all_rules()
                
                total_secrule = len([r for r in all_rules if r.get('rule_info', {}).get('type') == 'SecRule'])
                total_secaction = len([r for r in all_rules if r.get('rule_info', {}).get('type') == 'SecAction'])
                
                # 获取冲突信息
                conflicts = []
                for rule in all_rules:
                    # 这里应该调用冲突分析器重新分析或者从数据库获取冲突信息
                    pass
                
                return {
                    'total_rules': len(all_rules),
                    'secrule_count': total_secrule,
                    'secaction_count': total_secaction,
                    'file_count': len(self.rules_by_file),
                    'avg_rules_per_file': round(len(all_rules) / len(self.rules_by_file), 2) if self.rules_by_file else 0
                }
            else:
                # 使用原有的统计方法
                total_secrule = sum(stats.get('secrule', 0) for stats in self.rules_by_file.values())
                total_secaction = sum(stats.get('secaction', 0) for stats in self.rules_by_file.values())
                
                return {
                    'total_rules': self.rules_count,
                    'secrule_count': total_secrule,
                    'secaction_count': total_secaction,
                    'file_count': len(self.rules_by_file),
                    'avg_rules_per_file': round(self.rules_count / len(self.rules_by_file), 2) if self.rules_by_file else 0
                }
        except Exception as e:
            print(f"获取规则统计信息失败: {e}")
            return {'error': str(e)}
    
    def search_rules(self, query: str, filters: Dict[str, Any] = None) -> List[Dict[str, Any]]:
        """搜索规则
        
        Args:
            query: 搜索关键词
            filters: 过滤条件，如rule_type, severity等
            
        Returns:
            List[Dict[str, Any]]: 匹配的规则列表
        """
        if not self.initialized:
            return []
        
        try:
            if self.part2_available:
                # 使用Part2 analysis 2.0数据库搜索规则
                all_rules = self.database.get_all_rules()
                results = []
                
                for rule in all_rules:
                    rule_info = rule.get('rule_info', {})
                    rule_id = rule_info.get('id', '')
                    rule_type = rule_info.get('type', '')
                    raw_rule = rule_info.get('raw_rule', '')
                    
                    # 检查查询关键词
                    if query:
                        if (query.lower() not in str(rule_id).lower() and 
                            query.lower() not in str(rule_type).lower() and
                            query.lower() not in str(raw_rule).lower()):
                            continue
                    
                    # 应用过滤器
                    match_filter = True
                    if filters:
                        # 规则类型过滤
                        if 'rule_type' in filters and rule_type != filters['rule_type']:
                            match_filter = False
                        
                        # 严重性过滤
                        if 'severity' in filters:
                            severity = rule_info.get('severity', '')
                            if severity != filters['severity']:
                                match_filter = False
                    
                    if match_filter:
                        results.append({
                            'id': rule_id,
                            'type': rule_type,
                            'content': raw_rule,
                            'rule_data': rule
                        })
                
                return results
            else:
                # 使用原有的搜索方法
                results = []
                
                for rule in self.rules:
                    # 检查查询关键词
                    if query and query.lower() not in str(rule).lower():
                        continue
                    
                    # 应用过滤器
                    match_filter = True
                    if filters:
                        # 规则类型过滤
                        if 'rule_type' in filters and rule['type'] != filters['rule_type']:
                            match_filter = False
                        
                        # 文件过滤
                        if 'file' in filters and rule['file'] != filters['file']:
                            match_filter = False
                        
                        # 规则ID过滤
                        if 'rule_id' in filters and 'rule_id' in rule and rule['rule_id'] != filters['rule_id']:
                            match_filter = False
                    
                    if match_filter:
                        results.append(rule)
                
                return results
            
        except Exception as e:
            print(f"搜索规则失败: {e}")
            return []
    
    def get_status(self) -> Dict[str, Any]:
        """获取模块状态
        
        Returns:
            Dict[str, Any]: 状态信息
        """
        stats = self.get_rule_statistics() if self.initialized else {}
        
        return {
            'initialized': self.initialized,
            'part2_available': self.part2_available,
            'config': self.config,
            'rules_loaded': len(self.rules),
            'statistics': stats
        }