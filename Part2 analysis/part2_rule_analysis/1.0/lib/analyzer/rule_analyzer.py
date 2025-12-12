#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
规则分析器
用于分析ModSecurity规则，提取变量、操作符、动作等信息
"""

import os
import sys
import logging
from typing import List, Dict, Any
from pathlib import Path

# 添加解析器路径
current_dir = os.path.dirname(os.path.abspath(__file__))
parser_path = os.path.join(current_dir, '..', 'parser')
parser_path = os.path.normpath(parser_path)

if parser_path not in sys.path:
    sys.path.insert(0, parser_path)

# 导入新的解析器
try:
    from modsecurity_parser import parse_file
    from rule_node import RuleNode
except ImportError as e:
    print(f"导入解析器失败: {e}")
    # 尝试备用导入方法
    import importlib.util
    parser_init = os.path.join(parser_path, '__init__.py')
    spec = importlib.util.spec_from_file_location("parser_module", parser_init)
    parser_module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(parser_module)
    parse_file = getattr(parser_module, "parse_modsecurity_file")

logger = logging.getLogger(__name__)

class RuleAnalyzer:
    """规则分析器类"""
    
    def __init__(self):
        self.rules = []
        self.stats = {
            'total_rules': 0,
            'rules_with_chains': 0,
            'unique_ids': set(),
            'operators': {},
            'variables': {},
            'actions': {}
        }
    
    def analyze_file(self, file_path: str) -> List[Dict[str, Any]]:
        """分析单个规则文件
        
        Args:
            file_path: 规则文件路径
            
        Returns:
            解析后的规则列表
        """
        try:
            logger.info(f"开始分析规则文件: {file_path}")
            
            # 使用新的解析器解析文件
            parsed_rules = parse_file(file_path)
            
            # 转换为字典格式
            rules_data = []
            for rule in parsed_rules:
                if hasattr(rule, 'jsonify_rule'):
                    # 如果是SecRule对象
                    rule_data = rule.jsonify_rule()
                else:
                    # 如果已经是RuleNode对象
                    rule_data = rule.to_dict()
                rules_data.append(rule_data)
            
            self._update_stats(rules_data)
            self.rules.extend(rules_data)
            
            logger.info(f"成功分析文件 {file_path}，共 {len(rules_data)} 条规则")
            return rules_data
            
        except Exception as e:
            logger.error(f"分析文件 {file_path} 失败: {e}", exc_info=True)
            raise
    
    def analyze_directory(self, dir_path: str) -> List[Dict[str, Any]]:
        """分析目录下的所有规则文件
        
        Args:
            dir_path: 规则文件目录路径
            
        Returns:
            解析后的规则列表
        """
        all_rules = []
        
        # 查找所有.conf文件
        conf_files = Path(dir_path).glob("*.conf")
        
        for conf_file in conf_files:
            try:
                rules = self.analyze_file(str(conf_file))
                all_rules.extend(rules)
            except Exception as e:
                logger.error(f"分析文件 {conf_file} 失败: {e}")
        
        return all_rules
    
    def _update_stats(self, rules_data: List[Dict[str, Any]]):
        """更新统计信息
        
        Args:
            rules_data: 规则数据列表
        """
        for rule_data in rules_data:
            self.stats['total_rules'] += 1
            
            # 统计唯一ID
            rule_id = self._extract_rule_id(rule_data)
            if rule_id:
                self.stats['unique_ids'].add(rule_id)
            
            # 统计操作符
            operator = rule_data.get('operator', '')
            if operator:
                self.stats['operators'][operator] = self.stats['operators'].get(operator, 0) + 1
            
            # 统计变量
            variables = rule_data.get('variable', [])
            if isinstance(variables, str):
                variables = [variables]
            for var in variables:
                if var:
                    self.stats['variables'][var] = self.stats['variables'].get(var, 0) + 1
            
            # 统计动作
            actions = rule_data.get('action', [])
            if isinstance(actions, str):
                actions = [actions]
            for action in actions:
                if action:
                    self.stats['actions'][action] = self.stats['actions'].get(action, 0) + 1
            
            # 检查是否有链式规则
            if 'chain_rule' in rule_data and rule_data['chain_rule']:
                self.stats['rules_with_chains'] += 1
    
    def _extract_rule_id(self, rule_data: Dict[str, Any]) -> str:
        """从规则数据中提取规则ID
        
        Args:
            rule_data: 规则数据字典
            
        Returns:
            规则ID字符串
        """
        actions = rule_data.get('action', [])
        if isinstance(actions, str):
            actions = [actions]
        
        for action in actions:
            if action.startswith('id:'):
                return action[3:]  # 移除'id:'前缀
        return ''
    
    def get_statistics(self) -> Dict[str, Any]:
        """获取分析统计信息
        
        Returns:
            统计信息字典
        """
        stats = self.stats.copy()
        stats['unique_ids'] = len(stats['unique_ids'])
        return stats
    
    def export_to_json(self, output_file: str):
        """导出规则数据到JSON文件
        
        Args:
            output_file: 输出文件路径
        """
        import json
        
        try:
            with open(output_file, 'w', encoding='utf-8') as f:
                json.dump(self.rules, f, ensure_ascii=False, indent=2)
            logger.info(f"规则数据已导出到 {output_file}")
        except Exception as e:
            logger.error(f"导出规则数据失败: {e}", exc_info=True)
            raise

def main():
    """主函数，用于命令行调用"""
    import argparse
    
    parser = argparse.ArgumentParser(description='ModSecurity规则分析器')
    parser.add_argument('--file', '-f', help='要分析的规则文件路径')
    parser.add_argument('--dir', '-d', help='要分析的规则目录路径')
    parser.add_argument('--output', '-o', help='输出JSON文件路径')
    parser.add_argument('--stats', '-s', action='store_true', help='显示统计信息')
    
    args = parser.parse_args()
    
    analyzer = RuleAnalyzer()
    
    try:
        if args.file:
            rules = analyzer.analyze_file(args.file)
        elif args.dir:
            rules = analyzer.analyze_directory(args.dir)
        else:
            parser.print_help()
            return
        
        if args.stats:
            stats = analyzer.get_statistics()
            print("规则分析统计信息:")
            print(f"  总规则数: {stats['total_rules']}")
            print(f"  唯一ID数: {stats['unique_ids']}")
            print(f"  链式规则数: {stats['rules_with_chains']}")
            print(f"  不同操作符数: {len(stats['operators'])}")
            print(f"  不同变量数: {len(stats['variables'])}")
            print(f"  不同动作数: {len(stats['actions'])}")
        
        if args.output:
            analyzer.export_to_json(args.output)
            print(f"规则数据已导出到 {args.output}")
            
    except Exception as e:
        print(f"分析过程中出现错误: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()