#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
冲突分析器
检测WAF规则之间的冲突，包括逻辑冲突、优先级冲突和覆盖冲突
"""

import re
import logging
import operator
from collections import defaultdict

class ConflictAnalyzer:
    """冲突分析器"""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.conflicts = []
        self.rule_index = defaultdict(list)  # 规则索引：(变量, 阶段) -> [规则列表]
    
    def detect_conflicts(self, parsed_rules):
        """检测规则冲突"""
        try:
            self.logger.info(f"开始检测规则冲突，共 {len(parsed_rules)} 条规则")
            
            # 重置状态
            self.conflicts = []
            self.rule_index = defaultdict(list)
            
            # 建立规则索引
            self._build_rule_index(parsed_rules)
            
            # 检测各类冲突
            self._detect_logic_conflicts()
            self._detect_coverage_conflicts()
            self._detect_priority_conflicts(parsed_rules)
            
            self.logger.info(f"冲突检测完成，发现 {len(self.conflicts)} 个冲突")
            return self.conflicts
            
        except Exception as e:
            self.logger.error(f"冲突检测失败: {str(e)}", exc_info=True)
            raise
    
    def _build_rule_index(self, parsed_rules):
        """建立规则索引"""
        for rule in parsed_rules:
            if rule.node_type != "SecRule":
                continue
                
            rule.extract_rule_info()
            
            # 为每个变量和阶段组合建立索引
            for var in rule.variables:
                phase = rule.phase or 'default'
                key = (var, phase)
                self.rule_index[key].append(rule)
    
    def _detect_logic_conflicts(self):
        """检测逻辑冲突"""
        self.logger.info("正在检测逻辑冲突...")
        
        # 定义冲突的动作对
        conflicting_actions = [
            ('deny', 'pass'),
            ('deny', 'allow'),
            ('drop', 'pass'),
            ('drop', 'allow'),
            ('pass', 'deny'),
            ('pass', 'drop'),
            ('allow', 'deny'),
            ('allow', 'drop')
        ]
        
        for (var, phase), rules in self.rule_index.items():
            if len(rules) < 2:
                continue
                
            # 检查每对规则
            for i in range(len(rules)):
                for j in range(i + 1, len(rules)):
                    rule1 = rules[i]
                    rule2 = rules[j]
                    
                    # 检查是否有冲突的动作
                    for action1 in rule1.actions:
                        for action2 in rule2.actions:
                            action1_base = action1.split(':')[0]
                            action2_base = action2.split(':')[0]
                            
                            if (action1_base, action2_base) in conflicting_actions:
                                # 检查规则是否可能同时匹配
                                if self._rules_may_overlap(rule1, rule2):
                                    conflict = {
                                        'type': 'logical_conflict',
                                        'severity': 'high',
                                        'rule1_id': rule1.rule_id or f"rule_{rule1.line_num}",
                                        'rule2_id': rule2.rule_id or f"rule_{rule2.line_num}",
                                        'rule1_line': rule1.line_num,
                                        'rule2_line': rule2.line_num,
                                        'conflicting_actions': [action1, action2],
                                        'description': f"规则 {rule1.rule_id} 和 {rule2.rule_id} 在变量 {var} 和阶段 {phase} 上有冲突的动作: {action1} vs {action2}",
                                        'recommendation': "检查规则的匹配条件和动作优先级，确保防护逻辑的一致性"
                                    }
                                    self.conflicts.append(conflict)
    
    def _detect_coverage_conflicts(self):
        """检测覆盖冲突"""
        self.logger.info("正在检测覆盖冲突...")
        
        for (var, phase), rules in self.rule_index.items():
            if len(rules) < 2:
                continue
                
            # 按规则ID排序，确保稳定的比较顺序
            rules_sorted = sorted(rules, key=lambda x: x.rule_id or f"rule_{x.line_num}")
            
            for i in range(len(rules_sorted)):
                for j in range(i + 1, len(rules_sorted)):
                    rule1 = rules_sorted[i]
                    rule2 = rules_sorted[j]
                    
                    # 检查规则2是否完全覆盖规则1
                    if self._rule_covers_another(rule2, rule1):
                        # 检查动作是否不同
                        if self._actions_are_different(rule1, rule2):
                            conflict = {
                                'type': 'coverage_conflict',
                                'severity': 'medium',
                                'rule1_id': rule1.rule_id or f"rule_{rule1.line_num}",
                                'rule2_id': rule2.rule_id or f"rule_{rule2.line_num}",
                                'rule1_line': rule1.line_num,
                                'rule2_line': rule2.line_num,
                                'description': f"规则 {rule2.rule_id} 的匹配范围覆盖了规则 {rule1.rule_id}，但动作不同",
                                'recommendation': "缩小规则2的匹配范围，或者调整规则执行顺序"
                            }
                            self.conflicts.append(conflict)
    
    def _detect_priority_conflicts(self, parsed_rules):
        """检测优先级冲突"""
        self.logger.info("正在检测优先级冲突...")
        
        # 按行号排序规则
        rules_sorted = sorted(parsed_rules, key=lambda x: x.line_num)
        
        # 检查链式规则
        chain_stack = []
        for rule in rules_sorted:
            if rule.node_type != "SecRule":
                continue
                
            rule.extract_rule_info()
            
            if rule.is_chain:
                if not chain_stack:
                    # 没有开始的链式规则，却有chain动作
                    conflict = {
                        'type': 'priority_conflict',
                        'severity': 'error',
                        'rule_id': rule.rule_id or f"rule_{rule.line_num}",
                        'line': rule.line_num,
                        'description': f"链式规则 {rule.rule_id} 没有对应的起始规则",
                        'recommendation': "在链式规则前添加主规则，或者移除chain动作"
                    }
                    self.conflicts.append(conflict)
                else:
                    chain_stack.append(rule)
            else:
                # 检查是否有未结束的链式规则
                if chain_stack and not rule.is_chain:
                    conflict = {
                        'type': 'priority_conflict',
                        'severity': 'warning',
                        'rule_id': rule.rule_id or f"rule_{rule.line_num}",
                        'line': rule.line_num,
                        'description': f"规则 {rule.rule_id} 可能中断了链式规则序列",
                        'recommendation': "检查链式规则的完整性"
                    }
                    self.conflicts.append(conflict)
                chain_stack = []
        
        # 检查是否有未结束的链式规则
        if chain_stack:
            conflict = {
                'type': 'priority_conflict',
                'severity': 'error',
                'rule_id': chain_stack[-1].rule_id or f"rule_{chain_stack[-1].line_num}",
                'line': chain_stack[-1].line_num,
                'description': f"链式规则序列未正常结束",
                'recommendation': "确保链式规则序列完整"
            }
            self.conflicts.append(conflict)
    
    def _rules_may_overlap(self, rule1, rule2):
        """判断两个规则是否可能重叠"""
        # 如果两个规则使用相同的运算符和模式，肯定重叠
        if rule1.operator == rule2.operator and rule1.pattern == rule2.pattern:
            return True
        
        # 对于@rx运算符，检查正则表达式是否可能重叠
        if rule1.operator == '@rx' and rule2.operator == '@rx':
            try:
                # 简化的重叠检查
                pattern1 = rule1.pattern.lower()
                pattern2 = rule2.pattern.lower()
                
                # 如果一个模式是另一个的子集，可能重叠
                if pattern1 in pattern2 or pattern2 in pattern1:
                    return True
                
                # 检查常见的攻击模式重叠
                common_patterns = ['select', 'union', 'insert', 'delete', 'update', 'drop']
                for pattern in common_patterns:
                    if pattern in pattern1 and pattern in pattern2:
                        return True
                        
            except Exception as e:
                self.logger.debug(f"正则表达式重叠检查失败: {str(e)}")
        
        return False
    
    def _rule_covers_another(self, rule1, rule2):
        """判断rule1是否覆盖rule2"""
        if rule1.operator != rule2.operator:
            return False
            
        if rule1.operator != '@rx':
            # 只处理正则表达式规则
            return False
            
        try:
            # 简化的覆盖检查
            pattern1 = rule1.pattern.lower()
            pattern2 = rule2.pattern.lower()
            
            # 如果pattern1是pattern2的超集
            if '*' in pattern1 and '*' not in pattern2:
                return True
                
            # 检查常见的覆盖模式
            if pattern1 == '.*' or pattern1 == '.*' + pattern2 or pattern2 + '.*' == pattern1:
                return True
                
            return False
            
        except Exception as e:
            self.logger.debug(f"规则覆盖检查失败: {str(e)}")
            return False
    
    def _actions_are_different(self, rule1, rule2):
        """判断两个规则的动作是否不同"""
        # 提取核心动作（忽略参数）
        def get_core_actions(rule):
            core_actions = set()
            for action in rule.actions:
                core_action = action.split(':')[0]
                if core_action in ['deny', 'pass', 'drop', 'allow']:
                    core_actions.add(core_action)
            return core_actions
        
        actions1 = get_core_actions(rule1)
        actions2 = get_core_actions(rule2)
        
        # 如果两个规则都有核心动作且不同
        if actions1 and actions2 and actions1 != actions2:
            return True
            
        return False
    
    def generate_conflict_report(self, output_path):
        """生成冲突检测报告"""
        try:
            report = {
                'conflict_detection_report': {
                    'summary': {
                        'total_conflicts': len(self.conflicts),
                        'conflict_types': defaultdict(int),
                        'severity_distribution': defaultdict(int)
                    },
                    'conflicts': self.conflicts,
                    'recommendations': self._generate_recommendations()
                }
            }
            
            # 统计信息
            for conflict in self.conflicts:
                report['conflict_detection_report']['summary']['conflict_types'][conflict['type']] += 1
                report['conflict_detection_report']['summary']['severity_distribution'][conflict['severity']] += 1
            
            with open(output_path, 'w', encoding='utf-8') as f:
                import json
                json.dump(report, f, indent=2, ensure_ascii=False)
            
            self.logger.info(f"冲突检测报告已保存到: {output_path}")
            return output_path
            
        except Exception as e:
            self.logger.error(f"生成冲突报告失败: {str(e)}", exc_info=True)
            raise
    
    def _generate_recommendations(self):
        """生成优化建议"""
        recommendations = []
        
        if len(self.conflicts) == 0:
            recommendations.append("未发现规则冲突，规则配置良好")
            return recommendations
        
        # 按严重级别分组
        severity_groups = defaultdict(list)
        for conflict in self.conflicts:
            severity_groups[conflict['severity']].append(conflict)
        
        # 高风险冲突建议
        if severity_groups.get('high') or severity_groups.get('error'):
            recommendations.append("高风险冲突处理建议:")
            recommendations.append("- 立即解决逻辑冲突，确保防护策略的一致性")
            recommendations.append("- 修复链式规则的语法错误")
            recommendations.append("- 检查并调整冲突规则的执行顺序")
        
        # 中风险冲突建议
        if severity_groups.get('medium'):
            recommendations.append("\n中风险冲突处理建议:")
            recommendations.append("- 优化规则匹配模式，避免不必要的覆盖")
            recommendations.append("- 调整规则优先级，确保精确匹配优先于模糊匹配")
            recommendations.append("- 考虑合并功能相似的规则")
        
        # 一般建议
        recommendations.append("\n规则优化通用建议:")
        recommendations.append("- 为所有规则添加唯一的ID标识")
        recommendations.append("- 合理使用phase动作控制规则执行阶段")
        recommendations.append("- 定期审查和清理过时的规则")
        recommendations.append("- 使用测试环境验证规则变更")
        
        return recommendations

def main():
    """测试主函数"""
    import argparse
    from part2_rule_analysis.lib.parser.modsecurity_parser import ModSecurityParser
    
    parser = argparse.ArgumentParser(description='冲突分析器测试')
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
        
        # 进行冲突检测
        analyzer = ConflictAnalyzer()
        conflicts = analyzer.detect_conflicts(rules)
        
        # 显示结果
        print(f"\n=== 冲突检测结果 ===")
        print(f"发现冲突数量: {len(conflicts)}")
        
        if conflicts:
            # 按严重级别分组显示
            severity_groups = defaultdict(list)
            for conflict in conflicts:
                severity_groups[conflict['severity']].append(conflict)
            
            for severity in ['error', 'high', 'medium', 'warning']:
                if severity in severity_groups:
                    print(f"\n{severity.upper()} 级别冲突 ({len(severity_groups[severity])} 个):")
                    for conflict in severity_groups[severity]:
                        print(f"  - {conflict['description']}")
        
        # 保存冲突报告
        analyzer.generate_conflict_report('conflict_report.json')
        print(f"\n冲突检测报告已保存到: conflict_report.json")
        
    except Exception as e:
        print(f"分析失败: {str(e)}")

if __name__ == '__main__':
    main()