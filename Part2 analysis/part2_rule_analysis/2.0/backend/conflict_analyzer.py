import re
import logging
from collections import defaultdict, Counter

class ConflictAnalyzer:
    """冲突分析器，负责检测规则之间的冲突"""
    
    def __init__(self):
        # 严重级别映射到数值，用于比较优先级
        self.severity_map = {
            'CRITICAL': 5,
            'HIGH': 4,
            'MEDIUM': 3,
            'LOW': 2,
            'INFO': 1,
            '': 0
        }
        self.logger = logging.getLogger(__name__)
        
        # 冲突类型到解决建议的映射
        self.conflict_suggestions = {
            'logic_conflict': {
                'high': [
                    '检查两条规则的匹配条件，确保它们不会对同一变量产生相反的判断',
                    '考虑合并规则或调整匹配逻辑',
                    '使用明确的优先级设置',
                    '添加更精确的匹配条件，缩小匹配范围'
                ],
                'medium': [
                    '验证规则的执行顺序是否正确',
                    '检查规则的phase设置是否一致',
                    '考虑使用更具体的变量名或变量修饰符'
                ],
                'low': [
                    '监控规则的实际执行情况',
                    '考虑添加测试用例验证规则行为'
                ]
            },
            'coverage_conflict': {
                'high': [
                    '重新评估规则的优先级设置',
                    '考虑合并或重构规则，避免高优先级规则完全覆盖低优先级规则',
                    '调整规则的匹配条件，使它们的匹配范围更加明确'
                ],
                'medium': [
                    '验证规则的执行顺序是否合理',
                    '考虑添加更具体的标签或注释',
                    '检查规则的severity设置是否准确'
                ],
                'low': [
                    '监控规则的触发频率',
                    '考虑添加日志记录，以便分析规则执行情况'
                ]
            },
            'priority_conflict': {
                'high': [
                    '明确设置规则的执行顺序，使用id或phase参数',
                    '重新评估规则的动作设置，避免相反的动作',
                    '考虑使用secruleUpdateAction调整规则优先级'
                ],
                'medium': [
                    '验证规则的变量和操作符设置',
                    '考虑拆分复杂规则为多个简单规则',
                    '检查规则的phase设置是否一致'
                ],
                'low': [
                    '添加规则注释，说明预期行为',
                    '考虑添加测试用例验证规则执行顺序'
                ]
            },
            'overlap_conflict': {
                'high': [
                    '重构规则，合并相似的匹配条件',
                    '使用更精确的正则表达式或匹配模式',
                    '考虑使用secruleUpdateAction调整规则优先级'
                ],
                'medium': [
                    '验证规则的动作设置是否一致',
                    '考虑添加更具体的变量修饰符',
                    '检查规则的phase设置是否合理'
                ],
                'low': [
                    '监控规则的触发频率',
                    '考虑添加规则注释，说明规则的预期用途'
                ]
            },
            'dependency_conflict': {
                'high': [
                    '修复规则之间的依赖关系，确保依赖的规则先执行',
                    '重新评估规则的设计，减少不必要的依赖',
                    '考虑使用更模块化的规则设计'
                ],
                'medium': [
                    '添加明确的依赖声明',
                    '验证规则的执行顺序是否正确',
                    '考虑拆分复杂规则'
                ],
                'low': [
                    '添加规则注释，说明依赖关系',
                    '监控规则执行情况，确保依赖关系正常'
                ]
            },
            'chain_conflict': {
                'high': [
                    '修复链式规则的语法和逻辑',
                    '确保链式规则的每个部分都有正确的动作',
                    '验证链式规则的执行顺序'
                ],
                'medium': [
                    '检查链式规则的phase设置是否一致',
                    '考虑拆分过长的链式规则',
                    '添加规则注释，说明链式规则的用途'
                ],
                'low': [
                    '监控链式规则的执行情况',
                    '考虑添加测试用例验证链式规则行为'
                ]
            }
        }
    
    def batch_analyze(self, rules):
        """批量分析规则冲突"""
        conflicts = []
        
        # 分析逻辑冲突
        logic_conflicts = self._analyze_logic_conflicts(rules)
        conflicts.extend(logic_conflicts)
        
        # 分析覆盖冲突
        coverage_conflicts = self._analyze_coverage_conflicts(rules)
        conflicts.extend(coverage_conflicts)
        
        # 分析依赖冲突
        dependency_conflicts = self._analyze_dependency_conflicts(rules)
        conflicts.extend(dependency_conflicts)
        
        # 新增：检测优先级冲突
        priority_conflicts = self._analyze_priority_conflicts(rules)
        conflicts.extend(priority_conflicts)
        
        # 新增：检测可能重叠的规则冲突
        overlap_conflicts = self._analyze_overlap_conflicts(rules)
        conflicts.extend(overlap_conflicts)
        
        # 新增：检测链式规则冲突
        chain_conflicts = self._analyze_chain_conflicts(rules)
        conflicts.extend(chain_conflicts)
        
        # 优化冲突排序：按严重程度和冲突类型排序
        conflicts.sort(key=lambda x: (self.severity_map.get(x.get('severity', 'LOW').upper()), x.get('conflict_type')))
        
        return conflicts
    
    def _analyze_logic_conflicts(self, rules):
        """分析逻辑冲突：同一变量的相反匹配条件"""
        conflicts = []
        
        # 按变量和阶段分组规则
        rules_by_variable_phase = defaultdict(list)
        for rule in rules:
            rule_info = rule.get('rule_info', {})
            rule_id = rule_info.get('id', '')
            # 从rule_info中获取变量
            variables = rule_info.get('variables', [])
            operator = rule_info.get('operator', '')
            pattern = rule_info.get('pattern', '')
            actions = rule_info.get('actions', [])
            phase = rule_info.get('phase', '')
            
            for var in variables:
                if isinstance(var, dict):
                    var_name = var.get('variable', '')
                else:
                    var_name = var.split(':')[0].strip('&')
                
                key = (var_name, phase)
                rules_by_variable_phase[key].append({
                    'id': rule_id,
                    'operator': operator,
                    'pattern': pattern,
                    'actions': actions,
                    'rule': rule,
                    'raw_rule': rule
                })
        
        # 检查每个变量和阶段组合的规则冲突
        for (var_name, phase), var_rules in rules_by_variable_phase.items():
            # 只检查有多个规则的变量
            if len(var_rules) < 2:
                continue
            
            # 比较每对规则
            for i in range(len(var_rules)):
                for j in range(i+1, len(var_rules)):
                    rule1 = var_rules[i]
                    rule2 = var_rules[j]
                    
                    # 跳过同一规则
                    if rule1['id'] == rule2['id']:
                        continue
                    
                    # 检查是否有相反的动作
                    if self._has_opposite_actions(rule1['actions'], rule2['actions']):
                        # 改进：更智能的冲突检测，考虑操作符和模式的实际逻辑关系
                        if self._patterns_may_conflict(rule1['pattern'], rule2['pattern'], rule1['operator'], rule2['operator']):
                            # 评估冲突严重程度
                            severity = self._evaluate_conflict_severity(rule1['rule'], rule2['rule'])
                            
                            # 获取冲突解决建议
                            suggestions = self._get_conflict_suggestions('logic_conflict', severity)
                            
                            conflicts.append({
                                'conflict_type': 'logic_conflict',
                                'rule_ids': [rule1['id'], rule2['id']],
                                'conflict_field': f'variable: {var_name}, phase: {phase}',
                                'reason': f'规则 {rule1["id"]} 和 {rule2["id"]} 在同一phase {phase} 中对变量 {var_name} 有相反的匹配条件和动作',
                                'suggestion': suggestions,
                                'severity': severity,
                                'rule1': {
                                    'id': rule1['id'],
                                    'operator': rule1['operator'],
                                    'pattern': rule1['pattern'],
                                    'actions': rule1['actions']
                                },
                                'rule2': {
                                    'id': rule2['id'],
                                    'operator': rule2['operator'],
                                    'pattern': rule2['pattern'],
                                    'actions': rule2['actions']
                                }
                            })
        
        return conflicts
    
    def _analyze_coverage_conflicts(self, rules):
        """分析覆盖冲突：高优先级规则覆盖低优先级规则"""
        conflicts = []
        
        # 按phase分组规则
        rules_by_phase = defaultdict(list)
        for rule in rules:
            rule_info = rule.get('rule_info', {})
            phase = rule_info.get('phase', '')
            rules_by_phase[phase].append(rule)
        
        # 检查每个phase内的覆盖冲突
        for phase, phase_rules in rules_by_phase.items():
            if len(phase_rules) < 2:
                continue
                
            # 按规则ID排序（假设数字ID表示顺序）
            sorted_rules = sorted(phase_rules, key=lambda r: r.get('rule_info', {}).get('id', ''))
            
            # 检查所有规则对，而不仅仅是相邻规则
            for i in range(len(sorted_rules)):
                rule1 = sorted_rules[i]
                rule1_info = rule1.get('rule_info', {})
                severity1 = rule1_info.get('severity', 'LOW').upper()
                
                for j in range(i+1, len(sorted_rules)):
                    rule2 = sorted_rules[j]
                    rule2_info = rule2.get('rule_info', {})
                    severity2 = rule2_info.get('severity', 'LOW').upper()
                    
                    # 改进：更智能的覆盖冲突检测，考虑规则的实际匹配范围
                    if self._rules_may_overlap(rule1, rule2):
                        # 检查是否有不同的重要程度
                        if self.severity_map.get(severity1, 0) > self.severity_map.get(severity2, 0):
                            # 评估冲突严重程度
                            severity = self._evaluate_conflict_severity(rule1, rule2, 'coverage')
                            
                            # 获取冲突解决建议
                            suggestions = self._get_conflict_suggestions('coverage_conflict', severity)
                            
                            conflicts.append({
                                'conflict_type': 'coverage_conflict',
                                'rule_ids': [rule1_info.get('id', ''), rule2_info.get('id', '')],
                                'conflict_field': f'phase: {phase}',
                                'reason': f'高优先级规则 {rule1_info.get("id", "")} 可能覆盖低优先级规则 {rule2_info.get("id", "")}',
                                'suggestion': suggestions,
                                'severity': severity,
                                'rule1': {
                                    'id': rule1_info.get('id', ''),
                                    'severity': severity1,
                                    'pattern': rule1_info.get('pattern', '')
                                },
                                'rule2': {
                                    'id': rule2_info.get('id', ''),
                                    'severity': severity2,
                                    'pattern': rule2_info.get('pattern', '')
                                }
                            })
        
        return conflicts
    
    def _analyze_priority_conflicts(self, rules):
        """新增：分析优先级冲突"""
        conflicts = []
        
        # 建立规则索引：(变量, 阶段) -> [规则列表]
        rule_index = defaultdict(list)
        
        for rule in rules:
            rule_info = rule.get('rule_info', {})
            # 从rule_info中获取变量
            variables = rule_info.get('variables', [])
            phase = rule_info.get('phase', 'default')
            rule_id = rule_info.get('id', '')
            
            # 为每个变量和阶段组合建立索引
            for var in variables:
                if isinstance(var, dict):
                    var_name = var.get('variable', '')
                else:
                    var_name = var.split(':')[0].strip('&')
                
                key = (var_name, phase)
                rule_index[key].append({
                    'id': rule_id,
                    'rule': rule,
                    'info': rule_info
                })
        
        # 检测各类冲突
        for (var, phase), indexed_rules in rule_index.items():
            if len(indexed_rules) < 2:
                continue
                
            # 检查每对规则
            for i in range(len(indexed_rules)):
                for j in range(i + 1, len(indexed_rules)):
                    rule1 = indexed_rules[i]
                    rule2 = indexed_rules[j]
                    
                    # 跳过同一规则
                    if rule1['id'] == rule2['id']:
                        continue
                        
                    # 检查规则是否可能同时匹配
                    if self._rules_may_overlap(rule1['rule'], rule2['rule']):
                        # 检查动作冲突
                        actions1 = rule1['info'].get('actions', [])
                        actions2 = rule2['info'].get('actions', [])
                        
                        # 改进：更智能的动作冲突检测
                        if self._has_opposite_actions(actions1, actions2):
                            # 评估冲突严重程度
                            severity = self._evaluate_conflict_severity(rule1['rule'], rule2['rule'], 'priority')
                            
                            # 获取冲突解决建议
                            suggestions = self._get_conflict_suggestions('priority_conflict', severity)
                            
                            conflicts.append({
                                'conflict_type': 'priority_conflict',
                                'rule_ids': [rule1['id'], rule2['id']],
                                'conflict_field': f'variable: {var}, phase: {phase}',
                                'reason': f'规则 {rule1["id"]} 和 {rule2["id"]} 在变量 {var} 上可能存在优先级冲突',
                                'suggestion': suggestions,
                                'severity': severity,
                                'rule1': {
                                    'id': rule1['id'],
                                    'actions': [a.split(':')[0] for a in actions1]
                                },
                                'rule2': {
                                    'id': rule2['id'],
                                    'actions': [a.split(':')[0] for a in actions2]
                                }
                            })
        
        return conflicts
    
    def _analyze_overlap_conflicts(self, rules):
        """新增：分析可能重叠的规则冲突"""
        conflicts = []
        
        # 改进：使用更智能的规则对生成，减少不必要的比较
        # 按变量和阶段分组规则
        rules_by_variable_phase = defaultdict(list)
        for rule in rules:
            rule_info = rule.get('rule_info', {})
            variables = rule_info.get('variables', [])
            phase = rule_info.get('phase', '')
            
            for var in variables:
                if isinstance(var, dict):
                    var_name = var.get('variable', '')
                else:
                    var_name = var.split(':')[0].strip('&')
                
                key = (var_name, phase)
                rules_by_variable_phase[key].append(rule)
        
        # 只比较同一变量和阶段的规则
        for key, var_rules in rules_by_variable_phase.items():
            if len(var_rules) < 2:
                continue
                
            # 比较每对规则
            for i in range(len(var_rules)):
                rule1 = var_rules[i]
                rule1_info = rule1.get('rule_info', {})
                
                for j in range(i + 1, len(var_rules)):
                    rule2 = var_rules[j]
                    rule2_info = rule2.get('rule_info', {})
                    
                    # 跳过同一规则
                    if rule1_info.get('id') == rule2_info.get('id'):
                        continue
                        
                    # 改进：更智能的重叠检测，考虑规则的实际匹配条件
                    if self._rules_may_overlap(rule1, rule2):
                        # 改进：考虑规则的动作和匹配条件的相似性
                        actions1 = set(a.split(':')[0] for a in rule1_info.get('actions', []))
                        actions2 = set(a.split(':')[0] for a in rule2_info.get('actions', []))
                        
                        # 如果规则具有相似的操作且可能重叠，则可能存在冗余
                        if actions1 == actions2 or len(actions1.intersection(actions2)) > 0:
                            # 评估冲突严重程度
                            severity = self._evaluate_conflict_severity(rule1, rule2, 'overlap')
                            
                            # 获取冲突解决建议
                            suggestions = self._get_conflict_suggestions('overlap_conflict', severity)
                            
                            conflicts.append({
                                'conflict_type': 'overlap_conflict',
                                'rule_ids': [rule1_info.get('id', ''), rule2_info.get('id', '')],
                                'conflict_field': f'variable: {key[0]}, phase: {key[1]}',
                                'reason': f'规则 {rule1_info.get("id", "")} 和 {rule2_info.get("id", "")} 可能会匹配相同的请求',
                                'suggestion': suggestions,
                                'severity': severity,
                                'rule1': {
                                    'id': rule1_info.get('id', ''),
                                    'actions': list(actions1),
                                    'pattern': rule1_info.get('pattern', '')
                                },
                                'rule2': {
                                    'id': rule2_info.get('id', ''),
                                    'actions': list(actions2),
                                    'pattern': rule2_info.get('pattern', '')
                                }
                            })
        
        return conflicts
    
    def _analyze_dependency_conflicts(self, rules):
        """分析依赖冲突"""
        conflicts = []
        
        # 建立规则索引：id -> rule
        rule_by_id = {rule.get('rule_info', {}).get('id'): rule for rule in rules if rule.get('rule_info', {}).get('id')}
        
        # 检查规则的依赖关系
        for rule in rules:
            rule_info = rule.get('rule_info', {})
            rule_id = rule_info.get('id', '')
            actions = rule_info.get('actions', [])
            
            # 检查规则是否依赖其他规则
            for action in actions:
                if isinstance(action, str) and 'id:' in action:
                    # 提取依赖的规则ID
                    dep_id = action.split('id:')[1].split(',')[0].strip()
                    
                    # 检查依赖的规则是否存在
                    if dep_id not in rule_by_id:
                        # 评估冲突严重程度
                        severity = 'high' if 'block' in action.lower() or 'deny' in action.lower() else 'medium'
                        
                        # 获取冲突解决建议
                        suggestions = self._get_conflict_suggestions('dependency_conflict', severity)
                        
                        conflicts.append({
                            'conflict_type': 'dependency_conflict',
                            'rule_ids': [rule_id],
                            'conflict_field': f'action: {action}',
                            'reason': f'规则 {rule_id} 依赖不存在的规则 {dep_id}',
                            'suggestion': suggestions,
                            'severity': severity,
                            'rule1': {
                                'id': rule_id,
                                'action': action
                            }
                        })
        
        return conflicts
    
    def _analyze_chain_conflicts(self, rules):
        """新增：分析链式规则冲突"""
        conflicts = []
        
        # 检查链式规则的逻辑
        chain_rules = []
        for rule in rules:
            rule_info = rule.get('rule_info', {})
            if rule_info.get('is_chain', False):
                chain_rules.append(rule)
        
        # 分析链式规则内部冲突
        for rule in chain_rules:
            rule_info = rule.get('rule_info', {})
            rule_id = rule_info.get('id', '')
            actions = rule_info.get('actions', [])
            
            # 检查链式规则是否有终止动作
            has_terminal_action = any(action.startswith('deny') or action.startswith('drop') or action.startswith('allow') or action.startswith('pass') for action in actions)
            
            if not has_terminal_action:
                # 评估冲突严重程度
                severity = 'medium'
                
                # 获取冲突解决建议
                suggestions = self._get_conflict_suggestions('chain_conflict', severity)
                
                conflicts.append({
                    'conflict_type': 'chain_conflict',
                    'rule_ids': [rule_id],
                    'conflict_field': 'actions',
                    'reason': f'链式规则 {rule_id} 缺少终止动作',
                    'suggestion': suggestions,
                    'severity': severity,
                    'rule1': {
                        'id': rule_id,
                        'actions': [a.split(':')[0] for a in actions]
                    }
                })
        
        return conflicts
    
    def _has_opposite_actions(self, actions1, actions2):
        """检查是否有相反的动作"""
        action_set1 = {a.split(':')[0] for a in actions1}
        action_set2 = {a.split(':')[0] for a in actions2}
        
        opposite_pairs = [
            ('deny', 'allow'),
            ('allow', 'deny'),
            ('pass', 'deny'),
            ('deny', 'pass'),
            ('drop', 'allow'),
            ('allow', 'drop')
        ]
        
        for action1 in action_set1:
            for action2 in action_set2:
                if (action1, action2) in opposite_pairs or (action2, action1) in opposite_pairs:
                    return True
        return False
    
    def _patterns_may_conflict(self, pattern1, pattern2, operator1, operator2):
        """改进：更智能的模式冲突检测"""
        # 简化的冲突检查逻辑
        # 在实际应用中，这需要更复杂的正则表达式分析
        if not pattern1 or not pattern2:
            return False
            
        # 如果操作符不同，可能不存在冲突
        if operator1 != operator2:
            return False
            
        # 如果是正则表达式，进行简单的冲突检查
        if operator1 == '@rx' or operator2 == '@rx':
            # 检查是否有明显的相反模式
            if ('^' in pattern1 and '$' in pattern2 and pattern1 != pattern2) or ('^' in pattern2 and '$' in pattern1 and pattern1 != pattern2):
                return True
            
            # 检查是否有明显的互斥模式
            if (pattern1.startswith('^') and pattern2.startswith('^') and not pattern1.startswith(pattern2) and not pattern2.startswith(pattern1)):
                return False
        
        # 其他情况，认为可能存在冲突
        return True
    
    def _rules_may_overlap(self, rule1, rule2):
        """改进：更智能的规则重叠检测"""
        # 获取规则信息
        rule1_info = rule1.get('rule_info', {})
        rule2_info = rule2.get('rule_info', {})
        
        # 检查阶段是否相同
        phase1 = rule1_info.get('phase', '')
        phase2 = rule2_info.get('phase', '')
        
        # 不同阶段不会重叠
        if phase1 and phase2 and phase1 != phase2:
            return False
        
        # 获取变量
        vars1 = set()
        vars2 = set()
        
        # 处理规则1的变量
        variables1 = rule1_info.get('variables', [])
        if isinstance(variables1, list):
            for var in variables1:
                if isinstance(var, dict):
                    vars1.add(var.get('variable', ''))
                else:
                    vars1.add(var.split(':')[0].strip('&'))
        
        # 处理规则2的变量
        variables2 = rule2_info.get('variables', [])
        if isinstance(variables2, list):
            for var in variables2:
                if isinstance(var, dict):
                    vars2.add(var.get('variable', ''))
                else:
                    vars2.add(var.split(':')[0].strip('&'))
        
        # 如果没有共同变量，则不太可能重叠
        if not vars1.intersection(vars2):
            return False
        
        # 改进：考虑操作符和模式的实际匹配逻辑
        operator1 = rule1_info.get('operator', '')
        operator2 = rule2_info.get('operator', '')
        pattern1 = rule1_info.get('pattern', '')
        pattern2 = rule2_info.get('pattern', '')
        
        # 如果操作符都是精确匹配且模式不同，则不会重叠
        if (operator1 == '@streq' or operator1 == '@beginswith' or operator1 == '@endswith') and \
           (operator2 == '@streq' or operator2 == '@beginswith' or operator2 == '@endswith'):
            # 简单检查模式是否可能重叠
            if operator1 == '@streq' and operator2 == '@streq':
                return pattern1 == pattern2
            elif operator1 == '@beginswith' and operator2 == '@beginswith':
                return pattern1.startswith(pattern2) or pattern2.startswith(pattern1)
            elif operator1 == '@endswith' and operator2 == '@endswith':
                return pattern1.endswith(pattern2) or pattern2.endswith(pattern1)
        
        # 其他情况，认为可能重叠
        return True
    
    def _evaluate_conflict_severity(self, rule1, rule2, conflict_type='generic'):
        """新增：评估冲突严重程度"""
        rule1_info = rule1.get('rule_info', {})
        rule2_info = rule2.get('rule_info', {})
        
        # 基础严重程度
        severity = 'medium'
        
        # 根据冲突类型调整严重程度
        if conflict_type == 'logic' or conflict_type == 'priority':
            # 检查规则是否有相反的动作
            actions1 = rule1_info.get('actions', [])
            actions2 = rule2_info.get('actions', [])
            
            if self._has_opposite_actions(actions1, actions2):
                # 检查是否包含阻断动作
                if any(a.startswith('deny') or a.startswith('drop') for a in actions1 + actions2):
                    severity = 'high'
                else:
                    severity = 'medium'
            else:
                severity = 'low'
        elif conflict_type == 'coverage':
            # 检查高优先级规则是否包含阻断动作
            severity1 = rule1_info.get('severity', 'LOW').upper()
            actions1 = rule1_info.get('actions', [])
            
            if self.severity_map.get(severity1, 0) >= 4 and any(a.startswith('deny') or a.startswith('drop') for a in actions1):
                severity = 'high'
            else:
                severity = 'medium'
        elif conflict_type == 'overlap':
            # 检查规则的动作是否相同
            actions1 = set(a.split(':')[0] for a in rule1_info.get('actions', []))
            actions2 = set(a.split(':')[0] for a in rule2_info.get('actions', []))
            
            if actions1 == actions2 and len(actions1) > 0:
                severity = 'medium'
            else:
                severity = 'low'
        
        return severity
    
    def _get_conflict_suggestions(self, conflict_type, severity):
        """新增：获取冲突解决建议"""
        # 获取基本建议
        suggestions = self.conflict_suggestions.get(conflict_type, {}).get(severity, [])
        
        # 添加通用建议
        general_suggestions = [
            '参考ModSecurity官方文档，了解规则语法和最佳实践',
            '使用ModSecurity的调试模式验证规则行为',
            '考虑添加测试用例，验证规则的预期行为',
            '定期审查和更新规则，确保它们的有效性'
        ]
        
        # 合并建议并去重
        all_suggestions = suggestions + general_suggestions
        all_suggestions = list(dict.fromkeys(all_suggestions))
        
        # 限制建议数量，提高可读性
        return all_suggestions[:5]  # 最多返回5条建议