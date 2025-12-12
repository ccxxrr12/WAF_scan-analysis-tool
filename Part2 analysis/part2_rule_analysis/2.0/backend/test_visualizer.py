#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import sys
from visualizer import ASTVisualizer, DependencyVisualizer, ConflictVisualizer, AttackTypeVisualizer, RuleFlowVisualizer

# 测试数据
mock_rule = {
    'rule_info': {
        'id': 'test_rule_1',
        'phase': '1',
        'variables': ['REQUEST_URI', 'QUERY_STRING'],
        'operator': '@rx',
        'pattern': '\bSELECT\b',
        'actions': ['id:12345', 'phase:1', 'block', 'msg:SQL Injection Attempt', 'severity:HIGH'],
        'tags': ['SQL Injection', 'OWASP'],
        'message': 'SQL Injection Attempt',
        'severity': 'HIGH',
        'is_chain': False
    },
    'semantic_analysis': {
        'attack_types': ['SQL Injection', 'Input Validation'],
        'rule_classification': {
            'protection_layer': 'application_layer',
            'matching_method': 'regex_matching',
            'scenario': 'sql_injection_protection',
            'rule_type': 'request_rule'
        }
    },
    'dependency_analysis': {
        'variable_dependencies': ['REQUEST_URI', 'QUERY_STRING'],
        'marker_dependencies': [],
        'include_dependencies': []
    }
}

# 测试AST可视化
print("Testing AST Visualizer...")
ast_visualizer = ASTVisualizer()
ast_file = "test_ast.html"
try:
    ast_visualizer.save_ast_file(mock_rule, ast_file)
    print(f"✓ AST visualization saved to: {ast_file}")
except Exception as e:
    print(f"✗ AST visualization failed: {e}")

# 测试依赖关系可视化
print("\nTesting Dependency Visualizer...")
dependency_visualizer = DependencyVisualizer()
dependency_file = "test_dependency.html"
try:
    dependency_visualizer.save_dependency_file(mock_rule, dependency_file)
    print(f"✓ Dependency visualization saved to: {dependency_file}")
except Exception as e:
    print(f"✗ Dependency visualization failed: {e}")

# 测试攻击类型可视化
print("\nTesting Attack Type Visualizer...")
attack_visualizer = AttackTypeVisualizer()
mock_rules = [mock_rule] * 5
attack_file = "test_attack_type.html"
try:
    attack_visualizer.save_attack_type_file(mock_rules, attack_file)
    print(f"✓ Attack type visualization saved to: {attack_file}")
except Exception as e:
    print(f"✗ Attack type visualization failed: {e}")

# 测试规则流可视化
print("\nTesting Rule Flow Visualizer...")
ruleflow_visualizer = RuleFlowVisualizer()
ruleflow_file = "test_rule_flow.html"
try:
    ruleflow_visualizer.save_ruleflow_file(mock_rules, ruleflow_file)
    print(f"✓ Rule flow visualization saved to: {ruleflow_file}")
except Exception as e:
    print(f"✗ Rule flow visualization failed: {e}")

# 测试冲突检测可视化
print("\nTesting Conflict Visualizer...")
conflict_visualizer = ConflictVisualizer()
mock_conflicts = [
    {
        'conflict_type': 'logic_conflict',
        'rule_ids': ['test_rule_1', 'test_rule_2'],
        'reason': 'Logic conflict between rules',
        'severity': 'high'
    }
]
conflict_file = "test_conflict.html"
try:
    conflict_visualizer.save_conflict_file(mock_conflicts, conflict_file)
    print(f"✓ Conflict visualization saved to: {conflict_file}")
except Exception as e:
    print(f"✗ Conflict visualization failed: {e}")

print("\nAll tests completed!")
