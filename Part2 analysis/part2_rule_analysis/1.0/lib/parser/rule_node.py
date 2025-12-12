#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
规则节点定义
用于表示解析后的ModSecurity规则结构
"""

import json
from typing import List, Dict, Any, Optional

class Node:
    """基础节点类"""
    
    def __init__(self, node_type: str, value: Any = None):
        self.type = node_type
        self.value = value
        self.children: List['Node'] = []
    
    def add_child(self, child: 'Node'):
        """添加子节点"""
        self.children.append(child)
    
    def to_dict(self) -> Dict[str, Any]:
        """转换为字典"""
        result = {
            'type': self.type,
            'value': self.value
        }
        if self.children:
            result['children'] = [child.to_dict() for child in self.children]
        return result
    
    def __repr__(self):
        return f"Node(type={self.type}, value={self.value}, children={len(self.children)})"

class RuleNode:
    """规则节点类，表示一条完整的SecRule规则"""
    
    def __init__(self, rule_data: Dict[str, Any]):
        """根据解析器返回的数据初始化规则节点
        
        Args:
            rule_data: 解析器返回的规则数据字典
        """
        self.id = self._extract_id(rule_data)
        self.file = ""
        self.line_number = 0
        self.raw_rule = rule_data.get('rule', '')
        self.variables = self._extract_variables(rule_data)
        self.operator = self._extract_operator(rule_data)
        self.actions = self._extract_actions(rule_data)
        self.chain_rule = self._extract_chain_rule(rule_data)
        self.msg = self._extract_msg(rule_data)
        self.tags = self._extract_tags(rule_data)
        self.severity = self._extract_severity(rule_data)
        
    def _extract_id(self, rule_data: Dict[str, Any]) -> str:
        """从规则数据中提取规则ID"""
        actions = rule_data.get('action', [])
        if isinstance(actions, list):
            for action in actions:
                if action.startswith('id:'):
                    return action[3:]  # 去掉'id:'前缀
        return ""
    
    def _extract_variables(self, rule_data: Dict[str, Any]) -> List[str]:
        """从规则数据中提取变量"""
        variable = rule_data.get('variable')
        if variable:
            return [variable]
        return []
    
    def _extract_operator(self, rule_data: Dict[str, Any]) -> str:
        """从规则数据中提取操作符"""
        return rule_data.get('operator', '')
    
    def _extract_actions(self, rule_data: Dict[str, Any]) -> List[str]:
        """从规则数据中提取动作列表"""
        actions = rule_data.get('action', [])
        if isinstance(actions, list):
            return actions
        elif isinstance(actions, str):
            return [actions]
        return []
    
    def _extract_chain_rule(self, rule_data: Dict[str, Any]) -> Optional['RuleNode']:
        """从规则数据中提取链式规则"""
        chain_rule_data = rule_data.get('chain_rule')
        if chain_rule_data:
            return RuleNode(chain_rule_data)
        return None
    
    def _extract_msg(self, rule_data: Dict[str, Any]) -> str:
        """从规则数据中提取消息"""
        actions = rule_data.get('action', [])
        if isinstance(actions, list):
            for action in actions:
                if action.startswith('msg:'):
                    return action[4:]  # 去掉'msg:'前缀
        return ""
    
    def _extract_tags(self, rule_data: Dict[str, Any]) -> List[str]:
        """从规则数据中提取标签"""
        tags = []
        actions = rule_data.get('action', [])
        if isinstance(actions, list):
            for action in actions:
                if action.startswith('tag:'):
                    tags.append(action[4:])  # 去掉'tag:'前缀
        return tags
    
    def _extract_severity(self, rule_data: Dict[str, Any]) -> str:
        """从规则数据中提取严重性级别"""
        actions = rule_data.get('action', [])
        if isinstance(actions, list):
            for action in actions:
                if action.startswith('severity:'):
                    return action[9:]  # 去掉'severity:'前缀
        return ""
    
    def to_dict(self) -> Dict[str, Any]:
        """将规则节点转换为字典"""
        result = {
            'id': self.id,
            'file': self.file,
            'line_number': self.line_number,
            'raw_rule': self.raw_rule,
            'variables': self.variables,
            'operator': self.operator,
            'actions': self.actions,
            'msg': self.msg,
            'tags': self.tags,
            'severity': self.severity
        }
        
        if self.chain_rule:
            result['chain_rule'] = self.chain_rule.to_dict()
            
        return result
    
    def to_json(self) -> str:
        """将规则节点转换为JSON字符串"""
        return json.dumps(self.to_dict(), ensure_ascii=False, indent=2)
    
    def __repr__(self):
        return f"RuleNode(id={self.id}, msg={self.msg})"