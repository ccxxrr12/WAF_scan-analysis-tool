#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
规则节点数据结构
定义AST节点和规则节点的数据结构
"""

class Node:
    """AST节点基类"""
    
    def __init__(self, node_type, node_value, line_num, col_num):
        self.node_type = node_type  # 节点类型
        self.node_value = node_value  # 节点值
        self.line_num = line_num  # 行号
        self.col_num = col_num  # 列号
        self.parent = None  # 父节点
        self.children = []  # 子节点列表
    
    def add_child(self, child_node):
        """添加子节点"""
        if child_node:
            child_node.parent = self
            self.children.append(child_node)
    
    def get_child_by_type(self, child_type):
        """根据类型获取子节点"""
        for child in self.children:
            if child.node_type == child_type:
                return child
        return None
    
    def get_children_by_type(self, child_type):
        """根据类型获取所有子节点"""
        return [child for child in self.children if child.node_type == child_type]
    
    def to_dict(self):
        """转换为字典格式"""
        return {
            "type": self.node_type,
            "value": self.node_value,
            "line": self.line_num,
            "col": self.col_num,
            "children": [child.to_dict() for child in self.children]
        }
    
    def __repr__(self):
        return f"<{self.node_type}: '{self.node_value}' at ({self.line_num}:{self.col_num})>"

class RuleNode(Node):
    """规则节点类"""
    
    def __init__(self, rule_type, line_num, col_num):
        super().__init__(rule_type, "", line_num, col_num)
        self.rule_id = None  # 规则ID
        self.phase = None  # 处理阶段
        self.actions = []  # 动作列表
        self.variables = []  # 变量列表
        self.operator = None  # 运算符
        self.pattern = None  # 匹配模式
        self.tags = []  # 标签列表
        self.message = None  # 规则消息
        self.severity = None  # 严重级别
        self.is_chain = False  # 是否为链式规则
    
    def extract_rule_info(self):
        """提取规则信息"""
        # 提取变量
        var_list = self.get_child_by_type("VarList")
        if var_list:
            self.variables = [var.node_value for var in var_list.get_children_by_type("Variable")]
        
        # 提取运算符
        operator_node = self.get_child_by_type("Operator")
        if operator_node:
            self.operator = operator_node.node_value
        
        # 提取模式
        pattern_node = self.get_child_by_type("Pattern")
        if pattern_node:
            self.pattern = pattern_node.node_value
        
        # 提取动作信息
        action_list = self.get_child_by_type("ActionList")
        if action_list:
            self.actions = [action.node_value for action in action_list.get_children_by_type("Action")]
            
            # 从动作中提取具体信息
            for action in action_list.get_children_by_type("Action"):
                action_value = action.node_value
                if action_value.startswith("id:"):
                    self.rule_id = action_value[3:]
                elif action_value.startswith("phase:"):
                    self.phase = action_value[6:]
                elif action_value.startswith("msg:"):
                    self.message = action_value[4:]
                elif action_value.startswith("tag:"):
                    self.tags.append(action_value[4:])
                elif action_value.startswith("severity:"):
                    self.severity = action_value[9:]
                elif action_value == "chain":
                    self.is_chain = True
    
    def get_rule_summary(self):
        """获取规则摘要信息"""
        summary = {
            "type": self.node_type,
            "id": self.rule_id,
            "phase": self.phase,
            "variables": self.variables,
            "operator": self.operator,
            "pattern": self.pattern[:100] + "..." if self.pattern and len(self.pattern) > 100 else self.pattern,
            "actions": self.actions,
            "tags": self.tags,
            "message": self.message,
            "severity": self.severity,
            "is_chain": self.is_chain,
            "location": f"{self.line_num}:{self.col_num}"
        }
        return summary
    
    def to_dict(self):
        """转换为字典格式（包含规则信息）"""
        base_dict = super().to_dict()
        base_dict.update({
            "rule_info": self.get_rule_summary()
        })
        return base_dict
    
    def __repr__(self):
        rule_id_str = f" id:{self.rule_id}" if self.rule_id else ""
        return f"<RuleNode({self.node_type}{rule_id_str}) at ({self.line_num}:{self.col_num})>"