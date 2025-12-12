#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ModSecurity解析器适配器
提供统一的接口来使用不同的解析器实现
"""

import os
import sys
import logging
from typing import List

# 添加当前目录到Python路径以解决导入问题
current_dir = os.path.dirname(os.path.abspath(__file__))
if current_dir not in sys.path:
    sys.path.insert(0, current_dir)

from modsecurity_parser import parse_file as new_parse_file
from rule_node import RuleNode

logger = logging.getLogger(__name__)

class ModSecurityParser:
    """ModSecurity规则解析器适配器"""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.parsed_rules = []
        self.parse_errors = []
    
    def parse_file(self, file_path: str) -> List[RuleNode]:
        """解析规则文件
        
        Args:
            file_path: 规则文件路径
            
        Returns:
            解析后的规则节点列表
        """
        try:
            self.logger.info(f"开始解析文件: {file_path}")
            
            # 检查文件是否存在
            if not os.path.exists(file_path):
                raise FileNotFoundError(f"规则文件不存在: {file_path}")
            
            # 使用新的PLY解析器解析文件
            # 注意：新解析器直接打印结果，我们需要修改它以返回结构化数据
            self.parsed_rules = []
            self.parse_errors = []
            
            # 这里应该调用解析器并将结果转换为RuleNode对象
            # 由于新解析器的接口与旧的不同，我们需要做一些适配工作
            try:
                # 调用新解析器并获取结果
                sec_rules = new_parse_file(file_path)
                
                # 将SecRule对象转换为RuleNode对象
                for sec_rule in sec_rules:
                    rule_data = sec_rule.jsonify_rule()
                    rule_node = RuleNode(rule_data)
                    rule_node.file = file_path
                    self.parsed_rules.append(rule_node)
                    
            except Exception as e:
                self.logger.error(f"新解析器解析失败: {str(e)}")
                raise
            
            return self.parsed_rules
            
        except Exception as e:
            self.logger.error(f"解析文件失败: {str(e)}", exc_info=True)
            raise
    
    def parse_content(self, content: str, file_path: str = None) -> List[RuleNode]:
        """解析规则内容
        
        Args:
            content: 规则内容字符串
            file_path: 可选的文件路径，用于错误信息
            
        Returns:
            解析后的规则节点列表
        """
        try:
            self.logger.info("开始解析规则内容")
            
            # 创建临时文件进行解析
            import tempfile
            with tempfile.NamedTemporaryFile(mode='w', suffix='.conf', delete=False, encoding='utf-8') as f:
                f.write(content)
                temp_file_path = f.name
            
            try:
                # 解析临时文件
                rules = self.parse_file(temp_file_path)
                return rules
            finally:
                # 清理临时文件
                os.unlink(temp_file_path)
                
        except Exception as e:
            self.logger.error(f"解析内容失败: {str(e)}", exc_info=True)
            raise

# 为了保持接口一致性，提供与原来一样的函数
def parse_modsecurity_file(file_path: str) -> List[RuleNode]:
    """解析ModSecurity规则文件的便捷函数
    
    Args:
        file_path: 规则文件路径
        
    Returns:
        解析后的规则节点列表
    """
    parser = ModSecurityParser()
    return parser.parse_file(file_path)