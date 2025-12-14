import os
import sys
import tempfile
import json
from datetime import datetime

# 添加Part2分析模块到Python路径
part2_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'Part2 analysis', 'part2_rule_analysis', '2.0')
sys.path.insert(0, part2_path)
sys.path.insert(0, os.path.join(part2_path, 'backend'))
sys.path.insert(0, os.path.join(part2_path, 'backend', 'msc_pyparser-master'))

from msc_pyparser import MSCParser
from semantic_analyzer import SemanticAnalyzer
from dependency_analyzer import DependencyAnalyzer
from conflict_analyzer import ConflictAnalyzer
from database import RuleDatabase
from visualizer import RuleFlowVisualizer, AttackTypeVisualizer, ConflictVisualizer

def parse_rule_details(rule):
    """Extract detailed information from a parsed SecRule"""
    rule_info = {
        'id': "Unknown",
        'phase': "Unknown",
        'variables': [],
        'operator': "",
        'pattern': "",
        'actions': [],
        'tags': [],
        'message': "",
        'severity': "",
        'is_chain': rule.get('chained', False)
    }
    
    # Extract variables
    for v in rule['variables']:
        var_str = v['variable']
        if v['variable_part']:
            var_str += f":{v['variable_part']}"
        rule_info['variables'].append(var_str)
    
    # Extract operator and pattern
    operator = rule['operator']
    if rule['operator_negated']:
        operator = f"!{operator}"
    rule_info['operator'] = operator
    rule_info['pattern'] = rule['operator_argument']
    
    # Extract actions and action-specific details
    for action in rule.get('actions', []):
        act_name = action['act_name']
        act_arg = action['act_arg']
        
        # Add to actions list
        rule_info['actions'].append(f"{act_name}:{act_arg}" if act_arg else act_name)
        
        # Extract specific action values
        if act_name == 'id':
            rule_info['id'] = act_arg
        elif act_name == 'phase':
            rule_info['phase'] = act_arg
        elif act_name == 'msg':
            rule_info['message'] = act_arg
        elif act_name == 'severity':
            rule_info['severity'] = act_arg
        elif act_name == 'tag':
            rule_info['tags'].append(act_arg)
    
    return rule_info

def analyze_rules_file(file_content, file_name, db_path):
    """分析规则文件并插入到数据库"""
    try:
        # 初始化数据库连接
        db = RuleDatabase(db_path=db_path, auto_backup=False)
        
        # 初始化分析器
        semantic_analyzer = SemanticAnalyzer()
        dependency_analyzer = DependencyAnalyzer()
        
        # 解析规则文件
        parser = MSCParser()
        parser.parser.parse(file_content)
        
        # 获取所有SecRule
        secrules = [item for item in parser.configlines if item['type'] == 'SecRule']
        
        if not secrules:
            return {
                "success": False,
                "error": "文件中未找到任何SecRule规则"
            }
        
        # 分析规则
        analyzed_rules = []
        raw_rules = []
        
        for i, rule in enumerate(secrules):
            # 提取规则详情
            rule_info = parse_rule_details(rule)
            
            # 创建完整规则对象
            full_rule = {
                'rule_info': rule_info,
                'file_name': file_name,
                'rule_index': i
            }
            
            # 语义分析
            semantic_result = semantic_analyzer.analyze(full_rule)
            full_rule['semantic_analysis'] = semantic_result
            
            # 依赖分析
            dependency_result = dependency_analyzer.analyze(full_rule, str(rule))
            full_rule['dependency_analysis'] = dependency_result
            
            analyzed_rules.append(full_rule)
            raw_rules.append(str(rule))
        
        # 批量插入或更新规则到数据库
        db.batch_insert(analyzed_rules, "success", raw_rules)
        
        # 构造响应
        response = {
            "success": True,
            "message": f"规则分析成功",
            "data": {
                "filename": file_name,
                "rule_count": len(analyzed_rules),
                "processed_time": datetime.now().isoformat(),
                "rules": analyzed_rules
            }
        }
        
        return response
        
    except Exception as e:
        return {
            "success": False,
            "error": f"规则分析失败: {str(e)}"
        }
    finally:
        # RuleDatabase类没有close方法，不需要关闭连接
        pass

def get_rules_count(db_path):
    """获取数据库中的规则总数"""
    try:
        db = RuleDatabase(db_path=db_path, auto_backup=False)
        all_rules = db.get_all_rules()
        return {
            "success": True,
            "data": {
                "total_rules": len(all_rules),
                "db_path": db_path
            }
        }
    except Exception as e:
        return {
            "success": False,
            "error": f"获取规则总数失败: {str(e)}"
        }
    finally:
        # RuleDatabase类没有close方法，不需要关闭连接
        pass

def insert_rule(rule_data, db_path):
    """插入或更新单条规则"""
    try:
        db = RuleDatabase(db_path=db_path, auto_backup=False)
        result = db.insert(rule_data, "success", rule_data.get('raw_rule'))
        return {
            "success": True,
            "message": "规则插入/更新成功" if result else "规则已存在且内容未变化",
            "data": {
                "rule_id": rule_data['rule_info'].get('id', 'Unknown'),
                "action": "updated" if result else "unchanged"
            }
        }
    except Exception as e:
        return {
            "success": False,
            "error": f"插入规则失败: {str(e)}"
        }
    finally:
        # RuleDatabase类没有close方法，不需要关闭连接
        pass