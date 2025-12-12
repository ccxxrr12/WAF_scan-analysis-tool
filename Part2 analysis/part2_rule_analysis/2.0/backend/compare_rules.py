import sys
import os
import json
import sqlite3
from datetime import datetime

# Add the project directory to the Python path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'msc_pyparser-master'))

from msc_pyparser import MSCParser


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


def get_rules_from_files(rules_dir):
    """Get all rules from actual rule files"""
    print(f"正在从规则文件中读取规则: {rules_dir}")
    
    # Get all .conf files in the rules directory
    conf_files = [f for f in os.listdir(rules_dir) if f.endswith('.conf')]
    conf_files.sort()
    
    file_rules = {}
    total_rules = 0
    
    for file_path in conf_files:
        full_path = os.path.join(rules_dir, file_path)
        rules = []
        
        try:
            with open(full_path, 'r', encoding='utf-8') as rule_file:
                content = rule_file.read()
        except UnicodeDecodeError:
            with open(full_path, 'r', encoding='gbk') as rule_file:
                content = rule_file.read()
        
        # Create parser instance
        parser = MSCParser()
        parser.parser.parse(content)
        
        # Find all SecRule items
        secrules = [item for item in parser.configlines if item['type'] == 'SecRule']
        
        for rule in secrules:
            rule_info = parse_rule_details(rule)
            rules.append(rule_info)
        
        file_rules[file_path] = rules
        total_rules += len(rules)
        print(f"  文件: {file_path}, 规则数量: {len(rules)}")
    
    print(f"从文件中读取到的规则总数: {total_rules}")
    return file_rules, total_rules


def get_rules_from_db(db_path):
    """Get all rules from database"""
    print(f"正在从数据库中读取规则: {db_path}")
    
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    # Get total rules count
    cursor.execute("SELECT COUNT(*) FROM rules")
    total_rules = cursor.fetchone()[0]
    
    print(f"数据库中的规则总数: {total_rules}")
    
    # Get all rules with their IDs
    cursor.execute("SELECT id, rule_info, raw_rule FROM rules")
    db_rules = {}
    
    for row in cursor.fetchall():
        rule_id, rule_info_json, raw_rule = row
        try:
            rule_info = json.loads(rule_info_json)
            db_rules[rule_id] = rule_info
        except json.JSONDecodeError as e:
            print(f"  解析规则 {rule_id} 时出错: {e}")
    
    conn.close()
    print(f"成功解析的数据库规则数量: {len(db_rules)}")
    return db_rules, total_rules


def compare_rules(file_rules, db_rules):
    """Compare rules from files and database"""
    print("\n=== 开始比较规则 ===")
    
    # Flatten file rules into a list
    all_file_rules = []
    for file_path, rules in file_rules.items():
        for rule in rules:
            all_file_rules.append(rule)
    
    # Create a list of db rules
    all_db_rules = list(db_rules.values())
    
    print(f"文件中的规则总数: {len(all_file_rules)}")
    print(f"数据库中的规则总数: {len(all_db_rules)}")
    
    # Compare by rule core content, ignoring non-essential fields
    matched_count = 0
    unmatched_file_rules = []
    
    # Extract core rule content for comparison
    def get_core_rule_content(rule):
        """Extract core rule content for comparison"""
        # Core fields to compare
        core_fields = ['variables', 'operator', 'pattern', 'is_chain']
        core_content = {field: rule.get(field, '') for field in core_fields}
        
        # Normalize lists for comparison
        for key, value in core_content.items():
            if isinstance(value, list):
                core_content[key] = sorted(value)
        
        return core_content
    
    # Create a list of tuples with core content and original rule
    file_rules_with_core = [(get_core_rule_content(rule), rule, rule.get('id')) for rule in all_file_rules]
    db_rules_with_core = [(get_core_rule_content(rule), rule, rule.get('id')) for rule in all_db_rules]
    
    print(f"\n=== 开始比较规则 ===")
    print(f"文件中的规则总数: {len(file_rules_with_core)}")
    print(f"数据库中的规则总数: {len(db_rules_with_core)}")
    
    # Track matched rules
    matched_db_indices = set()
    matched_count = 0
    unmatched_file_rules = []
    
    for file_core, file_rule, file_id in file_rules_with_core:
        matched = False
        for i, (db_core, db_rule, db_id) in enumerate(db_rules_with_core):
            if i in matched_db_indices:
                continue
                
            if file_core == db_core:
                matched = True
                matched_count += 1
                matched_db_indices.add(i)
                break
        if not matched:
            unmatched_file_rules.append(file_rule)
    
    remaining_db_rules = [db_rule for i, (db_core, db_rule, db_id) in enumerate(db_rules_with_core) if i not in matched_db_indices]
    
    # Print results
    print(f"\n=== 比较结果 ===")
    print(f"完全匹配的规则数量: {matched_count}")
    print(f"文件中存在但数据库中没有的规则数量: {len(unmatched_file_rules)}")
    print(f"数据库中存在但文件中没有的规则数量: {len(remaining_db_rules)}")
    
    if unmatched_file_rules:
        print(f"\n文件中存在但数据库中没有的规则（前5个示例）:")
        for i, rule in enumerate(unmatched_file_rules[:5]):
            print(f"  示例 {i+1}: ID={rule['id']}, 变量={rule['variables']}, 操作符={rule['operator']}, 模式={rule['pattern'][:50]}...")
    
    if remaining_db_rules:
        print(f"\n数据库中存在但文件中没有的规则（前5个示例）:")
        for i, rule in enumerate(remaining_db_rules[:5]):
            print(f"  示例 {i+1}: ID={rule['id']}, 变量={rule['variables']}, 操作符={rule['operator']}, 模式={rule['pattern'][:50]}...")
    
    if matched_count == len(all_file_rules) and len(remaining_db_rules) == 0:
        print("\n✅ 所有规则完全一致！")
    
    return {
        'matched': matched_count,
        'only_in_files': len(unmatched_file_rules),
        'only_in_db': len(remaining_db_rules),
        'total_files': len(all_file_rules),
        'total_db': len(all_db_rules)
    }


def main():
    """Main function"""
    # Get the parent directory path
    parent_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    rules_dir = os.path.join(parent_dir, "rules")
    
    # Set analysis results directory
    analysis_results_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "analysis_results")
    db_path = os.path.join(analysis_results_dir, "rules.db")
    
    # Check if database exists
    if not os.path.exists(db_path):
        print(f"错误: 数据库文件不存在 {db_path}")
        print("请先运行 main.py 生成数据库")
        return 1
    
    # Get rules from files
    file_rules, file_total = get_rules_from_files(rules_dir)
    
    # Get rules from database
    db_rules, db_total = get_rules_from_db(db_path)
    
    # Compare rules
    compare_results = compare_rules(file_rules, db_rules)
    
    # Write results to file
    result_file = os.path.join(analysis_results_dir, "rules_comparison_result.md")
    with open(result_file, 'w', encoding='utf-8') as f:
        f.write("# 规则比较结果\n\n")
        f.write(f"生成时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
        f.write(f"## 比较统计\n\n")
        f.write(f"- 文件中的规则总数: {compare_results['total_files']}\n")
        f.write(f"- 数据库中的规则总数: {compare_results['total_db']}\n")
        f.write(f"- 完全匹配的规则数量: {compare_results['matched']}\n")
        f.write(f"- 仅存在于文件中的规则: {compare_results['only_in_files']}\n")
        f.write(f"- 仅存在于数据库中的规则: {compare_results['only_in_db']}\n")
        f.write(f"- 匹配率: {compare_results['matched']/compare_results['total_files']*100:.2f}%\n\n")
        
        if compare_results['only_in_files'] == 0 and compare_results['only_in_db'] == 0:
            f.write("## 结论\n\n✅ 所有规则完全一致！\n")
        else:
            f.write("## 结论\n\n❌ 规则存在差异，请检查！\n")
    
    print(f"\n比较结果已保存到: {result_file}")
    
    return 0


if __name__ == "__main__":
    sys.exit(main())
