import sys
import os
import glob
import json
from datetime import datetime

# Add the project directory to the Python path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'msc_pyparser-master'))

from msc_pyparser import MSCParser

# Import backend components
from semantic_analyzer import SemanticAnalyzer
from dependency_analyzer import DependencyAnalyzer
from conflict_analyzer import ConflictAnalyzer
from database import RuleDatabase
from visualizer import RuleFlowVisualizer, AttackTypeVisualizer, ConflictVisualizer, DependencyVisualizer, ASTVisualizer

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

def parse_detailed_rules(rules_dir, output_file):
    """Parse ModSecurity rules with detailed rule information"""
    # Get all .conf files in the rules directory
    conf_files = glob.glob(os.path.join(rules_dir, '*.conf'))
    conf_files.sort()
    
    with open(output_file, 'w', encoding='utf-8') as f:
        f.write("# Detailed ModSecurity Rules Parsing Report\n\n")
        f.write(f"Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write(f"Rules directory: {rules_dir}\n")
        f.write(f"Total files: {len(conf_files)}\n\n")
        f.write("="*100 + "\n\n")
        
        for file_path in conf_files:
            filename = os.path.basename(file_path)
            f.write(f"## File: {filename}\n\n")
            
            try:
                with open(file_path, 'r', encoding='utf-8') as rule_file:
                    content = rule_file.read()
                
                # Create parser instance
                parser = MSCParser()
                parser.parser.parse(content)
                
                # Find all SecRule items
                secrules = [item for item in parser.configlines if item['type'] == 'SecRule']
                
                f.write(f"### File Summary\n")
                f.write(f"- Total rules: {len(secrules)}\n")
                f.write(f"- Chained rules: {sum(1 for rule in secrules if rule.get('chained', False))}\n")
                f.write(f"- Non-chained rules: {sum(1 for rule in secrules if not rule.get('chained', False))}\n\n")
                
                f.write(f"### Detailed Rules\n\n")
                
                for i, rule in enumerate(secrules):
                    # Extract detailed rule info
                    rule_info = parse_rule_details(rule)
                    
                    f.write(f"#### Rule {i+1}: {rule_info['id']}\n")
                    f.write(f"- **Phase**: {rule_info['phase']}\n")
                    f.write(f"- **Variables**: {', '.join(rule_info['variables'])}\n")
                    f.write(f"- **Operator**: {rule_info['operator']}\n")
                    f.write(f"- **Pattern**: {rule_info['pattern']}\n")
                    f.write(f"- **Is Chain**: {rule_info['is_chain']}\n")
                    f.write(f"- **Message**: {rule_info['message']}\n")
                    f.write(f"- **Severity**: {rule_info['severity']}\n")
                    
                    if rule_info['tags']:
                        f.write(f"- **Tags**: {', '.join(rule_info['tags'])}\n")
                    
                    if rule_info['actions']:
                        f.write(f"- **Actions**: {', '.join(rule_info['actions'])}\n")
                    
                    f.write("\n")
                
                f.write("\n" + "="*100 + "\n\n")
                
            except UnicodeDecodeError:
                # Try with different encoding
                try:
                    with open(file_path, 'r', encoding='gbk') as rule_file:
                        content = rule_file.read()
                    
                    # Create parser instance
                    parser = MSCParser()
                    parser.parser.parse(content)
                    
                    # Find all SecRule items
                    secrules = [item for item in parser.configlines if item['type'] == 'SecRule']
                    
                    f.write(f"### File Summary\n")
                    f.write(f"- Total rules: {len(secrules)}\n")
                    f.write(f"- Chained rules: {sum(1 for rule in secrules if rule.get('chained', False))}\n")
                    f.write(f"- Non-chained rules: {sum(1 for rule in secrules if not rule.get('chained', False))}\n\n")
                    
                    f.write(f"### Detailed Rules\n\n")
                    
                    for i, rule in enumerate(secrules):
                        # Extract detailed rule info
                        rule_info = parse_rule_details(rule)
                        
                        f.write(f"#### Rule {i+1}: {rule_info['id']}\n")
                        f.write(f"- **Phase**: {rule_info['phase']}\n")
                        f.write(f"- **Variables**: {', '.join(rule_info['variables'])}\n")
                        f.write(f"- **Operator**: {rule_info['operator']}\n")
                        f.write(f"- **Pattern**: {rule_info['pattern']}\n")
                        f.write(f"- **Is Chain**: {rule_info['is_chain']}\n")
                        f.write(f"- **Message**: {rule_info['message']}\n")
                        f.write(f"- **Severity**: {rule_info['severity']}\n")
                        
                        if rule_info['tags']:
                            f.write(f"- **Tags**: {', '.join(rule_info['tags'])}\n")
                        
                        if rule_info['actions']:
                            f.write(f"- **Actions**: {', '.join(rule_info['actions'])}\n")
                        
                        f.write("\n")
                    
                    f.write("\n" + "="*100 + "\n\n")
                    
                except Exception as e:
                    f.write(f"### Parsing Error\n")
                    f.write(f"Error parsing {filename}: {e}\n\n")
                    f.write("="*100 + "\n\n")
                    continue
            except Exception as e:
                f.write(f"### Parsing Error\n")
                f.write(f"Error parsing {filename}: {e}\n\n")
                f.write("="*100 + "\n\n")
                continue
    
    print(f"Detailed parsing report generated: {output_file}")
    print(f"Total files parsed: {len(conf_files)}")

def main():
    """Main function"""
    # Get the parent directory path
    parent_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    rules_dir = os.path.join(parent_dir, "rules")
    
    # Set analysis results directory
    analysis_results_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "analysis_results")
    
    # Ensure analysis results directory exists
    if not os.path.exists(analysis_results_dir):
        os.makedirs(analysis_results_dir)
    
    output_file = os.path.join(analysis_results_dir, "detailed_rules_report.md")
    
    parse_detailed_rules(rules_dir, output_file)
    
    # Create JSON output with all analysis results
    json_output_file = os.path.join(analysis_results_dir, "detailed_rules_report.json")
    all_rules = create_json_output(rules_dir, json_output_file)
    
    # Perform conflict analysis
    if all_rules:
        print("\n=== Starting Conflict Analysis ===")
        conflict_analyzer = ConflictAnalyzer()
        conflicts = conflict_analyzer.batch_analyze(all_rules)
        
        # Write conflict results to JSON
        conflict_file = os.path.join(analysis_results_dir, "detailed_rules_conflicts.json")
        with open(conflict_file, 'w', encoding='utf-8') as f:
            json.dump(conflicts, f, indent=2, ensure_ascii=False)
        print(f"Conflict analysis results written to: {conflict_file}")
        print(f"Total conflicts found: {len(conflicts)}")
        
        # Store results in database
        print("\n=== Storing Results in Database ===")
        db_path = os.path.join(analysis_results_dir, "rules.db")
        
        # 设置备份目录到analysis_results下的backups子目录
        backup_dir = os.path.join(analysis_results_dir, "backups")
        
        # 清理旧的备份目录（在backend根目录下的备份目录）
        old_backup_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "backups")
        if os.path.exists(old_backup_dir) and os.path.isdir(old_backup_dir):
            import shutil
            shutil.rmtree(old_backup_dir)
            print(f"已清理旧的备份目录: {old_backup_dir}")
        
        # 初始化数据库，默认不启用自动备份
        db = RuleDatabase(db_path=db_path, backup_dir=backup_dir, auto_backup=False)
        db.batch_insert(all_rules, "success", [str(rule) for rule in all_rules])
        print(f"Results stored in database: {db_path}")
        
        # Generate visualizations
        print("\n=== Generating Visualizations ===")
        ruleflow_visualizer = RuleFlowVisualizer()
        ruleflow_file = os.path.join(analysis_results_dir, "rule_processing_flow.html")
        ruleflow_visualizer.save_ruleflow_file(all_rules, ruleflow_file)
        print(f"Rule flow visualization generated: {ruleflow_file}")
        
        attack_visualizer = AttackTypeVisualizer()
        attack_file = os.path.join(analysis_results_dir, "attack_type_distribution.html")
        attack_visualizer.save_attack_type_file(all_rules, attack_file)
        print(f"Attack type distribution visualization generated: {attack_file}")
        
        conflict_visualizer = ConflictVisualizer()
        conflict_viz_file = os.path.join(analysis_results_dir, "conflict_analysis.html")
        conflict_visualizer.save_conflict_file(conflicts, conflict_viz_file)
        print(f"Conflict analysis visualization generated: {conflict_viz_file}")

def create_json_output(rules_dir, output_file):
    """Create JSON output with structured rule data"""
    # Get all .conf files in the rules directory
    conf_files = glob.glob(os.path.join(rules_dir, '*.conf'))
    conf_files.sort()
    
    # Initialize analyzers
    semantic_analyzer = SemanticAnalyzer()
    dependency_analyzer = DependencyAnalyzer()
    
    all_rules = {}
    all_rules_list = []
    
    for file_path in conf_files:
        filename = os.path.basename(file_path)
        file_rules = []
        
        try:
            # Try different encodings
            try:
                with open(file_path, 'r', encoding='utf-8') as rule_file:
                    content = rule_file.read()
            except UnicodeDecodeError:
                with open(file_path, 'r', encoding='gbk') as rule_file:
                    content = rule_file.read()
            
            # Create parser instance
            parser = MSCParser()
            parser.parser.parse(content)
            
            # Find all SecRule items
            secrules = [item for item in parser.configlines if item['type'] == 'SecRule']
            
            for i, rule in enumerate(secrules):
                # Extract detailed rule info
                rule_info = parse_rule_details(rule)
                
                # Create rule object with all analysis
                full_rule = {
                    'rule_info': rule_info,
                    'file_name': filename,
                    'rule_index': i
                }
                
                # Perform semantic analysis
                semantic_result = semantic_analyzer.analyze(full_rule)
                full_rule['semantic_analysis'] = semantic_result
                
                # Perform dependency analysis
                dependency_result = dependency_analyzer.analyze(full_rule, str(rule))
                full_rule['dependency_analysis'] = dependency_result
                
                # Add to lists
                file_rules.append(full_rule)
                all_rules_list.append(full_rule)
            
            all_rules[filename] = file_rules
            
        except Exception as e:
            print(f"Error parsing {filename} for JSON output: {e}")
            continue
    
    # Write JSON output
    with open(output_file, 'w', encoding='utf-8') as f:
        json.dump(all_rules, f, indent=2, ensure_ascii=False)
    
    # Write combined rules list for further analysis
    combined_file = output_file.replace('.json', '_combined.json')
    with open(combined_file, 'w', encoding='utf-8') as f:
        json.dump(all_rules_list, f, indent=2, ensure_ascii=False)
    
    print(f"JSON output generated: {output_file}")
    print(f"Combined JSON output generated: {combined_file}")
    
    return all_rules_list

if __name__ == "__main__":
    main()
