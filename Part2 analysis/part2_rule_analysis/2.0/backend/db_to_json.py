import sys
import os
import json
import sqlite3
from datetime import datetime

# Add the project directory to the Python path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'msc_pyparser-master'))


class DatabaseExporter:
    """数据库导出类"""
    
    def __init__(self, db_path):
        """初始化数据库连接"""
        self.db_path = db_path
    
    def get_all_rules(self):
        """获取所有规则"""
        print(f"正在从数据库中读取所有规则: {self.db_path}")
        
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        
        # 查询所有规则
        cursor.execute('SELECT * FROM rules ORDER BY id')
        rows = cursor.fetchall()
        
        total_rules = len(rows)
        print(f"查询到的规则总数: {total_rules}")
        
        rules = []
        for row in rows:
            # 转换为字典
            rule_dict = {
                'id': row['id'],
                'rule_info': json.loads(row['rule_info']),
                'semantic_analysis': json.loads(row['semantic_analysis']),
                'dependency_analysis': json.loads(row['dependency_analysis']),
                'parse_status': row['parse_status'],
                'raw_rule': row['raw_rule'],
                'rule_type': row['rule_type'],
                'phase': row['phase'],
                'variables': json.loads(row['variables']),
                'operator': row['operator'],
                'pattern': row['pattern'],
                'actions': json.loads(row['actions']),
                'tags': json.loads(row['tags']),
                'message': row['message'],
                'severity': row['severity'],
                'is_chain': bool(row['is_chain']),
                'attack_types': json.loads(row['attack_types']),
                'protection_layer': row['protection_layer'],
                'matching_method': row['matching_method'],
                'scenario': row['scenario'],
                'variable_dependencies': json.loads(row['variable_dependencies']),
                'marker_dependencies': json.loads(row['marker_dependencies']),
                'include_dependencies': json.loads(row['include_dependencies']),
                'created_at': row['created_at'],
                'updated_at': row['updated_at']
            }
            rules.append(rule_dict)
        
        conn.close()
        return rules
    
    def export_to_json(self, output_file):
        """将所有规则导出为JSON文件"""
        rules = self.get_all_rules()
        
        print(f"正在将规则导出到JSON文件: {output_file}")
        
        # 写入JSON文件
        with open(output_file, 'w', encoding='utf-8') as f:
            json.dump(rules, f, indent=2, ensure_ascii=False, default=str)
        
        print(f"成功导出 {len(rules)} 条规则到JSON文件")
        return len(rules)


def main():
    """主函数"""
    # Set analysis results directory
    analysis_results_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "analysis_results")
    db_path = os.path.join(analysis_results_dir, "rules.db")
    
    # Check if database exists
    if not os.path.exists(db_path):
        print(f"错误: 数据库文件不存在 {db_path}")
        print("请先运行 main.py 生成数据库")
        return 1
    
    # Create exporter instance
    exporter = DatabaseExporter(db_path)
    
    # Export to JSON
    output_file = os.path.join(analysis_results_dir, "database_rules_export.json")
    exported_count = exporter.export_to_json(output_file)
    
    # Print summary
    print(f"\n=== 导出完成 ===")
    print(f"导出的规则数量: {exported_count}")
    print(f"JSON文件路径: {output_file}")
    print(f"导出时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    
    return 0


if __name__ == "__main__":
    sys.exit(main())
