import sys
import os
import tempfile
import json
from typing import Dict, Any

# 获取Part2目录的绝对路径
part2_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'Part2 analysis', 'part2_rule_analysis', '2.0', 'backend')

# 定义全局变量，将在函数内部动态导入
parse_detailed_rules = None
create_json_output = None
ConflictAnalyzer = None

# 动态导入Part2模块的函数
def _import_part2_modules():
    """动态导入Part2模块，避免与当前目录下的main.py冲突"""
    global parse_detailed_rules, create_json_output, ConflictAnalyzer
    
    # 保存原始sys.path
    original_path = sys.path.copy()
    
    try:
        # 临时添加Part2目录到Python路径，并确保它在最前面
        sys.path = [part2_path] + original_path
        
        # 清除可能存在的模块缓存
        if 'main' in sys.modules:
            del sys.modules['main']
        if 'conflict_analyzer' in sys.modules:
            del sys.modules['conflict_analyzer']
        
        # 从Part2目录导入模块
        import main as part2_main
        import conflict_analyzer as part2_conflict
        
        # 获取所需的函数和类
        parse_detailed_rules = part2_main.parse_detailed_rules
        create_json_output = part2_main.create_json_output
        ConflictAnalyzer = part2_conflict.ConflictAnalyzer
        
        return True
    except Exception as e:
        print(f"导入Part2模块时出错: {e}")
        # 如果导入失败，使用默认实现
        parse_detailed_rules = lambda *args, **kwargs: None
        create_json_output = lambda *args, **kwargs: []
        
        class DefaultConflictAnalyzer:
            def batch_analyze(self, rules):
                return []
        
        ConflictAnalyzer = DefaultConflictAnalyzer
        return False
    finally:
        # 恢复原始sys.path
        sys.path = original_path

# 初始化导入
_import_part2_modules()

def analyze_rules_file(file_content: bytes, filename: str) -> Dict[str, Any]:
    """
    分析上传的WAF规则文件
    
    Args:
        file_content: 文件内容的字节流
        filename: 文件名
        
    Returns:
        包含规则分析结果的字典
    """
    try:
        # 检查文件扩展名，支持.conf、.txt和.rules格式
        if not (filename.endswith('.conf') or filename.endswith('.txt') or filename.endswith('.rules')):
            return {
                "success": False,
                "error": "只支持.conf、.txt和.rules格式的规则文件"
            }
        
        # 创建临时目录和文件
        with tempfile.TemporaryDirectory() as temp_dir:
            # 创建规则文件
            rule_file_path = os.path.join(temp_dir, filename)
            with open(rule_file_path, 'wb') as f:
                f.write(file_content)
            
            # 创建结果目录
            results_dir = os.path.join(temp_dir, 'results')
            os.makedirs(results_dir, exist_ok=True)
            
            # 生成报告文件路径
            output_file = os.path.join(results_dir, "detailed_rules_report.md")
            json_output_file = os.path.join(results_dir, "detailed_rules_report.json")
            
            # 调用Part2的分析函数
            # 首先分析规则文件
            parse_detailed_rules(temp_dir, output_file)
            
            # 创建JSON输出
            all_rules = create_json_output(temp_dir, json_output_file)
            
            # 执行冲突分析
            conflicts = []
            if all_rules:
                conflict_analyzer = ConflictAnalyzer()
                conflicts = conflict_analyzer.batch_analyze(all_rules)
            
            # 构建最终结果
            final_result = {
                "filename": filename,
                "rule_count": len(all_rules),
                "conflict_count": len(conflicts),
                "rules": all_rules,
                "conflicts": conflicts
            }
            
            return {
                "success": True,
                "data": final_result
            }
            
    except Exception as e:
        return {
            "success": False,
            "error": str(e)
        }

# 测试函数
if __name__ == "__main__":
    # 测试代码
    test_file_path = os.path.join(part2_path, '..', 'rules', 'restricted-files.data')
    if os.path.exists(test_file_path):
        with open(test_file_path, 'rb') as f:
            content = f.read()
        result = analyze_rules_file(content, 'test.conf')
        print(f"规则分析结果: {json.dumps(result, indent=2, ensure_ascii=False)}")
    else:
        print("测试文件不存在")
