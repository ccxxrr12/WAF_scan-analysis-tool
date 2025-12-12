import os
import json
import tempfile
from database import RuleDatabase


def test_get_core_rule_content():
    """测试提取核心规则内容"""
    db = RuleDatabase(db_path=':memory:')
    
    # 测试规则
    rule_info = {
        'id': '1234',
        'variables': ['REQUEST_URI', 'QUERY_STRING'],
        'operator': 'contains',
        'pattern': 'attack',
        'is_chain': False,
        'message': 'Test rule',
        'severity': 'CRITICAL'
    }
    
    core_content = db.get_core_rule_content(rule_info)
    
    # 验证核心内容
    assert core_content == {
        'variables': ['QUERY_STRING', 'REQUEST_URI'],  # 应该被排序
        'operator': 'contains',
        'pattern': 'attack',
        'is_chain': False
    }
    
    print("✓ test_get_core_rule_content 测试通过")


def test_same_id_update():
    """测试相同ID规则的更新功能"""
    # 创建临时数据库
    with tempfile.NamedTemporaryFile(suffix='.db', delete=False) as f:
        temp_db_path = f.name
    
    try:
        db = RuleDatabase(db_path=temp_db_path)
        
        # 初始规则
        rule1 = {
            'rule_info': {
                'id': 'test_rule_1',
                'variables': ['REQUEST_URI'],
                'operator': 'contains',
                'pattern': 'old_pattern',
                'is_chain': False
            },
            'semantic_analysis': {},
            'dependency_analysis': {}
        }
        
        # 插入初始规则
        result1 = db.insert(rule1, 'success')
        assert result1 == True, "第一次插入应该成功"
        
        # 修改后的规则，相同ID但不同内容
        rule2 = {
            'rule_info': {
                'id': 'test_rule_1',
                'variables': ['REQUEST_URI'],
                'operator': 'contains',
                'pattern': 'new_pattern',
                'is_chain': False
            },
            'semantic_analysis': {},
            'dependency_analysis': {}
        }
        
        # 插入修改后的规则，应该更新
        result2 = db.insert(rule2, 'success')
        assert result2 == True, "更新操作应该成功"
        
        # 再次插入相同规则，应该跳过
        result3 = db.insert(rule2, 'success')
        assert result3 == False, "相同内容的规则应该跳过"
        
        # 获取规则，验证内容已更新
        updated_rule = db.get_rule_by_id('test_rule_1')
        assert updated_rule['rule_info']['pattern'] == 'new_pattern', "规则内容应该已更新"
        
        print("✓ test_same_id_update 测试通过")
    finally:
        # 清理临时文件
        if os.path.exists(temp_db_path):
            os.remove(temp_db_path)


def test_unknown_id_matching():
    """测试id:unknown规则的相似匹配功能"""
    # 创建临时数据库
    with tempfile.NamedTemporaryFile(suffix='.db', delete=False) as f:
        temp_db_path = f.name
    
    try:
        db = RuleDatabase(db_path=temp_db_path)
        
        # 初始规则，带有明确ID
        rule1 = {
            'rule_info': {
                'id': 'test_rule_2',
                'variables': ['REQUEST_URI'],
                'operator': 'contains',
                'pattern': 'test_pattern',
                'is_chain': False
            },
            'semantic_analysis': {},
            'dependency_analysis': {}
        }
        
        # 插入初始规则
        db.insert(rule1, 'success')
        
        # 相同内容但id:unknown的规则
        rule2 = {
            'rule_info': {
                'id': 'Unknown',
                'variables': ['REQUEST_URI'],
                'operator': 'contains',
                'pattern': 'test_pattern',
                'is_chain': False
            },
            'semantic_analysis': {},
            'dependency_analysis': {}
        }
        
        # 插入id:unknown规则，应该找到相似规则并使用现有ID
        result = db.insert(rule2, 'success')
        assert result == False, "相似规则应该被识别并跳过"
        
        # 不同内容的id:unknown规则
        rule3 = {
            'rule_info': {
                'id': 'Unknown',
                'variables': ['QUERY_STRING'],
                'operator': 'contains',
                'pattern': 'different_pattern',
                'is_chain': False
            },
            'semantic_analysis': {},
            'dependency_analysis': {}
        }
        
        # 插入不同内容的id:unknown规则，应该生成新ID
        result = db.insert(rule3, 'success')
        assert result == True, "不同内容的id:unknown规则应该生成新ID"
        
        # 获取所有规则，验证数量
        all_rules = db.get_all_rules()
        assert len(all_rules) == 2, "应该只有2条规则（一条原有规则，一条新规则）"
        
        print("✓ test_unknown_id_matching 测试通过")
    finally:
        # 清理临时文件
        if os.path.exists(temp_db_path):
            os.remove(temp_db_path)


def test_batch_insert_duplicates():
    """测试批量插入重复规则"""
    # 创建临时数据库
    with tempfile.NamedTemporaryFile(suffix='.db', delete=False) as f:
        temp_db_path = f.name
    
    try:
        db = RuleDatabase(db_path=temp_db_path)
        
        # 创建一组规则，包含重复内容
        rules = []
        for i in range(3):
            rules.append({
                'rule_info': {
                    'id': 'Unknown' if i > 0 else 'batch_test_rule',
                    'variables': ['REQUEST_URI', 'QUERY_STRING'],
                    'operator': 'contains',
                    'pattern': 'batch_pattern',
                    'is_chain': False
                },
                'semantic_analysis': {},
                'dependency_analysis': {}
            })
        
        # 批量插入规则
        db.batch_insert(rules, 'success')
        
        # 获取所有规则，验证数量
        all_rules = db.get_all_rules()
        assert len(all_rules) == 1, "批量插入重复规则后应该只有1条规则"
        
        print("✓ test_batch_insert_duplicates 测试通过")
    finally:
        # 清理临时文件
        if os.path.exists(temp_db_path):
            os.remove(temp_db_path)


if __name__ == "__main__":
    print("开始测试数据库添加逻辑...")
    
    test_get_core_rule_content()
    test_same_id_update()
    test_unknown_id_matching()
    test_batch_insert_duplicates()
    
    print("\n所有测试通过！")
