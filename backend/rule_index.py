#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
规则索引模块
"""

import os
import sqlite3
from pathlib import Path

# 默认数据库路径
DEFAULT_DB_PATH = str(Path(__file__).parent.parent / 'rules.db')

def init_db(db_path=DEFAULT_DB_PATH):
    """
    初始化规则索引数据库
    
    参数:
        db_path: 数据库文件路径
    
    返回:
        str: 数据库文件路径
    """
    # 创建数据库目录
    db_dir = os.path.dirname(db_path)
    if not os.path.exists(db_dir):
        os.makedirs(db_dir, exist_ok=True)
    
    # 连接数据库
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    # 创建规则表
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS rules (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            rule_id TEXT,
            node_type TEXT,
            line INTEGER,
            raw TEXT,
            tags TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    # 创建索引
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_rule_id ON rules(rule_id)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_node_type ON rules(node_type)')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_tags ON rules(tags)')
    
    # 提交并关闭连接
    conn.commit()
    conn.close()
    
    return db_path

def insert_rule(rule, db_path=DEFAULT_DB_PATH):
    """
    插入规则到索引数据库
    
    参数:
        rule: 规则字典
        db_path: 数据库文件路径
    """
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    # 提取规则字段
    rule_id = rule.get('id')
    node_type = rule.get('node_type')
    line = rule.get('line')
    raw = rule.get('raw')
    tags = ','.join(rule.get('tags', []))
    
    # 插入规则
    cursor.execute('''
        INSERT INTO rules (rule_id, node_type, line, raw, tags) 
        VALUES (?, ?, ?, ?, ?)
    ''', (rule_id, node_type, line, raw, tags))
    
    # 提交并关闭连接
    conn.commit()
    conn.close()

def search_rules(query, db_path=DEFAULT_DB_PATH):
    """
    搜索规则
    
    参数:
        query: 搜索条件
        db_path: 数据库文件路径
    
    返回:
        list: 匹配的规则列表
    """
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    # 搜索规则
    cursor.execute('''
        SELECT * FROM rules 
        WHERE rule_id LIKE ? OR node_type LIKE ? OR raw LIKE ? OR tags LIKE ?
    ''', (f'%{query}%', f'%{query}%', f'%{query}%', f'%{query}%'))
    
    # 获取结果
    results = cursor.fetchall()
    
    # 关闭连接
    conn.close()
    
    # 转换为字典格式
    rules = []
    for row in results:
        rules.append({
            'id': row[0],
            'rule_id': row[1],
            'node_type': row[2],
            'line': row[3],
            'raw': row[4],
            'tags': row[5].split(',') if row[5] else [],
            'created_at': row[6]
        })
    
    return rules

def get_all_rules(db_path=DEFAULT_DB_PATH):
    """
    获取所有规则
    
    参数:
        db_path: 数据库文件路径
    
    返回:
        list: 所有规则列表
    """
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    # 获取所有规则
    cursor.execute('SELECT * FROM rules')
    
    # 获取结果
    results = cursor.fetchall()
    
    # 关闭连接
    conn.close()
    
    # 转换为字典格式
    rules = []
    for row in results:
        rules.append({
            'id': row[0],
            'rule_id': row[1],
            'node_type': row[2],
            'line': row[3],
            'raw': row[4],
            'tags': row[5].split(',') if row[5] else [],
            'created_at': row[6]
        })
    
    return rules

def delete_rule(rule_id, db_path=DEFAULT_DB_PATH):
    """
    删除规则
    
    参数:
        rule_id: 规则ID
        db_path: 数据库文件路径
    """
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    # 删除规则
    cursor.execute('DELETE FROM rules WHERE rule_id = ?', (rule_id,))
    
    # 提交并关闭连接
    conn.commit()
    conn.close()

def clear_rules(db_path=DEFAULT_DB_PATH):
    """
    清空所有规则
    
    参数:
        db_path: 数据库文件路径
    """
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    
    # 清空规则表
    cursor.execute('DELETE FROM rules')
    
    # 提交并关闭连接
    conn.commit()
    conn.close()
