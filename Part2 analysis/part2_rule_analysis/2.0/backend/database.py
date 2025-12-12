import sqlite3
import json
import logging
import os
import gzip
import shutil
from datetime import datetime, timedelta
from typing import List, Dict, Any, Optional

logger = logging.getLogger(__name__)

class RuleDatabase:
    """规则数据库操作类"""
    
    def __init__(self, db_path='rules.db', backup_dir=None, auto_backup=False, retention_days=7):
        """初始化数据库连接
        
        Args:
            db_path: 数据库文件路径
            backup_dir: 备份目录路径，如果为None，则使用数据库所在目录下的backups子目录
            auto_backup: 是否启用自动备份
            retention_days: 备份保留天数
        """
        self.db_path = db_path
        
        # 设置备份目录
        if backup_dir:
            self.backup_dir = backup_dir
        else:
            # 如果没有指定备份目录，使用数据库所在目录下的backups子目录
            db_dir = os.path.dirname(os.path.abspath(self.db_path))
            self.backup_dir = os.path.join(db_dir, 'backups')
        
        self.auto_backup_enabled = auto_backup
        self.retention_days = retention_days
        
        # 只有当启用自动备份时才创建备份目录
        if self.auto_backup_enabled:
            os.makedirs(self.backup_dir, exist_ok=True)
        
        self._init_db()
    
    def _init_db(self):
        """初始化数据库表结构"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # 创建规则表，添加更多结构化字段
            cursor.execute('''
            CREATE TABLE IF NOT EXISTS rules (
                id TEXT PRIMARY KEY,
                rule_info TEXT NOT NULL,
                semantic_analysis TEXT NOT NULL,
                dependency_analysis TEXT NOT NULL,
                parse_status TEXT NOT NULL,
                raw_rule TEXT,
                -- 结构化字段
                rule_type TEXT,
                phase TEXT,
                variables TEXT,  -- JSON数组格式存储
                operator TEXT,
                pattern TEXT,
                actions TEXT,    -- JSON数组格式存储
                tags TEXT,       -- JSON数组格式存储
                message TEXT,
                severity TEXT,
                is_chain INTEGER,
                -- 语义分析结构化字段
                attack_types TEXT,  -- JSON数组格式存储
                protection_layer TEXT,
                matching_method TEXT,
                scenario TEXT,
                -- 依赖分析结构化字段
                variable_dependencies TEXT,  -- JSON数组格式存储
                marker_dependencies TEXT,    -- JSON数组格式存储
                include_dependencies TEXT,   -- JSON数组格式存储
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
            ''')
            
            # 创建索引
            # 基础索引
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_rules_id ON rules (id)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_rules_severity ON rules (severity)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_rules_phase ON rules (phase)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_rules_parse_status ON rules (parse_status)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_rules_rule_type ON rules (rule_type)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_rules_operator ON rules (operator)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_rules_protection_layer ON rules (protection_layer)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_rules_matching_method ON rules (matching_method)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_rules_scenario ON rules (scenario)')
            
            # 新增：联合索引，提高查询性能
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_rules_phase_severity ON rules (phase, severity)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_rules_phase_protection ON rules (phase, protection_layer)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_rules_rule_type_phase ON rules (rule_type, phase)')
            cursor.execute('CREATE INDEX IF NOT EXISTS idx_rules_created_at ON rules (created_at)')
            
            # 新增：全文搜索支持
            cursor.execute('''
            CREATE VIRTUAL TABLE IF NOT EXISTS rules_fts USING FTS5(
                id,
                message,
                pattern,
                tags,
                attack_types,
                content=rules, 
                content_rowid=rowid
            )
            ''')
            
            # 创建触发器，自动更新FTS表
            cursor.execute('''
            CREATE TRIGGER IF NOT EXISTS rules_ai AFTER INSERT ON rules BEGIN
                INSERT INTO rules_fts(rowid, id, message, pattern, tags, attack_types)
                VALUES (new.rowid, new.id, new.message, new.pattern, new.tags, new.attack_types);
            END;
            ''')
            
            cursor.execute('''
            CREATE TRIGGER IF NOT EXISTS rules_ad AFTER DELETE ON rules BEGIN
                DELETE FROM rules_fts WHERE rowid = old.rowid;
            END;
            ''')
            
            cursor.execute('''
            CREATE TRIGGER IF NOT EXISTS rules_au AFTER UPDATE ON rules BEGIN
                UPDATE rules_fts SET
                    id = new.id,
                    message = new.message,
                    pattern = new.pattern,
                    tags = new.tags,
                    attack_types = new.attack_types
                WHERE rowid = new.rowid;
            END;
            ''')
            
            conn.commit()
            conn.close()
            logger.info("数据库初始化成功")
        except Exception as e:
            logger.error(f"数据库初始化失败: {e}")
            raise
    
    def backup(self, backup_name=None):
        """备份数据库
        
        Args:
            backup_name: 备份文件名，不包含扩展名。如果为None，将使用时间戳作为文件名
        
        Returns:
            str: 备份文件的完整路径
        """
        try:
            if not backup_name:
                # 使用时间戳作为备份文件名
                timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
                backup_name = f'backup_{timestamp}'
            
            # 创建备份文件路径
            backup_path = os.path.join(self.backup_dir, f'{backup_name}.db.gz')
            
            # 连接到数据库
            conn = sqlite3.connect(self.db_path)
            
            # 创建备份
            with gzip.open(backup_path, 'wb') as f:
                for line in conn.iterdump():
                    f.write((line + '\n').encode('utf-8'))
            
            conn.close()
            logger.info(f"数据库备份成功: {backup_path}")
            return backup_path
        except Exception as e:
            logger.error(f"数据库备份失败: {e}")
            raise
    
    def restore(self, backup_path):
        """从备份恢复数据库
        
        Args:
            backup_path: 备份文件的完整路径
        """
        try:
            # 确保备份文件存在
            if not os.path.exists(backup_path):
                raise FileNotFoundError(f"备份文件不存在: {backup_path}")
            
            # 关闭可能存在的数据库连接
            conn = sqlite3.connect(self.db_path)
            conn.close()
            
            # 从备份恢复
            if backup_path.endswith('.gz'):
                # 压缩备份
                with gzip.open(backup_path, 'rb') as f:
                    sql_script = f.read().decode('utf-8')
            else:
                # 非压缩备份
                with open(backup_path, 'r', encoding='utf-8') as f:
                    sql_script = f.read()
            
            # 执行恢复操作
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.executescript(sql_script)
            conn.commit()
            conn.close()
            
            logger.info(f"数据库恢复成功: {backup_path}")
        except Exception as e:
            logger.error(f"数据库恢复失败: {e}")
            raise
    
    def auto_backup(self, retention_days=7):
        """自动备份数据库并清理旧备份
        
        Args:
            retention_days: 备份保留天数
        """
        try:
            # 创建新备份
            backup_path = self.backup()
            
            # 清理旧备份
            self._cleanup_old_backups(retention_days)
            
            return backup_path
        except Exception as e:
            logger.error(f"自动备份失败: {e}")
            raise
    
    def _cleanup_old_backups(self, retention_days):
        """清理旧备份
        
        Args:
            retention_days: 备份保留天数
        """
        try:
            cutoff_date = datetime.now() - timedelta(days=retention_days)
            
            # 遍历备份目录，删除超过保留天数的备份
            for filename in os.listdir(self.backup_dir):
                if filename.endswith('.db.gz'):
                    backup_path = os.path.join(self.backup_dir, filename)
                    # 获取文件修改时间
                    mtime = datetime.fromtimestamp(os.path.getmtime(backup_path))
                    # 如果文件修改时间早于截止日期，则删除
                    if mtime < cutoff_date:
                        os.remove(backup_path)
                        logger.info(f"删除旧备份: {backup_path}")
        except Exception as e:
            logger.error(f"清理旧备份失败: {e}")
            raise
    
    def search_rules(self, query, limit=100):
        """使用全文搜索查找规则
        
        Args:
            query: 搜索查询
            limit: 返回结果的最大数量
        
        Returns:
            List[Dict]: 匹配的规则列表
        """
        try:
            conn = sqlite3.connect(self.db_path)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            
            # 使用FTS表进行全文搜索
            cursor.execute('''
            SELECT r.* FROM rules r
            JOIN rules_fts fts ON r.rowid = fts.rowid
            WHERE fts MATCH ?
            LIMIT ?
            ''', (query, limit))
            
            rows = cursor.fetchall()
            conn.close()
            
            # 转换结果为字典列表
            results = []
            for row in rows:
                results.append({
                    'id': row['id'],
                    'rule_info': json.loads(row['rule_info']),
                    'semantic_analysis': json.loads(row['semantic_analysis']),
                    'dependency_analysis': json.loads(row['dependency_analysis']),
                    'parse_status': row['parse_status'],
                    'raw_rule': row['raw_rule']
                })
            
            return results
        except Exception as e:
            logger.error(f"搜索规则失败: {e}")
            return []
    
    def batch_insert(self, rules: List[Dict], parse_status: str, raw_rules: Optional[List[str]] = None):
        """批量插入规则"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            inserted_count = 0
            updated_count = 0
            
            # 用于跟踪本次批量插入中已处理的规则核心内容和对应的ID
            processed_rules = {}
            
            for i, rule in enumerate(rules):
                rule_info = rule.get('rule_info', {})
                semantic_analysis = rule.get('semantic_analysis', {})
                dependency_analysis = rule.get('dependency_analysis', {})
                
                rule_id = rule_info.get('id')
                raw_rule = raw_rules[i] if raw_rules and i < len(raw_rules) else None
                
                # 提取核心规则内容，用于比较
                current_core = self.get_core_rule_content(rule_info)
                
                # 生成核心内容的哈希键，用于快速查找
                # 将列表转换为元组，确保所有值都是可哈希的
                hashable_core = {}
                for key, value in current_core.items():
                    if isinstance(value, list):
                        hashable_core[key] = tuple(value)
                    else:
                        hashable_core[key] = value
                core_hash = tuple(sorted(hashable_core.items()))
                
                # 处理id:unknown的情况
                if not rule_id or rule_id == "Unknown":
                    # 先检查本次批量处理中是否已经有相似规则
                    if core_hash in processed_rules:
                        # 找到相似规则，使用现有ID
                        rule_id = processed_rules[core_hash]
                        rule_info['id'] = rule_id
                        logger.debug(f"批量处理中找到相似规则，使用现有ID: {rule_id}")
                    else:
                        # 搜索数据库中是否有相似规则
                        variables_str = json.dumps(sorted(rule_info.get('variables', [])))
                        operator = rule_info.get('operator', '')
                        pattern = rule_info.get('pattern', '')
                        is_chain = 1 if rule_info.get('is_chain', False) else 0
                        
                        cursor.execute('''
                        SELECT id, rule_info FROM rules 
                        WHERE variables = ? AND operator = ? AND pattern = ? AND is_chain = ?
                        ''', (variables_str, operator, pattern, is_chain))
                        
                        existing_rule = cursor.fetchone()
                        if existing_rule:
                            # 找到相似规则，使用现有ID
                            rule_id = existing_rule[0]
                            rule_info['id'] = rule_id
                            logger.debug(f"找到相似规则，使用现有ID: {rule_id}")
                            # 将该规则添加到已处理列表
                            processed_rules[core_hash] = rule_id
                        else:
                            # 没有找到相似规则，生成唯一ID
                            import uuid
                            rule_id = f"no_id_{uuid.uuid4().hex}"
                            rule_info['id'] = rule_id
                            logger.debug(f"生成新规则ID: {rule_id}")
                
                # 检查规则是否已存在（包括本次批量处理中已插入的规则）
                existing_rule = None
                if rule_id in processed_rules.values():
                    # 本次批量处理中已插入该ID的规则
                    existing_rule = True
                else:
                    # 检查数据库中是否存在该ID的规则
                    cursor.execute('SELECT id, rule_info FROM rules WHERE id = ?', (rule_id,))
                    existing_rule = cursor.fetchone()
                    
                if existing_rule:
                    # 规则已存在，比较核心内容
                    if isinstance(existing_rule, tuple):
                        # 从数据库中获取的规则
                        existing_rule_info = json.loads(existing_rule[1])
                        existing_core = self.get_core_rule_content(existing_rule_info)
                    else:
                        # 本次批量处理中已插入的规则
                        existing_core = current_core
                    
                    if current_core != existing_core:
                        # 核心内容发生变化，执行更新操作
                        cursor.execute('''
                        UPDATE rules SET 
                            rule_info = ?, semantic_analysis = ?, dependency_analysis = ?, 
                            parse_status = ?, raw_rule = ?, rule_type = ?, phase = ?, 
                            variables = ?, operator = ?, pattern = ?, actions = ?, 
                            tags = ?, message = ?, severity = ?, is_chain = ?, 
                            attack_types = ?, protection_layer = ?, matching_method = ?, 
                            scenario = ?, variable_dependencies = ?, 
                            marker_dependencies = ?, include_dependencies = ?, 
                            updated_at = CURRENT_TIMESTAMP
                        WHERE id = ?
                        ''', (
                            json.dumps(rule_info),
                            json.dumps(semantic_analysis),
                            json.dumps(dependency_analysis),
                            parse_status,
                            raw_rule,
                            rule_info.get('type'),
                            rule_info.get('phase'),
                            json.dumps(rule_info.get('variables', [])),
                            rule_info.get('operator'),
                            rule_info.get('pattern'),
                            json.dumps(rule_info.get('actions', [])),
                            json.dumps(rule_info.get('tags', [])),
                            rule_info.get('message'),
                            rule_info.get('severity'),
                            1 if rule_info.get('is_chain') else 0,
                            json.dumps(semantic_analysis.get('attack_types', [])),
                            semantic_analysis.get('rule_classification', {}).get('protection_layer') if isinstance(semantic_analysis.get('rule_classification'), dict) else None,
                            semantic_analysis.get('rule_classification', {}).get('matching_method') if isinstance(semantic_analysis.get('rule_classification'), dict) else None,
                            semantic_analysis.get('rule_classification', {}).get('scenario') if isinstance(semantic_analysis.get('rule_classification'), dict) else None,
                            json.dumps(dependency_analysis.get('variable_dependencies', [])),
                            json.dumps(dependency_analysis.get('marker_dependencies', [])),
                            json.dumps(dependency_analysis.get('include_dependencies', [])),
                            rule_id
                        ))
                        updated_count += 1
                        logger.debug(f"规则 {rule_id} 已更新")
                        # 更新已处理规则列表
                        processed_rules[core_hash] = rule_id
                    else:
                        # 核心内容未变化，跳过
                        logger.debug(f"规则 {rule_id} 内容未变化，跳过")
                        # 将该规则添加到已处理列表
                        processed_rules[core_hash] = rule_id
                        continue
                else:
                    # 规则不存在，插入新规则
                    cursor.execute('''
                    INSERT INTO rules (
                        id, rule_info, semantic_analysis, dependency_analysis, parse_status, raw_rule,
                        rule_type, phase, variables, operator, pattern, actions, tags, message, severity, is_chain,
                        attack_types, protection_layer, matching_method, scenario,
                        variable_dependencies, marker_dependencies, include_dependencies
                    )
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    ''', (
                        rule_id,
                        json.dumps(rule_info),
                        json.dumps(semantic_analysis),
                        json.dumps(dependency_analysis),
                        parse_status,
                        raw_rule,
                        rule_info.get('type'),
                        rule_info.get('phase'),
                        json.dumps(rule_info.get('variables', [])),
                        rule_info.get('operator'),
                        rule_info.get('pattern'),
                        json.dumps(rule_info.get('actions', [])),
                        json.dumps(rule_info.get('tags', [])),
                        rule_info.get('message'),
                        rule_info.get('severity'),
                        1 if rule_info.get('is_chain') else 0,
                        json.dumps(semantic_analysis.get('attack_types', [])),
                        semantic_analysis.get('rule_classification', {}).get('protection_layer') if isinstance(semantic_analysis.get('rule_classification'), dict) else None,
                        semantic_analysis.get('rule_classification', {}).get('matching_method') if isinstance(semantic_analysis.get('rule_classification'), dict) else None,
                        semantic_analysis.get('rule_classification', {}).get('scenario') if isinstance(semantic_analysis.get('rule_classification'), dict) else None,
                        json.dumps(dependency_analysis.get('variable_dependencies', [])),
                        json.dumps(dependency_analysis.get('marker_dependencies', [])),
                        json.dumps(dependency_analysis.get('include_dependencies', []))
                    ))
                    inserted_count += 1
                    logger.debug(f"规则 {rule_id} 已插入")
                    # 将该规则添加到已处理列表
                    processed_rules[core_hash] = rule_id
            
            conn.commit()
            conn.close()
            logger.info(f"成功批量处理 {inserted_count + updated_count} 条规则，其中插入 {inserted_count} 条，更新 {updated_count} 条")
        except Exception as e:
            logger.error(f"批量插入规则失败: {e}")
            raise
    
    def insert(self, rule: Dict, parse_status: str, raw_rule: Optional[str] = None):
        """插入或更新单条规则"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            rule_info = rule.get('rule_info', {})
            semantic_analysis = rule.get('semantic_analysis', {})
            dependency_analysis = rule.get('dependency_analysis', {})
            
            rule_id = rule_info.get('id')
            
            # 提取核心规则内容，用于比较
            current_core = self.get_core_rule_content(rule_info)
            
            # 处理id:unknown的情况
            if not rule_id or rule_id == "Unknown":
                # 搜索数据库中是否有相似规则
                variables_str = json.dumps(sorted(rule_info.get('variables', [])))
                operator = rule_info.get('operator', '')
                pattern = rule_info.get('pattern', '')
                is_chain = 1 if rule_info.get('is_chain', False) else 0
                
                cursor.execute('''
                SELECT id, rule_info FROM rules 
                WHERE variables = ? AND operator = ? AND pattern = ? AND is_chain = ?
                ''', (variables_str, operator, pattern, is_chain))
                
                existing_rule = cursor.fetchone()
                if existing_rule:
                    # 找到相似规则，使用现有ID
                    rule_id = existing_rule[0]
                    rule_info['id'] = rule_id
                    logger.debug(f"找到相似规则，使用现有ID: {rule_id}")
                else:
                    # 没有找到相似规则，生成唯一ID
                    import uuid
                    rule_id = f"no_id_{uuid.uuid4().hex}"
                    rule_info['id'] = rule_id
                    logger.debug(f"生成新规则ID: {rule_id}")
            
            # 检查规则是否已存在
            cursor.execute('SELECT id, rule_info FROM rules WHERE id = ?', (rule_id,))
            existing_rule = cursor.fetchone()
            
            if existing_rule:
                # 规则已存在，比较核心内容是否变化
                existing_rule_info = json.loads(existing_rule[1])
                existing_core = self.get_core_rule_content(existing_rule_info)
                
                if current_core != existing_core:
                    # 核心内容发生变化，执行更新操作
                    cursor.execute('''
                    UPDATE rules SET 
                        rule_info = ?, semantic_analysis = ?, dependency_analysis = ?, 
                        parse_status = ?, raw_rule = ?, rule_type = ?, phase = ?, 
                        variables = ?, operator = ?, pattern = ?, actions = ?, 
                        tags = ?, message = ?, severity = ?, is_chain = ?, 
                        attack_types = ?, protection_layer = ?, matching_method = ?, 
                        scenario = ?, variable_dependencies = ?, 
                        marker_dependencies = ?, include_dependencies = ?, 
                        updated_at = CURRENT_TIMESTAMP
                    WHERE id = ?
                    ''', (
                        json.dumps(rule_info),
                        json.dumps(semantic_analysis),
                        json.dumps(dependency_analysis),
                        parse_status,
                        raw_rule,
                        rule_info.get('type'),
                        rule_info.get('phase'),
                        json.dumps(rule_info.get('variables', [])),
                        rule_info.get('operator'),
                        rule_info.get('pattern'),
                        json.dumps(rule_info.get('actions', [])),
                        json.dumps(rule_info.get('tags', [])),
                        rule_info.get('message'),
                        rule_info.get('severity'),
                        1 if rule_info.get('is_chain') else 0,
                        json.dumps(semantic_analysis.get('attack_types', [])),
                        semantic_analysis.get('rule_classification', {}).get('protection_layer') if isinstance(semantic_analysis.get('rule_classification'), dict) else None,
                        semantic_analysis.get('rule_classification', {}).get('matching_method') if isinstance(semantic_analysis.get('rule_classification'), dict) else None,
                        semantic_analysis.get('rule_classification', {}).get('scenario') if isinstance(semantic_analysis.get('rule_classification'), dict) else None,
                        json.dumps(dependency_analysis.get('variable_dependencies', [])),
                        json.dumps(dependency_analysis.get('marker_dependencies', [])),
                        json.dumps(dependency_analysis.get('include_dependencies', [])),
                        rule_id
                    ))
                    conn.commit()
                    conn.close()
                    logger.info(f"规则 {rule_id} 已更新")
                    return True  # 规则已更新
                else:
                    # 核心内容未变化，跳过
                    conn.close()
                    logger.debug(f"规则 {rule_id} 内容未变化，跳过")
                    return False  # 规则已存在且内容未变化
            else:
                # 规则不存在，插入新规则
                cursor.execute('''
                INSERT INTO rules (
                    id, rule_info, semantic_analysis, dependency_analysis, parse_status, raw_rule,
                    rule_type, phase, variables, operator, pattern, actions, tags, message, severity, is_chain,
                    attack_types, protection_layer, matching_method, scenario,
                    variable_dependencies, marker_dependencies, include_dependencies
                )
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    rule_id,
                    json.dumps(rule_info),
                    json.dumps(semantic_analysis),
                    json.dumps(dependency_analysis),
                    parse_status,
                    raw_rule,
                    rule_info.get('type'),
                    rule_info.get('phase'),
                    json.dumps(rule_info.get('variables', [])),
                    rule_info.get('operator'),
                    rule_info.get('pattern'),
                    json.dumps(rule_info.get('actions', [])),
                    json.dumps(rule_info.get('tags', [])),
                    rule_info.get('message'),
                    rule_info.get('severity'),
                    1 if rule_info.get('is_chain') else 0,
                    json.dumps(semantic_analysis.get('attack_types', [])),
                    semantic_analysis.get('rule_classification', {}).get('protection_layer') if isinstance(semantic_analysis.get('rule_classification'), dict) else None,
                    semantic_analysis.get('rule_classification', {}).get('matching_method') if isinstance(semantic_analysis.get('rule_classification'), dict) else None,
                    semantic_analysis.get('rule_classification', {}).get('scenario') if isinstance(semantic_analysis.get('rule_classification'), dict) else None,
                    json.dumps(dependency_analysis.get('variable_dependencies', [])),
                    json.dumps(dependency_analysis.get('marker_dependencies', [])),
                    json.dumps(dependency_analysis.get('include_dependencies', []))
                ))
                
                conn.commit()
                conn.close()
                logger.info(f"规则 {rule_id} 插入成功")
                return True  # 规则已插入
        except Exception as e:
            logger.error(f"插入规则失败: {e}")
            raise
    
    def search_by_wafw00f(self, wafw00f_json: Dict) -> List[Dict]:
        """根据wafw00f返回的JSON检索规则"""
        try:
            # 解析wafw00f JSON获取WAF类型
            logger.info(f"开始根据wafw00f数据搜索规则: {wafw00f_json}")
            
            waf_name = wafw00f_json.get('firewall', '').lower().strip()
            manufacturer = wafw00f_json.get('manufacturer', '').lower().strip()
            
            # 如果没有检测到WAF或检测到的是通用WAF，返回所有规则
            if (not wafw00f_json.get('detected', False) or 
                waf_name in ['', 'none', 'generic', 'unknown', 'false']):
                logger.info("未检测到特定WAF或检测结果为通用WAF，返回所有规则")
                return self.get_all_rules()
            
            conn = sqlite3.connect(self.db_path)
            conn.row_factory = sqlite3.Row
            cursor = conn.cursor()
            
            # 使用全文搜索优化WAF规则匹配
            search_terms = [waf_name, manufacturer]
            if waf_name:
                search_terms.extend(waf_name.split())
            if manufacturer:
                search_terms.extend(manufacturer.split())
            
            # 去重并过滤空字符串
            search_terms = list(filter(None, search_terms))
            
            if not search_terms:
                logger.info("没有有效的搜索术语，返回所有规则")
                return self.get_all_rules()
            
            # 构建全文搜索查询
            fts_query = ' OR '.join(search_terms)
            
            logger.info(f"使用全文搜索查询: {fts_query}")
            
            # 使用FTS表进行全文搜索
            cursor.execute('''
            SELECT id, rule_info, semantic_analysis, dependency_analysis, parse_status, raw_rule
            FROM rules r
            JOIN rules_fts fts ON r.rowid = fts.rowid
            WHERE fts MATCH ?
            ORDER BY id
            ''', (fts_query,))
            
            rows = cursor.fetchall()
            conn.close()
            
            # 转换结果为字典列表
            results = []
            for row in rows:
                results.append({
                    'id': row['id'],
                    'rule_info': json.loads(row['rule_info']),
                    'semantic_analysis': json.loads(row['semantic_analysis']),
                    'dependency_analysis': json.loads(row['dependency_analysis']),
                    'parse_status': row['parse_status'],
                    'raw_rule': row['raw_rule']
                })
            
            logger.info(f"总共找到 {len(results)} 条匹配规则")
            return results
        except Exception as e:
            logger.error(f"根据WAF类型搜索规则失败: {e}")
            return []
    
    def get_rules_by_phase_severity(self, phase: str, severity: str) -> List[Dict]:
        """根据阶段和严重程度获取规则（使用联合索引优化）"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # 使用联合索引 phase + severity 提高查询性能
            cursor.execute('''
            SELECT id, rule_info, semantic_analysis, dependency_analysis, parse_status, raw_rule
            FROM rules 
            WHERE phase = ? AND severity = ?
            ORDER BY id
            ''', (phase, severity))
            
            rows = cursor.fetchall()
            conn.close()
            
            # 转换结果为字典列表
            results = []
            for row in rows:
                results.append({
                    'id': row[0],
                    'rule_info': json.loads(row[1]),
                    'semantic_analysis': json.loads(row[2]),
                    'dependency_analysis': json.loads(row[3]),
                    'parse_status': row[4],
                    'raw_rule': row[5]
                })
            
            return results
        except Exception as e:
            logger.error(f"根据阶段和严重程度获取规则失败: {e}")
            return []
    
    def get_rules_by_protection_layer(self, protection_layer: str) -> List[Dict]:
        """根据防护层获取规则"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # 使用索引提高查询性能
            cursor.execute('''
            SELECT id, rule_info, semantic_analysis, dependency_analysis, parse_status, raw_rule
            FROM rules 
            WHERE protection_layer = ?
            ORDER BY id
            ''', (protection_layer,))
            
            rows = cursor.fetchall()
            conn.close()
            
            # 转换结果为字典列表
            results = []
            for row in rows:
                results.append({
                    'id': row[0],
                    'rule_info': json.loads(row[1]),
                    'semantic_analysis': json.loads(row[2]),
                    'dependency_analysis': json.loads(row[3]),
                    'parse_status': row[4],
                    'raw_rule': row[5]
                })
            
            return results
        except Exception as e:
            logger.error(f"根据防护层获取规则失败: {e}")
            return []
    
    def get_rule_by_id(self, rule_id: str) -> Optional[Dict]:
        """根据ID获取规则"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
            SELECT id, rule_info, semantic_analysis, dependency_analysis, parse_status, raw_rule
            FROM rules 
            WHERE id = ?
            ''', (rule_id,))
            
            row = cursor.fetchone()
            conn.close()
            
            if row:
                return {
                    'id': row[0],
                    'rule_info': json.loads(row[1]),
                    'semantic_analysis': json.loads(row[2]),
                    'dependency_analysis': json.loads(row[3]),
                    'parse_status': row[4],
                    'raw_rule': row[5]
                }
            
            return None
        except Exception as e:
            logger.error(f"根据ID获取规则失败: {e}")
            return None
    
    def get_rules_by_phase(self, phase: str) -> List[Dict]:
        """根据阶段获取规则"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
            SELECT id, rule_info, semantic_analysis, dependency_analysis, parse_status, raw_rule
            FROM rules 
            WHERE phase = ?
            ORDER BY id
            ''', (phase,))
            
            rows = cursor.fetchall()
            conn.close()
            
            # 转换结果为字典列表
            results = []
            for row in rows:
                results.append({
                    'id': row[0],
                    'rule_info': json.loads(row[1]),
                    'semantic_analysis': json.loads(row[2]),
                    'dependency_analysis': json.loads(row[3]),
                    'parse_status': row[4],
                    'raw_rule': row[5]
                })
            
            return results
        except Exception as e:
            logger.error(f"根据阶段获取规则失败: {e}")
            return []
    
    def get_rules_by_severity(self, severity: str) -> List[Dict]:
        """根据严重程度获取规则"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
            SELECT id, rule_info, semantic_analysis, dependency_analysis, parse_status, raw_rule
            FROM rules 
            WHERE severity = ?
            ORDER BY id
            ''', (severity,))
            
            rows = cursor.fetchall()
            conn.close()
            
            # 转换结果为字典列表
            results = []
            for row in rows:
                results.append({
                    'id': row[0],
                    'rule_info': json.loads(row[1]),
                    'semantic_analysis': json.loads(row[2]),
                    'dependency_analysis': json.loads(row[3]),
                    'parse_status': row[4],
                    'raw_rule': row[5]
                })
            
            return results
        except Exception as e:
            logger.error(f"根据严重程度获取规则失败: {e}")
            return []
    
    def get_all_rules(self) -> List[Dict]:
        """获取所有规则"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
            SELECT id, rule_info, semantic_analysis, dependency_analysis, parse_status, raw_rule
            FROM rules 
            ORDER BY id
            ''')
            
            rows = cursor.fetchall()
            conn.close()
            
            # 转换结果为字典列表
            results = []
            for row in rows:
                results.append({
                    'id': row[0],
                    'rule_info': json.loads(row[1]),
                    'semantic_analysis': json.loads(row[2]),
                    'dependency_analysis': json.loads(row[3]),
                    'parse_status': row[4],
                    'raw_rule': row[5]
                })
            
            logger.info(f"获取到 {len(results)} 条规则")
            return results
        except Exception as e:
            logger.error(f"获取所有规则失败: {e}")
            return []
    
    def get_core_rule_content(self, rule_info: Dict) -> Dict:
        """提取规则的核心内容用于比较
        
        Args:
            rule_info: 规则信息字典
            
        Returns:
            Dict: 包含核心规则内容的字典
        """
        core_fields = ['variables', 'operator', 'pattern', 'is_chain']
        core_content = {field: rule_info.get(field, '') for field in core_fields}
        
        # 归一化列表类型字段，以便比较
        for key, value in core_content.items():
            if isinstance(value, list):
                core_content[key] = sorted(value)
        
        return core_content
    
    def delete_rule_by_id(self, rule_id: str) -> bool:
        """根据ID删除规则"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('DELETE FROM rules WHERE id = ?', (rule_id,))
            affected_rows = cursor.rowcount
            
            conn.commit()
            conn.close()
            
            if affected_rows > 0:
                logger.info(f"成功删除规则 {rule_id}")
                return True
            else:
                logger.debug(f"未找到规则 {rule_id}")
                return False
        except Exception as e:
            logger.error(f"删除规则失败: {e}")
            return False
    
    def update_rule(self, rule_id: str, updates: Dict) -> bool:
        """更新规则"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            # 构建更新语句
            set_clauses = []
            params = []
            
            for key, value in updates.items():
                if key in ['rule_info', 'semantic_analysis', 'dependency_analysis']:
                    set_clauses.append(f"{key} = ?")
                    params.append(json.dumps(value))
                elif key == 'parse_status':
                    set_clauses.append("parse_status = ?")
                    params.append(value)
                elif key == 'raw_rule':
                    set_clauses.append("raw_rule = ?")
                    params.append(value)
                # 处理结构化字段
                elif key in ['rule_type', 'phase', 'operator', 'pattern', 'message', 'severity']:
                    set_clauses.append(f"{key} = ?")
                    params.append(value)
                elif key in ['variables', 'actions', 'tags', 'attack_types', 'variable_dependencies', 'marker_dependencies', 'include_dependencies']:
                    set_clauses.append(f"{key} = ?")
                    params.append(json.dumps(value) if isinstance(value, (list, dict)) else value)
                elif key == 'is_chain':
                    set_clauses.append("is_chain = ?")
                    params.append(1 if value else 0)
                elif key in ['protection_layer', 'matching_method', 'scenario']:
                    set_clauses.append(f"{key} = ?")
                    params.append(value)
            
            if not set_clauses:
                logger.warning("没有有效的更新字段")
                return False
            
            set_clause = ", ".join(set_clauses)
            params.append(rule_id)
            
            # 执行更新
            cursor.execute(f'''
            UPDATE rules 
            SET {set_clause}, updated_at = CURRENT_TIMESTAMP
            WHERE id = ?
            ''', params)
            
            affected_rows = cursor.rowcount
            
            conn.commit()
            conn.close()
            
            if affected_rows > 0:
                logger.info(f"成功更新规则 {rule_id}")
                return True
            else:
                logger.debug(f"未找到规则 {rule_id}")
                return False
        except Exception as e:
            logger.error(f"更新规则失败: {e}")
            return False