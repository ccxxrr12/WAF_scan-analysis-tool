import sqlite3
import os
from typing import Dict, Any, List

DB_FILENAME = 'rule_index.db'


def init_db(db_path: str = None) -> str:
    """Initialize the SQLite DB and create tables. Returns the DB path."""
    if db_path is None:
        db_path = os.path.join(os.path.dirname(__file__), DB_FILENAME)

    conn = sqlite3.connect(db_path)
    cur = conn.cursor()

    cur.execute('''
    CREATE TABLE IF NOT EXISTS rules (
        id TEXT PRIMARY KEY,
        rule_id TEXT,
        node_type TEXT,
        line INTEGER,
        raw_text TEXT,
        attributes TEXT
    )
    ''')

    cur.execute('''
    CREATE TABLE IF NOT EXISTS tags (
        tag TEXT,
        rule_id TEXT,
        FOREIGN KEY(rule_id) REFERENCES rules(rule_id)
    )
    ''')

    conn.commit()
    conn.close()
    return db_path


def insert_rule(rule: Dict[str, Any], db_path: str = None):
    """Insert a parsed rule into the DB.
    Expected minimal rule dict: { 'id': 'task_xxx', 'node_type': 'SecRule', 'line': 10, 'raw': '...', 'attrs': {...} }
    """
    if db_path is None:
        db_path = os.path.join(os.path.dirname(__file__), DB_FILENAME)

    conn = sqlite3.connect(db_path)
    cur = conn.cursor()

    rule_id = rule.get('id') or rule.get('rule_id') or f"r{rule.get('line', 0)}_{os.urandom(4).hex()}"
    node_type = rule.get('node_type') or rule.get('nodeType') or ''
    line = rule.get('line') or 0
    raw = rule.get('raw', '')
    attributes = str(rule.get('attrs', rule.get('attributes', {})))

    try:
        cur.execute('INSERT OR REPLACE INTO rules (id, rule_id, node_type, line, raw_text, attributes) VALUES (?, ?, ?, ?, ?, ?)',
                    (rule_id, rule_id, node_type, line, raw, attributes))

        # insert tags if available
        tags = rule.get('tags') or []
        for tag in tags:
            cur.execute('INSERT INTO tags (tag, rule_id) VALUES (?, ?)', (tag, rule_id))

        conn.commit()
    finally:
        conn.close()


def query_rule_by_id(rule_id: str, db_path: str = None) -> Dict[str, Any]:
    if db_path is None:
        db_path = os.path.join(os.path.dirname(__file__), DB_FILENAME)

    conn = sqlite3.connect(db_path)
    cur = conn.cursor()

    cur.execute('SELECT id, rule_id, node_type, line, raw_text, attributes FROM rules WHERE rule_id = ?', (rule_id,))
    row = cur.fetchone()
    conn.close()
    if not row:
        return {}
    return {
        'id': row[0],
        'rule_id': row[1],
        'node_type': row[2],
        'line': row[3],
        'raw_text': row[4],
        'attributes': row[5]
    }


def query_rules_by_tag(tag: str, db_path: str = None) -> List[Dict[str, Any]]:
    if db_path is None:
        db_path = os.path.join(os.path.dirname(__file__), DB_FILENAME)

    conn = sqlite3.connect(db_path)
    cur = conn.cursor()

    cur.execute('''
    SELECT r.id, r.rule_id, r.node_type, r.line, r.raw_text, r.attributes
    FROM rules r JOIN tags t ON r.rule_id = t.rule_id WHERE t.tag = ?
    ''', (tag,))

    rows = cur.fetchall()
    conn.close()
    result = []
    for row in rows:
        result.append({
            'id': row[0],
            'rule_id': row[1],
            'node_type': row[2],
            'line': row[3],
            'raw_text': row[4],
            'attributes': row[5]
        })
    return result
