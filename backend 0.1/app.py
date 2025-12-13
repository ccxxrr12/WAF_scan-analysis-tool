#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
WAF规则分析工具 - 命令行工具
提供命令行接口进行WAF分析功能
"""

import os
import sys
import json
import logging
import argparse
from pathlib import Path
from datetime import datetime

# 设置项目根目录
PROJECT_ROOT = Path(__file__).parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

# 添加 Part1 waf_scanner 到 Python 模块搜索路径
part1_scanner_path = os.path.abspath(os.path.join(os.path.dirname(__file__), '../Part1 waf_scanner'))
if part1_scanner_path not in sys.path:
    sys.path.insert(0, part1_scanner_path)

# 添加 Part2 analysis 到 Python 模块搜索路径
part2_analysis_path = os.path.abspath(os.path.join(os.path.dirname(__file__), '../Part2 analysis'))
if part2_analysis_path not in sys.path:
    sys.path.insert(0, part2_analysis_path)

# 添加 Part2 analysis 2.0 到 Python 模块搜索路径
part2_2_0_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 
                             'Part2 analysis', 'part2_rule_analysis', '2.0')
part2_2_0_backend_path = os.path.join(part2_2_0_path, 'backend')
if part2_2_0_path not in sys.path:
    sys.path.append(part2_2_0_path)
if part2_2_0_backend_path not in sys.path:
    sys.path.append(part2_2_0_backend_path)

# 默认的 CoreRuleSet 目录
DEFAULT_CRS_RULES_DIR = PROJECT_ROOT / 'Part2 analysis' / 'part2_rule_analysis' / '2.0' / 'rules'

# 默认的规则数据库路径
DEFAULT_RULES_DB = PROJECT_ROOT / 'Part2 analysis' / 'part2_rule_analysis' / '2.0' / 'backend' / 'analysis_results' / 'rules.db'

# 初始化日志记录器
from common.utils.log_utils import setup_logger
logger = setup_logger('WAFAnalysisTool', log_level='INFO')

# 导入Part1模块
try:
    from wafw00f.main import WAFW00F
    HAS_WAFW00F = True
except ImportError:
    HAS_WAFW00F = False
    logger.error("无法导入wafw00f模块")

# 导入Part2模块
try:
    # 尝试从新的Part2解析器导入
    from backend.msc_pyparser import MSCParser
    from backend.database import RuleDatabase
    HAS_PART2_MODULES = True
    HAS_ANTLR = False
    HAS_SECRULES_PARSING = False
    logger.info("使用新的Part2解析器")
except ImportError as e:
    HAS_PART2_MODULES = False
    HAS_ANTLR = False
    HAS_SECRULES_PARSING = False
    logger.error(f"无法导入Part2模块: {e}")

def analyze_url(url):
    """分析URL的WAF指纹并关联规则"""
    if not HAS_WAFW00F:
        logger.error("WAFW00F模块不可用")
        return None
    
    try:
        logger.info(f"开始分析URL: {url}")
        
        # Part1: WAF指纹识别
        waf_scanner = WAFW00F(target=url)
        
        # 检查网站是否可访问
        if waf_scanner.rq is None:
            logger.error(f"网站 {url} 无法访问")
            return None
        
        # 执行WAF检测
        detected_wafs, trigger_url = waf_scanner.identwaf(findall=False)
        
        # 构造WAF指纹识别结果
        fingerprint_results = {
            'waf_detected': len(detected_wafs) > 0,
            'waf_type': detected_wafs[0] if detected_wafs else 'Unknown',
            'confidence': 0.95,  # 可以根据实际情况调整置信度
            'headers': {
                'Server': getattr(waf_scanner.rq, 'Server', ''),
                'X-Frame-Options': getattr(waf_scanner.rq, 'X-Frame-Options', ''),
                'X-Content-Type-Options': getattr(waf_scanner.rq, 'X-Content-Type-Options', '')
            },
            'fingerprint_matches': [f'Detected WAF: {waf}' for waf in detected_wafs]
        }
        
        # 执行通用检测（如果没有检测到特定WAF）
        if not detected_wafs:
            generic_result = waf_scanner.genericdetect()
            if generic_result:
                fingerprint_results['waf_detected'] = True
                fingerprint_results['waf_type'] = 'Generic WAF'
                fingerprint_results['fingerprint_matches'].append(f'Generic WAF detected: {waf_scanner.knowledge["generic"]["reason"]}')
        
        logger.info(f"WAF指纹识别完成: {fingerprint_results}")
        
        # Part2: 规则匹配引擎
        rule_analysis_results = None
        if HAS_PART2_MODULES:
            try:
                # 初始化数据库
                database = RuleDatabase(str(DEFAULT_RULES_DB))
                
                # 构造wafw00f格式的JSON数据用于Part2规则匹配
                wafw00f_json = {
                    'url': url,
                    'detected': fingerprint_results['waf_detected'],
                    'trigger_url': trigger_url,
                    'firewall': fingerprint_results['waf_type'],
                    'manufacturer': ''  # 暂时留空
                }
                
                # 根据WAF类型搜索规则
                matched_rules = database.search_by_wafw00f(wafw00f_json)
                
                rule_analysis_results = {
                    'rules': matched_rules,
                    'total': len(matched_rules)
                }
                
                logger.info(f"规则匹配完成，找到 {len(matched_rules)} 条相关规则")
            except Exception as e:
                logger.error(f"规则分析时发生错误: {str(e)}")
                rule_analysis_results = {'error': f'Rule analysis failed: {str(e)}'}
        else:
            logger.warning("Part2模块不可用，跳过规则分析")
            rule_analysis_results = {'error': 'Part2 modules not available'}
        
        # 整合所有结果
        results = {
            'status': 'completed',
            'timestamp': datetime.now().isoformat(),
            'url': url,
            'fingerprint': fingerprint_results,
            'rule_analysis': rule_analysis_results
        }
        
        return results
        
    except Exception as e:
        logger.error(f"URL分析失败: {str(e)}")
        return None

def load_rules(rules_dir=None):
    """加载规则集到数据库"""
    if not HAS_PART2_MODULES:
        logger.error("Part2模块不可用")
        return False
    
    try:
        # Part2 2.0使用预生成的数据库，不需要重新解析规则
        # 这里可以添加数据库检查或重新生成逻辑
        logger.info("Part2 2.0使用预生成的规则数据库")
        logger.info(f"规则数据库路径: {DEFAULT_RULES_DB}")
        
        # 检查数据库文件是否存在
        if not os.path.exists(DEFAULT_RULES_DB):
            logger.error(f"规则数据库文件不存在: {DEFAULT_RULES_DB}")
            return False
            
        logger.info("规则数据库已就绪")
        return True
        
    except Exception as e:
        logger.error(f"检查规则数据库时出错: {str(e)}")
        return False


def extract_rule_id(rule_data):
    """从规则数据中提取规则ID"""
    actions = rule_data.get('action', [])
    if isinstance(actions, str):
        actions = [actions]
    
    for action in actions:
        if action.startswith('id:'):
            return action[3:]  # 移除'id:'前缀
    return ''


def extract_phase(rule_data):
    """从规则数据中提取phase"""
    actions = rule_data.get('action', [])
    if isinstance(actions, str):
        actions = [actions]
    
    for action in actions:
        if action.startswith('phase:'):
            return action[6:]  # 移除'phase:'前缀
    return ''


def extract_tags(rule_data):
    """从规则数据中提取tags"""
    actions = rule_data.get('action', [])
    if isinstance(actions, str):
        actions = [actions]
    
    tags = []
    for action in actions:
        if action.startswith('tag:'):
            tags.append(action[4:])  # 移除'tag:'前缀
    return tags


def extract_message(rule_data):
    """从规则数据中提取消息"""
    actions = rule_data.get('action', [])
    if isinstance(actions, str):
        actions = [actions]
    
    for action in actions:
        if action.startswith('msg:'):
            return action[4:]  # 移除'msg:'前缀
    return ''


def extract_severity(rule_data):
    """从规则数据中提取严重性"""
    actions = rule_data.get('action', [])
    if isinstance(actions, str):
        actions = [actions]
    
    for action in actions:
        if action.startswith('severity:'):
            return action[9:]  # 移除'severity:'前缀
        elif action.startswith('sev:'):
            return action[4:]  # 移除'sev:'前缀
    return ''


def main():
    """主函数"""
    parser = argparse.ArgumentParser(description='WAF规则分析工具命令行接口')
    parser.add_argument('-u', '--url', help='要分析的URL')
    parser.add_argument('-l', '--load-rules', action='store_true', help='加载规则到数据库')
    parser.add_argument('-r', '--rules-dir', help='自定义规则目录路径')
    parser.add_argument('-o', '--output', help='输出结果到文件')
    
    args = parser.parse_args()
    
    # 如果指定了加载规则
    if args.load_rules:
        success = load_rules(args.rules_dir)
        if success:
            print("规则加载成功")
            return 0
        else:
            print("规则加载失败")
            return 1
    
    # 如果指定了URL分析
    if args.url:
        results = analyze_url(args.url)
        if results:
            output = json.dumps(results, indent=2, ensure_ascii=False)
            
            # 如果指定了输出文件
            if args.output:
                try:
                    with open(args.output, 'w', encoding='utf-8') as f:
                        f.write(output)
                    print(f"结果已保存到 {args.output}")
                except Exception as e:
                    print(f"保存结果失败: {str(e)}")
                    return 1
            else:
                # 直接打印结果
                print(output)
            
            return 0
        else:
            print("URL分析失败")
            return 1
    
    # 如果没有指定任何操作，显示帮助信息
    parser.print_help()
    return 0

if __name__ == '__main__':
    sys.exit(main())