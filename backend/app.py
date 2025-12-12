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
                             'Part2 analysis', 'part2_rule_analysis', '2.0', 'backend')
if part2_2_0_path not in sys.path:
    sys.path.append(part2_2_0_path)

# 默认的 CoreRuleSet 目录
DEFAULT_CRS_RULES_DIR = PROJECT_ROOT / 'Part2 analysis' / 'coreruleset-main' / 'rules'

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
    from parser import parse_file
    HAS_PART2_MODULES = True
    HAS_ANTLR = False
    HAS_SECRULES_PARSING = False
    logger.info("使用新的Part2解析器")
except ImportError:
    HAS_PART2_MODULES = False
    HAS_ANTLR = False
    HAS_SECRULES_PARSING = False
    logger.error("无法导入Part2模块")

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
                database = RuleDatabase()
                
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
        rules_dir = rules_dir or str(DEFAULT_CRS_RULES_DIR)
        logger.info(f"开始从目录加载规则: {rules_dir}")
        
        # 初始化数据库
        # 注意：这里我们需要实现数据库功能或者暂时跳过
        try:
            # 使用动态导入方式导入数据库模块
            import importlib.util
            db_path = os.path.join(part2_2_0_path, 'database.py')
            spec = importlib.util.spec_from_file_location("database", db_path)
            db_module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(db_module)
            RuleDatabase = getattr(db_module, "RuleDatabase")
            database = RuleDatabase()
        except Exception as e:
            logger.warning(f"无法导入RuleDatabase，将跳过数据库存储: {e}")
            database = None
        
        # 导入新的解析器
        from parser import parse_file
        
        # 解析目录中的所有规则文件
        import glob
        rule_files = glob.glob(os.path.join(rules_dir, "*.conf"))
        logger.info(f"找到 {len(rule_files)} 个规则文件")
        
        total_parsed = 0
        total_inserted = 0
        
        for rule_file in rule_files:
            try:
                logger.info(f"正在处理规则文件: {rule_file}")
                
                # 使用新的解析器解析规则文件
                parsed_rules = parse_file(rule_file)
                if parsed_rules is not None:
                    total_parsed += len(parsed_rules)
                    
                    # 如果有数据库，将规则插入数据库
                    if database:
                        for rule in parsed_rules:
                            try:
                                # 获取规则的JSON表示
                                rule_data = rule.jsonify_rule()
                                
                                # 构造符合数据库期望的数据结构
                                db_rule_data = {
                                    'rule_info': {
                                        'id': extract_rule_id(rule_data),
                                        'type': 'SecRule',
                                        'phase': extract_phase(rule_data),
                                        'variables': [rule_data.get('variable')] if rule_data.get('variable') else [],
                                        'operator': rule_data.get('operator'),
                                        'pattern': None,  # 模式需要从操作符中提取
                                        'actions': rule_data.get('action', []) if rule_data.get('action') else [],
                                        'tags': extract_tags(rule_data),
                                        'message': extract_message(rule_data),
                                        'severity': extract_severity(rule_data),
                                        'is_chain': False  # 简化处理
                                    },
                                    'semantic_analysis': {},
                                    'dependency_analysis': {}
                                }
                                
                                # 插入数据库
                                success = database.insert(db_rule_data, 'parsed', rule_data.get('rule', ''))
                                if success:
                                    total_inserted += 1
                            except Exception as e:
                                logger.warning(f"插入规则时出错: {str(e)}")
                                # 不要中断整个过程，继续处理其他规则
                                continue
                else:
                    logger.warning(f"解析规则文件失败: {rule_file}")
                        
            except Exception as e:
                logger.warning(f"处理规则文件 {rule_file} 时出错: {str(e)}")
                # 不要中断整个过程，继续处理其他规则文件
                continue
        
        logger.info(f"规则加载完成，共解析 {total_parsed} 条规则，成功插入 {total_inserted} 条规则")
        return True
        
    except Exception as e:
        logger.error(f"加载规则集失败: {str(e)}")
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