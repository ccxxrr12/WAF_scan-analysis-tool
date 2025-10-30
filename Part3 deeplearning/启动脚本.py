# Part1_WAFFingerprint/lib/utils.py
# -*- coding: utf-8 -*-
"""
WAF指纹识别工具函数
提供数据处理、日志记录等辅助功能
"""

import json
import logging
import numpy as np
from typing import Dict, List, Any
from datetime import datetime

def setup_logging(log_file: str = None, level: str = 'INFO'):
    """
    设置日志配置
    
    参数:
        log_file: 日志文件路径
        level: 日志级别
    """
    log_format = '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    
    if log_file:
        logging.basicConfig(
            filename=log_file,
            level=getattr(logging, level),
            format=log_format
        )
    else:
        logging.basicConfig(
            level=getattr(logging, level),
            format=log_format
        )

def save_detection_result(result: Dict[str, Any], file_path: str):
    """
    保存检测结果到文件
    
    参数:
        result: 检测结果字典
        file_path: 文件保存路径
    """
    try:
        with open(file_path, 'w', encoding='utf-8') as f:
            json.dump(result, f, indent=2, ensure_ascii=False)
    except Exception as e:
        logging.error(f"保存检测结果失败: {e}")

def load_training_data(file_path: str) -> tuple:
    """
    加载训练数据
    
    参数:
        file_path: 训练数据文件路径
        
    返回:
        (特征矩阵, 标签列表) 元组
    """
    try:
        # 这里应该根据实际数据格式实现
        # 示例实现
        features = []
        labels = []
        
        # 实际实现应该读取CSV或JSON文件
        # 并提取特征和标签
        
        return np.array(features), labels
    except Exception as e:
        logging.error(f"加载训练数据失败: {e}")
        return np.array([]), []

def validate_url(url: str) -> bool:
    """
    验证URL格式
    
    参数:
        url: 待验证的URL
        
    返回:
        是否有效的布尔值
    """
    import re
    url_pattern = re.compile(
        r'^(https?://)?'  # http:// or https://
        r'(([A-Z0-9-]+\.)+[A-Z]{2,})'  # domain
        r'(:\d+)?'  # port
        r'(/.*)?$', re.IGNORECASE)  # path
    
    return bool(url_pattern.match(url))

def format_detection_report(result: Dict[str, Any]) -> str:
    """
    格式化检测报告
    
    参数:
        result: 检测结果字典
        
    返回:
        格式化的报告字符串
    """
    report = []
    report.append("=" * 50)
    report.append("WAF指纹检测报告")
    report.append("=" * 50)
    
    report.append(f"目标URL: {result.get('target_url', 'N/A')}")
    report.append(f"检测时间: {result.get('timestamp', 'N/A')}")
    report.append(f"检测方法: {result.get('detection_method', 'N/A')}")
    
    # 最终结论
    conclusion = result.get('final_conclusion', {})
    if conclusion:
        report.append("\n最终结论:")
        report.append(f"  WAF检测: {'是' if conclusion.get('waf_detected') else '否'}")
        report.append(f"  检测到的WAF: {', '.join(conclusion.get('detected_wafs', []))}")
        report.append(f"  总体置信度: {conclusion.get('overall_confidence', 0):.2f}")
        report.append(f"  建议: {conclusion.get('recommendation', '')}")
    
    # 被动检测结果
    passive = result.get('passive_detection', {})
    if passive and 'error' not in passive:
        report.append("\n被动检测结果:")
        ml_result = passive.get('ml_detection', {})
        if 'waf_type' in ml_result:
            report.append(f"  机器学习检测: {ml_result['waf_type']} (置信度: {ml_result.get('confidence', 0):.2f})")
        
        rule_result = passive.get('rule_based_detection', {})
        if rule_result.get('detected_wafs'):
            report.append(f"  规则检测: {', '.join(rule_result['detected_wafs'])}")
    
    # 主动检测结果
    active = result.get('active_detection', {})
    if active and 'error' not in active:
        report.append("\n主动检测结果:")
        ml_result = active.get('ml_detection', {})
        if 'waf_type' in ml_result:
            report.append(f"  机器学习检测: {ml_result['waf_type']} (置信度: {ml_result.get('confidence', 0):.2f})")
        
        rule_result = active.get('rule_based_detection', {})
        if rule_result.get('detected_wafs'):
            report.append(f"  规则检测: {', '.join(rule_result['detected_wafs'])}")
        report.append(f"  请求拦截率: {rule_result.get('block_ratio', 0):.2f}")
    
    report.append("=" * 50)
    return "\n".join(report)