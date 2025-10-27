# Part1_WAFFingerprint/lib/config.py
# -*- coding: utf-8 -*-
"""
WAF指纹识别系统配置文件
配置WAF特征库、模型参数和检测参数
"""

import os

class FingerprintConfig:
    """WAF指纹识别配置类"""
    
    # 路径配置
    DATA_DIR = os.path.join(os.path.dirname(__file__), '../data')
    MODEL_DIR = os.path.join(os.path.dirname(__file__), '../models')
    
    # WAF指纹数据库文件
    FINGERPRINT_DB = os.path.join(DATA_DIR, 'waf_fingerprints.json')
    TRAINING_DATA = os.path.join(DATA_DIR, 'training_data.csv')
    
    # 特征提取配置
    MAX_PAYLOAD_LENGTH = 1000           # 最大载荷长度
    FEATURE_VECTOR_SIZE = 50            # 特征向量大小
    
    # 机器学习模型配置
    MODEL_TYPES = ['random_forest', 'xgboost', 'svm', 'neural_network']
    DEFAULT_MODEL = 'random_forest'
    
    # 检测阈值配置
    CONFIDENCE_THRESHOLD = 0.7          # 置信度阈值
    SIMILARITY_THRESHOLD = 0.8          # 相似度阈值
    
    # 主动探测配置
    PROBE_TIMEOUT = 5                   # 探测超时时间（秒）
    MAX_PROBE_REQUESTS = 10             # 最大探测请求数
    
    # 支持的WAF厂商列表
    SUPPORTED_WAFS = [
        'Cloudflare', 'AWS WAF', 'Imperva', 'Akamai', 
        'F5 BIG-IP', 'ModSecurity', 'FortiWeb', 'Barracuda',
        'Sucuri', 'Wordfence', 'Unknown'
    ]

class PassiveDetectionConfig:
    """被动检测配置"""
    
    # HTTP头部特征关键词
    WAF_HEADER_KEYWORDS = [
        'waf', 'cloudflare', 'imperva', 'akamai',
        'f5', 'mod_security', 'fortiweb', 'barracuda'
    ]
    
    # Cookie特征关键词
    WAF_COOKIE_PATTERNS = [
        'waf', 'cf_', 'ak_', 'incap_', 'visid'
    ]
    
    # 响应内容特征
    RESPONSE_PATTERNS = [
        'cloudflare', 'imperva', 'akamai', 'bigip',
        'mod_security', 'waf', 'forbidden', 'blocked'
    ]

class ActiveProbeConfig:
    """主动探测配置"""
    
    # 恶意载荷用于主动探测
    MALICIOUS_PAYLOADS = [
        # SQL注入载荷
        "' OR '1'='1",
        "UNION SELECT NULL--",
        # XSS载荷
        "<script>alert('XSS')</script>",
        # 路径遍历载荷
        "../../../etc/passwd",
        # 命令注入载荷
        "; ls -la"
    ]
    
    # 探测目标路径
    TARGET_PATHS = ['/', '/admin', '/login', '/api']