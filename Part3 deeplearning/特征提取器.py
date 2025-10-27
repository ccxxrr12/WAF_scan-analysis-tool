# Part1_WAFFingerprint/lib/feature_extractor.py
# -*- coding: utf-8 -*-
"""
WAF指纹特征提取器
从HTTP请求和响应中提取WAF特征
"""

import re
import hashlib
from typing import Dict, List, Any, Optional
import numpy as np
from config import FingerprintConfig, PassiveDetectionConfig

class WAFFeatureExtractor:
    """WAF指纹特征提取器类"""
    
    def __init__(self):
        """初始化特征提取器"""
        self.config = FingerprintConfig()
        self.passive_config = PassiveDetectionConfig()
    
    def extract_http_header_features(self, headers: Dict[str, str]) -> Dict[str, Any]:
        """
        从HTTP头部提取WAF特征
        
        参数:
            headers: HTTP头部字典
            
        返回:
            头部特征字典
        """
        features = {}
        header_keys = [k.lower() for k in headers.keys()]
        header_values = ' '.join([v.lower() for v in headers.values()])
        
        # 1. 检查特定WAF头部
        waf_header_count = 0
        for keyword in self.passive_config.WAF_HEADER_KEYWORDS:
            if any(keyword in key for key in header_keys):
                waf_header_count += 1
            if keyword in header_values:
                waf_header_count += 1
        
        features['waf_header_count'] = waf_header_count
        
        # 2. 检查服务器头部
        server_header = headers.get('Server', '').lower()
        features['has_server_header'] = 1 if server_header else 0
        
        # 3. 检查特定WAF标识
        features['is_cloudflare'] = 1 if 'cloudflare' in header_values else 0
        features['is_aws_waf'] = 1 if any(x in header_values for x in ['aws', 'waf']) else 0
        features['is_imperva'] = 1 if 'imperva' in header_values else 0
        
        # 4. 计算头部熵（复杂度）
        features['header_entropy'] = self._calculate_entropy(header_values)
        
        return features
    
    def extract_cookie_features(self, cookies: Dict[str, str]) -> Dict[str, Any]:
        """
        从Cookie中提取WAF特征
        
        参数:
            cookies: Cookie字典
            
        返回:
            Cookie特征字典
        """
        features = {}
        cookie_names = ' '.join(cookies.keys()).lower()
        cookie_values = ' '.join(cookies.values()).lower()
        
        # 1. 检查WAF相关Cookie模式
        waf_cookie_count = 0
        for pattern in self.passive_config.WAF_COOKIE_PATTERNS:
            if pattern in cookie_names:
                waf_cookie_count += 1
        
        features['waf_cookie_count'] = waf_cookie_count
        
        # 2. Cookie数量和长度特征
        features['cookie_count'] = len(cookies)
        features['avg_cookie_length'] = np.mean([len(v) for v in cookies.values()]) if cookies else 0
        
        return features
    
    def extract_response_features(self, response_text: str, status_code: int) -> Dict[str, Any]:
        """
        从响应内容提取WAF特征
        
        参数:
            response_text: 响应文本内容
            status_code: HTTP状态码
            
        返回:
            响应特征字典
        """
        features = {}
        response_lower = response_text.lower()
        
        # 1. 检查WAF相关响应模式
        waf_response_count = 0
        for pattern in self.passive_config.RESPONSE_PATTERNS:
            if pattern in response_lower:
                waf_response_count += 1
        
        features['waf_response_count'] = waf_response_count
        
        # 2. 状态码特征
        features['status_code'] = status_code
        features['is_blocked'] = 1 if status_code in [403, 406, 418, 429] else 0
        
        # 3. 响应内容特征
        features['response_length'] = len(response_text)
        features['response_entropy'] = self._calculate_entropy(response_text)
        
        # 4. 特定WAF响应模式
        features['has_cloudflare_challenge'] = 1 if 'challenge' in response_lower and 'cloudflare' in response_lower else 0
        features['has_imperva_block'] = 1 if 'imperva' in response_lower and 'blocked' in response_lower else 0
        
        return features
    
    def extract_probe_features(self, probe_results: List[Dict]) -> Dict[str, Any]:
        """
        从主动探测结果中提取特征
        
        参数:
            probe_results: 探测结果列表
            
        返回:
            探测特征字典
        """
        features = {}
        
        if not probe_results:
            return features
        
        # 1. 统计探测结果
        blocked_count = sum(1 for result in probe_results if result.get('blocked', False))
        features['blocked_ratio'] = blocked_count / len(probe_results)
        
        # 2. 响应时间特征
        response_times = [result.get('response_time', 0) for result in probe_results]
        features['avg_response_time'] = np.mean(response_times)
        features['max_response_time'] = np.max(response_times)
        
        # 3. 状态码分布
        status_codes = [result.get('status_code', 200) for result in probe_results]
        features['unique_status_codes'] = len(set(status_codes))
        features['block_status_ratio'] = sum(1 for code in status_codes if code in [403, 406]) / len(status_codes)
        
        return features
    
    def extract_comprehensive_features(self, http_data: Dict[str, Any]) -> np.ndarray:
        """
        提取综合特征向量
        
        参数:
            http_data: 包含HTTP请求和响应数据的字典
            
        返回:
            特征向量numpy数组
        """
        features = []
        
        # 提取头部特征
        header_features = self.extract_http_header_features(http_data.get('headers', {}))
        features.extend(header_features.values())
        
        # 提取Cookie特征
        cookie_features = self.extract_cookie_features(http_data.get('cookies', {}))
        features.extend(cookie_features.values())
        
        # 提取响应特征
        response_features = self.extract_response_features(
            http_data.get('response_text', ''), 
            http_data.get('status_code', 200)
        )
        features.extend(response_features.values())
        
        # 提取探测特征（如果有）
        if 'probe_results' in http_data:
            probe_features = self.extract_probe_features(http_data['probe_results'])
            features.extend(probe_features.values())
        
        # 填充或截断到固定长度
        if len(features) < self.config.FEATURE_VECTOR_SIZE:
            features.extend([0] * (self.config.FEATURE_VECTOR_SIZE - len(features)))
        else:
            features = features[:self.config.FEATURE_VECTOR_SIZE]
        
        return np.array(features, dtype=np.float32)
    
    def _calculate_entropy(self, text: str) -> float:
        """
        计算文本熵
        
        参数:
            text: 输入文本
            
        返回:
            熵值
        """
        if not text:
            return 0.0
        
        entropy = 0.0
        for char in set(text):
            p_x = float(text.count(char)) / len(text)
            if p_x > 0:
                entropy += - p_x * np.log2(p_x)
        
        return entropy
    
    def normalize_features(self, features: np.ndarray) -> np.ndarray:
        """
        特征归一化
        
        参数:
            features: 原始特征向量
            
        返回:
            归一化后的特征向量
        """
        # 避免除零
        features = np.nan_to_num(features)
        
        # Min-Max归一化
        min_val = np.min(features)
        max_val = np.max(features)
        
        if max_val - min_val > 0:
            normalized = (features - min_val) / (max_val - min_val)
        else:
            normalized = features
        
        return normalized