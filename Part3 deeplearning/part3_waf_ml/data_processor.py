#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
数据处理模块

该模块负责处理来自Part1和Part2的输入数据，生成机器学习模型所需的训练数据和特征。
主要功能包括：
1. 数据收集和清洗
2. 特征工程
3. 数据集划分
4. 数据增强

文件结构：
- process_waf_fingerprint(): 处理Part1的WAF指纹识别结果
- extract_features(): 从HTTP请求中提取特征
- generate_training_data(): 生成训练数据集 (需要Part2数据)
- load_dataset(): 加载数据集 (支持CSV格式)
- preprocess_data(): 数据预处理 (支持去重和缺失值处理)
"""

import re
import numpy as np
import pandas as pd
from urllib.parse import urlparse, parse_qs


# WAF类型映射，将WAF名称映射到简化的类型
WAF_TYPES = {
    'Cloudflare': 'cloudflare',
    'ModSecurity': 'modsecurity',
    'AWS': 'aws',
    'Cloudfront': 'aws',
    'Incapsula': 'imperva',
    'Imperva': 'imperva',
    'F5': 'f5',
    'Fortinet': 'fortinet',
    'Fortiweb': 'fortinet',
    'Sucuri': 'sucuri',
    'Akamai': 'akamai',
    'Radware': 'radware'
}


class DataProcessor:
    """数据处理器类"""
    
    def __init__(self):
        """
        初始化数据处理器
        """
        pass
    
    def process_waf_fingerprint(self, fingerprint_data):
        """
        处理Part1的WAF指纹识别结果
        
        Args:
            fingerprint_data: WAF指纹数据，包含WAF名称和置信度等信息
            
        Returns:
            processed_data: 处理后的数据，包括WAF类型和特征
        """
        if not fingerprint_data or 'waf_type' not in fingerprint_data:
            return {
                'waf_type': 'unknown',
                'waf_confidence': 0.0,
                'waf_features': [0] * len(WAF_TYPES)
            }
        
        waf_name = fingerprint_data.get('waf_type', 'unknown')
        confidence = fingerprint_data.get('confidence', 0.0)
        
        # 标准化WAF类型
        waf_type = 'unknown'
        for key, value in WAF_TYPES.items():
            if key.lower() in waf_name.lower():
                waf_type = value
                break
        
        # 创建WAF类型特征向量
        waf_features = [0] * len(WAF_TYPES)
        if waf_type in WAF_TYPES.values():
            waf_features[list(WAF_TYPES.values()).index(waf_type)] = 1
        
        return {
            'waf_type': waf_type,
            'waf_confidence': confidence,
            'waf_features': waf_features
        }
    
    def extract_features(self, http_request):
        """
        从HTTP请求中提取特征
        
        Args:
            http_request: HTTP请求对象，包含request和response信息
            
        Returns:
            features: 提取的特征字典
        """
        features = {}
        
        # 解析HTTP请求
        request_str = http_request.get("request", "")
        response_status = http_request.get("response_status", 200)
        
        # 提取URL特征
        url_match = re.search(r'^(GET|POST|PUT|DELETE)\s+(.*?)\s+HTTP', request_str)
        if url_match:
            method = url_match.group(1)
            url = url_match.group(2)
            
            # URL长度
            features["url_length"] = len(url)
            
            # 解析URL参数
            parsed_url = urlparse(url)
            query_params = parse_qs(parsed_url.query)
            
            # 参数数量
            features["param_count"] = len(query_params)
            
            # 参数值总长度
            param_value_length = 0
            for key, values in query_params.items():
                for value in values:
                    param_value_length += len(value)
            features["param_value_length"] = param_value_length
            
            # 特殊字符计数
            special_chars = ['"', "'", "<", ">", "=", "(", ")", "{", "}", "[", "]", 
                           "script", "alert", "union", "select", "insert", "update", 
                           "delete", "drop", "create", "alter", "exec", "eval"]
            special_char_count = 0
            for char in special_chars:
                special_char_count += url.lower().count(char)
            features["special_char_count"] = special_char_count
            
        else:
            # 默认值
            features["url_length"] = 0
            features["param_count"] = 0
            features["param_value_length"] = 0
            features["special_char_count"] = 0
        
        # 请求方法特征
        features["is_get"] = 1 if "GET" in request_str else 0
        features["is_post"] = 1 if "POST" in request_str else 0
        features["is_put"] = 1 if "PUT" in request_str else 0
        features["is_delete"] = 1 if "DELETE" in request_str else 0
        
        # 响应状态特征
        features["response_status"] = response_status
        features["is_4xx"] = 1 if 400 <= response_status < 500 else 0
        features["is_5xx"] = 1 if 500 <= response_status < 600 else 0
        
        # 请求体长度
        body_start = request_str.find("\r\n\r\n")
        if body_start != -1:
            body = request_str[body_start+4:]
            features["request_body_length"] = len(body)
        else:
            features["request_body_length"] = 0
            
        # 请求头数量
        header_lines = request_str.split("\r\n")[1:]  # 跳过第一行（请求行）
        header_count = 0
        for line in header_lines:
            if ":" in line:
                header_count += 1
        features["header_count"] = header_count
        
        # 常见攻击模式特征
        request_lower = request_str.lower()
        features["has_sql_keywords"] = 1 if any(keyword in request_lower 
                                               for keyword in ['select', 'union', 'insert', 'update', 'delete', 'drop']) else 0
        features["has_xss_keywords"] = 1 if any(keyword in request_lower 
                                               for keyword in ['script', 'alert', 'onerror', 'onload', 'eval']) else 0
        features["has_lfi_keywords"] = 1 if any(keyword in request_lower 
                                               for keyword in ['../', '..\\', 'etc/passwd', 'boot.ini']) else 0
        
        return features
    
    def generate_training_data(self, rules_data):
        """
        根据规则数据生成训练样本
        
        Args:
            rules_data: Part2解析的规则数据，应包含以下字段:
              - rule_info: 规则基本信息，包括id, phase, variables, operator, pattern等
              - semantic_analysis: 语义分析结果，包括攻击类型分类等
              - dependency_analysis: 依赖分析结果，包括变量依赖、标记依赖等
              - conflict_analysis: 冲突分析结果，包括潜在冲突规则等
            
        Returns:
            training_data: 生成的训练数据，包含特征和标签
        """
        # 初始化训练数据列表
        training_samples = []
        labels = []
        
        # 遍历所有规则数据
        for file_name, rules in rules_data.items():
            for rule_obj in rules:
                # 获取规则信息
                rule_info = rule_obj.get('rule_info', {})
                semantic_analysis = rule_obj.get('semantic_analysis', {})
                pattern = rule_info.get('pattern', '')
                rule_id = rule_info.get('id', 'unknown')
                
                # 根据规则的攻击类型生成正样本
                attack_types = semantic_analysis.get('attack_types', [])
                
                # 创建一个能触发此规则的示例请求（正样本）
                sample_request = self._generate_positive_sample(pattern, rule_info)
                if sample_request:
                    # 为每个攻击类型生成样本
                    for attack_type in attack_types:
                        # 提取特征
                        features = self.extract_features(sample_request)
                        
                        # 添加规则相关信息作为额外特征
                        features['rule_id'] = hash(rule_id) % 10000  # 将规则ID哈希为数值特征
                        features['attack_type'] = self._encode_attack_type(attack_type)
                        
                        training_samples.append(features)
                        labels.append(1)  # 正样本标签为1
                
                # 生成负样本（不会触发规则的正常请求）
                negative_sample = self._generate_negative_sample()
                if negative_sample:
                    features = self.extract_features(negative_sample)
                    
                    # 添加规则相关信息作为额外特征
                    features['rule_id'] = 0  # 负样本不关联特定规则
                    features['attack_type'] = 0  # 负样本不关联特定攻击类型
                    
                    training_samples.append(features)
                    labels.append(0)  # 负样本标签为0
        
        # 转换为DataFrame格式
        if training_samples:
            df = pd.DataFrame(training_samples)
            df['label'] = labels
            return df
        else:
            return None
    
    def _generate_positive_sample(self, pattern, rule_info):
        """
        根据规则模式生成正样本请求
        
        Args:
            pattern: 规则匹配模式
            rule_info: 规则信息
            
        Returns:
            sample_request: 示例HTTP请求
        """
        # 基于规则模式生成能触发规则的示例请求
        if not pattern:
            return None
            
        # 简单示例：构造包含模式的GET请求
        sample_request = {
            "request": f"GET /test?param={pattern} HTTP/1.1\r\nHost: example.com\r\nUser-Agent: Mozilla/5.0\r\n\r\n",
            "response_status": 200
        }
        
        return sample_request
    
    def _generate_negative_sample(self):
        """
        生成负样本请求（正常的请求）
        
        Returns:
            sample_request: 正常的HTTP请求示例
        """
        # 生成正常的请求示例
        sample_request = {
            "request": "GET /index.html HTTP/1.1\r\nHost: example.com\r\nUser-Agent: Mozilla/5.0\r\n\r\n",
            "response_status": 200
        }
        
        return sample_request
    
    def _encode_attack_type(self, attack_type):
        """
        将攻击类型编码为数值
        
        Args:
            attack_type: 攻击类型字符串
            
        Returns:
            encoded_type: 编码后的数值
        """
        attack_type_mapping = {
            "SQL Injection": 1,
            "Cross-Site Scripting (XSS)": 2,
            "Command Injection": 3,
            "LDAP Injection": 4,
            "XML External Entity (XXE)": 5,
            "File Inclusion": 6,
            "HTTP Request Smuggling": 7,
            "HTTP Response Splitting": 8,
            "Server-Side Request Forgery (SSRF)": 9
        }
        
        return attack_type_mapping.get(attack_type, 0)
    
    def load_dataset(self, dataset_path):
        """
        加载数据集
        
        Args:
            dataset_path: 数据集路径
            
        Returns:
            dataset: 加载的数据集
        """
        try:
            # 尝试加载CSV格式数据
            if dataset_path.endswith('.csv'):
                data = pd.read_csv(dataset_path)
                print(f"成功加载CSV数据集: {dataset_path}")
                return data
            else:
                print("目前仅支持CSV格式数据集")
                return None
        except Exception as e:
            print(f"加载数据集时出错: {e}")
            return None
    
    def preprocess_data(self, raw_data):
        """
        数据预处理
        
        Args:
            raw_data: 原始数据
            
        Returns:
            processed_data: 预处理后的数据
        """
        try:
            # 检查输入数据
            if raw_data is None:
                print("输入数据为空")
                return None
                
            # 如果是DataFrame，进行基本的预处理
            if isinstance(raw_data, pd.DataFrame):
                # 删除完全重复的行
                data = raw_data.drop_duplicates()
                
                # 处理缺失值 - 数值型用均值填充，分类型用众数填充
                for column in data.columns:
                    if data[column].isnull().any():
                        if data[column].dtype in ['int64', 'float64']:
                            # 数值型用均值填充
                            data[column].fillna(data[column].mean(), inplace=True)
                        else:
                            # 分类型用众数填充
                            mode_value = data[column].mode()
                            if not mode_value.empty:
                                data[column].fillna(mode_value[0], inplace=True)
                
                print(f"数据预处理完成，原始数据 shape: {raw_data.shape}, 处理后数据 shape: {data.shape}")
                return data
            else:
                print("目前仅支持pandas DataFrame格式的数据预处理")
                return raw_data
                
        except Exception as e:
            print(f"数据预处理时出错: {e}")
            return raw_data


def main():
    """
    主函数，用于测试数据处理模块
    """
    # TODO: 实现主函数逻辑
    pass


if __name__ == "__main__":
    main()