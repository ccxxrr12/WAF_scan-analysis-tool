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
- generate_training_data(): 生成训练数据集
- load_dataset(): 加载数据集
- preprocess_data(): 数据预处理
"""

import re
import numpy as np
from urllib.parse import urlparse, parse_qs


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
            fingerprint_data: WAF指纹数据
            
        Returns:
            processed_data: 处理后的数据
        """
        # TODO: 实现WAF指纹数据处理逻辑
        pass
    
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
        
        return features
    
    def generate_training_data(self, rules_data):
        """
        根据规则数据生成训练样本
        
        Args:
            rules_data: Part2解析的规则数据
            
        Returns:
            training_data: 生成的训练数据
        """
        # TODO: 实现训练数据生成逻辑
        pass
    
    def load_dataset(self, dataset_path):
        """
        加载数据集
        
        Args:
            dataset_path: 数据集路径
            
        Returns:
            dataset: 加载的数据集
        """
        # TODO: 实现数据集加载逻辑
        pass
    
    def preprocess_data(self, raw_data):
        """
        数据预处理
        
        Args:
            raw_data: 原始数据
            
        Returns:
            processed_data: 预处理后的数据
        """
        # TODO: 实现数据预处理逻辑
        # 包括数据清洗、标准化、归一化等
        pass


def main():
    """
    主函数，用于测试数据处理模块
    """
    # TODO: 实现主函数逻辑
    pass


if __name__ == "__main__":
    main()