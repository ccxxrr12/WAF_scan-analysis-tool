#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
示例脚本：演示如何使用更新后的数据处理器处理WAF指纹和HTTP请求
"""

import sys
import os
sys.path.append(os.path.join(os.path.dirname(__file__), '.'))

from data_processor import DataProcessor


def create_sample_waf_fingerprints():
    """
    创建示例WAF指纹数据用于演示
    """
    sample_fingerprints = [
        {
            "waf_type": "Cloudflare (Cloudflare Inc.)",
            "confidence": 0.95
        },
        {
            "waf_type": "ModSecurity (SpiderLabs)",
            "confidence": 0.87
        },
        {
            "waf_type": "AWS Elastic Load Balancer (Amazon)",
            "confidence": 0.92
        },
        {
            "waf_type": "Unknown WAF",
            "confidence": 0.30
        }
    ]
    
    return sample_fingerprints


def create_sample_http_requests():
    """
    创建示例HTTP请求数据用于演示
    """
    sample_requests = [
        {
            "request": "GET /login?username=admin' OR 1=1 --&password=password HTTP/1.1\r\nHost: example.com\r\nUser-Agent: Mozilla/5.0\r\n\r\n",
            "response_status": 403,
            "is_attack": True
        },
        {
            "request": "GET /index.html HTTP/1.1\r\nHost: example.com\r\nUser-Agent: Mozilla/5.0\r\n\r\n",
            "response_status": 200,
            "is_attack": False
        },
        {
            "request": "POST /search HTTP/1.1\r\nHost: example.com\r\nContent-Type: application/x-www-form-urlencoded\r\n\r\nquery=<script>alert(1)</script>",
            "response_status": 406,
            "is_attack": True
        },
        {
            "request": "GET /about HTTP/1.1\r\nHost: example.com\r\nUser-Agent: Mozilla/5.0\r\nAccept: */*\r\n\r\n",
            "response_status": 200,
            "is_attack": False
        }
    ]
    
    return sample_requests


def main():
    """
    主函数：演示数据处理流程
    """
    print("=== WAF指纹和HTTP请求处理演示 ===")
    
    # 1. 创建示例数据
    print("\n1. 创建示例数据...")
    waf_fingerprints = create_sample_waf_fingerprints()
    http_requests = create_sample_http_requests()
    
    print(f"创建了 {len(waf_fingerprints)} 个WAF指纹样本")
    print(f"创建了 {len(http_requests)} 个HTTP请求样本")
    
    # 2. 初始化数据处理器
    print("\n2. 初始化数据处理器...")
    processor = DataProcessor()
    
    # 3. 处理WAF指纹
    print("\n3. 处理WAF指纹...")
    for i, fingerprint in enumerate(waf_fingerprints):
        processed_waf = processor.process_waf_fingerprint(fingerprint)
        print(f"WAF指纹 {i+1}:")
        print(f"  原始数据: {fingerprint}")
        print(f"  处理结果: {processed_waf}")
    
    # 4. 提取HTTP请求特征
    print("\n4. 提取HTTP请求特征...")
    for i, req in enumerate(http_requests):
        features = processor.extract_features(req)
        print(f"HTTP请求 {i+1}:")
        print(f"  请求预览: {req['request'][:50]}...")
        print(f"  提取特征: {features}")
        print(f"  是否攻击: {req['is_attack']}")
    
    print("\n=== 演示完成 ===")


if __name__ == "__main__":
    main()