#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
示例脚本：演示如何使用数据处理和模型模块
"""

import numpy as np
from data_processor import DataProcessor
from models import ModelFactory
from config import MODEL_CONFIGS


def create_sample_data():
    """
    创建示例数据用于演示
    """
    # 创建一些示例HTTP请求数据
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
        }
    ]
    
    return sample_fingerprints


def main():
    """
    主函数：演示数据处理和模型使用流程
    """
    print("=== WAF拦截预测系统演示 ===")
    
    # 1. 创建示例数据
    print("\n1. 创建示例数据...")
    sample_data = create_sample_data()
    sample_waf_fingerprints = create_sample_waf_fingerprints()
    print(f"创建了 {len(sample_data)} 个示例请求")
    print(f"创建了 {len(sample_waf_fingerprints)} 个示例WAF指纹")
    
    # 2. 初始化数据处理器
    print("\n2. 初始化数据处理器...")
    processor = DataProcessor()
    
    # 3. 处理WAF指纹
    print("\n3. 处理WAF指纹...")
    for i, fingerprint in enumerate(sample_waf_fingerprints):
        processed_waf = processor.process_waf_fingerprint(fingerprint)
        print(f"WAF指纹 {i+1}: {processed_waf}")
    
    # 4. 提取特征
    print("\n4. 提取特征...")
    features_list = []
    labels = []
    
    for req in sample_data:
        features = processor.extract_features(req)
        features_list.append(features)
        labels.append(int(req["is_attack"]))
        print(f"请求特征: {features}")
        print(f"标签: {req['is_attack']}")
    
    # 5. 转换为numpy数组
    print("\n5. 转换特征为numpy数组...")
    # 获取所有特征名称
    feature_names = list(features_list[0].keys())
    print(f"特征名称: {feature_names}")
    
    # 构建特征矩阵
    X = np.array([[features[name] for name in feature_names] for features in features_list])
    y = np.array(labels)
    
    print(f"特征矩阵形状: {X.shape}")
    print(f"标签数组形状: {y.shape}")
    
    # 6. 划分训练集和测试集（简单划分）
    print("\n6. 划分训练集和测试集...")
    split_idx = len(X) // 2
    X_train, X_test = X[:split_idx], X[split_idx:]
    y_train, y_test = y[:split_idx], y[split_idx:]
    
    print(f"训练集大小: {X_train.shape[0]}")
    print(f"测试集大小: {X_test.shape[0]}")
    
    # 7. 创建并训练模型
    print("\n7. 创建并训练逻辑回归模型...")
    model_params = MODEL_CONFIGS["logistic_regression"]
    model = ModelFactory.create_model("logistic_regression", model_params)
    
    # 训练模型
    model.train(X_train, y_train)
    print("模型训练完成")
    
    # 8. 模型预测
    print("\n8. 模型预测...")
    predictions = model.predict(X_test)
    print(f"测试集预测结果: {predictions}")
    print(f"测试集真实标签: {y_test}")
    
    # 9. 模型评估
    print("\n9. 模型评估...")
    metrics = model.evaluate(X_test, y_test)
    print("评估指标:")
    for metric, value in metrics.items():
        print(f"  {metric}: {value:.4f}")
    
    print("\n=== 演示完成 ===")


if __name__ == "__main__":
    main()