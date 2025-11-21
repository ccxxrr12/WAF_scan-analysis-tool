#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
配置文件

该模块定义了Part3的各种配置参数。
包括模型参数、数据处理参数、训练参数等。

文件结构：
- MODEL_CONFIGS: 模型配置
- DATA_CONFIGS: 数据配置
- TRAINING_CONFIGS: 训练配置
- DEFAULT_FEATURES: 默认特征列表
"""

# 模型配置
MODEL_CONFIGS = {
    "logistic_regression": {
        "penalty": "l2",
        "C": 1.0,
        "random_state": 42
    },
    
    "random_forest": {
        "n_estimators": 100,
        "max_depth": 10,
        "random_state": 42
    },
    
    "xgboost": {
        "n_estimators": 100,
        "max_depth": 6,
        "learning_rate": 0.1,
        "random_state": 42
    },
    
    "lstm": {
        "hidden_units": 64,
        "layers": 2,
        "dropout": 0.2
    },
    
    "cnn": {
        "filters": 32,
        "kernel_size": 3,
        "pool_size": 2
    }
}

# 数据配置
DATA_CONFIGS = {
    "test_size": 0.2,
    "val_size": 0.1,
    "random_state": 42,
    "shuffle": True
}

# 训练配置
TRAINING_CONFIGS = {
    "cv_folds": 5,
    "scoring": "accuracy"
}

# 默认特征列表
DEFAULT_FEATURES = [
    "url_length",
    "param_count",
    "param_value_length",
    "special_char_count",
    "encoding_type",
    "user_agent_anomaly",
    "content_type_anomaly",
    "header_count"
]

# WAF类型映射
WAF_TYPES = {
    "cloudflare": "Cloudflare WAF",
    "modsecurity": "ModSecurity",
    "aws": "AWS WAF",
    "imperva": "Imperva WAF",
    "f5": "F5 WAF"
}

# 攻击类型
ATTACK_TYPES = [
    "xss",
    "sqli",
    "cmd_injection",
    "file_inclusion",
    "csrf"
]