#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
主程序入口

该模块是Part3的主程序入口，整合了数据处理、模型训练、预测和评估等功能。
支持命令行参数配置不同运行模式。

文件结构：
- main(): 主函数
- train_mode(): 训练模式
- predict_mode(): 预测模式
- evaluate_mode(): 评估模式
- parse_args(): 解析命令行参数

命令行参数：
--mode: 运行模式，可选 train/predict/evaluate，默认为 predict
--model-type: 模型类型，可选 logistic_regression/random_forest/xgboost
--data-path: 数据路径，训练和评估模式必需
--model-path: 模型路径，预测和评估模式必需
--output-path: 输出路径（预留）
--waf-info-path: WAF指纹信息路径（JSON格式）
--waf-type: WAF类型，可选 modsecurity/generic，用于训练模式
"""

import argparse
import json
import pickle
import numpy as np
from data_processor import DataProcessor
from trainer import ModelTrainer
from predictor import Predictor
from models import ModelFactory


def parse_args():
    """
    解析命令行参数
    
    Returns:
        args: 参数对象
    """
    parser = argparse.ArgumentParser(description="WAF拦截预测系统")
    
    parser.add_argument(
        "--mode", 
        choices=["train", "predict", "evaluate"],
        default="predict",
        help="运行模式"
    )
    
    parser.add_argument(
        "--model-type",
        choices=["logistic_regression", "random_forest", "xgboost"],
        default="random_forest",
        help="模型类型"
    )
    
    parser.add_argument(
        "--data-path",
        help="数据路径"
    )
    
    parser.add_argument(
        "--model-path",
        help="模型路径"
    )
    
    parser.add_argument(
        "--output-path",
        help="输出路径"
    )
    
    parser.add_argument(
        "--waf-info-path",
        help="WAF指纹信息路径"
    )
    
    parser.add_argument(
        "--waf-type",
        choices=["modsecurity", "generic"],
        default="generic",
        help="WAF类型（用于训练模式）"
    )
    
    return parser.parse_args()


def train_mode(args):
    """
    训练模式
    
    Args:
        args: 命令行参数
    """
    print("进入训练模式...")
    
    # 检查必要参数
    if not args.data_path:
        print("错误: 训练模式需要指定 --data-path 参数")
        return
    
    # 初始化数据处理器
    data_processor = DataProcessor()
    
    # 加载和预处理数据
    # 这里简化处理，实际应用中需要根据数据格式进行适当处理
    try:
        # 假设数据是CSV格式，包含特征列和标签列
        # 在实际应用中需要根据具体情况实现数据加载逻辑
        print(f"正在加载数据: {args.data_path}")
        # 示例数据加载（需要根据实际情况修改）
        # data = pd.read_csv(args.data_path)
        # X = data.drop('label', axis=1)
        # y = data['label']
        
        # 为了演示，我们创建一些示例数据
        print("创建示例训练数据...")
        X = np.random.rand(100, 10)  # 100个样本，10个特征
        y = np.random.randint(0, 2, 100)  # 二分类标签
        
        print(f"数据形状: X={X.shape}, y={y.shape}")
    except Exception as e:
        print(f"加载数据时出错: {e}")
        return
    
    # 如果提供了WAF指纹信息，则处理它
    if args.waf_info_path:
        try:
            with open(args.waf_info_path, 'r', encoding='utf-8') as f:
                waf_info = json.load(f)
            processed_waf = data_processor.process_waf_fingerprint(waf_info)
            print(f"处理WAF指纹信息: {processed_waf}")
        except Exception as e:
            print(f"处理WAF指纹信息时出错: {e}")
    
    # 初始化模型训练器
    trainer = ModelTrainer(args.model_type)
    
    # 训练模型
    try:
        trainer.train_model(X, y)
        print("模型训练完成")
    except Exception as e:
        print(f"模型训练时出错: {e}")
        return
    
    # 保存模型
    model_path = args.model_path or f"{args.waf_type}_model.pkl"
    try:
        trainer.save_model(model_path)
        print(f"模型已保存到: {model_path}")
    except Exception as e:
        print(f"保存模型时出错: {e}")
    
    print("训练模式完成")


def predict_mode(args):
    """
    预测模式
    
    Args:
        args: 命令行参数
    """
    print("进入预测模式...")
    
    # 初始化预测器
    predictor = Predictor()
    
    # 加载模型
    model_path = args.model_path
    if model_path:
        # 根据模型路径判断模型类型
        if "modsecurity" in model_path.lower():
            predictor.load_model(model_path, "modsecurity")
        else:
            predictor.load_model(model_path, "generic")
    else:
        # 尝试加载默认模型
        print("未指定模型路径，尝试加载默认模型...")
        predictor.load_model("modsecurity_model.pkl", "modsecurity")
        predictor.load_model("generic_model.pkl", "generic")
    
    # 如果提供了WAF指纹信息，则处理它
    waf_info = None
    if args.waf_info_path:
        try:
            with open(args.waf_info_path, 'r', encoding='utf-8') as f:
                waf_info = json.load(f)
            print(f"加载WAF指纹信息: {waf_info}")
        except Exception as e:
            print(f"加载WAF指纹信息时出错: {e}")
    
    # 创建示例HTTP请求进行预测
    # 实际应用中应该从文件或网络加载真实的HTTP请求
    sample_request = {
        "request": "GET /index.html HTTP/1.1\r\nHost: example.com\r\nUser-Agent: Mozilla/5.0\r\n\r\n",
        "response_status": 200
    }
    
    # 进行预测
    try:
        prediction, confidence = predictor.predict(sample_request, waf_info)
        print(f"预测结果: {prediction}")
        print(f"置信度: {confidence}")
    except Exception as e:
        print(f"预测时出错: {e}")
    
    print("预测模式完成")


def evaluate_mode(args):
    """
    评估模式
    
    Args:
        args: 命令行参数
    """
    print("进入评估模式...")
    
    # 检查必要参数
    if not args.model_path or not args.data_path:
        print("错误: 评估模式需要指定 --model-path 和 --data-path 参数")
        return
    
    # 初始化数据处理器
    data_processor = DataProcessor()
    
    # 加载和预处理数据
    try:
        print(f"正在加载测试数据: {args.data_path}")
        # 示例数据加载（需要根据实际情况修改）
        X_test = np.random.rand(50, 10)  # 50个测试样本，10个特征
        y_test = np.random.randint(0, 2, 50)  # 测试标签
        print(f"测试数据形状: X_test={X_test.shape}, y_test={y_test.shape}")
    except Exception as e:
        print(f"加载测试数据时出错: {e}")
        return
    
    # 如果提供了WAF指纹信息，则处理它
    if args.waf_info_path:
        try:
            with open(args.waf_info_path, 'r', encoding='utf-8') as f:
                waf_info = json.load(f)
            processed_waf = data_processor.process_waf_fingerprint(waf_info)
            print(f"处理WAF指纹信息: {processed_waf}")
        except Exception as e:
            print(f"处理WAF指纹信息时出错: {e}")
    
    # 初始化模型训练器用于评估
    trainer = ModelTrainer(args.model_type)
    
    # 加载模型
    try:
        with open(args.model_path, 'rb') as f:
            trainer.model = ModelFactory.create_model(args.model_type)
            trainer.model.model = pickle.load(f)
        print(f"成功加载模型: {args.model_path}")
    except Exception as e:
        print(f"加载模型时出错: {e}")
        return
    
    # 进行评估
    try:
        metrics = trainer.evaluate_model(X_test, y_test)
        if metrics:
            print("模型评估结果:")
            for metric, value in metrics.items():
                print(f"  {metric}: {value:.4f}")
        else:
            print("评估失败")
    except Exception as e:
        print(f"评估时出错: {e}")
    
    print("评估模式完成")


def main():
    """
    主函数
    """
    # 解析命令行参数
    args = parse_args()
    
    # 根据模式执行相应功能
    if args.mode == "train":
        train_mode(args)
    elif args.mode == "predict":
        predict_mode(args)
    elif args.mode == "evaluate":
        evaluate_mode(args)
    else:
        print("未知模式")


if __name__ == "__main__":
    main()