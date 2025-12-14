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
import pandas as pd
from data_processor import DataProcessor
from trainer import ModelTrainer
from predictor import Predictor
from models import ModelFactory
from utils import setup_logger
from config import LOG_CONFIG


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
    
    parser.add_argument(
        "--rules-data-path",
        help="Part2规则数据路径（JSON格式）"
    )
    
    parser.add_argument(
        "--request-data-path",
        help="HTTP请求数据路径（JSON格式）"
    )
    
    return parser.parse_args()


def train_mode(args):
    """
    训练模式
    
    Args:
        args: 命令行参数
    """
    # 初始化训练模式日志器
    train_logger = setup_logger("TrainMode", log_file=LOG_CONFIG['log_file'], level=LOG_CONFIG['log_level'])
    train_logger.info("进入训练模式...")
    
    # 检查必要参数
    if not args.data_path and not args.rules_data_path:
        train_logger.error("训练模式需要指定 --data-path 或 --rules-data-path 参数")
        return
    
    # 初始化数据处理器
    data_processor = DataProcessor()
    
    # 加载和预处理数据
    # 这里简化处理，实际应用中需要根据数据格式进行适当处理
    try:
        if args.rules_data_path:
            # 使用Part2规则数据生成训练数据
            train_logger.info(f"正在加载Part2规则数据: {args.rules_data_path}")
            with open(args.rules_data_path, 'r', encoding='utf-8') as f:
                rules_data = json.load(f)
            
            # 生成训练数据
            train_logger.info("正在根据规则数据生成训练样本...")
            training_data = data_processor.generate_training_data(rules_data)
            
            if training_data is not None:
                # 分离特征和标签
                label_column = training_data['label']
                feature_columns = training_data.drop('label', axis=1)
                X = feature_columns.values
                y = label_column.values
                train_logger.info(f"生成训练数据完成，共 {len(X)} 个样本")
            else:
                train_logger.error("未能生成有效的训练数据")
                return
        elif args.data_path:
            # 从CSV文件加载数据
            train_logger.info(f"正在加载数据: {args.data_path}")
            try:
                data = pd.read_csv(args.data_path)
                
                # 检查数据是否包含'label'列
                if 'label' not in data.columns:
                    train_logger.error("CSV文件中缺少'label'列")
                    return
                
                # 分离特征和标签
                label_column = data['label']
                feature_columns = data.drop('label', axis=1)
                X = feature_columns.values
                y = label_column.values
                
                train_logger.info(f"数据加载完成，共 {len(X)} 个样本，{X.shape[1]} 个特征")
            except FileNotFoundError:
                train_logger.error(f"文件未找到: {args.data_path}")
                return
            except Exception as e:
                train_logger.error(f"加载CSV数据时出错: {e}")
                # 为了演示，创建示例数据作为备选
                train_logger.info("创建示例训练数据...")
                X = np.random.rand(100, 10)  # 100个样本，10个特征
                y = np.random.randint(0, 2, 100)  # 二分类标签
        else:
            train_logger.error("未提供有效的数据路径")
            return
        
        train_logger.info(f"数据形状: X={X.shape}, y={y.shape}")
    except Exception as e:
        train_logger.error(f"加载数据时出错: {e}")
        return
    
    # 如果提供了WAF指纹信息，则处理它
    if args.waf_info_path:
        try:
            with open(args.waf_info_path, 'r', encoding='utf-8') as f:
                waf_info = json.load(f)
            processed_waf = data_processor.process_waf_fingerprint(waf_info)
            train_logger.info(f"处理WAF指纹信息: {processed_waf}")
        except Exception as e:
            train_logger.error(f"处理WAF指纹信息时出错: {e}")
    
    # 初始化模型训练器
    trainer = ModelTrainer(args.model_type)
    
    # 训练模型
    try:
        trainer.train_model(X, y)
        train_logger.info("模型训练完成")
    except Exception as e:
        train_logger.error(f"模型训练时出错: {e}")
        return
    
    # 保存模型
    model_path = args.model_path or f"{args.waf_type}_model.pkl"
    try:
        trainer.save_model(model_path)
        train_logger.info(f"模型已保存到: {model_path}")
    except Exception as e:
        train_logger.error(f"保存模型时出错: {e}")
    
    train_logger.info("训练模式完成")


def predict_mode(args):
    """
    预测模式
    
    Args:
        args: 命令行参数
    """
    # 初始化预测模式日志器
    predict_logger = setup_logger("PredictMode", log_file=LOG_CONFIG['log_file'], level=LOG_CONFIG['log_level'])
    predict_logger.info("进入预测模式...")
    
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
        predict_logger.info("未指定模型路径，尝试加载默认模型...")
        predictor.load_model("modsecurity_model.pkl", "modsecurity")
        predictor.load_model("generic_model.pkl", "generic")
    
    # 如果提供了WAF指纹信息，则处理它
    waf_info = None
    if args.waf_info_path:
        try:
            with open(args.waf_info_path, 'r', encoding='utf-8') as f:
                waf_info = json.load(f)
            predict_logger.info(f"加载WAF指纹信息: {waf_info}")
        except Exception as e:
            predict_logger.error(f"加载WAF指纹信息时出错: {e}")
    
    # 获取HTTP请求数据
    if args.request_data_path:
        try:
            with open(args.request_data_path, 'r', encoding='utf-8') as f:
                sample_request = json.load(f)
            predict_logger.info(f"加载HTTP请求数据: {sample_request}")
        except Exception as e:
            predict_logger.error(f"加载HTTP请求数据时出错: {e}")
            # 使用默认示例请求
            sample_request = {
                "request": "GET /index.html HTTP/1.1\r\nHost: example.com\r\nUser-Agent: Mozilla/5.0\r\n\r\n",
                "response_status": 200
            }
    else:
        # 使用默认示例请求
        sample_request = {
            "request": "GET /index.html HTTP/1.1\r\nHost: example.com\r\nUser-Agent: Mozilla/5.0\r\n\r\n",
            "response_status": 200
        }
    
    # 进行预测
    try:
        prediction, confidence = predictor.predict(sample_request, waf_info)
        predict_logger.info(f"预测结果: {prediction}")
        predict_logger.info(f"置信度: {confidence}")
    except Exception as e:
        predict_logger.error(f"预测时出错: {e}")
    
    predict_logger.info("预测模式完成")


def evaluate_mode(args):
    """
    评估模式
    
    Args:
        args: 命令行参数
    """
    # 初始化评估模式日志器
    eval_logger = setup_logger("EvaluateMode", log_file=LOG_CONFIG['log_file'], level=LOG_CONFIG['log_level'])
    eval_logger.info("进入评估模式...")
    
    # 检查必要参数
    if not args.model_path or not args.data_path:
        eval_logger.error("评估模式需要指定 --model-path 和 --data-path 参数")
        return
    
    # 初始化数据处理器
    data_processor = DataProcessor()
    
    # 加载和预处理数据
    try:
        eval_logger.info(f"正在加载测试数据: {args.data_path}")
        # 从CSV文件加载测试数据
        data = pd.read_csv(args.data_path)
        
        # 检查数据是否包含'label'列
        if 'label' not in data.columns:
            eval_logger.error("CSV文件中缺少'label'列")
            return
        
        # 分离特征和标签
        label_column = data['label']
        feature_columns = data.drop('label', axis=1)
        X_test = feature_columns.values
        y_test = label_column.values
        
        eval_logger.info(f"测试数据加载完成，共 {len(X_test)} 个样本，{X_test.shape[1]} 个特征")
        eval_logger.info(f"测试数据形状: X_test={X_test.shape}, y_test={y_test.shape}")
    except FileNotFoundError:
        eval_logger.error(f"文件未找到: {args.data_path}")
        return
    except Exception as e:
        eval_logger.error(f"加载测试数据时出错: {e}")
        # 为了演示，创建示例测试数据
        eval_logger.info("创建示例测试数据...")
        X_test = np.random.rand(50, 10)  # 50个测试样本，10个特征
        y_test = np.random.randint(0, 2, 50)  # 测试标签
        eval_logger.info(f"测试数据形状: X_test={X_test.shape}, y_test={y_test.shape}")
        return
    
    # 如果提供了WAF指纹信息，则处理它
    if args.waf_info_path:
        try:
            with open(args.waf_info_path, 'r', encoding='utf-8') as f:
                waf_info = json.load(f)
            processed_waf = data_processor.process_waf_fingerprint(waf_info)
            eval_logger.info(f"处理WAF指纹信息: {processed_waf}")
        except Exception as e:
            eval_logger.error(f"处理WAF指纹信息时出错: {e}")
    
    # 初始化模型训练器用于评估
    trainer = ModelTrainer(args.model_type)
    
    # 加载模型
    try:
        with open(args.model_path, 'rb') as f:
            trainer.model = ModelFactory.create_model(args.model_type)
            trainer.model.model = pickle.load(f)
        eval_logger.info(f"成功加载模型: {args.model_path}")
    except Exception as e:
        eval_logger.error(f"加载模型时出错: {e}")
        return
    
    # 进行评估
    try:
        metrics = trainer.evaluate_model(X_test, y_test)
        if metrics:
            eval_logger.info("模型评估结果:")
            for metric, value in metrics.items():
                eval_logger.info(f"  {metric}: {value:.4f}")
        else:
            eval_logger.error("评估失败")
    except Exception as e:
        eval_logger.error(f"评估时出错: {e}")
    
    eval_logger.info("评估模式完成")


def main():
    """
    主函数
    """
    # 初始化主日志器
    main_logger = setup_logger("Main", log_file=LOG_CONFIG['log_file'], level=LOG_CONFIG['log_level'])
    
    # 解析命令行参数
    args = parse_args()
    main_logger.info(f"启动程序，运行模式: {args.mode}")
    
    # 根据模式执行相应功能
    if args.mode == "train":
        train_mode(args)
    elif args.mode == "predict":
        predict_mode(args)
    elif args.mode == "evaluate":
        evaluate_mode(args)
    else:
        main_logger.error("未知模式")


if __name__ == "__main__":
    main()