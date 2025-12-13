#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
预测器模块

该模块负责使用训练好的模型对新的HTTP请求进行拦截预测。
支持不同WAF类型的特化模型和通用模型。

文件结构：
- Predictor: 预测器类
- predict(): 预测单个请求
- batch_predict(): 批量预测
- load_model(): 加载模型
- select_model_by_waf(): 根据WAF类型选择模型
"""

import os
import pickle
from data_processor import DataProcessor
from utils import setup_logger
from config import LOG_CONFIG


class Predictor:
    """
    预测器类
    """
    
    def __init__(self):
        """
        初始化预测器
        """
        self.data_processor = DataProcessor()
        self.models = {}  # 存储不同类型的模型
        self.default_model = None  # 默认模型
        self.logger = setup_logger("Predictor", log_file=LOG_CONFIG['log_file'], level=LOG_CONFIG['log_level'])
        self.logger.info("初始化预测器")
    
    def load_model(self, model_path, model_type="default"):
        """
        加载模型
        
        Args:
            model_path: 模型路径
            model_type: 模型类型 ("modsecurity", "generic", "default")
        """
        if os.path.exists(model_path):
            try:
                with open(model_path, 'rb') as f:
                    model = pickle.load(f)
                
                if model_type == "default":
                    self.default_model = model
                else:
                    self.models[model_type] = model
                    
                self.logger.info(f"成功加载{model_type}模型: {model_path}")
            except Exception as e:
                self.logger.error(f"加载模型失败: {e}")
        else:
            self.logger.error(f"模型文件不存在: {model_path}")
    
    def select_model_by_waf(self, waf_type):
        """
        根据WAF类型选择模型
        
        Args:
            waf_type: WAF类型
            
        Returns:
            model: 选择的模型
        """
        # 标准化WAF类型
        waf_type = waf_type.lower() if waf_type else ""
        
        # 如果是ModSecurity，优先使用特化模型
        if "modsecurity" in waf_type and "modsecurity" in self.models:
            return self.models["modsecurity"]
        
        # 如果是其他WAF类型，使用通用模型
        if "generic" in self.models:
            return self.models["generic"]
        
        # 如果都没有，使用默认模型
        return self.default_model
    
    def predict(self, http_request, waf_info=None):
        """
        预测单个HTTP请求是否会被拦截
        
        Args:
            http_request: HTTP请求
            waf_info: WAF信息（可选）
            
        Returns:
            prediction: 预测结果
            confidence: 置信度
        """
        # 提取特征
        features = self.data_processor.extract_features(http_request)
        
        # 获取WAF类型
        waf_type = None
        if waf_info and isinstance(waf_info, dict):
            waf_type = waf_info.get("waf_type", None)
        
        # 选择模型
        model = self.select_model_by_waf(waf_type)
        
        if model is None:
            self.logger.error("没有可用的模型")
            return None, 0.0
        
        # 转换特征为模型所需格式（这里简化处理）
        # 实际应用中需要根据具体模型要求进行特征处理
        feature_vector = list(features.values())
        
        try:
            # 预测
            prediction = model.predict([feature_vector])[0]
            
            # 获取预测概率（如果模型支持）
            confidence = 0.0
            if hasattr(model, "predict_proba"):
                proba = model.predict_proba([feature_vector])[0]
                confidence = max(proba)
            
            self.logger.info(f"预测完成，结果: {prediction}, 置信度: {confidence:.4f}")
            return prediction, confidence
        except Exception as e:
            self.logger.error(f"预测过程中出现错误: {e}")
            return None, 0.0
    
    def batch_predict(self, http_requests, waf_info_list=None):
        """
        批量预测HTTP请求
        
        Args:
            http_requests: HTTP请求列表
            waf_info_list: WAF信息列表（可选）
            
        Returns:
            predictions: 预测结果列表
        """
        predictions = []
        
        for i, request in enumerate(http_requests):
            waf_info = None
            if waf_info_list and i < len(waf_info_list):
                waf_info = waf_info_list[i]
            
            prediction, confidence = self.predict(request, waf_info)
            predictions.append({
                'prediction': prediction,
                'confidence': confidence
            })
        
        return predictions


def main():
    """
    主函数，用于测试预测器
    """
    # TODO: 实现主函数逻辑
    pass


if __name__ == "__main__":
    main()