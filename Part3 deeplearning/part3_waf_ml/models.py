#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
模型定义模块

该模块定义了用于WAF拦截预测的各种机器学习模型。
包括传统机器学习模型。

文件结构：
- BaseModel: 基础模型类
- LogisticRegressionModel: 逻辑回归模型
- RandomForestModel: 随机森林模型
- XGBoostModel: XGBoost模型
- ModelFactory: 模型工厂类
"""

import numpy as np
from abc import ABC, abstractmethod
from sklearn.linear_model import LogisticRegression
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score
import xgboost as xgb
from utils import setup_logger
from config import LOG_CONFIG


class BaseModel(ABC):
    """
    基础模型类，定义模型接口
    """
    
    def __init__(self, model_params=None):
        """
        初始化基础模型
        
        Args:
            model_params: 模型参数
        """
        self.model = None
        self.model_params = model_params or {}
        self.logger = setup_logger(self.__class__.__name__, 
                                   log_file=LOG_CONFIG['log_file'], 
                                   level=LOG_CONFIG['log_level'])
        self.logger.info(f"初始化{self.__class__.__name__}模型，参数：{self.model_params}")
    
    @abstractmethod
    def train(self, X_train, y_train):
        """
        训练模型
        
        Args:
            X_train: 训练特征
            y_train: 训练标签
        """
        self.logger.info(f"开始训练模型，训练数据形状：X_train={X_train.shape}, y_train={y_train.shape}")
        pass
    
    @abstractmethod
    def predict(self, X):
        """
        预测
        
        Args:
            X: 输入特征
            
        Returns:
            predictions: 预测结果
        """
        self.logger.info(f"开始预测，输入数据形状：{X.shape}")
        pass
    
    @abstractmethod
    def evaluate(self, X_test, y_test):
        """
        评估模型
        
        Args:
            X_test: 测试特征
            y_test: 测试标签
            
        Returns:
            metrics: 评估指标
        """
        pass


class LogisticRegressionModel(BaseModel):
    """
    逻辑回归模型
    """
    
    def __init__(self, model_params=None):
        """
        初始化逻辑回归模型
        
        Args:
            model_params: 模型参数
        """
        super().__init__(model_params)
        self.model = LogisticRegression(**self.model_params)
    
    def train(self, X_train, y_train):
        """
        训练逻辑回归模型
        
        Args:
            X_train: 训练特征
            y_train: 训练标签
        """
        super().train(X_train, y_train)
        try:
            self.model.fit(X_train, y_train)
            self.logger.info("逻辑回归模型训练完成")
        except Exception as e:
            self.logger.error(f"逻辑回归模型训练失败: {e}")
            raise
    
    def predict(self, X):
        """
        逻辑回归预测
        
        Args:
            X: 输入特征
            
        Returns:
            predictions: 预测结果
        """
        super().predict(X)
        try:
            predictions = self.model.predict(X)
            self.logger.info(f"逻辑回归模型预测完成，预测结果形状：{predictions.shape}")
            return predictions
        except Exception as e:
            self.logger.error(f"逻辑回归模型预测失败: {e}")
            raise
    
    def evaluate(self, X_test, y_test):
        """
        评估逻辑回归模型
        
        Args:
            X_test: 测试特征
            y_test: 测试标签
            
        Returns:
            metrics: 评估指标字典
        """
        self.logger.info(f"开始评估模型，测试数据形状：X_test={X_test.shape}, y_test={y_test.shape}")
        try:
            y_pred = self.predict(X_test)
            metrics = {
                'accuracy': accuracy_score(y_test, y_pred),
                'precision': precision_score(y_test, y_pred, average='binary'),
                'recall': recall_score(y_test, y_pred, average='binary'),
                'f1': f1_score(y_test, y_pred, average='binary')
            }
            self.logger.info(f"逻辑回归模型评估完成，指标：{metrics}")
            return metrics
        except Exception as e:
            self.logger.error(f"逻辑回归模型评估失败: {e}")
            raise


class RandomForestModel(BaseModel):
    """
    随机森林模型
    """
    
    def __init__(self, model_params=None):
        """
        初始化随机森林模型
        
        Args:
            model_params: 模型参数
        """
        super().__init__(model_params)
        self.model = RandomForestClassifier(**self.model_params)
    
    def train(self, X_train, y_train):
        """
        训练随机森林模型
        
        Args:
            X_train: 训练特征
            y_train: 训练标签
        """
        super().train(X_train, y_train)
        try:
            self.model.fit(X_train, y_train)
            self.logger.info("随机森林模型训练完成")
        except Exception as e:
            self.logger.error(f"随机森林模型训练失败: {e}")
            raise
    
    def predict(self, X):
        """
        随机森林预测
        
        Args:
            X: 输入特征
            
        Returns:
            predictions: 预测结果
        """
        super().predict(X)
        try:
            predictions = self.model.predict(X)
            self.logger.info(f"随机森林模型预测完成，预测结果形状：{predictions.shape}")
            return predictions
        except Exception as e:
            self.logger.error(f"随机森林模型预测失败: {e}")
            raise
    
    def evaluate(self, X_test, y_test):
        """
        评估随机森林模型
        
        Args:
            X_test: 测试特征
            y_test: 测试标签
            
        Returns:
            metrics: 评估指标字典
        """
        self.logger.info(f"开始评估模型，测试数据形状：X_test={X_test.shape}, y_test={y_test.shape}")
        try:
            y_pred = self.predict(X_test)
            metrics = {
                'accuracy': accuracy_score(y_test, y_pred),
                'precision': precision_score(y_test, y_pred, average='binary'),
                'recall': recall_score(y_test, y_pred, average='binary'),
                'f1': f1_score(y_test, y_pred, average='binary')
            }
            self.logger.info(f"随机森林模型评估完成，指标：{metrics}")
            return metrics
        except Exception as e:
            self.logger.error(f"随机森林模型评估失败: {e}")
            raise


class XGBoostModel(BaseModel):
    """
    XGBoost模型
    """
    
    def __init__(self, model_params=None):
        """
        初始化XGBoost模型
        
        Args:
            model_params: 模型参数
        """
        super().__init__(model_params)
        self.model = xgb.XGBClassifier(**self.model_params)
    
    def train(self, X_train, y_train):
        """
        训练XGBoost模型
        
        Args:
            X_train: 训练特征
            y_train: 训练标签
        """
        super().train(X_train, y_train)
        try:
            self.model.fit(X_train, y_train)
            self.logger.info("XGBoost模型训练完成")
        except Exception as e:
            self.logger.error(f"XGBoost模型训练失败: {e}")
            raise
    
    def predict(self, X):
        """
        XGBoost预测
        
        Args:
            X: 输入特征
            
        Returns:
            predictions: 预测结果
        """
        super().predict(X)
        try:
            predictions = self.model.predict(X)
            self.logger.info(f"XGBoost模型预测完成，预测结果形状：{predictions.shape}")
            return predictions
        except Exception as e:
            self.logger.error(f"XGBoost模型预测失败: {e}")
            raise
    
    def evaluate(self, X_test, y_test):
        """
        评估XGBoost模型
        
        Args:
            X_test: 测试特征
            y_test: 测试标签
            
        Returns:
            metrics: 评估指标字典
        """
        self.logger.info(f"开始评估模型，测试数据形状：X_test={X_test.shape}, y_test={y_test.shape}")
        try:
            y_pred = self.predict(X_test)
            metrics = {
                'accuracy': accuracy_score(y_test, y_pred),
                'precision': precision_score(y_test, y_pred, average='binary'),
                'recall': recall_score(y_test, y_pred, average='binary'),
                'f1': f1_score(y_test, y_pred, average='binary')
            }
            self.logger.info(f"XGBoost模型评估完成，指标：{metrics}")
            return metrics
        except Exception as e:
            self.logger.error(f"XGBoost模型评估失败: {e}")
            raise



class ModelFactory:
    """
    模型工厂类，用于创建不同类型的模型
    """
    
    logger = setup_logger("ModelFactory", 
                         log_file=LOG_CONFIG['log_file'], 
                         level=LOG_CONFIG['log_level'])
    
    @staticmethod
    def create_model(model_type, model_params=None):
        """
        创建模型实例
        
        Args:
            model_type: 模型类型
            model_params: 模型参数
            
        Returns:
            model: 模型实例
        """
        ModelFactory.logger.info(f"创建模型，类型：{model_type}，参数：{model_params}")
        if model_type == "logistic_regression":
            return LogisticRegressionModel(model_params)
        elif model_type == "random_forest":
            return RandomForestModel(model_params)
        elif model_type == "xgboost":
            return XGBoostModel(model_params)
        else:
            ModelFactory.logger.error(f"不支持的模型类型: {model_type}")
            raise ValueError(f"Unsupported model type: {model_type}")


def main():
    """
    主函数，用于测试模型定义
    """
    logger = setup_logger("ModelTest", 
                         log_file=LOG_CONFIG['log_file'], 
                         level=LOG_CONFIG['log_level'])
    logger.info("开始测试模型定义")
    
    # 测试创建模型
    try:
        model = ModelFactory.create_model("random_forest", {"n_estimators": 100})
        logger.info("成功创建随机森林模型")
        
        # 测试基础功能
        X_test = np.random.rand(10, 5)
        y_test = np.random.randint(0, 2, 10)
        
        logger.info("完成模型测试")
    except Exception as e:
        logger.error(f"模型测试失败: {e}")
        raise


if __name__ == "__main__":
    main()