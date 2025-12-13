#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
模型训练器模块

该模块负责模型的训练、验证和测试过程。
包括超参数调优、交叉验证、模型选择等功能。

文件结构：
- ModelTrainer: 模型训练器类
- train_model(): 训练模型
- cross_validate(): 交叉验证 (使用分层K折交叉验证)
- hyperparameter_tuning(): 超参数调优
- select_best_model(): 模型选择
"""

import pickle
from models import ModelFactory
from sklearn.model_selection import cross_val_score, StratifiedKFold
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score
import numpy as np
from utils import setup_logger
from config import LOG_CONFIG


class ModelTrainer:
    """
    模型训练器类
    """
    
    def __init__(self, model_type, model_params=None):
        """
        初始化模型训练器
        
        Args:
            model_type: 模型类型
            model_params: 模型参数
        """
        self.model_type = model_type
        self.model_params = model_params or {}
        self.model = None
        self.logger = setup_logger("ModelTrainer", 
                                   log_file=LOG_CONFIG['log_file'], 
                                   level=LOG_CONFIG['log_level'])
        self.logger.info(f"初始化模型训练器，类型：{model_type}，参数：{model_params}")
    
    def train_model(self, X_train, y_train):
        """
        训练模型
        
        Args:
            X_train: 训练特征
            y_train: 训练标签
        """
        try:
            self.logger.info(f"开始训练{self.model_type}模型，训练数据形状：X_train={X_train.shape}, y_train={y_train.shape}")
            # 创建模型
            self.model = ModelFactory.create_model(self.model_type, self.model_params)
            
            # 训练模型
            self.model.train(X_train, y_train)
            
            self.logger.info(f"模型训练完成: {self.model_type}")
        except Exception as e:
            self.logger.error(f"模型训练失败: {e}")
            raise
    
    def cross_validate(self, X, y, cv_folds=5):
        """
        交叉验证
        
        Args:
            X: 特征数据
            y: 标签数据
            cv_folds: 交叉验证折数
            
        Returns:
            cv_scores: 交叉验证得分
        """
        if self.model is None or self.model.model is None:
            self.logger.warning("模型未训练，无法进行交叉验证")
            return None
        
        try:
            self.logger.info(f"开始交叉验证，折数：{cv_folds}")
            # 使用分层K折交叉验证确保每折中类别分布均匀
            skf = StratifiedKFold(n_splits=cv_folds, shuffle=True, random_state=42)
            cv_scores = cross_val_score(self.model.model, X, y, cv=skf, scoring='accuracy')
            self.logger.info(f"交叉验证完成，得分：{cv_scores.mean():.4f} ± {cv_scores.std():.4f}")
            return cv_scores
        except Exception as e:
            self.logger.error(f"交叉验证过程中出现错误: {e}")
            return None
    
    def hyperparameter_tuning(self, X_train, y_train, param_grid):
        """
        超参数调优
        
        Args:
            X_train: 训练特征
            y_train: 训练标签
            param_grid: 参数网格
            
        Returns:
            best_params: 最佳参数
        """
        from sklearn.model_selection import GridSearchCV
        
        try:
            if self.model is None:
                # 如果模型未初始化，先创建模型
                self.model = ModelFactory.create_model(self.model_type, self.model_params)
            
            # 使用GridSearchCV进行超参数调优
            grid_search = GridSearchCV(
                estimator=self.model.model,
                param_grid=param_grid,
                cv=5,
                scoring='accuracy',
                n_jobs=-1,
                verbose=2
            )
            
            self.logger.info(f"开始超参数调优，参数网格: {param_grid}")
            grid_search.fit(X_train, y_train)
            
            best_params = grid_search.best_params_
            self.logger.info(f"超参数调优完成，最佳参数: {best_params}")
            
            # 更新模型参数并重新训练模型
            self.model_params = best_params
            self.model = ModelFactory.create_model(self.model_type, self.model_params)
            self.model.train(X_train, y_train)
            
            return best_params
        except Exception as e:
            self.logger.error(f"超参数调优过程中出现错误: {e}")
            return self.model_params
    
    def select_best_model(self, models, waf_type=None):
        """
        根据WAF类型选择最佳模型
        
        Args:
            models: 模型字典，键为模型类型，值为模型实例
            waf_type: WAF类型
            
        Returns:
            best_model: 最佳模型
        """
        if not models:
            self.logger.warning("模型列表为空，无法选择最佳模型")
            return None
        
        # 标准化WAF类型
        waf_type = waf_type.lower() if waf_type else ""
        self.logger.info(f"根据WAF类型选择最佳模型，WAF类型：{waf_type}")
        
        # 如果是ModSecurity，优先使用特化模型
        if "modsecurity" in waf_type and "modsecurity" in models:
            self.logger.info("选择ModSecurity特化模型")
            return models["modsecurity"]
        
        # 如果是其他WAF类型，使用通用模型
        if "generic" in models:
            self.logger.info("选择通用模型")
            return models["generic"]
        
        # 如果都没有，返回默认模型或第一个模型
        if "default" in models:
            self.logger.info("选择默认模型")
            return models["default"]
        
        # 返回第一个可用的模型
        self.logger.warning("未找到特定模型，使用第一个可用模型")
        for model in models.values():
            return model
        
        return None
    
    def evaluate_model(self, X_test, y_test):
        """
        评估模型性能
        
        Args:
            X_test: 测试特征
            y_test: 测试标签
            
        Returns:
            metrics: 性能指标
        """
        if self.model is None:
            self.logger.warning("模型未训练，无法进行评估")
            return None
        
        try:
            self.logger.info(f"开始评估模型，测试数据形状：X_test={X_test.shape}, y_test={y_test.shape}")
            # 预测
            y_pred = self.model.predict(X_test)
            
            # 计算指标
            metrics = {
                'accuracy': accuracy_score(y_test, y_pred),
                'precision': precision_score(y_test, y_pred, average='binary'),
                'recall': recall_score(y_test, y_pred, average='binary'),
                'f1': f1_score(y_test, y_pred, average='binary')
            }
            
            self.logger.info(f"模型评估完成，指标：{metrics}")
            return metrics
        except Exception as e:
            self.logger.error(f"模型评估过程中出现错误: {e}")
            return None
    
    def save_model(self, model_path):
        """
        保存模型到文件
        
        Args:
            model_path: 模型保存路径
        """
        if self.model is None:
            print("没有可保存的模型")
            return
        
        try:
            with open(model_path, 'wb') as f:
                pickle.dump(self.model.model, f)
            print(f"模型已保存到: {model_path}")
        except Exception as e:
            print(f"保存模型时出现错误: {e}")


def main():
    """
    主函数，用于测试模型训练器
    """
    # TODO: 实现主函数逻辑
    pass


if __name__ == "__main__":
    main()