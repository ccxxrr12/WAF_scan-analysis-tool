"""
深度学习模块实现
实现DeepLearningInterface接口，封装Part3 deeplearning的功能
"""

import os
import sys
import json
from typing import Dict, List, Optional, Any, Union
import importlib.util

from backend.api_interface import DeepLearningInterface


class DeepLearningImplementation(DeepLearningInterface):
    """深度学习模块的具体实现"""
    
    def __init__(self):
        self.config = {
            'model_dir': os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 
                                    'Part3 deeplearning', 'part3_waf_ml'),
            'model_file': None,
            'data_dir': os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 
                                   'Part3 deeplearning', 'data'),
            'default_model': 'waf_model.pkl'
        }
        self.initialized = False
        self.model = None
        self.model_loaded = False
        self.training_history = {}
        
        # Part3模块组件
        self.predictor = None
        self.trainer = None
        self.evaluator = None
        self.data_processor = None
    
    def initialize(self, config: Dict[str, Any] = None) -> bool:
        """初始化深度学习模块
        
        Args:
            config: 配置参数
            
        Returns:
            bool: 初始化是否成功
        """
        try:
            # 更新配置
            if config:
                self.config.update(config)
            
            # 验证深度学习模块目录是否存在
            if not os.path.exists(self.config['model_dir']):
                print(f"深度学习模块目录不存在: {self.config['model_dir']}")
                return False
            
            # 添加深度学习模块路径到sys.path
            if self.config['model_dir'] not in sys.path:
                sys.path.append(self.config['model_dir'])
            
            # 动态导入Part3模块
            try:
                import predictor
                import trainer
                import evaluator
                import data_processor
                
                self.predictor = predictor.Predictor()
                self.trainer = trainer.Trainer()
                self.evaluator = evaluator.Evaluator()
                self.data_processor = data_processor.DataProcessor()
                
                # 尝试加载默认模型
                default_model_path = os.path.join(self.config['model_dir'], self.config['default_model'])
                if os.path.exists(default_model_path):
                    self.load_model(default_model_path)
                    
            except ImportError as e:
                print(f"无法导入Part3模块: {e}")
                return False
            
            self.initialized = True
            return True
            
        except Exception as e:
            print(f"初始化深度学习模块失败: {e}")
            self.initialized = False
            return False
    
    def train_model(self, training_data: Union[str, List[Dict[str, Any]]], 
                   model_config: Dict[str, Any] = None) -> Dict[str, Any]:
        """训练模型
        
        Args:
            training_data: 训练数据路径或数据列表
            model_config: 模型配置参数
            
        Returns:
            Dict[str, Any]: 训练结果
        """
        if not self.initialized:
            return {'error': '模块未初始化'}
        
        try:
            # 合并模型配置
            config = {
                'epochs': 50,
                'batch_size': 32,
                'learning_rate': 0.001,
                'test_split': 0.2,
                'random_state': 42
            }
            if model_config:
                config.update(model_config)
            
            # 准备训练数据
            if isinstance(training_data, str):
                if not os.path.exists(training_data):
                    return {'error': f'训练数据文件不存在: {training_data}'}
                # 加载文件数据
                with open(training_data, 'r') as f:
                    training_data = json.load(f)
            
            # 使用Part3 trainer进行训练
            training_results = self.trainer.train(training_data, config)
            
            # 保存训练历史
            self.training_history = training_results
            
            return training_results
            
        except Exception as e:
            print(f"模型训练失败: {e}")
            return {'error': str(e)}
    
    def predict(self, data: Union[str, Dict[str, Any]]) -> Dict[str, Any]:
        """预测数据
        
        Args:
            data: 待预测的数据，可以是字符串或字典
            
        Returns:
            Dict[str, Any]: 预测结果
        """
        if not self.initialized:
            return {'error': '模块未初始化'}
        
        if not self.model_loaded and self.predictor.default_model is None:
            return {'error': '模型未加载'}
        
        try:
            # 使用Part3 predictor进行预测
            if isinstance(data, str):
                # 字符串数据处理
                prediction, confidence = self.predictor.predict({'raw_data': data})
            elif isinstance(data, dict):
                # 字典数据处理
                prediction, confidence = self.predictor.predict(data)
            else:
                prediction, confidence = self.predictor.predict({'raw_data': str(data)})
            
            return {
                'prediction': 'Attack' if prediction == 1 else 'Benign',
                'confidence': confidence,
                'input_type': type(data).__name__,
                'timestamp': '2024-01-01T00:00:00Z'  # 实际应用中应该使用真实时间
            }
            
        except Exception as e:
            print(f"预测失败: {e}")
            return {'error': str(e)}
    
    def evaluate_model(self, test_data: Union[str, List[Dict[str, Any]]]) -> Dict[str, float]:
        """评估模型性能
        
        Args:
            test_data: 测试数据路径或数据列表
            
        Returns:
            Dict[str, float]: 评估指标
        """
        if not self.initialized:
            return {'error': '模块未初始化'}
        
        if not self.model_loaded:
            return {'error': '模型未加载'}
        
        try:
            # 准备测试数据
            if isinstance(test_data, str):
                if not os.path.exists(test_data):
                    return {'error': f'测试数据文件不存在: {test_data}'}
                with open(test_data, 'r') as f:
                    test_data = json.load(f)
            
            # 使用Part3 evaluator进行评估
            evaluation_metrics = self.evaluator.evaluate(test_data)
            
            return evaluation_metrics
            
        except Exception as e:
            print(f"模型评估失败: {e}")
            return {'error': str(e)}
    
    def save_model(self, path: str) -> bool:
        """保存模型
        
        Args:
            path: 模型保存路径
            
        Returns:
            bool: 保存是否成功
        """
        if not self.initialized:
            return False
        
        try:
            # 确保目录存在
            model_dir = os.path.dirname(path)
            if model_dir and not os.path.exists(model_dir):
                os.makedirs(model_dir)
            
            # 使用Part3保存模型
            if self.trainer.model:
                import pickle
                with open(path, 'wb') as f:
                    pickle.dump(self.trainer.model, f)
            
            return True
            
        except Exception as e:
            print(f"保存模型失败: {e}")
            return False
    
    def load_model(self, path: str) -> bool:
        """加载模型
        
        Args:
            path: 模型加载路径
            
        Returns:
            bool: 加载是否成功
        """
        if not self.initialized:
            return False
        
        try:
            if not os.path.exists(path):
                print(f"模型文件不存在: {path}")
                return False
            
            # 使用Part3 predictor加载模型
            self.predictor.load_model(path)
            
            # 更新配置
            self.config['model_file'] = path
            self.model_loaded = True
            
            return True
            
        except Exception as e:
            print(f"加载模型失败: {e}")
            self.model_loaded = False
            return False
    
    def get_status(self) -> Dict[str, Any]:
        """获取模块状态
        
        Returns:
            Dict[str, Any]: 状态信息
        """
        return {
            'initialized': self.initialized,
            'model_loaded': self.model_loaded,
            'model_file': self.config.get('model_file'),
            'config': self.config,
            'last_training_results': self.training_history
        }
