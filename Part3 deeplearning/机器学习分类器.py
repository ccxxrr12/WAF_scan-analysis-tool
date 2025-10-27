# Part1_WAFFingerprint/lib/ml_classifier.py
# -*- coding: utf-8 -*-
"""
WAF指纹识别机器学习分类器
使用多种算法进行WAF类型分类
"""

import joblib
import numpy as np
from typing import Dict, List, Any, Tuple
from sklearn.ensemble import RandomForestClassifier
from sklearn.svm import SVC
from xgboost import XGBClassifier
from sklearn.neural_network import MLPClassifier
from sklearn.preprocessing import LabelEncoder, StandardScaler
from sklearn.metrics import accuracy_score, classification_report

from config import FingerprintConfig
from feature_extractor import WAFFeatureExtractor

class WAFClassifier:
    """WAF指纹识别分类器类"""
    
    def __init__(self, model_type: str = None):
        """
        初始化分类器
        
        参数:
            model_type: 模型类型
        """
        self.config = FingerprintConfig()
        self.feature_extractor = WAFFeatureExtractor()
        self.model_type = model_type or self.config.DEFAULT_MODEL
        self.model = None
        self.scaler = StandardScaler()
        self.label_encoder = LabelEncoder()
        self.is_trained = False
    
    def create_model(self, model_type: str = None) -> Any:
        """
        创建指定的机器学习模型
        
        参数:
            model_type: 模型类型
            
        返回:
            机器学习模型实例
        """
        model_type = model_type or self.model_type
        
        if model_type == 'random_forest':
            return RandomForestClassifier(
                n_estimators=100,
                max_depth=10,
                random_state=42,
                n_jobs=-1
            )
        elif model_type == 'xgboost':
            return XGBClassifier(
                n_estimators=100,
                max_depth=6,
                learning_rate=0.1,
                random_state=42,
                n_jobs=-1
            )
        elif model_type == 'svm':
            return SVC(
                C=1.0,
                kernel='rbf',
                probability=True,
                random_state=42
            )
        elif model_type == 'neural_network':
            return MLPClassifier(
                hidden_layer_sizes=(64, 32),
                activation='relu',
                learning_rate_init=0.001,
                random_state=42,
                max_iter=1000
            )
        else:
            raise ValueError(f"不支持的模型类型: {model_type}")
    
    def train(self, features: np.ndarray, labels: List[str], model_type: str = None) -> Dict[str, Any]:
        """
        训练WAF分类器
        
        参数:
            features: 特征矩阵
            labels: 标签列表
            model_type: 模型类型
            
        返回:
            训练结果字典
        """
        try:
            # 编码标签
            encoded_labels = self.label_encoder.fit_transform(labels)
            
            # 特征标准化
            scaled_features = self.scaler.fit_transform(features)
            
            # 创建并训练模型
            self.model_type = model_type or self.model_type
            self.model = self.create_model(self.model_type)
            self.model.fit(scaled_features, encoded_labels)
            
            self.is_trained = True
            
            # 计算训练准确率
            predictions = self.model.predict(scaled_features)
            accuracy = accuracy_score(encoded_labels, predictions)
            
            return {
                'status': 'success',
                'accuracy': accuracy,
                'model_type': self.model_type,
                'classes': self.label_encoder.classes_.tolist()
            }
            
        except Exception as e:
            return {
                'status': 'error',
                'error': str(e)
            }
    
    def predict(self, http_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        预测WAF类型
        
        参数:
            http_data: HTTP数据字典
            
        返回:
            预测结果字典
        """
        if not self.is_trained or self.model is None:
            return {'error': '模型未训练'}
        
        try:
            # 提取特征
            features = self.feature_extractor.extract_comprehensive_features(http_data)
            features = features.reshape(1, -1)
            
            # 特征标准化
            scaled_features = self.scaler.transform(features)
            
            # 预测
            prediction = self.model.predict(scaled_features)[0]
            probability = self.model.predict_proba(scaled_features)[0]
            
            # 获取预测类别和置信度
            predicted_class = self.label_encoder.inverse_transform([prediction])[0]
            confidence = np.max(probability)
            
            # 获取所有类别的概率
            class_probabilities = {}
            for i, class_name in enumerate(self.label_encoder.classes_):
                class_probabilities[class_name] = float(probability[i])
            
            return {
                'waf_type': predicted_class,
                'confidence': float(confidence),
                'probabilities': class_probabilities,
                'is_detected': confidence > self.config.CONFIDENCE_THRESHOLD
            }
            
        except Exception as e:
            return {'error': f'预测失败: {str(e)}'}
    
    def predict_batch(self, http_data_list: List[Dict]) -> List[Dict[str, Any]]:
        """
        批量预测WAF类型
        
        参数:
            http_data_list: HTTP数据字典列表
            
        返回:
            预测结果列表
        """
        results = []
        for http_data in http_data_list:
            result = self.predict(http_data)
            result['target'] = http_data.get('target_url', 'unknown')
            results.append(result)
        
        return results
    
    def save_model(self, model_path: str = None):
        """
        保存训练好的模型
        
        参数:
            model_path: 模型保存路径
        """
        if not self.is_trained:
            raise ValueError("没有训练好的模型可以保存")
        
        if model_path is None:
            model_path = f"{self.config.MODEL_DIR}/waf_classifier_{self.model_type}.pkl"
        
        # 保存模型和相关组件
        model_data = {
            'model': self.model,
            'scaler': self.scaler,
            'label_encoder': self.label_encoder,
            'model_type': self.model_type,
            'feature_extractor': self.feature_extractor
        }
        
        joblib.dump(model_data, model_path)
    
    def load_model(self, model_path: str):
        """
        加载训练好的模型
        
        参数:
            model_path: 模型文件路径
        """
        try:
            model_data = joblib.load(model_path)
            
            self.model = model_data['model']
            self.scaler = model_data['scaler']
            self.label_encoder = model_data['label_encoder']
            self.model_type = model_data['model_type']
            self.feature_extractor = model_data['feature_extractor']
            self.is_trained = True
            
        except Exception as e:
            raise ValueError(f"加载模型失败: {str(e)}")
    
    def evaluate(self, features: np.ndarray, labels: List[str]) -> Dict[str, Any]:
        """
        评估模型性能
        
        参数:
            features: 测试特征
            labels: 测试标签
            
        返回:
            评估结果字典
        """
        if not self.is_trained:
            return {'error': '模型未训练'}
        
        try:
            # 编码标签
            encoded_labels = self.label_encoder.transform(labels)
            
            # 特征标准化
            scaled_features = self.scaler.transform(features)
            
            # 预测
            predictions = self.model.predict(scaled_features)
            probabilities = self.model.predict_proba(scaled_features)
            
            # 计算指标
            accuracy = accuracy_score(encoded_labels, predictions)
            
            # 计算平均置信度
            confidences = np.max(probabilities, axis=1)
            avg_confidence = np.mean(confidences)
            
            # 分类报告
            class_report = classification_report(
                encoded_labels, 
                predictions, 
                target_names=self.label_encoder.classes_,
                output_dict=True
            )
            
            return {
                'accuracy': accuracy,
                'average_confidence': avg_confidence,
                'classification_report': class_report,
                'predictions': predictions.tolist(),
                'confidences': confidences.tolist()
            }
            
        except Exception as e:
            return {'error': f'评估失败: {str(e)}'}