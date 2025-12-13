#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
模型评估模块

该模块负责评估训练好的模型性能。
包括各种评估指标的计算和可视化。

文件结构：
- Evaluator: 评估器类
- calculate_metrics(): 计算评估指标 (支持准确率、精确率、召回率、F1分数和AUC)
- plot_roc_curve(): 绘制ROC曲线
- plot_confusion_matrix(): 绘制混淆矩阵
- generate_report(): 生成评估报告
"""

import numpy as np
import matplotlib.pyplot as plt
import pandas as pd
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, roc_curve, auc, confusion_matrix
from utils import setup_logger
from config import LOG_CONFIG


class Evaluator:
    """
    评估器类
    """
    
    def __init__(self):
        """
        初始化评估器
        """
        self.logger = setup_logger("Evaluator", 
                                   log_file=LOG_CONFIG['log_file'], 
                                   level=LOG_CONFIG['log_level'])
        self.logger.info("初始化模型评估器")
    
    def calculate_metrics(self, y_true, y_pred, y_pred_proba=None):
        """
        计算评估指标
        
        Args:
            y_true: 真实标签
            y_pred: 预测标签
            y_pred_proba: 预测概率
            
        Returns:
            metrics: 评估指标字典
        """
        metrics = {}
        
        # 计算基本指标
        metrics['accuracy'] = accuracy_score(y_true, y_pred)
        metrics['precision'] = precision_score(y_true, y_pred, average='binary')
        metrics['recall'] = recall_score(y_true, y_pred, average='binary')
        metrics['f1'] = f1_score(y_true, y_pred, average='binary')
        
        # 如果提供了预测概率，计算AUC
        if y_pred_proba is not None:
            try:
                fpr, tpr, _ = roc_curve(y_true, y_pred_proba)
                metrics['auc'] = auc(fpr, tpr)
                self.logger.info(f"成功计算AUC: {metrics['auc']:.4f}")
            except Exception as e:
                self.logger.error(f"计算AUC时出错: {e}")
                metrics['auc'] = None
        else:
            metrics['auc'] = None
            
        return metrics
    
    def plot_roc_curve(self, y_true, y_pred_proba, save_path=None):
        """
        绘制ROC曲线
        
        Args:
            y_true: 真实标签
            y_pred_proba: 预测概率
            save_path: 图表保存路径（可选）
        """
        try:
            fpr, tpr, thresholds = roc_curve(y_true, y_pred_proba)
            roc_auc = auc(fpr, tpr)
            
            plt.figure(figsize=(10, 8))
            plt.plot(fpr, tpr, color='darkorange', lw=2, label='ROC curve (area = %0.2f)' % roc_auc)
            plt.plot([0, 1], [0, 1], color='navy', lw=2, linestyle='--')
            plt.xlim([0.0, 1.0])
            plt.ylim([0.0, 1.05])
            plt.xlabel('False Positive Rate')
            plt.ylabel('True Positive Rate')
            plt.title('Receiver Operating Characteristic (ROC) Curve')
            plt.legend(loc="lower right")
            plt.grid(True)
            
            if save_path:
                plt.savefig(save_path, dpi=300, bbox_inches='tight')
                self.logger.info(f"ROC曲线已保存到: {save_path}")
            
            plt.close()
            self.logger.info(f"成功绘制ROC曲线，AUC: {roc_auc:.4f}")
            return roc_auc
        except Exception as e:
            self.logger.error(f"绘制ROC曲线时出错: {e}")
            return None
    
    def plot_confusion_matrix(self, y_true, y_pred, save_path=None, labels=['Allowed', 'Blocked']):
        """
        绘制混淆矩阵
        
        Args:
            y_true: 真实标签
            y_pred: 预测标签
            save_path: 图表保存路径（可选）
            labels: 类别标签
        """
        try:
            cm = confusion_matrix(y_true, y_pred)
            
            plt.figure(figsize=(10, 8))
            plt.imshow(cm, interpolation='nearest', cmap=plt.cm.Blues)
            plt.title('Confusion Matrix')
            plt.colorbar()
            
            tick_marks = np.arange(len(labels))
            plt.xticks(tick_marks, labels, rotation=45)
            plt.yticks(tick_marks, labels)
            
            # 在混淆矩阵中显示数值
            thresh = cm.max() / 2.
            for i, j in np.ndindex(cm.shape):
                plt.text(j, i, format(cm[i, j], 'd'),
                        horizontalalignment="center",
                        color="white" if cm[i, j] > thresh else "black")
            
            plt.tight_layout()
            plt.ylabel('True Label')
            plt.xlabel('Predicted Label')
            
            if save_path:
                plt.savefig(save_path, dpi=300, bbox_inches='tight')
                self.logger.info(f"混淆矩阵已保存到: {save_path}")
            
            plt.close()
            self.logger.info(f"成功绘制混淆矩阵，矩阵形状：{cm.shape}")
            return cm
        except Exception as e:
            self.logger.error(f"绘制混淆矩阵时出错: {e}")
            return None
    
    def generate_report(self, metrics, save_path=None):
        """
        生成评估报告
        
        Args:
            metrics: 评估指标
            save_path: 报告保存路径（可选）
        """
        try:
            report = "# 模型评估报告\n\n"
            report += "## 评估指标\n\n"
            
            for metric, value in metrics.items():
                if value is not None:
                    report += f"- {metric}: {value:.4f}\n"
                else:
                    report += f"- {metric}: N/A\n"
            
            report += "\n## 报告生成时间\n"
            report += f"{pd.Timestamp.now()}\n"
            
            if save_path:
                with open(save_path, 'w', encoding='utf-8') as f:
                    f.write(report)
                self.logger.info(f"评估报告已保存到: {save_path}")
            
            self.logger.info("成功生成模型评估报告")
            return report
        except Exception as e:
            self.logger.error(f"生成评估报告时出错: {e}")
            return None


def main():
    """
    主函数，用于测试评估器
    """
    logger = setup_logger("EvaluatorTest", 
                         log_file=LOG_CONFIG['log_file'], 
                         level=LOG_CONFIG['log_level'])
    logger.info("开始测试评估器功能")
    
    try:
        evaluator = Evaluator()
        
        # 生成测试数据
        y_true = np.random.randint(0, 2, 100)
        y_pred = np.random.randint(0, 2, 100)
        y_pred_proba = np.random.rand(100)
        
        # 测试计算指标
        metrics = evaluator.calculate_metrics(y_true, y_pred, y_pred_proba)
        logger.info(f"计算评估指标完成: {metrics}")
        
        # 测试生成报告
        report = evaluator.generate_report(metrics)
        logger.info("生成评估报告完成")
        
        logger.info("评估器测试完成")
    except Exception as e:
        logger.error(f"评估器测试失败: {e}")
        raise


if __name__ == "__main__":
    main()