# Part3: 智能检测与机器学习集成

## 简介

Part3是基于机器学习的智能检测模块，旨在预测HTTP请求是否可能被WAF拦截。该模块通过集成多种机器学习算法，实现对WAF拦截行为的智能预测。

## 功能特点

- 支持多种机器学习模型（逻辑回归、随机森林、XGBoost等）
- 特征工程：从HTTP请求中提取多种特征
- 模型训练、预测和评估一体化
- 可扩展的架构设计

## 安装依赖

```bash
pip install -r requirements.txt
```

## 使用示例

### 基本使用

```python
# 导入必要模块
from data_processor import DataProcessor
from models import ModelFactory

# 初始化数据处理器
processor = DataProcessor()

# 提取HTTP请求特征
features = processor.extract_features(http_request)

# 创建并训练模型
model = ModelFactory.create_model("logistic_regression")
model.train(X_train, y_train)

# 进行预测
predictions = model.predict(X_test)
```

### 运行示例脚本

```bash
python example_usage.py
```

## 模块说明

### 数据处理模块 (data_processor.py)

负责处理输入数据，提取特征等。

### 模型定义模块 (models.py)

定义了多种机器学习模型，包括逻辑回归、随机森林、XGBoost等。

### 配置文件 (config.py)

包含了模型和训练的配置参数。

## 支持的模型

- 逻辑回归 (logistic_regression)
- 随机森林 (random_forest)
- XGBoost (xgboost)

## 开发计划

1. 完善数据处理模块的功能
2. 增加更多的特征工程功能
3. 提供完整的训练和预测流程