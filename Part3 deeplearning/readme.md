# Part3: 智能检测与机器学习集成

## 简介

Part3是基于机器学习的智能检测模块，旨在预测HTTP请求是否可能被WAF拦截。该模块通过集成多种机器学习算法，实现对WAF拦截行为的智能预测。

## 功能特点

- 支持多种机器学习模型（逻辑回归、随机森林、XGBoost等）
- 特征工程：从HTTP请求中提取多种特征
- WAF指纹处理：处理Part1识别的WAF类型信息
- 模型训练、预测和评估一体化
- 根据WAF类型自动选择最适合的模型（ModSecurity专用模型或其他通用模型）
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
from predictor import Predictor

# 初始化数据处理器
processor = DataProcessor()

# 处理WAF指纹信息
waf_info = {"waf_type": "ModSecurity (SpiderLabs)", "confidence": 0.95}
processed_waf = processor.process_waf_fingerprint(waf_info)

# 提取HTTP请求特征
features = processor.extract_features(http_request)

# 使用预测器进行预测（会自动根据WAF类型选择模型）
predictor = Predictor()
predictor.load_model("modsecurity_model.pkl", "modsecurity")  # 加载ModSecurity特化模型
predictor.load_model("generic_model.pkl", "generic")  # 加载通用模型
prediction, confidence = predictor.predict(http_request, waf_info)
```

### 运行示例脚本

```bash
# 训练ModSecurity特化模型
python main.py --mode train --model-type xgboost --waf-type modsecurity --data-path modsecurity_data.csv --model-path modsecurity_model.pkl

# 训练通用模型
python main.py --mode train --model-type random_forest --waf-type generic --data-path generic_data.csv --model-path generic_model.pkl

# 使用预测模式
python main.py --mode predict --waf-info-path waf_info.json

# 评估模型
python main.py --mode evaluate --model-path modsecurity_model.pkl --data-path test_data.csv
```

## 模块说明

### 数据处理模块 (data_processor.py)

负责处理输入数据，提取特征以及处理WAF指纹信息。

### 模型定义模块 (models.py)

定义了多种机器学习模型，包括逻辑回归、随机森林、XGBoost等。

### 预测器模块 (predictor.py)

根据WAF类型自动选择最适合的模型进行预测：
- 如果目标网站使用ModSecurity，则使用ModSecurity特化模型
- 否则使用通用模型处理其他所有WAF类型

### 配置文件 (config.py)

包含了模型和训练的配置参数。

## 支持的模型

- 逻辑回归 (logistic_regression)
- 随机森林 (random_forest)
- XGBoost (xgboost)

## 模型选择策略

1. **ModSecurity特化模型**：当检测到目标网站使用ModSecurity时使用
2. **通用模型**：处理所有其他WAF类型
3. **默认模型**：当特化模型不可用时的备用选择

## 开发计划

1. 完善数据处理模块的功能
2. 增加更多的特征工程功能
3. 提供完整的训练和预测流程