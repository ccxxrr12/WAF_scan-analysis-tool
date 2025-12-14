# Part3: 智能检测与机器学习集成

## 目录结构

```
Part3 deeplearning/
├── part3_waf_ml/             # 核心代码目录
│   ├── models/               # 模型文件目录
│   ├── __init__.py           # Python包初始化文件
│   ├── config.py             # 配置文件
│   ├── data_processor.py     # 数据处理模块
│   ├── evaluator.py          # 模型评估模块
│   ├── main.py               # 程序主入口
│   ├── models.py             # 模型定义模块
│   ├── predictor.py          # 预测器模块
│   ├── trainer.py            # 模型训练器模块
│   └── utils.py              # 工具模块
├── models/                   # 训练好的模型存储目录
├── README.md                 # 项目说明文件
├── requirements.txt          # 依赖包列表
├── 使用说明.md               # 使用说明文档
├── 开发进度.md               # 开发进度文档
└── Prompt_for_AI.md          # AI提示文档
```

## 模块功能介绍

| 模块名称 | 功能描述 | 主要文件 |
|---------|---------|---------|
| 主程序 | 程序入口，解析命令行参数并调度各模块 | main.py |
| 数据处理 | 处理输入数据，提取特征以及处理WAF指纹信息 | data_processor.py |
| 模型定义 | 定义各种机器学习模型的实现 | models.py |
| 模型训练器 | 负责模型的训练、评估和保存 | trainer.py |
| 预测器 | 使用训练好的模型进行预测 | predictor.py |
| 模型评估 | 评估训练好的模型性能 | evaluator.py |
| 工具模块 | 提供通用工具函数 | utils.py |
| 配置模块 | 包含各种配置参数 | config.py |

## 简介

Part3是基于传统机器学习的智能检测模块，旨在预测HTTP请求是否可能被WAF拦截。该模块通过集成多种机器学习算法，实现对WAF拦截行为的智能预测。

## 整体架构

Part3采用模块化设计，主要包括以下组件：

### 程序入口
- [main.py](./part3_waf_ml/main.py) - 程序主入口，负责解析命令行参数并调度各模块执行相应任务

### 核心模块
1. [data_processor.py](./part3_waf_ml/data_processor.py) - 数据处理模块，负责数据加载、预处理和特征提取
2. [models.py](./part3_waf_ml/models.py) - 模型定义模块，包含各种机器学习模型的实现
3. [trainer.py](./part3_waf_ml/trainer.py) - 模型训练器模块，负责模型训练、评估和保存
4. [predictor.py](./part3_waf_ml/predictor.py) - 预测器模块，使用训练好的模型进行预测
5. [evaluator.py](./part3_waf_ml/evaluator.py) - 模型评估模块，负责评估模型性能
6. [utils.py](./part3_waf_ml/utils.py) - 工具模块，提供通用工具函数
7. [config.py](./part3_waf_ml/config.py) - 配置模块，包含各种配置参数

## 执行流程

### 训练流程
1. [main.py](./part3_waf_ml/main.py) 解析命令行参数，进入训练模式
2. [data_processor.py](./part3_waf_ml/data_processor.py) 加载和预处理训练数据
3. [trainer.py](./part3_waf_ml/trainer.py) 使用指定算法训练模型
4. 训练好的模型保存到文件系统

### 预测流程
1. [main.py](./part3_waf_ml/main.py) 解析命令行参数，进入预测模式
2. [predictor.py](./part3_waf_ml/predictor.py) 加载训练好的模型
3. [data_processor.py](./part3_waf_ml/data_processor.py) 处理输入数据并提取特征
4. [predictor.py](./part3_waf_ml/predictor.py) 使用模型进行预测并返回结果

### 评估流程
1. [main.py](./part3_waf_ml/main.py) 解析命令行参数，进入评估模式
2. [data_processor.py](./part3_waf_ml/data_processor.py) 加载测试数据
3. [trainer.py](./part3_waf_ml/trainer.py) 或 [evaluator.py](./part3_waf_ml/evaluator.py) 评估模型性能
4. 输出评估结果

## 模块功能详解

### 数据处理模块 (data_processor.py)
负责处理输入数据，提取特征以及处理WAF指纹信息。
- HTTP请求特征提取：从原始HTTP请求中提取URL长度、参数数量、特殊字符等特征
- WAF指纹处理：处理Part1识别的WAF类型信息，标准化WAF类型
- 数据加载：支持CSV格式数据集加载
- 数据预处理：提供去重和缺失值处理功能
- 训练数据生成：基于Part2规则数据自动生成训练样本

### 模型定义模块 (models.py)
定义了多种传统机器学习模型，包括：
- 逻辑回归模型 (LogisticRegressionModel)
- 随机森林模型 (RandomForestModel)
- XGBoost模型 (XGBoostModel)
所有模型都继承自基础模型类(BaseModel)，提供统一的接口

### 模型训练器模块 (trainer.py)
负责模型的训练和评估：
- 模型训练：使用训练数据训练指定的模型
- 交叉验证：实现分层K折交叉验证以评估模型稳定性
- 模型保存：将训练好的模型序列化保存到文件
- 模型评估：计算模型在测试集上的性能指标
- 模型选择：根据WAF类型选择最适合的模型

### 预测器模块 (predictor.py)
使用训练好的模型进行预测：
- 模型加载：从文件系统加载训练好的模型
- 模型选择：根据WAF类型自动选择最适合的模型（ModSecurity专用模型或其他通用模型）
- 预测：对单个或批量HTTP请求进行拦截预测

### 模型评估模块 (evaluator.py)
负责评估训练好的模型性能：
- 指标计算：计算准确率、精确率、召回率、F1分数和AUC等评估指标
- 可视化：提供ROC曲线和混淆矩阵绘制功能（待实现）

### 工具模块 (utils.py)
提供通用工具函数：
- JSON文件读写：支持JSON格式配置文件和数据的读写
- 日志记录：提供日志记录功能
- 数据转换：HTTP请求与其他格式之间的转换
- 文本处理：文本标准化和Payload编码解码功能

### 配置模块 (config.py)
包含项目配置参数：
- 模型配置：各种模型的默认参数
- 数据配置：数据处理相关参数
- 训练配置：训练过程相关参数
- 特征列表：默认特征列表
- WAF类型映射：WAF类型标准化映射
- 攻击类型：支持的攻击类型列表
- 模型路径配置：默认模型路径

## 技术实现原理

### 特征工程
从HTTP请求中提取以下特征：
- URL特征：URL长度、参数数量、参数值总长度、特殊字符计数
- 请求方法：GET、POST、PUT、DELETE等方法的独热编码
- 响应状态：响应状态码及其分类（4xx、5xx）
- 请求体：请求体长度
- 请求头：请求头数量
- 攻击模式：SQL注入、XSS、文件包含等攻击模式特征

### 模型选择策略
1. **ModSecurity特化模型**：当检测到目标网站使用ModSecurity时使用
2. **通用模型**：处理所有其他WAF类型
3. **默认模型**：当特化模型不可用时的备用选择

### 使用的技术栈
- scikit-learn：传统机器学习算法实现
- XGBoost：梯度提升算法
- pandas/numpy：数据处理
- matplotlib：数据可视化（待实现）

## 安装依赖

```bash
pip install -r requirements.txt
```

## 使用示例

### 运行示例脚本

```bash
# 训练ModSecurity特化模型
python main.py --mode train --model-type xgboost --waf-type modsecurity --data-path modsecurity_data.csv --model-path modsecurity_model.pkl

# 使用Part2规则数据训练ModSecurity特化模型
python main.py --mode train --model-type xgboost --waf-type modsecurity --rules-data-path detailed_rules_report.json --model-path modsecurity_model.pkl

# 训练通用模型
python main.py --mode train --model-type random_forest --waf-type generic --data-path generic_data.csv --model-path generic_model.pkl

# 使用预测模式（使用默认示例请求）
python main.py --mode predict --waf-info-path waf_info.json

# 使用预测模式（指定HTTP请求数据文件）
python main.py --mode predict --waf-info-path waf_info.json --request-data-path http_request.json

# 评估模型
python main.py --mode evaluate --model-path modsecurity_model.pkl --data-path test_data.csv
```

## 支持的模型

- 逻辑回归 (logistic_regression)
- 随机森林 (random_forest)
- XGBoost (xgboost)