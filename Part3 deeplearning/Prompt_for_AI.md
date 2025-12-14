# Part3 模块 AI 开发指南

## 1. 项目概述

Part3 是基于传统机器学习的智能检测模块，旨在预测 HTTP 请求是否会被目标网站的 WAF 拦截。该模块通过集成多种机器学习算法，实现对 WAF 拦截行为的智能预测。

## 2. 模块架构

Part3采用模块化设计，主要包括以下组件：

### 2.1 程序入口
- [main.py](./part3_waf_ml/main.py) - 程序主入口，负责解析命令行参数并调度各模块执行相应任务

### 2.2 核心模块
1. [data_processor.py](./part3_waf_ml/data_processor.py) - 数据处理模块，负责数据加载、预处理和特征提取
2. [models.py](./part3_waf_ml/models.py) - 模型定义模块，包含各种机器学习模型的实现
3. [trainer.py](./part3_waf_ml/trainer.py) - 模型训练器模块，负责模型训练、评估和保存
4. [predictor.py](./part3_waf_ml/predictor.py) - 预测器模块，使用训练好的模型进行预测
5. [evaluator.py](./part3_waf_ml/evaluator.py) - 模型评估模块，负责评估模型性能
6. [utils.py](./part3_waf_ml/utils.py) - 工具模块，提供通用工具函数
7. [config.py](./part3_waf_ml/config.py) - 配置模块，包含各种配置参数

## 3. 模块详细说明

### 3.1 数据处理模块 (data_processor.py)

#### 3.1.1 类和方法

##### DataProcessor 类
- `__init__()`: 初始化数据处理器
- `process_waf_fingerprint(fingerprint_data)`: 处理 Part1 的 WAF 指纹识别结果
- `extract_features(http_request)`: 从 HTTP 请求中提取特征
- `generate_training_data(rules_data)`: 根据规则数据生成训练样本
- `load_dataset(dataset_path)`: 加载数据集
- `preprocess_data(raw_data)`: 数据预处理

#### 3.1.2 功能说明
负责处理输入数据，提取特征以及处理WAF指纹信息。
- HTTP请求特征提取：从原始HTTP请求中提取URL长度、参数数量、特殊字符等特征
- WAF指纹处理：处理Part1识别的WAF类型信息，标准化WAF类型
- 数据加载：支持CSV格式数据集加载
- 数据预处理：提供去重和缺失值处理功能
- 训练数据生成：基于Part2规则数据自动生成训练样本

### 3.2 模型定义模块 (models.py)

#### 3.2.1 类和方法

##### BaseModel 类（抽象基类）
- `__init__(model_params)`: 初始化基础模型
- `train(X_train, y_train)`: 训练模型（抽象方法）
- `predict(X)`: 预测（抽象方法）
- `evaluate(X_test, y_test)`: 评估模型（抽象方法）

##### LogisticRegressionModel 类
- `__init__(model_params)`: 初始化逻辑回归模型
- `train(X_train, y_train)`: 训练逻辑回归模型
- `predict(X)`: 逻辑回归预测
- `evaluate(X_test, y_test)`: 评估逻辑回归模型

##### RandomForestModel 类
- `__init__(model_params)`: 初始化随机森林模型
- `train(X_train, y_train)`: 训练随机森林模型
- `predict(X)`: 随机森林预测
- `evaluate(X_test, y_test)`: 评估随机森林模型

##### XGBoostModel 类
- `__init__(model_params)`: 初始化XGBoost模型
- `train(X_train, y_train)`: 训练XGBoost模型
- `predict(X)`: XGBoost预测
- `evaluate(X_test, y_test)`: 评估XGBoost模型

##### ModelFactory 类
- `create_model(model_type, model_params)`: 创建模型实例

#### 3.2.2 功能说明
定义了多种传统机器学习模型，所有模型都继承自基础模型类(BaseModel)，提供统一的接口。

### 3.3 模型训练器模块 (trainer.py)

#### 3.3.1 类和方法

##### ModelTrainer 类
- `__init__(model_type, model_params)`: 初始化模型训练器
- `train_model(X_train, y_train)`: 训练模型
- `cross_validate(X, y, cv_folds)`: 交叉验证
- `hyperparameter_tuning(X_train, y_train, param_grid)`: 超参数调优
- `select_best_model(models, waf_type)`: 模型选择
- `evaluate_model(X_test, y_test)`: 评估模型性能
- `save_model(model_path)`: 保存模型到文件

#### 3.3.2 功能说明
负责模型的训练和评估：
- 模型训练：使用训练数据训练指定的模型
- 交叉验证：实现分层K折交叉验证以评估模型稳定性
- 模型保存：将训练好的模型序列化保存到文件
- 模型评估：计算模型在测试集上的性能指标
- 模型选择：根据WAF类型选择最适合的模型

### 3.4 预测器模块 (predictor.py)

#### 3.4.1 类和方法

##### Predictor 类
- `__init__()`: 初始化预测器
- `load_model(model_path, model_type)`: 加载模型
- `select_model_by_waf(waf_type)`: 根据WAF类型选择模型
- `predict(http_request, waf_info)`: 预测单个HTTP请求是否会被拦截
- `batch_predict(http_requests, waf_info_list)`: 批量预测HTTP请求

#### 3.4.2 功能说明
使用训练好的模型进行预测：
- 模型加载：从文件系统加载训练好的模型
- 模型选择：根据WAF类型自动选择最适合的模型（ModSecurity专用模型或其他通用模型）
- 预测：对单个或批量HTTP请求进行拦截预测

### 3.5 模型评估模块 (evaluator.py)

#### 3.5.1 类和方法

##### Evaluator 类
- `__init__()`: 初始化评估器
- `calculate_metrics(y_true, y_pred, y_pred_proba)`: 计算评估指标
- `plot_roc_curve(y_true, y_pred_proba)`: 绘制ROC曲线
- `plot_confusion_matrix(y_true, y_pred)`: 绘制混淆矩阵
- `generate_report(metrics)`: 生成评估报告

#### 3.5.2 功能说明
负责评估训练好的模型性能：
- 指标计算：计算准确率、精确率、召回率、F1分数和AUC等评估指标
- 可视化：提供ROC曲线和混淆矩阵绘制功能（待实现）

### 3.6 工具模块 (utils.py)

#### 3.6.1 函数列表

- `load_json(file_path)`: 加载JSON文件
- `save_json(data, file_path)`: 保存数据为JSON文件
- `setup_logger(name, log_file, level)`: 设置日志记录器
- `http_request_to_dict(http_request)`: 将HTTP请求转换为字典
- `dict_to_http_request(request_dict)`: 将字典转换为HTTP请求
- `normalize_text(text)`: 标准化文本
- `encode_payload(payload)`: 编码Payload
- `decode_payload(encoded_payload)`: 解码Payload

#### 3.6.2 功能说明
提供通用工具函数：
- JSON文件读写：支持JSON格式配置文件和数据的读写
- 日志记录：提供日志记录功能
- 数据转换：HTTP请求与其他格式之间的转换
- 文本处理：文本标准化和Payload编码解码功能

### 3.7 配置模块 (config.py)

#### 3.7.1 配置项

- `MODEL_CONFIGS`: 模型配置
- `DATA_CONFIGS`: 数据配置
- `TRAINING_CONFIGS`: 训练配置
- `DEFAULT_FEATURES`: 默认特征列表
- `WAF_TYPES`: WAF类型映射
- `ATTACK_TYPES`: 攻击类型列表
- `MODEL_PATHS`: 模型路径配置

#### 3.7.2 功能说明
包含项目配置参数，供各模块使用。

## 4. 执行流程

### 4.1 训练流程
1. [main.py](./part3_waf_ml/main.py) 解析命令行参数，进入训练模式
2. [data_processor.py](./part3_waf_ml/data_processor.py) 加载和预处理训练数据
3. [trainer.py](./part3_waf_ml/trainer.py) 使用指定算法训练模型
4. 训练好的模型保存到文件系统

### 4.2 预测流程
1. [main.py](./part3_waf_ml/main.py) 解析命令行参数，进入预测模式
2. [predictor.py](./part3_waf_ml/predictor.py) 加载训练好的模型
3. [data_processor.py](./part3_waf_ml/data_processor.py) 处理输入数据并提取特征
4. [predictor.py](./part3_waf_ml/predictor.py) 使用模型进行预测并返回结果

### 4.3 评估流程
1. [main.py](./part3_waf_ml/main.py) 解析命令行参数，进入评估模式
2. [data_processor.py](./part3_waf_ml/data_processor.py) 加载测试数据
3. [trainer.py](./part3_waf_ml/trainer.py) 或 [evaluator.py](./part3_waf_ml/evaluator.py) 评估模型性能
4. 输出评估结果

## 5. 技术实现原理

### 5.1 特征工程
从HTTP请求中提取以下特征：
- URL特征：URL长度、参数数量、参数值总长度、特殊字符计数
- 请求方法：GET、POST、PUT、DELETE等方法的独热编码
- 响应状态：响应状态码及其分类（4xx、5xx）
- 请求体：请求体长度
- 请求头：请求头数量
- 攻击模式：SQL注入、XSS、文件包含等攻击模式特征

### 5.2 模型选择策略
1. **ModSecurity特化模型**：当检测到目标网站使用ModSecurity时使用
2. **通用模型**：处理所有其他WAF类型
3. **默认模型**：当特化模型不可用时的备用选择

### 5.3 使用的技术栈
- scikit-learn：传统机器学习算法实现
- XGBoost：梯度提升算法
- pandas/numpy：数据处理
- matplotlib：数据可视化（待实现）

## 6. 命令行参数说明

### 6.1 主要参数
- `--mode`: 运行模式，可选 train/predict/evaluate，默认为 predict
- `--model-type`: 模型类型，可选 logistic_regression/random_forest/xgboost
- `--data-path`: 数据路径
- `--model-path`: 模型路径
- `--output-path`: 输出路径
- `--waf-type`: WAF类型，可选 modsecurity/generic，用于训练模式
- `--rules-data-path`: Part2规则数据路径（JSON格式）
- `--request-data-path`: HTTP请求数据路径（JSON格式），用于预测模式

## 7. 与其它模块的集成

### 7.1 与Part1的集成
- 利用Part1提供的WAF指纹信息选择最适合的预测模型
- 根据识别出的WAF类型调整特征提取策略

### 7.2 与Part2的集成
- 利用Part2规则解析结果生成高质量的训练数据
- 基于规则语义分析结果进行分类训练
- 使用规则依赖关系提取高级特征

## 8. 开发注意事项

### 8.1 模块依赖
- 所有模块都依赖 config.py 提供的配置信息
- data_processor.py 是数据处理的核心模块
- models.py 定义了所有支持的模型类型
- trainer.py 负责模型训练和评估
- predictor.py 负责使用训练好的模型进行预测
- evaluator.py 提供详细的模型评估功能
- utils.py 提供通用工具函数

### 8.2 数据依赖
- 需要Part1提供的WAF指纹数据（JSON格式）
- 需要Part2提供的规则解析数据（JSON格式）
- 支持CSV格式的传统数据集
- 需要用户提供HTTP请求数据（JSON格式），用于预测模式

### 8.3 代码规范
- 遵循PEP8 Python代码规范
- 所有函数都需要有详细的文档字符串
- 类和方法命名采用驼峰命名法
- 常量命名采用大写字母加下划线
- 变量命名采用小写字母加下划线

### 8.4 当前开发状态
- 所有核心功能模块已完成
- 工具模块已完成
- 模型评估模块的可视化功能待实现
- 超参数调优功能待实现