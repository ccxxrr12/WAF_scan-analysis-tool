# Part3 模块 AI辅助开发提示文档

## 项目概述

Part3是基于传统机器学习的智能检测模块，用于预测HTTP请求是否可能被WAF拦截。该模块通过集成多种机器学习算法，实现对WAF拦截行为的智能预测。

项目采用模块化设计，主要包括以下组件：

### 核心模块
1. [data_processor.py](./part3_waf_ml/data_processor.py) - 数据处理模块
2. [models.py](./part3_waf_ml/models.py) - 模型定义模块
3. [trainer.py](./part3_waf_ml/trainer.py) - 模型训练器模块
4. [predictor.py](./part3_waf_ml/predictor.py) - 预测器模块
5. [evaluator.py](./part3_waf_ml/evaluator.py) - 模型评估模块
6. [utils.py](./part3_waf_ml/utils.py) - 工具模块
7. [config.py](./part3_waf_ml/config.py) - 配置模块
8. [main.py](./part3_waf_ml/main.py) - 主程序入口

## 模块详细说明

### 1. 数据处理模块 (data_processor.py)

#### 功能描述
负责处理输入数据，提取特征以及处理WAF指纹信息。

#### 主要类和方法
- `DataProcessor` 类
  - `process_waf_fingerprint(fingerprint_data)`: 处理Part1的WAF指纹识别结果
  - `extract_features(http_request)`: 从HTTP请求中提取特征
  - `generate_training_data(rules_data)`: 根据规则数据生成训练样本（需要Part2数据）
  - `load_dataset(dataset_path)`: 加载数据集（支持CSV格式）
  - `preprocess_data(raw_data)`: 数据预处理（支持去重和缺失值处理）

#### 特征提取内容
- URL特征：URL长度、参数数量、参数值总长度、特殊字符计数
- 请求方法：GET、POST、PUT、DELETE等方法的独热编码
- 响应状态：响应状态码及其分类（4xx、5xx）
- 请求体：请求体长度
- 请求头：请求头数量
- 攻击模式：SQL注入、XSS、文件包含等攻击模式特征

### 2. 模型定义模块 (models.py)

#### 功能描述
定义了用于WAF拦截预测的各种传统机器学习模型。

#### 主要类和方法
- `BaseModel` 基础模型类（抽象类）
  - `train(X_train, y_train)`: 训练模型
  - `predict(X)`: 预测
  - `evaluate(X_test, y_test)`: 评估模型

- `LogisticRegressionModel` 逻辑回归模型
- `RandomForestModel` 随机森林模型
- `XGBoostModel` XGBoost模型

- `ModelFactory` 模型工厂类
  - `create_model(model_type, model_params)`: 创建模型实例

#### 支持的模型类型
- logistic_regression: 逻辑回归
- random_forest: 随机森林
- xgboost: XGBoost

### 3. 模型训练器模块 (trainer.py)

#### 功能描述
负责模型的训练、验证和测试过程。

#### 主要类和方法
- `ModelTrainer` 模型训练器类
  - `train_model(X_train, y_train)`: 训练模型
  - `cross_validate(X, y, cv_folds)`: 交叉验证（使用分层K折交叉验证）
  - `hyperparameter_tuning(X_train, y_train, param_grid)`: 超参数调优（待实现）
  - `select_best_model(models, waf_type)`: 模型选择（根据WAF类型选择最佳模型）
  - `evaluate_model(X_test, y_test)`: 模型评估
  - `save_model(model_path)`: 保存模型

### 4. 预测器模块 (predictor.py)

#### 功能描述
使用训练好的模型对新的HTTP请求进行拦截预测，支持不同WAF类型的特化模型和通用模型。

#### 主要类和方法
- `Predictor` 预测器类
  - `load_model(model_path, model_type)`: 加载模型
  - `select_model_by_waf(waf_type)`: 根据WAF类型选择模型
  - `predict(http_request, waf_info)`: 预测单个请求
  - `batch_predict(http_requests, waf_info_list)`: 批量预测

#### 模型选择策略
- 如果是ModSecurity，优先使用特化模型
- 如果是其他WAF类型，使用通用模型
- 如果都没有，使用默认模型

### 5. 模型评估模块 (evaluator.py)

#### 功能描述
负责评估训练好的模型性能，包括各种评估指标的计算和可视化。

#### 主要类和方法
- `Evaluator` 评估器类
  - `calculate_metrics(y_true, y_pred, y_pred_proba)`: 计算评估指标（支持准确率、精确率、召回率、F1分数和AUC）
  - `plot_roc_curve(y_true, y_pred_proba)`: 绘制ROC曲线（待实现）
  - `plot_confusion_matrix(y_true, y_pred)`: 绘制混淆矩阵（待实现）
  - `generate_report(metrics)`: 生成评估报告（待实现）

### 6. 工具模块 (utils.py)

#### 功能描述
提供Part3所需的通用工具函数。

#### 主要函数
- `load_json(file_path)`: 加载JSON文件（支持UTF-8编码）
- `save_json(data, file_path)`: 保存JSON文件（支持UTF-8编码和格式化输出）
- `setup_logger(name, log_file, level)`: 设置日志记录器（待实现）
- `http_request_to_dict(http_request)`: HTTP请求转字典（待实现）
- `dict_to_http_request(request_dict)`: 字典转HTTP请求（待实现）

### 7. 配置模块 (config.py)

#### 功能描述
定义了Part3的各种配置参数。

#### 主要配置项
- `MODEL_CONFIGS`: 模型配置
- `DATA_CONFIGS`: 数据配置
- `TRAINING_CONFIGS`: 训练配置
- `DEFAULT_FEATURES`: 默认特征列表
- `WAF_TYPES`: WAF类型映射
- `ATTACK_TYPES`: 攻击类型
- `MODEL_PATHS`: 模型路径配置

### 8. 主程序模块 (main.py)

#### 功能描述
程序主入口，整合了数据处理、模型训练、预测和评估等功能，支持命令行参数配置不同运行模式。

#### 主要函数
- `parse_args()`: 解析命令行参数
- `train_mode(args)`: 训练模式
- `predict_mode(args)`: 预测模式
- `evaluate_mode(args)`: 评估模式
- `main()`: 主函数

#### 命令行参数
- `--mode`: 运行模式，可选 train/predict/evaluate，默认为 predict
- `--model-type`: 模型类型，可选 logistic_regression/random_forest/xgboost
- `--data-path`: 数据路径，训练和评估模式必需
- `--model-path`: 模型路径，预测和评估模式必需
- `--output-path`: 输出路径（预留）
- `--waf-info-path`: WAF指纹信息路径（JSON格式）
- `--waf-type`: WAF类型，可选 modsecurity/generic，用于训练模式

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

## 开发注意事项

### 依赖关系
- 所有模块都依赖 [config.py](./part3_waf_ml/config.py) 提供的配置参数
- [trainer.py](./part3_waf_ml/trainer.py) 依赖 [models.py](./part3_waf_ml/models.py) 创建模型实例
- [predictor.py](./part3_waf_ml/predictor.py) 依赖 [data_processor.py](./part3_waf_ml/data_processor.py) 处理输入数据
- [main.py](./part3_waf_ml/main.py) 是程序入口，整合所有模块功能

### 当前开发状态
- ✅ 核心功能已实现：数据处理、模型定义、模型训练、预测、基础评估
- 🔄 待完善功能：模型评估可视化、工具模块扩展、超参数调优

### Part1/Part2数据依赖
- [data_processor.py](./part3_waf_ml/data_processor.py) 中的 `generate_training_data()` 函数需要Part2规则数据
- [predictor.py](./part3_waf_ml/predictor.py) 的模型选择功能需要Part1的WAF指纹数据进行完整测试
- 目前使用模拟数据进行开发和测试

### 代码规范
- 遵循Python PEP8编码规范
- 所有公共接口都需要完整的文档字符串
- 函数参数和返回值需要明确的类型注释（如适用）
- 异常处理需要明确的错误信息输出