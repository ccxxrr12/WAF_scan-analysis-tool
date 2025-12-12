# Part3 模块待办任务清单

## 概述

Part3是基于传统机器学习的智能检测模块，用于预测HTTP请求是否可能被WAF拦截。目前项目已完成基础框架搭建，但多个核心功能仍待实现。

## 当前状态

- ✅ 已完成：配置模块、模型定义模块、预测器模块、主程序模块、工具模块(JSON功能)、评估模块(基础功能)、数据处理模块(基础功能)
- 🔄 开发中：数据处理模块(85%)、模型训练器(80%)、评估模块(40%)、工具模块(30%)

## 短期目标：实现第一个可用版本

### 1. 数据处理模块 (data_processor.py)
- [x] 实现 `load_dataset()` 函数，支持CSV格式数据加载
- [x] 实现 `preprocess_data()` 函数，支持基本的数据清洗和预处理
- [ ] 完成 `generate_training_data()` 基础实现，能够根据规则生成训练数据 *(需要Part2数据)*

### 2. 模型训练器 (trainer.py)
- [x] 确保 `train_model()` 完整实现
- [x] 确保 `save_model()` 完整实现
- [x] 完善 `evaluate_model()` 实现
- [x] 实现 `cross_validate()` 函数，支持交叉验证
- [ ] 实现 `hyperparameter_tuning()` 函数，支持超参数调优 *(需要更多数据支持)*
- [ ] 完善 `select_best_model()` 函数，支持模型选择

### 3. 模型评估模块 (evaluator.py)
- [x] 实现 `calculate_metrics()` 函数，支持基本评估指标计算（准确率、精确率、召回率、F1分数）
- [ ] 实现 `plot_roc_curve()` 函数，支持ROC曲线绘制
- [ ] 实现 `plot_confusion_matrix()` 函数，支持混淆矩阵绘制
- [ ] 实现 `generate_report()` 函数，支持评估报告生成

### 4. 工具模块 (utils.py)
- [x] 实现 `load_json()` 和 `save_json()` 函数，支持配置和数据读写
- [ ] 实现 `setup_logger()` 函数，支持日志记录
- [ ] 实现 `http_request_to_dict()` 和 `dict_to_http_request()` 函数，支持HTTP请求转换
- [ ] 实现其他工具函数

### 5. 主程序 (main.py)
- [x] 完善训练模式，支持从真实文件加载数据 *(基础框架已完成，实际数据加载需Part1/Part2数据支持)*
- [x] 完善评估模式，支持真实数据评估 *(基础框架已完成，实际数据加载需Part1/Part2数据支持)*

## 中期目标：功能完善

### 1. 增强数据处理能力
- [ ] 完善 `generate_training_data()`，更好地利用Part2规则解析结果 *(需要Part2数据)*
- [ ] 增强 `preprocess_data()`，提供更多预处理选项

### 2. 完善模型训练器
- [ ] 实现 `cross_validate()` 函数，支持交叉验证 *(已完成)*
- [ ] 实现 `hyperparameter_tuning()` 函数，支持超参数调优 *(需要更多数据支持)*
- [ ] 完善 `select_best_model()` 函数，支持模型选择

### 3. 完善模型评估模块
- [ ] 实现 `plot_roc_curve()` 函数，支持ROC曲线绘制
- [ ] 实现 `plot_confusion_matrix()` 函数，支持混淆矩阵绘制
- [ ] 实现 `generate_report()` 函数，支持评估报告生成

### 4. 完善工具模块
- [ ] 实现 `setup_logger()` 函数，支持日志记录
- [ ] 实现 `http_request_to_dict()` 和 `dict_to_http_request()` 函数，支持HTTP请求转换
- [ ] 实现其他工具函数

## 关键实现点

### 1. Part2规则数据集成
Part3需要利用Part2的规则解析结果来生成训练数据，`generate_training_data()` 函数的实现尤为关键。*(需要Part2数据)*

### 2. 模型选择策略
根据WAF类型（特别是ModSecurity）自动选择最适合的模型这一功能需要确保稳定运行。*(需要Part1数据)*

### 3. 端到端流程
确保从训练到预测到评估的完整流程能够顺畅运行，包括模型的保存和加载。

## 预期成果

完成短期目标后，将获得一个基本可用的版本，能够进行完整的：
训练模型 → 保存模型 → 加载模型 → 进行预测和评估 的端到端流程。