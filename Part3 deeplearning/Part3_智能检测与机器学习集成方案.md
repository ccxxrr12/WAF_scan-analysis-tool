# Part3: 智能检测与机器学习集成方案

## 1. 方案概述

Part3 是基于传统机器学习的智能检测模块，旨在预测 HTTP 请求是否会被目标网站的 WAF 拦截。该模块通过集成多种机器学习算法，实现对 WAF 拦截行为的智能预测。

## 2. 设计理念

### 2.1 技术选型原则
1. **优先使用传统机器学习方法**：逻辑回归、随机森林、XGBoost等传统机器学习方法具有良好的可解释性、较低的资源消耗和足够的有效性，在WAF检测场景中具有高性价比。
2. **避免使用深度学习模型**：在结构化特征明显的WAF检测场景中，深度学习模型的复杂性和资源消耗与其带来的性能提升不成正比。
3. **模型演进路径**：从简单的逻辑回归/随机森林开始，逐步过渡到XGBoost等集成方法，必要时才考虑使用LSTM/CNN等深度学习模型。
4. **注重特征工程**：初期使用简单模型验证特征有效性，中期使用集成方法提升性能，后期聚焦特征工程优化而非复杂模型。

### 2.2 多层级建模策略
1. **通用模型**：基于常见攻击模式训练，不依赖具体规则文件，用于无规则访问场景的初步预测。
2. **WAF类型特化模型**：根据WAF指纹识别结果（如ModSecurity、Cloudflare等），使用对应类型的规则数据进行训练，提升特定WAF预测精度。
3. **自定义规则适配层**：当可获取目标网站规则文件时，利用规则解析结果对通用或特化模型进行微调，实现个性化适配。

### 2.3 模型动态选择策略
- 若WAF类型为ModSecurity，则使用基于Part2规则文件训练的特化模型
- 其他情况使用基于Part1指纹插件训练的通用模型
- 设计优势：
  1. **针对性**：ModSecurity特化模型可更好处理其特有的规则模式
  2. **兼容性**：通用模型确保对所有WAF类型都有良好预测效果
  3. **可扩展性**：便于未来添加其他WAF类型的特化模型
  4. **资源效率**：仅对需要的WAF类型训练专门模型

## 3. 架构设计

### 3.1 技术实现规范
1. 统一通过ModelFactory管理模型，支持按需切换
2. 数据准备需保证代表性，标注工具确保质量、效率与一致性
3. 生产环境谨慎引入深度学习，优先使用Scikit-learn、XGBoost/LightGBM

### 3.2 Part3模块架构设计
- 采用传统机器学习路线（逻辑回归/随机森林/XGBoost），移除深度学习依赖
- 模块化分层：数据处理→模型定义→训练/预测/评估
- 通过ModelFactory实现模型统一管理

## 4. 核心功能

### 4.1 数据处理
1. 提取URL、请求方法、响应状态等HTTP特征
2. 处理Part1输出的WAF指纹信息，生成标准化特征向量
3. 检测SQL注入、XSS、文件包含等攻击模式特征

### 4.2 模型能力
1. 支持三种传统机器学习模型：逻辑回归、随机森林、XGBoost
2. 统一模型接口规范

### 4.3 系统集成
1. 输入：接收Part1的WAF类型识别结果和Part2的规则解析数据
2. 输出：拦截预测结果及置信度

## 5. 运行规范

### 5.1 运行模式
- 训练模式: `python main.py --mode train --model-type <type> --data-path <path>`
- 预测模式（默认）: `python main.py --mode predict --model-path <path> --data-path <path>`
- 评估模式: `python main.py --mode evaluate --model-path <path> --data-path <path>`

### 5.2 工作流程
1. 训练阶段：数据处理 → 模型训练 → 模型保存
2. 预测阶段：加载模型 → 请求预测
3. 评估阶段：性能评估 → 报告生成

### 5.3 系统集成
- Part1：利用WAF指纹识别结果选择特化模型
- Part2：利用规则解析结果生成训练数据和特征

## 6. Part2规则数据应用

### 6.1 规则解析产物应用规范
1. **自动化标注**：基于规则语义自动判断请求是否触发规则，生成高质量带标签训练数据集。
2. **多样化样本生成**：通过反向推导规则条件，系统化生成覆盖各类边界情况的正负样本，提升数据代表性。
3. **特征工程支持**：将规则依赖关系、抽象语法树结构等作为高级特征输入模型，增强模型可解释性与判别能力。
4. **模型验证基准**：利用规则逻辑构建确定性测试集，用于评估模型预测准确性与一致性。

## 7. 模型训练规范

### 7.1 训练命令规范
- 训练命令需支持`--waf-type`参数指定模型针对的WAF类型
- ModSecurity特化模型使用独立数据集训练
- 通用模型使用包含多种WAF类型的数据集训练
- 不同类型模型应保存到不同路径以便管理

### 7.2 数据处理模块输入规范
- **Part1输入**: WAF指纹识别结果，格式为JSON，包含`waf_type`和`confidence`字段
- **Part2输入**: 规则解析数据，格式为JSON，包含`rule_info`、`semantic_analysis`和`dependency_analysis`三个主要部分
- **开发建议**: 可使用模拟数据进行模块独立开发，待功能完善后与真实P1/P2数据集成测试

## 8. 当前实现状态

### 8.1 已完成模块
- 配置模块：定义了各种配置参数
- 数据处理模块：实现特征提取、WAF指纹处理、数据加载和预处理、基于Part2规则数据的训练数据生成功能
- 模型定义模块：实现了逻辑回归、随机森林、XGBoost三种传统机器学习模型
- 模型训练器模块：实现了模型训练、交叉验证、模型保存、模型评估、模型选择等功能
- 预测器模块：实现了模型加载、根据WAF类型选择模型、单个请求预测、批量预测等功能
- 模型评估模块：实现了基础评估指标计算功能
- 工具模块：实现了JSON读写、日志记录、HTTP请求转换、文本标准化、Payload编码解码等功能
- 主程序模块：实现了命令行参数解析和三种运行模式的处理逻辑

### 8.2 待完善模块
- 模型评估模块：可视化功能和评估报告生成功能待实现
- 模型训练器模块：超参数调优功能待实现

## 9. 使用示例

### 9.1 训练模型
```bash
# 使用Part2规则数据训练ModSecurity特化模型
python main.py --mode train --model-type xgboost --waf-type modsecurity --rules-data-path detailed_rules_report.json --model-path modsecurity_model.pkl

# 训练通用模型
python main.py --mode train --model-type random_forest --waf-type generic --rules-data-path detailed_rules_report.json --model-path generic_model.pkl

# 使用传统CSV数据训练
python main.py --mode train --model-type xgboost --data-path training_data.csv --model-path model.pkl
```

### 9.2 预测请求
```bash
# 使用指定模型进行预测
python main.py --mode predict --model-path modsecurity_model.pkl --waf-info-path waf_info.json

# 自动选择模型进行预测
python main.py --mode predict --waf-info-path waf_info.json
```

### 9.3 评估模型
```bash
python main.py --mode evaluate --model-path modsecurity_model.pkl --data-path test_data.csv
```

## 10. 未来发展方向

### 10.1 短期计划
1. 实现模型评估模块的可视化功能和评估报告生成功能
2. 实现模型训练器的超参数调优功能

### 10.2 中期计划
1. 完成各模块的集成测试
2. 与 Part1 和 Part2 进行集成

### 10.3 长期计划
1. 性能优化和功能完善
2. 文档编写和示例开发
3. 部署和上线准备