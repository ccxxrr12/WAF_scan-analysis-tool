`up to 2025.11.04`
  
- 完成模块一 wafscanner的适应性更改和打包，现已可build
- 统一了plugins的文件规范，详情见`Part1 waf_scanner/wafw00f/plugins/example.md`

`preview`
- 阅读模块三进度，重设架构以符合要求
- 计划增设program'自动识别记录未知waf行为指纹'

`up to 2025.11.21`

- 重构模块三
- 完成基本架构设计及mod框架

`preview`
- 完善part3各模块功能
- 首先实现数据处理模块及模型定义模块

`up to 2025.11.26`

- 框架已经搭建完成
- 各模块接口已定义
- 实现数据处理模块中的特征提取功能
- 实现模型定义模块的具体模型实现
```
## 数据处理模块实现
实现了数据处理模块中的特征提取功能，能够从HTTP请求中提取以下特征：

URL特征：

URL长度
参数数量
参数值总长度
特殊字符计数（如'"', "'", "<", ">", "=", "script"等）
请求方法特征：

是否为GET、POST、PUT、DELETE请求
响应状态特征：

响应状态码
是否为4xx错误
是否为5xx错误
请求体特征：

请求体长度
请求头特征：

请求头数量

## 模型定义模块实现
实现了三种传统机器学习模型：

逻辑回归模型（LogisticRegressionModel）：

基于sklearn的LogisticRegression实现
支持训练、预测和评估功能
随机森林模型（RandomForestModel）：

基于sklearn的RandomForestClassifier实现
支持训练、预测和评估功能
XGBoost模型（XGBoostModel）：

基于xgboost的XGBClassifier实现
支持训练、预测和评估功能
模型工厂（ModelFactory）：

提供统一的模型创建接口
支持根据不同类型创建相应的模型实例

## 示例使用脚本
创建了一个示例脚本，演示了如何使用这些模块：

创建示例HTTP请求数据
使用数据处理器提取特征
将特征转换为numpy数组
划分训练集和测试集
创建并训练逻辑回归模型
进行预测和评估
```

在经过组内研讨深思熟虑之后，我们决定扔掉cnn和lstm两个深度学习模型，将精力放在传统的机器学习模型上