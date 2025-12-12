from abc import ABC, abstractmethod
from typing import Dict, List, Any, Optional


class WAFModuleInterface(ABC):
    """
    WAF模块基础接口类，定义所有WAF相关模块的通用接口
    """
    
    @abstractmethod
    def initialize(self, **kwargs) -> bool:
        """
        初始化模块
        
        Args:
            **kwargs: 初始化参数
            
        Returns:
            bool: 初始化是否成功
        """
        pass
    
    @abstractmethod
    def get_status(self) -> Dict[str, Any]:
        """
        获取模块状态
        
        Returns:
            Dict[str, Any]: 模块状态信息
        """
        pass


class WAFScannerInterface(WAFModuleInterface):
    """
    WAF扫描器接口类
    """
    
    @abstractmethod
    def scan_url(self, url: str, **kwargs) -> Dict[str, Any]:
        """
        扫描单个URL
        
        Args:
            url: 要扫描的URL
            **kwargs: 扫描参数
            
        Returns:
            Dict[str, Any]: 扫描结果
        """
        pass
    
    @abstractmethod
    def batch_scan(self, urls: List[str], **kwargs) -> List[Dict[str, Any]]:
        """
        批量扫描URL
        
        Args:
            urls: 要扫描的URL列表
            **kwargs: 扫描参数
            
        Returns:
            List[Dict[str, Any]]: 扫描结果列表
        """
        pass
    
    @abstractmethod
    def get_supported_wafs(self) -> List[str]:
        """
        获取支持的WAF列表
        
        Returns:
            List[str]: 支持的WAF名称列表
        """
        pass


class RuleAnalysisInterface(WAFModuleInterface):
    """
    规则分析接口类
    """
    
    @abstractmethod
    def load_rules(self, rules_dir: Optional[str] = None) -> int:
        """
        加载规则
        
        Args:
            rules_dir: 规则目录路径，如果为None则使用默认目录
            
        Returns:
            int: 成功加载的规则数量
        """
        pass
    
    @abstractmethod
    def analyze_request(self, request: Dict[str, Any]) -> Dict[str, Any]:
        """
        分析请求
        
        Args:
            request: 请求数据
            
        Returns:
            Dict[str, Any]: 分析结果
        """
        pass
    
    @abstractmethod
    def get_rule_statistics(self) -> Dict[str, Any]:
        """
        获取规则统计信息
        
        Returns:
            Dict[str, Any]: 规则统计信息
        """
        pass
    
    @abstractmethod
    def search_rules(self, query: str, filters: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
        """
        搜索规则
        
        Args:
            query: 搜索关键词
            filters: 过滤条件
            
        Returns:
            List[Dict[str, Any]]: 匹配的规则列表
        """
        pass


class DeepLearningInterface(WAFModuleInterface):
    """
    深度学习接口类
    """
    
    @abstractmethod
    def train_model(self, training_data: List[Dict[str, Any]], **kwargs) -> Dict[str, Any]:
        """
        训练模型
        
        Args:
            training_data: 训练数据
            **kwargs: 训练参数
            
        Returns:
            Dict[str, Any]: 训练结果
        """
        pass
    
    @abstractmethod
    def predict(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """
        预测数据
        
        Args:
            data: 要预测的数据
            
        Returns:
            Dict[str, Any]: 预测结果
        """
        pass
    
    @abstractmethod
    def save_model(self, model_path: str) -> bool:
        """
        保存模型
        
        Args:
            model_path: 模型保存路径
            
        Returns:
            bool: 保存是否成功
        """
        pass
    
    @abstractmethod
    def load_model(self, model_path: str) -> bool:
        """
        加载模型
        
        Args:
            model_path: 模型加载路径
            
        Returns:
            bool: 加载是否成功
        """
        pass


class WAFSystemInterface:
    """
    WAF系统接口类，整合所有模块
    """
    
    def __init__(self):
        self.waf_scanner = None
        self.rule_analyzer = None
        self.deep_learning = None
    
    def initialize(self, scanner_config: Optional[Dict[str, Any]] = None, 
                  analyzer_config: Optional[Dict[str, Any]] = None,
                  dl_config: Optional[Dict[str, Any]] = None) -> bool:
        """
        初始化所有模块
        
        Args:
            scanner_config: 扫描器配置
            analyzer_config: 分析器配置
            dl_config: 深度学习配置
            
        Returns:
            bool: 初始化是否成功
        """
        # 实现初始化逻辑
        return True
    
    def scan_and_analyze(self, url: str) -> Dict[str, Any]:
        """
        扫描URL并分析其WAF规则
        
        Args:
            url: 要扫描和分析的URL
            
        Returns:
            Dict[str, Any]: 扫描和分析结果
        """
        # 实现扫描和分析逻辑
        return {}