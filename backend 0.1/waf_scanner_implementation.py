import os
import sys
import json
from typing import Dict, List, Any, Optional

# 添加项目根目录到Python路径
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

# 导入API接口
from backend.api_interface import WAFScannerInterface

# 添加Part1 waf_scanner目录到Python路径
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'Part1 waf_scanner')))

# 导入wafw00f模块
try:
    from wafw00f.main import WAFW00F
    wafw00f_available = True
except ImportError:
    wafw00f_available = False


class WAFScannerImplementation(WAFScannerInterface):
    """
    WAF扫描器实现类，基于wafw00f工具
    """
    
    def __init__(self):
        self.initialized = False
        self.waf_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'Part1 waf_scanner'))
        self.supported_wafs = []
        self.status = {
            'initialized': False,
            'wafw00f_available': wafw00f_available,
            'error': None
        }
    
    def initialize(self, **kwargs) -> bool:
        """
        初始化WAF扫描器
        
        Args:
            **kwargs: 初始化参数
                - waf_dir: 自定义的waf_scanner目录路径
                
        Returns:
            bool: 初始化是否成功
        """
        try:
            # 更新waf_dir如果提供了自定义路径
            if 'waf_dir' in kwargs:
                self.waf_dir = os.path.abspath(kwargs['waf_dir'])
            
            # 验证wafw00f是否可用
            if not wafw00f_available:
                self.status['error'] = 'wafw00f模块未找到'
                return False
            
            # 获取支持的WAF列表
            self._load_supported_wafs()
            
            self.initialized = True
            self.status['initialized'] = True
            self.status['error'] = None
            return True
        except Exception as e:
            self.status['error'] = str(e)
            return False
    
    def scan_url(self, url: str, **kwargs) -> Dict[str, Any]:
        """
        扫描单个URL，识别其使用的WAF
        
        Args:
            url: 要扫描的URL
            **kwargs: 扫描参数
                - follow_redirect: 是否跟随重定向
                - timeout: 请求超时时间（秒）
                - proxy: 代理服务器URL
                - extra_headers: 额外的HTTP头信息
                - find_all: 是否查找所有可能的WAF
            
        Returns:
            Dict[str, Any]: 扫描结果的JSON格式数据
        """
        if not self.initialized:
            return {
                'url': url,
                'success': False,
                'error': '模块未初始化',
                'detection_result': None
            }
        
        # 确保URL格式正确
        if not url.startswith('http'):
            url = 'https://' + url
        
        try:
            # 解析扫描参数
            follow_redirect = kwargs.get('follow_redirect', True)
            timeout = kwargs.get('timeout', 30)
            proxy = kwargs.get('proxy', None)
            extra_headers = kwargs.get('extra_headers', {})
            find_all = kwargs.get('find_all', False)
            
            # 设置代理
            proxies = {}
            if proxy:
                proxies = {
                    'http': proxy,
                    'https': proxy,
                }
            
            # 创建WAFW00F实例
            waf_scanner = WAFW00F(
                url,
                debuglevel=0,
                followredirect=follow_redirect,
                extraheaders=extra_headers,
                proxies=proxies,
                timeout=timeout
            )
            
            # 执行WAF检测
            waf_list, _ = waf_scanner.identwaf(find_all)
            
            # 执行通用检测
            generic_result = waf_scanner.genericdetect()
            
            # 构建结果
            result = {
                'url': url,
                'success': True,
                'detection_result': {
                    'identified_wafs': waf_list,
                    'generic_detection': {
                        'detected': generic_result is not None,
                        'reason': waf_scanner.knowledge.get('generic', {}).get('reason', '') if generic_result else ''
                    },
                    'request_count': waf_scanner.requestnumber
                }
            }
            
            return result
        except Exception as e:
            return {
                'url': url,
                'success': False,
                'error': str(e),
                'detection_result': None
            }
    
    def batch_scan(self, urls: List[str], **kwargs) -> List[Dict[str, Any]]:
        """
        批量扫描多个URL
        
        Args:
            urls: 要扫描的URL列表
            **kwargs: 扫描参数（与scan_url相同）
            
        Returns:
            List[Dict[str, Any]]: 扫描结果列表，每个结果都是JSON格式
        """
        results = []
        
        for url in urls:
            result = self.scan_url(url, **kwargs)
            results.append(result)
        
        return results
    
    def get_supported_wafs(self) -> List[str]:
        """
        获取支持的WAF列表
        
        Returns:
            List[str]: 支持的WAF名称列表
        """
        if not self.supported_wafs and wafw00f_available:
            self._load_supported_wafs()
        
        return self.supported_wafs
    
    def get_status(self) -> Dict[str, Any]:
        """
        获取模块状态
        
        Returns:
            Dict[str, Any]: 模块状态的JSON格式数据
        """
        return {
            'initialized': self.initialized,
            'wafw00f_available': wafw00f_available,
            'supported_wafs_count': len(self.supported_wafs),
            'waf_dir': self.waf_dir,
            'error': self.status.get('error')
        }
    
    def _load_supported_wafs(self):
        """
        加载支持的WAF列表
        """
        if not wafw00f_available:
            return
        
        try:
            # 从wafw00f中提取支持的WAF列表
            # 由于wafw00f.main中的wafdetections字典是私有的，我们通过创建一个实例并访问其属性来获取
            temp_scanner = WAFW00F('https://example.com', debuglevel=0)
            if hasattr(temp_scanner, 'wafdetections'):
                self.supported_wafs = list(temp_scanner.wafdetections.keys())
            else:
                # 如果无法直接访问，使用默认列表
                self.supported_wafs = [
                    'ModSecurity', 'CloudFlare', 'AWS WAF', 'Akamai', 'F5 BIG-IP',
                    'Imperva', 'Sucuri', 'Incapsula', 'Microsoft Azure WAF', 'Barracuda',
                    'FortiWeb', 'Palo Alto Networks', 'Sophos', 'Radware', 'Sitelock'
                ]
        except Exception:
            # 如果出现错误，使用空列表
            self.supported_wafs = []


# 示例用法（如果直接运行此文件）
if __name__ == '__main__':
    scanner = WAFScannerImplementation()
    if scanner.initialize():
        print(json.dumps(scanner.get_status(), indent=2, ensure_ascii=False))
        print(f"支持的WAF数量: {len(scanner.get_supported_wafs())}")
        
        # 扫描示例URL
        # 注意：取消下面的注释以进行实际扫描
        # result = scanner.scan_url('https://example.com')
        # print(json.dumps(result, indent=2, ensure_ascii=False))
    else:
        print(f"初始化失败: {scanner.get_status().get('error')}")
