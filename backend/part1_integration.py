import sys
import os
import urllib.parse

# 添加Part1目录到Python路径
part1_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'Part1 waf_scanner')
sys.path.insert(0, part1_path)

from wafw00f.main import WAFW00F, buildResultRecord

def scan_waf(url: str, debuglevel: int = 0, followredirect: bool = True) -> dict:
    """
    扫描指定URL的WAF类型
    
    Args:
        url: 目标URL
        debuglevel: 调试级别
        followredirect: 是否跟随重定向
        
    Returns:
        包含WAF检测结果的字典
    """
    try:
        # 确保URL格式正确
        if not url.startswith('http'):
            url = 'https://' + url
        
        # 解析URL获取路径
        pret = urllib.parse.urlparse(url)
        path = pret.path if pret.path else '/'  # 默认路径为'/'
        
        # 创建WAFW00F实例
        attacker = WAFW00F(
            target=url, 
            debuglevel=debuglevel, 
            path=path,
            followredirect=followredirect
        )
        
        # 检查请求是否成功
        if attacker.rq is None:
            return {
                "success": False,
                "error": f"Site {url} appears to be down"
            }
        
        # 识别WAF
        waf_list, xurl = attacker.identwaf(findall=True)
        
        results = []
        if len(waf_list) > 0:
            for waf in waf_list:
                results.append(buildResultRecord(url, waf, xurl))
        else:
            # 使用通用检测
            generic_url = attacker.genericdetect()
            if generic_url:
                results.append(buildResultRecord(url, 'generic', generic_url))
            else:
                results.append(buildResultRecord(url, None, None))
        
        # 构建最终结果
        final_result = {
            "url": url,
            "detected": len([r for r in results if r['detected']]) > 0,
            "wafs": [{
                "name": r['firewall'],
                "manufacturer": r['manufacturer'],
                "trigger_url": r['trigger_url']
            } for r in results if r['detected']],
            "request_count": attacker.requestnumber,
            "knowledge_base": attacker.knowledge
        }
        
        return {
            "success": True,
            "data": final_result
        }
        
    except Exception as e:
        return {
            "success": False,
            "error": str(e)
        }

# 测试函数
if __name__ == "__main__":
    test_url = "https://example.com"
    result = scan_waf(test_url)
    print(f"WAF扫描结果: {result}")
