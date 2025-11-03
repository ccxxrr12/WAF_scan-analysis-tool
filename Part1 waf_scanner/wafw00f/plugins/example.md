* 插件文件需要包含以下内容
  ``` python
        #!/usr/bin/env python3
        #-*- coding: utf-8 -*-

        #定义WAF名称，格式为'WAF名称 (厂商名称)'
        NAME = 'MyWAF (MyCompany)'

    def is_waf(self):
        """
     检测目标是否使用MyWAF
    
        返回:
        如果检测到MyWAF则返回True，否则返回False
        """
        # 示例检测方法:
    
         # 1. 检查HTTP响应头
        if self.matchHeader(('Server', r'MyWAF')):
        return True
    
        # 2. 检查特定Cookie
        if self.matchCookie(r'mywaf_session'):
        return True
    
        # 3. 检查响应内容
        if self.matchContent(r'blocked by MyWAF'):
        return True
    
        # 4. 检查HTTP状态码
        if self.matchStatus(403):
        # 结合其他检测方法
        if self.matchReason('Forbidden By MyWAF'):
            return True
    
        return False

