import re
from collections import defaultdict

class SemanticAnalyzer:
    """语义分析器，负责攻击类型分类和规则分类"""
    
    def __init__(self):
        # 攻击类型模式库，扩展至25+种
        self.attack_patterns = {
            # 传统Web攻击
            'SQL Injection': {
                'patterns': [
                    r'sql', r'select', r'union', r'insert', r'update', r'delete',
                    r'drop', r'alter', r'create', r'truncate', r'xp_cmdshell',
                    r'1=1', r"' or '", r"' AND '", r'--', r'#',
                    r'/*', r'*/', r'exec', r'procedure', r'function',
                    r'sp_', r'concat\(', r'group_concat\(', r'concat_ws\(',
                    r'char\(', r'convert\(', r'cast\(', r'replace\(',
                    r'benchmark\(', r'sleep\(', r'waitfor delay', r'if\(condition\)'
                ],
                'priority': 10
            },
            'Cross-Site Scripting (XSS)': {
                'patterns': [
                    r'<script', r'</script>', r'javascript:', r'vbscript:',
                    r'onload=', r'onerror=', r'onclick=', r'onmouseover=',
                    r'alert\(', r'prompt\(', r'confirm\(', r'document\.cookie',
                    r'document\.write', r'<iframe', r'<img', r'<link',
                    r'<style', r'<body', r'<input', r'<textarea',
                    r'<button', r'<a', r'<div', r'<span',
                    r'<svg', r'on\w+=', r'expression\(', r'vbscript:',
                    r'data:text/html', r'blob:', r'file:', r'javascript:.*=',
                    r'<object', r'<embed', r'<applet', r'<form'
                ],
                'priority': 9
            },
            'Path Traversal': {
                'patterns': [
                    r'\.\./', r'\.\.\\', r'%2e%2e%2f', r'%2e%2e%5c',
                    r'\.\\', r'\./', r'~', r'\.\.\\',
                    r'/etc/passwd', r'/etc/shadow', r'/proc/self/environ',
                    r'c:\\windows', r'c:\\winnt', r'c:\\system32',
                    r'c:\\boot\.ini', r'c:\\windows\\system32\\',
                    r'\\windows\\system32\\', r'\\system32\\'
                ],
                'priority': 8
            },
            'Command Injection': {
                'patterns': [
                    r';', r'\|', r'&', r'&&', r'\|\|', r'`', r'\$\(',
                    r'command\.com', r'cmd\.exe', r'bash', r'sh', r'ksh',
                    r'cat', r'ls', r'dir', r'rm', r'cp', r'mv', r'mkdir',
                    r'chmod', r'chown', r'wget', r'curl', r'ping', r'nslookup',
                    r'telnet', r'ssh', r'ftp', r'scp', r'rsync',
                    r'grep', r'awk', r'sed', r'cut', r'tail', r'head',
                    r'python', r'php', r'perl', r'ruby', r'java',
                    r'eval\(', r'exec\(', r'system\(', r'popen\('
                ],
                'priority': 7
            },
            'Remote File Inclusion': {
                'patterns': [
                    r'http://', r'https://', r'ftp://', r'ftps://', r'sftp://',
                    r'file://', r'phar://', r'zlib://', r'data://',
                    r'include\(', r'require\(', r'include_once\(', r'require_once\(',
                    r'fopen\(', r'file_get_contents\(', r'curl_exec\(',
                    r'readfile\(', r'file\(', r'parse_ini_file\('
                ],
                'priority': 6
            },
            'Local File Inclusion': {
                'patterns': [
                    r'file://', r'phar://', r'zlib://', r'bzip2://',
                    r'include\(', r'require\(', r'include_once\(', r'require_once\(',
                    r'/etc/', r'/var/', r'/tmp/', r'/dev/', r'/proc/',
                    r'c:\\', r'd:\\', r'\\\\',
                    r'fopen\(', r'file_get_contents\(', r'readfile\(',
                    r'file\(', r'parse_ini_file\(', r'shell_exec\('
                ],
                'priority': 5
            },
            'Server-Side Request Forgery (SSRF)': {
                'patterns': [
                    r'http://', r'https://', r'ftp://', r'file://',
                    r'localhost', r'127\.0\.0\.1', r'0\.0\.0\.0', r'::1',
                    r'169\.254\.169\.254', r'10\.0\.0\.0/8', r'172\.16\.0\.0/12',
                    r'192\.168\.0\.0/16', r'request\(', r'fetch\(', r'curl\(',
                    r'wget\(', r'file_get_contents\(', r'fopen\(',
                    r'get_headers\(', r'fsockopen\(', r'stream_socket_client\('
                ],
                'priority': 4
            },
            
            # 新增攻击类型
            'Server-Side Template Injection (SSTI)': {
                'patterns': [
                    r'\{\{', r'\}\}', r'\{%', r'%\}', r'\{#', r'#\}',
                    r'\{\%\s*if', r'\{\%\s*for', r'\{\%\s*include',
                    r'\{\{\s*.*\s*\}\}.*\{\{', r'\{\%\s*set',
                    r'\{\{\s*config\.', r'\{\{\s*self\.', r'\{\{\s*request\.',
                    r'\{\{\s*session\.', r'\{\{\s*url_for', r'\{\{\s*range',
                    r'\{\{\s*loop', r'\{\{\s*super\(', r'\{\{\s*block'
                ],
                'priority': 11
            },
            'Deserialization Attack': {
                'patterns': [
                    r'__wakeup', r'__sleep', r'__destruct', r'__call',
                    r'__get', r'__set', r'__isset', r'__unset',
                    r'__toString', r'__invoke', r'__callStatic', r'__clone',
                    r'pickle', r'json.loads', r'json.load', r'yaml.safe_load',
                    r'yaml.load', r'msgpack.unpackb', r'msgpack.loads',
                    r'pickle.loads', r'pickle.load', r'php_unserialize',
                    r'java.io.ObjectInputStream', r'java.io.ObjectOutputStream'
                ],
                'priority': 12
            },
            'XML External Entity (XXE)': {
                'patterns': [
                    r'<!DOCTYPE', r'<!ENTITY', r'<?xml', r'CDATA\[',
                    r'http://www.w3.org/2001/XMLSchema', r'http://www.w3.org/XML/1998/namespace',
                    r'\!\[CDATA\[', r'\]\]>', r'\&\w+;', r'\<!ELEMENT',
                    r'\<!ATTLIST', r'\<!NOTATION', r'\<!ENTITY',
                    r'file://', r'http://', r'https://', r'ftp://'
                ],
                'priority': 13
            },
            'Code Injection': {
                'patterns': [
                    r'eval\(', r'exec\(', r'system\(', r'popen\(',
                    r'shell_exec\(', r'passthru\(', r'backtick',
                    r'create_function\(', r'array_map\(', r'call_user_func\(',
                    r'call_user_func_array\(', r'assert\(', r'preg_replace.*e\)',
                    r'create_function\(', r'dynamic\s+language', r'php.*code',
                    r'python.*code', r'ruby.*code', r'java.*code',
                    r'javascript.*code', r'execute.*code', r'run.*code'
                ],
                'priority': 14
            },
            'Cross-Site Request Forgery (CSRF)': {
                'patterns': [
                    r'\bcsrf\b', r'\bcross-site request forgery\b',
                    r'\bxcsrf\b', r'\banti-csrf\b', r'\btoken\b',
                    r'\bcsrf_token\b', r'\bx-csrf-token\b', r'\bcookie.*token\b',
                    r'\bform.*token\b', r'\brequest.*token\b', r'\bsession.*token\b',
                    r'\bxsrf.*token\b', r'\bcrsf\b', r'\bnonce\b', r'\bsynchronizer.*token\b'
                ],
                'priority': 3
            },
            'Authentication Bypass': {
                'patterns': [
                    r'admin', r'root', r'guest', r'user',
                    r'login', r'logout', r'register', r'password',
                    r'passwd', r'token', r'session', r'cookie',
                    r'jwt', r'auth', r'authorization', r'basic ',
                    r'bearer ', r'oauth', r'openid', r'access.*token',
                    r'refresh.*token', r'id.*token', r'token.*invalid',
                    r'auth.*bypass', r'authentication.*bypass', r'access.*denied'
                ],
                'priority': 2
            },
            'Clickjacking': {
                'patterns': [
                    r'\bclickjack\b', r'\bframebust\b', r'\bx-frame-options\b',
                    r'\bx-content-type-options\b', r'\bx-xss-protection\b',
                    r'\bx-permitted-cross-domain-policies\b', r'\bframe-ancestors\b',
                    r'\bx-frame-options\s*=\s*deny', r'\bx-frame-options\s*=\s*sameorigin',
                    r'\bclickjacking\b', r'\bframe\s*busting\b'
                ],
                'priority': 1
            },
            'Denial of Service (DoS)': {
                'patterns': [
                    r'\bdos\b', r'\bdenial of service\b', r'\brate limit\b',
                    r'\bflood\b', r'\bslowloris\b', r'\brudra\b',
                    r'\bslowhttp\b', r'\bcookie\s+flood\b', r'\bhttp\s+flood\b',
                    r'\bconnection\s+flood\b', r'\bsyn\s+flood\b', r'\bping\s+flood\b',
                    r'\bbenchmark\(', r'\bsleep\(', r'\brepeat\(', r'\bwhile\s*\(1'
                ],
                'priority': 4
            },
            'Information Disclosure': {
                'patterns': [
                    r'\binfo\b', r'\bdisclosure\b', r'\berror\b',
                    r'\bwarning\b', r'\bexception\b', r'\btraceback\b',
                    r'\bdebug\b', r'\bstack trace\b', r'\bphpinfo\(',
                    r'\bphpinfo\.php', r'\bmysql_error\(', r'\bmysqli_error\(',
                    r'\bORA-', r'\bSQLSTATE', r'\bPG::Error', r'\bTraceback \(most recent call last\)',
                    r'\bFatal error:', r'\bWarning:', r'\bNotice:', r'\bParse error:',
                    r'\bDeprecated:', r'\bStrict Standards:', r'\bNotice:',
                    r'\bHTTP/1\.1\s+500', r'\bInternal Server Error', r'\b404 Not Found'
                ],
                'priority': 3
            },
            'Web Shell': {
                'patterns': [
                    r'\bshell\b', r'\bwebshell\b', r'\br57\b',
                    r'\bc99\b', r'\bg00nshell\b', r'\bphpspy\b',
                    r'\bsymlink\(', r'\beval\(', r'\bassert\(',
                    r'\bpassthru\(', r'\bshell_exec\(', r'\bexec\(',
                    r'\bproc_open\(', r'\bpopen\(', r'\bsystem\(',
                    r'\bphpinfo\(', r'\bcreate_function\(', r'\bcurl_exec\('
                ],
                'priority': 15
            },
            'HTTP Request Smuggling': {
                'patterns': [
                    r'\btransfer-encoding\b', r'\bcontent-length\b',
                    r'\bchunked\b', r'\b0\r\n\r\n', r'\b0\n\n',
                    r'\bmultipart/byteranges\b', r'\bmultipart/form-data\b',
                    r'\bhttp/1\.1\b', r'\bhttp/1\.0\b', r'\bhttp/2\.0\b',
                    r'\bkeep-alive\b', r'\bconnection\b', r'\bproxy\b'
                ],
                'priority': 7
            },
            'HTTP Response Splitting': {
                'patterns': [
                    r'\r\n', r'\n\r', r'\n\n', r'\r\r',
                    r'%0d%0a', r'%0a%0d', r'%0a', r'%0d',
                    r'\bset-cookie\b', r'\blocation\b', r'\bcontent-type\b',
                    r'\bcontent-length\b', r'\btransfer-encoding\b',
                    r'\bhttp/1\.1\s+', r'\bhttp/1\.0\s+', r'\b200\s+ok'
                ],
                'priority': 6
            },
            'Insecure Direct Object Reference (IDOR)': {
                'patterns': [
                    r'\bid=\d+', r'\buserid=\d+', r'\baccountid=\d+',
                    r'\borderid=\d+', r'\bfileid=\d+', r'\bdocumentid=\d+',
                    r'\bmessageid=\d+', r'\bpostid=\d+', r'\bcommentid=\d+',
                    r'\bitemid=\d+', r'\bid\s*=', r'\bkey\s*=', r'\btoken\s*='
                ],
                'priority': 5
            },
            'LDAP Injection': {
                'patterns': [
                    r'\bldap://', r'\bldaps://',
                    r'\bobjectclass=', r'\buid=', r'\bcn=',
                    r'\b\(|', r'\b\(&', r'\b\(!', r'\b\)',
                    r'\b\*\)\)', r'\b\*\)', r'\b=*', r'\b~='
                ],
                'priority': 4
            },
            'NoSQL Injection': {
                'patterns': [
                    r'\b\$eq\s*:', r'\b\$ne\s*:', r'\b\$gt\s*:',
                    r'\b\$lt\s*:', r'\b\$gte\s*:', r'\b\$lte\s*:',
                    r'\b\$in\s*:', r'\b\$nin\s*:', r'\b\$exists\s*:',
                    r'\b\$regex\s*:', r'\b\$options\s*:', r'\b\$where\s*:',
                    r'\b\$match\s*:', r'\b\$group\s*:', r'\b\$project\s*:',
                    r'\b\$sort\s*:', r'\b\$limit\s*:', r'\b\$skip\s*:',
                    r'\b\$lookup\s*:', r'\b\$unwind\s*:', r'\b\$aggregate\s*:'
                ],
                'priority': 6
            },
            'SSRF - Internal Service': {
                'patterns': [
                    r'169\.254\.169\.254', r'127\.0\.0\.1:9000',
                    r'127\.0\.0\.1:3306', r'127\.0\.0\.1:6379',
                    r'127\.0\.0\.1:27017', r'localhost:9000',
                    r'localhost:3306', r'localhost:6379', r'localhost:27017',
                    r'10\.0\.0\.0/8', r'172\.16\.0\.0/12', r'192\.168\.0\.0/16',
                    r'::1', r'fe80::1', r'\[::1\]'
                ],
                'priority': 7
            },
            'Invalid Authentication': {
                'patterns': [
                    r'\binvalid\s+username', r'\binvalid\s+password',
                    r'\binvalid\s+token', r'\bexpired\s+token',
                    r'\bwrong\s+username', r'\bwrong\s+password',
                    r'\bauthentication\s+failed', r'\bauth\s+failed',
                    r'\baccess\s+denied', r'\bforbidden', r'\b401\s+unauthorized',
                    r'\b403\s+forbidden', r'\bsession\s+expired', r'\bsession\s+timeout'
                ],
                'priority': 2
            }
        }
        
        # 规则ID前缀到攻击类型的映射
        self.rule_id_prefix_map = {
            '942': 'SQL Injection',
            '941': 'Cross-Site Scripting (XSS)',
            '931': 'Remote File Inclusion',
            '930': 'Path Traversal',
            '932': 'Command Injection',
            '943': 'Application Attack - Generic',
            '944': 'Application Attack - Java',
            '921': 'Protocol Attack',
            '922': 'Multipart Attack',
            '933': 'PHP Injection',
            '949': 'Blocking Evaluation',
            '950': 'Data Leakages',
            '951': 'SQL Injection Data Leakage',
            '952': 'Java Data Leakage',
            '953': 'PHP Data Leakage',
            '954': 'IIS Data Leakage',
            '955': 'Web Shells',
            '956': 'Ruby Data Leakage',
            '959': 'Response Blocking Evaluation',
            '980': 'Correlation'
        }
    
    def analyze(self, rule):
        """对规则进行语义分析"""
        # 提取规则信息
        rule_info = rule.get('rule_info', {})
        rule_id = rule_info.get('id', '')
        message = rule_info.get('message', '')
        pattern = rule_info.get('pattern', '')
        tags = rule_info.get('tags', [])
        variables = rule_info.get('variables', [])
        actions = rule_info.get('actions', [])
        operator = rule_info.get('operator', '')
        
        # 分析攻击类型
        attack_types = self._classify_attack_types(rule_id, message, pattern, tags, variables, actions, operator)
        
        # 分析规则分类
        rule_classification = self._classify_rule(message, pattern, tags, variables, actions, operator)
        
        return {
            'attack_types': attack_types,
            'rule_classification': rule_classification
        }
    
    def _classify_attack_types(self, rule_id, message, pattern, tags, variables, actions=None, operator=None):
        """根据规则ID、消息、模式、标签和变量分类攻击类型"""
        attack_types = []
        
        # 1. 基于规则ID的分类（优先级最高）
        attack_types_from_id = self._classify_by_rule_id(rule_id)
        attack_types.extend(attack_types_from_id)
        
        # 2. 基于标签的分类（优先级次之）
        attack_types_from_tags = self._classify_by_tags(tags)
        for at in attack_types_from_tags:
            if at not in attack_types:
                attack_types.append(at)
        
        # 3. 基于变量和操作符的分类（优先级中等）
        attack_types_from_vars_ops = self._classify_by_variables_and_operator(variables, operator)
        for at in attack_types_from_vars_ops:
            if at not in attack_types:
                attack_types.append(at)
        
        # 4. 基于文本内容的分类（优先级最低）
        # 合并所有文本用于分析
        message_str = message or ''
        pattern_str = pattern or ''
        tags_str = ' '.join(tags) if isinstance(tags, list) else str(tags)
        actions_str = ' '.join(actions) if isinstance(actions, list) else str(actions)
        text = (message_str + ' ' + pattern_str + ' ' + tags_str + ' ' + actions_str + ' ' + str(operator)).lower()
        
        # 按优先级排序攻击类型
        sorted_attack_types = sorted(
            self.attack_patterns.items(),
            key=lambda x: x[1]['priority'],
            reverse=True
        )
        
        # 检查每种攻击类型的模式
        for attack_type, config in sorted_attack_types:
            if attack_type in attack_types:
                continue  # 已经通过其他方式识别
                
            matched = False
            for p in config['patterns']:
                if re.search(p, text, re.IGNORECASE):
                    matched = True
                    break
            
            if matched:
                attack_types.append(attack_type)
        
        # 去重和优化
        attack_types = list(dict.fromkeys(attack_types))  # 保持顺序去重
        
        # 如果没有识别到攻击类型，添加默认类型
        if not attack_types:
            attack_types.append('Generic Attack')
        
        return attack_types
    
    def _classify_by_rule_id(self, rule_id):
        """基于规则ID的攻击类型分类"""
        attack_types = []
        
        if not rule_id:
            return attack_types
        
        # 根据规则ID的前缀判断攻击类型
        for prefix, attack_type in self.rule_id_prefix_map.items():
            if str(rule_id).startswith(prefix):
                attack_types.append(attack_type)
                break
        
        return attack_types
    
    def _classify_by_tags(self, tags):
        """基于标签的攻击类型分类"""
        attack_types = []
        
        if not isinstance(tags, list):
            return attack_types
        
        for tag in tags:
            tag_lower = tag.lower()
            # 直接匹配标签中的攻击类型
            for attack_type in self.attack_patterns.keys():
                if attack_type.lower() in tag_lower:
                    attack_types.append(attack_type)
                    break
            
            # 匹配OWASP CRS标签
            if tag_lower.startswith('attack-'):
                # 提取attack-后面的部分
                attack_part = tag_lower[7:].replace('-', ' ')
                for attack_type in self.attack_patterns.keys():
                    if attack_part in attack_type.lower():
                        attack_types.append(attack_type)
                        break
        
        return list(dict.fromkeys(attack_types))  # 去重
    
    def _classify_by_variables_and_operator(self, variables, operator):
        """基于变量和操作符的攻击类型分类"""
        attack_types = []
        
        if not variables:
            return attack_types
        
        # 变量分析
        var_str = ' '.join(map(str, variables)).lower()
        op_str = str(operator).lower()
        
        # 检查特定变量模式
        if any(keyword in var_str for keyword in ['cookie', 'session', 'token']):
            attack_types.append('Session Fixation')
        
        if 'response' in var_str:
            attack_types.append('Information Disclosure')
        
        if any(keyword in var_str for keyword in ['header', 'user-agent', 'referer']):
            attack_types.append('HTTP Request Smuggling')
        
        # 检查操作符模式
        if '@rx' in op_str:
            # 正则匹配通常用于复杂攻击检测
            pass
        
        return list(dict.fromkeys(attack_types))  # 去重
    
    def _classify_rule(self, message, pattern, tags, variables, actions=None, operator=None):
        """根据消息、模式、标签和变量分类规则"""
        # 合并所有文本用于分析
        message_str = message or ''
        pattern_str = pattern or ''
        tags_str = ' '.join(tags) if isinstance(tags, list) else str(tags)
        actions_str = ' '.join(actions) if isinstance(actions, list) else str(actions)
        text = (message_str + ' ' + pattern_str + ' ' + tags_str + ' ' + actions_str + ' ' + str(operator)).lower()
        
        # 确定防护层
        protection_layer = self._determine_protection_layer(text, tags, variables, operator)
        
        # 确定匹配方式
        matching_method = self._determine_matching_method(text, pattern, operator)
        
        # 确定适用场景
        scenario = self._determine_scenario(text, tags, actions)
        
        # 新增：确定规则类型
        rule_type = self._determine_rule_type(text, tags, variables, operator)
        
        return {
            'protection_layer': protection_layer,
            'matching_method': matching_method,
            'scenario': scenario,
            'rule_type': rule_type
        }
    
    def _determine_protection_layer(self, text, tags, variables, operator=None):
        """确定防护层"""
        if isinstance(tags, list):
            if any(tag.lower().startswith('attack-') for tag in tags):
                return 'application_layer'
        
        if isinstance(variables, list):
            for var in variables:
                var_str = str(var).lower()
                if 'protocol' in var_str:
                    return 'protocol_layer'
                elif 'request' in var_str:
                    return 'request_layer'
                elif 'response' in var_str:
                    return 'response_layer'
        
        return 'generic_layer'
    
    def _determine_matching_method(self, text, pattern, operator=None):
        """确定匹配方式"""
        op_str = str(operator).lower()
        if '@rx' in text or op_str == '@rx' or (pattern and re.search(r'[.^$*+?{}\[\]()|\\]', pattern)):
            return 'regex_matching'
        elif '@pm' in text or op_str == '@pm':
            return 'phrase_matching'
        elif '@contains' in text or op_str == '@contains':
            return 'contains_matching'
        elif '@streq' in text or op_str == '@streq':
            return 'string_equal_matching'
        elif '@beginswith' in text or op_str == '@beginswith':
            return 'begins_with_matching'
        elif '@endswith' in text or op_str == '@endswith':
            return 'ends_with_matching'
        elif '@ipmatch' in text or op_str == '@ipmatch':
            return 'ip_matching'
        elif '@geoip' in text or op_str == '@geoip':
            return 'geoip_matching'
        elif '@inspectfile' in text or op_str == '@inspectfile':
            return 'file_inspection_matching'
        else:
            return 'generic_matching'
    
    def _determine_scenario(self, text, tags, actions=None):
        """确定适用场景"""
        if isinstance(tags, list):
            for tag in tags:
                tag_lower = tag.lower()
                if 'paranoia-level/1' in tag_lower:
                    return 'paranoia_level_1'
                elif 'paranoia-level/2' in tag_lower:
                    return 'paranoia_level_2'
                elif 'paranoia-level/3' in tag_lower:
                    return 'paranoia_level_3'
                elif 'paranoia-level/4' in tag_lower:
                    return 'paranoia_level_4'
                elif 'owasp_crs' in tag_lower:
                    return 'owasp_crs_default'
                elif 'application-attack' in tag_lower:
                    return 'application_protection'
                elif 'protocol' in tag_lower:
                    return 'protocol_enforcement'
        
        return 'generic_scenario'
    
    def _determine_rule_type(self, text, tags, variables, operator=None):
        """确定规则类型"""
        # 基于标签的规则类型判断
        if isinstance(tags, list):
            for tag in tags:
                tag_lower = tag.lower()
                if 'blocking' in tag_lower:
                    return 'blocking'
                elif 'detection-only' in tag_lower:
                    return 'detection_only'
                elif 'monitoring' in tag_lower:
                    return 'monitoring'
        
        # 基于动作的规则类型判断
        if variables and isinstance(variables, list):
            var_str = ' '.join(map(str, variables)).lower()
            if 'request' in var_str:
                return 'request_rule'
            elif 'response' in var_str:
                return 'response_rule'
        
        return 'generic_rule'
    
    def batch_analyze(self, rules):
        """批量分析规则"""
        for rule in rules:
            semantic_result = self.analyze(rule)
            rule['semantic_analysis'] = semantic_result
        
        return rules