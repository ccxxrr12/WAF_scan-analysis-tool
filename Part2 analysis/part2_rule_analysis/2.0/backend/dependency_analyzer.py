import re

class DependencyAnalyzer:
    """依赖分析器，负责识别规则中的变量依赖、标记依赖和包含依赖"""
    
    def __init__(self):
        # 内置变量列表
        self.builtin_variables = {
            'REQUEST_URI': '请求路径',
            'REQUEST_METHOD': '请求方法',
            'REQUEST_HEADERS': '请求头',
            'REQUEST_BODY': '请求体',
            'ARGS': '请求参数',
            'ARGS_GET': 'GET请求参数',
            'ARGS_POST': 'POST请求参数',
            'QUERY_STRING': '查询字符串',
            'REMOTE_ADDR': '客户端IP地址',
            'REMOTE_PORT': '客户端端口',
            'SERVER_ADDR': '服务器IP地址',
            'SERVER_PORT': '服务器端口',
            'HTTP_USER_AGENT': 'User-Agent头',
            'HTTP_COOKIE': 'Cookie头',
            'HTTP_REFERER': 'Referer头',
            'HTTP_HOST': 'Host头',
            'HTTP_CONTENT_TYPE': 'Content-Type头',
            'HTTP_CONTENT_LENGTH': 'Content-Length头',
            'RESPONSE_STATUS': '响应状态码',
            'RESPONSE_HEADERS': '响应头',
            'RESPONSE_BODY': '响应体',
            'TX': '事务变量',
            'ENV': '环境变量',
            'FILES': '上传文件',
            'GLOBAL': '全局变量'
        }
    
    def analyze(self, rule, raw_rule=None):
        """对规则进行依赖分析"""
        # 提取规则信息
        rule_info = rule.get('rule_info', {})
        variables = rule_info.get('variables', [])
        message = rule_info.get('message', '')
        actions = rule_info.get('actions', [])
        operator = rule_info.get('operator', '')
        pattern = rule_info.get('pattern', '')
        
        # 分析变量依赖
        variable_dependencies = self._analyze_variable_dependencies(variables, message, actions, raw_rule, operator, pattern)
        
        # 分析标记依赖
        marker_dependencies = self._analyze_marker_dependencies(actions, message, raw_rule)
        
        # 分析包含依赖
        include_dependencies = self._analyze_include_dependencies(actions, raw_rule)
        
        return {
            'variable_dependencies': variable_dependencies,
            'marker_dependencies': marker_dependencies,
            'include_dependencies': include_dependencies
        }
    
    def _analyze_variable_dependencies(self, variables, message, actions, raw_rule, operator=None, pattern=None):
        """分析变量依赖"""
        variable_dependencies = []
        
        # 从variables字段提取
        if isinstance(variables, list):
            for var in variables:
                if isinstance(var, str):
                    # 提取变量名
                    var_name = var.split(':')[0].strip('&')
                    # 获取变量用途
                    purpose = self.builtin_variables.get(var_name, '自定义变量')
                    dep_str = f"{var_name}：{purpose}"
                    if dep_str not in variable_dependencies:
                        variable_dependencies.append(dep_str)
                elif isinstance(var, dict):
                    # 处理字典格式的变量
                    var_name = var.get('variable', '')
                    purpose = self.builtin_variables.get(var_name, '自定义变量')
                    dep_str = f"{var_name}：{purpose}"
                    if dep_str not in variable_dependencies:
                        variable_dependencies.append(dep_str)
        
        # 从raw_rule中提取更多变量
        if raw_rule:
            # 匹配所有变量引用
            var_pattern = r'(?:REQUEST_URI|REQUEST_METHOD|REQUEST_HEADERS|REQUEST_BODY|ARGS|ARGS_GET|ARGS_POST|QUERY_STRING|REMOTE_ADDR|REMOTE_PORT|SERVER_ADDR|SERVER_PORT|HTTP_\w+|RESPONSE_STATUS|RESPONSE_HEADERS|RESPONSE_BODY|TX|ENV|FILES|GLOBAL|ARGS_NAMES|ARGS_GET_NAMES|ARGS_POST_NAMES|REQUEST_COOKIES|REQUEST_COOKIES_NAMES|REQUEST_LINE|REQUEST_URI_RAW|REQUEST_PROTOCOL|REQUEST_METHOD|REQUEST_FILENAME|RESPONSE_PROTOCOL|RESPONSE_CONTENT_TYPE|RESPONSE_CONTENT_LENGTH|SERVER_NAME|REMOTE_HOST|REMOTE_USER|TIME|TIME_EPOCH|TIME_YEAR|TIME_MON|TIME_DAY|TIME_HOUR|TIME_MIN|TIME_SEC|TIME_WDAY|UNIQUE_ID|URLENCODED_ERROR|REQBODY_ERROR|REQBODY_ERROR_MSG|REQBODY_PROCESSOR|REQBODY_PROCESSOR_ERROR|INBOUND_DATA_ERROR|OUTBOUND_DATA_ERROR|ARGS_COMBINED_SIZE|FILES_COMBINED_SIZE|FILES_NAMES|FILES_SIZES|FILES_TMPNAMES|FILES_TMP_CONTENT|GEO|HIGHEST_SEVERITY|MATCHED_VAR|MATCHED_VARS|MATCHED_VAR_NAME|MATCHED_VARS_NAMES|MODSEC_BUILD|MULTIPART_BOUNDARY_QUOTED|MULTIPART_CRLF_LF_LINES|MULTIPART_FILENAME|MULTIPART_NAME|MULTIPART_STRICT_ERROR|MULTIPART_UNMATCHED_BOUNDARY|MULTIPART_BOUNDARY_WHITESPACE|MULTIPART_DATA_BEFORE|MULTIPART_DATA_AFTER|MULTIPART_HEADER_FOLDING|MULTIPART_LF_LINE|MULTIPART_INVALID_QUOTING|MULTIPART_INVALID_HEADER_FOLDING|MULTIPART_INVALID_PART|MULTIPART_FILE_LIMIT_EXCEEDED|MULTIPART_PART_HEADERS|SDBM_DELETE_ERROR|SCRIPT_BASENAME|SCRIPT_FILENAME|SCRIPT_GID|SCRIPT_GROUPNAME|SCRIPT_MODE|SCRIPT_UID|SCRIPT_USERNAME|SESSION|SESSIONID|STATUS_LINE|STREAM_INPUT_BODY|STREAM_OUTPUT_BODY|TX|USERID|USERAGENT_IP|WEBAPPID|WEBSERVER_ERROR_LOG|XML):?\w*'
            matches = re.findall(var_pattern, raw_rule)
            
            for match in matches:
                var_name = match.split(':')[0]
                purpose = self.builtin_variables.get(var_name, '自定义变量')
                dep_str = f"{var_name}：{purpose}"
                if dep_str not in variable_dependencies:
                    variable_dependencies.append(dep_str)
        
        return variable_dependencies
    
    def _analyze_marker_dependencies(self, actions, message, raw_rule):
        """分析标记依赖"""
        marker_dependencies = []
        
        # 从actions和message中提取标记
        message_str = message or ''
        
        # 处理动作
        combined_text = ''
        if isinstance(actions, list):
            for action in actions:
                if isinstance(action, str):
                    combined_text += ' ' + action
                elif isinstance(action, dict):
                    combined_text += ' ' + action.get('act_name', '') + ':' + action.get('act_arg', '')
        elif isinstance(actions, str):
            combined_text = actions
        
        combined_text += ' ' + message_str
        
        # 匹配skipAfter、skipBefore等标记
        marker_pattern = r'(?:skipAfter|skipBefore|chain):?\s*"?([\w-]+)"?'
        matches = re.findall(marker_pattern, combined_text, re.IGNORECASE)
        
        for match in matches:
            marker = match.strip('"')
            if marker:
                # 尝试从raw_rule中获取更多信息
                marker_info = f"{marker}：规则标记"
                marker_dependencies.append(marker_info)
        
        # 从raw_rule中提取更多标记
        if raw_rule:
            # 匹配SecMarker指令
            secmarker_pattern = r'SecMarker\s+"?([\w-]+)"?'
            matches = re.findall(secmarker_pattern, raw_rule)
            
            for match in matches:
                marker = match.strip('"')
                if marker:
                    marker_info = f"{marker}：规则标记"
                    if marker_info not in marker_dependencies:
                        marker_dependencies.append(marker_info)
        
        return marker_dependencies
    
    def _analyze_include_dependencies(self, actions, raw_rule):
        """分析包含依赖"""
        include_dependencies = []
        
        # 从actions中提取包含指令
        if isinstance(actions, list):
            for action in actions:
                if isinstance(action, str):
                    if action.startswith('include:'):
                        include_path = action[8:].strip('"')
                        include_dependencies.append(include_path)
                elif isinstance(action, dict):
                    if action.get('act_name') == 'include':
                        include_path = action.get('act_arg', '').strip('"')
                        if include_path:
                            include_dependencies.append(include_path)
        
        # 从raw_rule中提取Include指令
        if raw_rule:
            include_pattern = r'Include\s+"?([^\s"]+)"?'
            matches = re.findall(include_pattern, raw_rule, re.IGNORECASE)
            
            for match in matches:
                include_path = match.strip('"')
                if include_path and include_path not in include_dependencies:
                    include_dependencies.append(include_path)
        
        return include_dependencies
    
    def batch_analyze(self, rules, raw_rules=None):
        """批量分析规则依赖"""
        for i, rule in enumerate(rules):
            raw_rule = raw_rules[i] if raw_rules and i < len(raw_rules) else None
            dependency_result = self.analyze(rule, raw_rule)
            rule['dependency_analysis'] = dependency_result
        
        return rules