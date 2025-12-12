#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
工具模块

该模块提供Part3所需的通用工具函数。
包括文件操作、日志记录、数据转换等。

文件结构：
- load_json(): 加载JSON文件 (支持UTF-8编码)
- save_json(): 保存JSON文件 (支持UTF-8编码和格式化输出)
- setup_logger(): 设置日志记录器
- http_request_to_dict(): HTTP请求转字典
- dict_to_http_request(): 字典转HTTP请求
- normalize_text(): 文本标准化
"""

import json
import logging
import re
from urllib.parse import quote, unquote


def load_json(file_path):
    """
    加载JSON文件
    
    Args:
        file_path: 文件路径
        
    Returns:
        data: 加载的数据
    """
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
        return data
    except Exception as e:
        print(f"加载JSON文件时出错: {e}")
        return None


def save_json(data, file_path):
    """
    保存数据为JSON文件
    
    Args:
        data: 要保存的数据
        file_path: 文件路径
    """
    try:
        with open(file_path, 'w', encoding='utf-8') as f:
            json.dump(data, f, ensure_ascii=False, indent=2)
        print(f"数据已保存到: {file_path}")
    except Exception as e:
        print(f"保存JSON文件时出错: {e}")


def setup_logger(name, log_file=None, level=logging.INFO):
    """
    设置日志记录器
    
    Args:
        name: 日志名称
        log_file: 日志文件路径
        level: 日志级别
        
    Returns:
        logger: 日志记录器
    """
    # 创建logger对象
    logger = logging.getLogger(name)
    logger.setLevel(level)
    
    # 避免重复添加处理器
    if logger.handlers:
        return logger
    
    # 创建格式化器
    formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    # 创建控制台处理器
    console_handler = logging.StreamHandler()
    console_handler.setLevel(level)
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)
    
    # 如果指定了日志文件，则创建文件处理器
    if log_file:
        file_handler = logging.FileHandler(log_file, encoding='utf-8')
        file_handler.setLevel(level)
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)
    
    return logger


def http_request_to_dict(http_request):
    """
    将HTTP请求转换为字典
    
    Args:
        http_request: HTTP请求字符串
        
    Returns:
        request_dict: 请求字典，包含method, uri, version, headers, body等字段
    """
    if not http_request:
        return {}
    
    try:
        # 分割请求行、头部和主体
        parts = http_request.split('\r\n\r\n', 1)
        header_section = parts[0]
        body = parts[1] if len(parts) > 1 else ''
        
        # 分割请求行和请求头
        lines = header_section.split('\r\n')
        request_line = lines[0]
        header_lines = lines[1:]
        
        # 解析请求行
        request_parts = request_line.split(' ', 2)
        method = request_parts[0] if len(request_parts) > 0 else ''
        uri = request_parts[1] if len(request_parts) > 1 else ''
        version = request_parts[2] if len(request_parts) > 2 else ''
        
        # 解析请求头
        headers = {}
        for line in header_lines:
            if ':' in line:
                key, value = line.split(':', 1)
                headers[key.strip()] = value.strip()
        
        # 构建请求字典
        request_dict = {
            'method': method,
            'uri': uri,
            'version': version,
            'headers': headers,
            'body': body
        }
        
        return request_dict
    except Exception as e:
        print(f"HTTP请求转字典时出错: {e}")
        return {}


def dict_to_http_request(request_dict):
    """
    将字典转换为HTTP请求
    
    Args:
        request_dict: 请求字典，应包含method, uri, version, headers, body等字段
        
    Returns:
        http_request: HTTP请求字符串
    """
    if not request_dict:
        return ""
    
    try:
        # 获取请求字段
        method = request_dict.get('method', 'GET')
        uri = request_dict.get('uri', '/')
        version = request_dict.get('version', 'HTTP/1.1')
        headers = request_dict.get('headers', {})
        body = request_dict.get('body', '')
        
        # 构建请求行
        request_line = f"{method} {uri} {version}"
        
        # 构建请求头
        header_lines = []
        for key, value in headers.items():
            header_lines.append(f"{key}: {value}")
        
        # 组合HTTP请求
        http_request_parts = [request_line] + header_lines + ['', body]
        http_request = '\r\n'.join(http_request_parts)
        
        return http_request
    except Exception as e:
        print(f"字典转HTTP请求时出错: {e}")
        return ""


def normalize_text(text):
    """
    标准化文本
    
    Args:
        text: 输入文本
        
    Returns:
        normalized_text: 标准化后的文本
    """
    if not text:
        return ""
    
    try:
        # 移除多余的空白字符
        normalized = re.sub(r'\s+', ' ', text)
        # 去除首尾空白字符
        normalized = normalized.strip()
        # 转换为小写
        normalized = normalized.lower()
        return normalized
    except Exception as e:
        print(f"文本标准化时出错: {e}")
        return text


def encode_payload(payload):
    """
    编码Payload
    
    Args:
        payload: 原始payload
        
    Returns:
        encoded_payload: 编码后的payload
    """
    if not payload:
        return ""
    
    try:
        # URL编码
        encoded = quote(payload, safe='')
        return encoded
    except Exception as e:
        print(f"Payload编码时出错: {e}")
        return payload


def decode_payload(encoded_payload):
    """
    解码Payload
    
    Args:
        encoded_payload: 编码的payload
        
    Returns:
        payload: 解码后的payload
    """
    if not encoded_payload:
        return ""
    
    try:
        # URL解码
        decoded = unquote(encoded_payload)
        return decoded
    except Exception as e:
        print(f"Payload解码时出错: {e}")
        return encoded_payload


def main():
    """
    主函数，用于测试工具函数
    """
    # 测试日志功能
    logger = setup_logger("test_logger", "test.log", logging.DEBUG)
    logger.info("这是测试日志")
    
    # 测试HTTP请求转换
    sample_request = (
        "GET /index.html HTTP/1.1\r\n"
        "Host: example.com\r\n"
        "User-Agent: Mozilla/5.0\r\n"
        "\r\n"
    )
    
    request_dict = http_request_to_dict(sample_request)
    print("请求字典:", request_dict)
    
    reconstructed_request = dict_to_http_request(request_dict)
    print("重构的请求:", reconstructed_request)
    
    # 测试文本标准化
    text = "  Hello   World  \n\t "
    normalized = normalize_text(text)
    print(f"标准化文本: '{normalized}'")
    
    # 测试Payload编码解码
    payload = "SELECT * FROM users WHERE id = 1"
    encoded = encode_payload(payload)
    print(f"编码后的Payload: {encoded}")
    
    decoded = decode_payload(encoded)
    print(f"解码后的Payload: {decoded}")


if __name__ == "__main__":
    main()