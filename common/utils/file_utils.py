#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
文件工具类
提供文件读写、路径处理等功能
"""

import os
import sys
import json
import hashlib
import tempfile
from pathlib import Path
from typing import Union, List, Dict, Any

def read_file_content(file_path: Union[str, Path], encoding: str = 'utf-8') -> str:
    """
    读取文件内容
    """
    try:
        with open(file_path, 'r', encoding=encoding) as f:
            return f.read()
    except UnicodeDecodeError:
        # 尝试其他编码
        try:
            with open(file_path, 'r', encoding='latin-1') as f:
                return f.read()
        except Exception as e:
            raise Exception(f"读取文件失败: {str(e)}")
    except Exception as e:
        raise Exception(f"读取文件失败: {str(e)}")

def write_file_content(file_path: Union[str, Path], content: str, encoding: str = 'utf-8') -> None:
    """
    写入文件内容
    """
    try:
        os.makedirs(os.path.dirname(file_path), exist_ok=True)
        with open(file_path, 'w', encoding=encoding) as f:
            f.write(content)
    except Exception as e:
        raise Exception(f"写入文件失败: {str(e)}")

def read_json_file(file_path: Union[str, Path]) -> Dict[str, Any]:
    """
    读取JSON文件
    """
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            return json.load(f)
    except Exception as e:
        raise Exception(f"读取JSON文件失败: {str(e)}")

def write_json_file(file_path: Union[str, Path], data: Dict[str, Any], indent: int = 2) -> None:
    """
    写入JSON文件
    """
    try:
        os.makedirs(os.path.dirname(file_path), exist_ok=True)
        with open(file_path, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=indent, ensure_ascii=False)
    except Exception as e:
        raise Exception(f"写入JSON文件失败: {str(e)}")

def get_file_hash(file_path: Union[str, Path], algorithm: str = 'md5') -> str:
    """
    获取文件哈希值
    """
    try:
        hash_obj = hashlib.new(algorithm)
        with open(file_path, 'rb') as f:
            while chunk := f.read(4096):
                hash_obj.update(chunk)
        return hash_obj.hexdigest()
    except Exception as e:
        raise Exception(f"计算文件哈希失败: {str(e)}")

def get_file_size(file_path: Union[str, Path]) -> int:
    """
    获取文件大小（字节）
    """
    try:
        return os.path.getsize(file_path)
    except Exception as e:
        raise Exception(f"获取文件大小失败: {str(e)}")

def list_files_in_directory(directory: Union[str, Path], extension: str = None) -> List[str]:
    """
    列出目录中的文件
    """
    try:
        files = []
        for file in os.listdir(directory):
            file_path = os.path.join(directory, file)
            if os.path.isfile(file_path):
                if extension is None or file.endswith(extension):
                    files.append(file_path)
        return files
    except Exception as e:
        raise Exception(f"列出目录文件失败: {str(e)}")

def create_temp_file(content: str = '', suffix: str = '') -> str:
    """
    创建临时文件
    """
    try:
        with tempfile.NamedTemporaryFile(mode='w', suffix=suffix, delete=False, encoding='utf-8') as f:
            if content:
                f.write(content)
            return f.name
    except Exception as e:
        raise Exception(f"创建临时文件失败: {str(e)}")

def delete_file(file_path: Union[str, Path]) -> bool:
    """
    删除文件
    """
    try:
        if os.path.exists(file_path):
            os.remove(file_path)
            return True
        return False
    except Exception as e:
        raise Exception(f"删除文件失败: {str(e)}")

def copy_file(src_path: Union[str, Path], dst_path: Union[str, Path]) -> None:
    """
    复制文件
    """
    try:
        import shutil
        os.makedirs(os.path.dirname(dst_path), exist_ok=True)
        shutil.copy2(src_path, dst_path)
    except Exception as e:
        raise Exception(f"复制文件失败: {str(e)}")

def move_file(src_path: Union[str, Path], dst_path: Union[str, Path]) -> None:
    """
    移动文件
    """
    try:
        import shutil
        os.makedirs(os.path.dirname(dst_path), exist_ok=True)
        shutil.move(src_path, dst_path)
    except Exception as e:
        raise Exception(f"移动文件失败: {str(e)}")

def get_relative_path(base_path: Union[str, Path], target_path: Union[str, Path]) -> str:
    """
    获取相对路径
    """
    try:
        return os.path.relpath(target_path, base_path)
    except Exception as e:
        raise Exception(f"获取相对路径失败: {str(e)}")

def is_file_empty(file_path: Union[str, Path]) -> bool:
    """
    检查文件是否为空
    """
    try:
        return get_file_size(file_path) == 0
    except Exception as e:
        raise Exception(f"检查文件是否为空失败: {str(e)}")

def find_files_by_pattern(directory: Union[str, Path], pattern: str) -> List[str]:
    """
    根据模式查找文件
    """
    try:
        import fnmatch
        matches = []
        for root, dirnames, filenames in os.walk(directory):
            for filename in fnmatch.filter(filenames, pattern):
                matches.append(os.path.join(root, filename))
        return matches
    except Exception as e:
        raise Exception(f"根据模式查找文件失败: {str(e)}")

def replace_in_file(file_path: Union[str, Path], old_str: str, new_str: str) -> int:
    """
    在文件中替换字符串
    """
    try:
        content = read_file_content(file_path)
        new_content = content.replace(old_str, new_str)
        if new_content != content:
            write_file_content(file_path, new_content)
            return content.count(old_str)
        return 0
    except Exception as e:
        raise Exception(f"在文件中替换字符串失败: {str(e)}")

def backup_file(file_path: Union[str, Path], backup_suffix: str = '.bak') -> str:
    """
    备份文件
    """
    try:
        backup_path = f"{file_path}{backup_suffix}"
        copy_file(file_path, backup_path)
        return backup_path
    except Exception as e:
        raise Exception(f"备份文件失败: {str(e)}")

def get_file_modification_time(file_path: Union[str, Path]) -> float:
    """
    获取文件修改时间
    """
    try:
        return os.path.getmtime(file_path)
    except Exception as e:
        raise Exception(f"获取文件修改时间失败: {str(e)}")

def get_file_creation_time(file_path: Union[str, Path]) -> float:
    """
    获取文件创建时间
    """
    try:
        return os.path.getctime(file_path)
    except Exception as e:
        raise Exception(f"获取文件创建时间失败: {str(e)}")

def is_valid_file_path(file_path: Union[str, Path]) -> bool:
    """
    检查文件路径是否有效
    """
    try:
        # 尝试创建目录（如果不存在）
        os.makedirs(os.path.dirname(file_path), exist_ok=True)
        # 检查是否可以写入
        test_path = f"{file_path}.test"
        with open(test_path, 'w') as f:
            f.write('test')
        os.remove(test_path)
        return True
    except Exception as e:
        return False