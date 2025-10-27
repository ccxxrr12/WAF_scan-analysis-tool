#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
日志工具类
提供统一的日志配置和管理功能
"""

import logging
import logging.config
import os
import sys
from datetime import datetime
from pathlib import Path
from logging.handlers import RotatingFileHandler

class LogUtils:
    """日志工具类"""
    
    @staticmethod
    def create_default_config(log_dir: str = None, log_level: str = 'INFO') -> dict:
        """
        创建默认的日志配置
        
        Args:
            log_dir: 日志目录
            log_level: 日志级别
        
        Returns:
            日志配置字典
        """
        if log_dir is None:
            log_dir = Path(__file__).parent.parent.parent / 'logs'
        
        os.makedirs(log_dir, exist_ok=True)
        
        # 日志文件名
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        log_file = f"waf_analysis_{timestamp}.log"
        log_path = os.path.join(log_dir, log_file)
        
        # 日志级别映射
        level_map = {
            'DEBUG': logging.DEBUG,
            'INFO': logging.INFO,
            'WARNING': logging.WARNING,
            'ERROR': logging.ERROR,
            'CRITICAL': logging.CRITICAL
        }
        
        return {
            'version': 1,
            'disable_existing_loggers': False,
            'formatters': {
                'console': {
                    'format': '%(asctime)s [%(levelname)s] %(name)s: %(message)s',
                    'datefmt': '%Y-%m-%d %H:%M:%S'
                },
                'file': {
                    'format': '%(asctime)s [%(levelname)s] %(name)s [%(filename)s:%(lineno)d]: %(message)s',
                    'datefmt': '%Y-%m-%d %H:%M:%S'
                }
            },
            'handlers': {
                'console': {
                    'class': 'logging.StreamHandler',
                    'formatter': 'console',
                    'level': level_map.get(log_level, logging.INFO),
                    'stream': sys.stdout
                },
                'file': {
                    'class': 'logging.handlers.RotatingFileHandler',
                    'formatter': 'file',
                    'level': level_map.get(log_level, logging.INFO),
                    'filename': log_path,
                    'maxBytes': 10485760,  # 10MB
                    'backupCount': 10,
                    'encoding': 'utf-8'
                }
            },
            'loggers': {
                '': {
                    'handlers': ['console', 'file'],
                    'level': level_map.get(log_level, logging.INFO),
                    'propagate': True
                }
            }
        }
    
    @staticmethod
    def setup_logger(name: str = None, config: dict = None, log_dir: str = None, log_level: str = 'INFO') -> logging.Logger:
        """
        设置日志配置
        
        Args:
            name: 日志器名称
            config: 日志配置字典
            log_dir: 日志目录
            log_level: 日志级别
        
        Returns:
            配置好的日志器
        """
        if config is None:
            config = LogUtils.create_default_config(log_dir, log_level)
        
        logging.config.dictConfig(config)
        
        if name:
            return logging.getLogger(name)
        else:
            return logging.getLogger()
    
    @staticmethod
    def get_logger(name: str = None) -> logging.Logger:
        """
        获取日志器
        
        Args:
            name: 日志器名称
        
        Returns:
            日志器实例
        """
        return logging.getLogger(name)

# 全局日志器
def setup_logger(name: str = None, config: dict = None, log_dir: str = None, log_level: str = 'INFO') -> logging.Logger:
    """
    全局日志设置函数
    
    Args:
        name: 日志器名称
        config: 日志配置字典
        log_dir: 日志目录
        log_level: 日志级别
    
    Returns:
        配置好的日志器
    """
    return LogUtils.setup_logger(name, config, log_dir, log_level)

def get_logger(name: str = None) -> logging.Logger:
    """
    获取全局日志器
    
    Args:
        name: 日志器名称
    
    Returns:
        日志器实例
    """
    return LogUtils.get_logger(name)

# 默认日志器
logger = setup_logger('WAFDefaultLogger')