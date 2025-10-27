#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
依赖分析器
分析WAF规则之间的依赖关系，包括变量依赖、标记依赖和包含依赖
"""

import os
import logging
import networkx as nx
import matplotlib.pyplot as plt
from collections import defaultdict, deque

class DependencyAnalyzer:
    """依赖分析器"""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.dependency_graph = nx.DiGraph()
        self.rule_dependencies = []
        self.include_dependencies = []
        self.marker_dependencies = []
    
    def analyze_dependencies(self, parsed_rules):
        """分析规则依赖关系"""
        try:
            self.logger.info(f"开始分析依赖关系，共 {len(parsed_rules)} 条规则")
            
            # 重置状态
            self.dependency_graph = nx.DiGraph()
            self.rule_dependencies = []
            self.include_dependencies = []
            self.marker_dependencies = []
            
            # 分析各类依赖
            self._analyze_variable_dependencies(parsed_rules)
            self._analyze_marker_dependencies(parsed_rules)
            self._analyze_include_dependencies(parsed_rules)
            
            # 构建依赖图
            self._build_dependency_graph()
            
            self.logger.info("依赖关系分析完成")
            return {
                'variable_dependencies': self.rule_dependencies,
                'marker_dependencies': self.marker_dependencies,
                'include_dependencies': self.include_dependencies,
                'total_dependencies': len(self.rule_dependencies) + len(self.marker_dependencies) + len(self.include_dependencies)
            }
            
        except Exception as e:
            self.logger.error(f"依赖分析失败: {str(e)}", exc_info=True)
            raise
    
    def _analyze_variable_dependencies(self, parsed_rules):
        """分析变量依赖关系"""
        # 记录变量设置和使用
        variable_definitions = defaultdict(list)  # var_name -> [rule_ids]
        variable_usage = defaultdict(list)       # var_name -> [rule_ids]
        
        # 第一遍：收集变量定义和使用
        for rule in parsed_rules:
            if rule.node_type != "SecRule":
                continue
                
            rule.extract_rule_info()
            rule_id = rule.rule_id if rule.rule_id else f"rule_{rule.line_num}"
            
            # 检查动作中的变量设置
            for action in rule.actions:
                if action.startswith('setvar:'):
                    var_part = action[7:]
                    # 提取变量名（支持复杂表达式）
                    if var_part.startswith('TX.'):
                        var_name = var_part.split('=')[0].strip()
                        variable_definitions[var_name].append({
                            'rule_id': rule_id,
                            'line': rule.line_num,
                            'rule': rule
                        })
            
            # 检查条件中的变量使用
            for var in rule.variables:
                if var.startswith('TX:'):
                    var_name = var
                    variable_usage[var_name].append({
                        'rule_id': rule_id,
                        'line': rule.line_num,
                        'rule': rule
                    })
        
        # 第二遍：建立依赖关系
        for var_name, users in variable_usage.items():
            # TX:var -> TX.var
            tx_var_name = var_name.replace('TX:', 'TX.')
            if tx_var_name in variable_definitions:
                for definition in variable_definitions[tx_var_name]:
                    for user in users:
                        # 只建立同阶段内的依赖，或者前阶段到后阶段的依赖
                        def_phase = definition['rule'].phase
                        user_phase = user['rule'].phase
                        
                        if (not def_phase or not user_phase) or (def_phase <= user_phase):
                            dependency = {
                                'type': 'variable_dependency',
                                'source': definition['rule_id'],
                                'target': user['rule_id'],
                                'variable': var_name,
                                'source_line': definition['line'],
                                'target_line': user['line'],
                                'description': f"规则 {definition['rule_id']} 设置变量 {var_name}，规则 {user['rule_id']} 使用该变量"
                            }
                            self.rule_dependencies.append(dependency)
    
    def _analyze_marker_dependencies(self, parsed_rules):
        """分析标记依赖关系"""
        markers = {}  # marker_name -> rule_info
        current_markers = []
        
        for rule in parsed_rules:
            rule.extract_rule_info()
            rule_id = rule.rule_id if rule.rule_id else f"rule_{rule.line_num}"
            
            if rule.node_type == "SecMarker":
                # 提取标记内容
                marker_node = rule.get_child_by_type("MarkerContent")
                if marker_node:
                    marker_name = marker_node.node_value
                    markers[marker_name] = {
                        'rule_id': rule_id,
                        'line': rule.line_num,
                        'rule': rule
                    }
                    current_markers.append(marker_name)
            
            # 检查动作中的skipAfter
            for action in rule.actions:
                if action.startswith('skipAfter:'):
                    marker_name = action[9:]
                    if marker_name in markers:
                        marker_info = markers[marker_name]
                        dependency = {
                            'type': 'marker_dependency',
                            'source': rule_id,
                            'target': marker_info['rule_id'],
                            'marker': marker_name,
                            'source_line': rule.line_num,
                            'target_line': marker_info['line'],
                            'description': f"规则 {rule_id} 使用 skipAfter 跳转到标记 {marker_name}"
                        }
                        self.marker_dependencies.append(dependency)
    
    def _analyze_include_dependencies(self, parsed_rules):
        """分析包含依赖关系"""
        includes = []
        
        for rule in parsed_rules:
            if rule.node_type == "Include":
                include_node = rule.get_child_by_type("IncludePath")
                if include_node:
                    include_path = include_node.node_value
                    dependency = {
                        'type': 'include_dependency',
                        'source': 'main_file',
                        'target': include_path,
                        'line': rule.line_num,
                        'description': f"主文件包含 {include_path}"
                    }
                    self.include_dependencies.append(dependency)
    
    def _build_dependency_graph(self,):
        """构建依赖图"""
        # 添加节点
        all_nodes = set()
        
        # 添加规则节点
        for dep in self.rule_dependencies:
            all_nodes.add(dep['source'])
            all_nodes.add(dep['target'])
        
        # 添加标记节点
        for dep in self.marker_dependencies:
            all_nodes.add(dep['source'])
            all_nodes.add(dep['target'])
        
        # 添加包含节点
        for dep in self.include_dependencies:
            all_nodes.add(dep['source'])
            all_nodes.add(dep['target'])
        
        # 添加节点到图中
        for node in all_nodes:
            self.dependency_graph.add_node(node)
        
        # 添加边
        for dep in self.rule_dependencies:
            self.dependency_graph.add_edge(dep['source'], dep['target'], 
                                         label=dep['variable'], type='variable')
        
        for dep in self.marker_dependencies:
            self.dependency_graph.add_edge(dep['source'], dep['target'], 
                                         label=dep['marker'], type='marker')
        
        for dep in self.include_dependencies:
            self.dependency_graph.add_edge(dep['source'], dep['target'], 
                                         label='include', type='include')
    
    def find_cyclic_dependencies(self):
        """查找循环依赖"""
        try:
            cycles = list(nx.simple_cycles(self.dependency_graph))
            return cycles
        except Exception as e:
            self.logger.error(f"查找循环依赖失败: {str(e)}", exc_info=True)
            return []
    
    def get_dependency_chain(self, rule_id):
        """获取规则的依赖链"""
        if rule_id not in self.dependency_graph:
            return []
        
        # 获取所有前驱节点（依赖的规则）
        predecessors = list(nx.predecessors(self.dependency_graph, rule_id))
        # 获取所有后继节点（被依赖的规则）
        successors = list(nx.successors(self.dependency_graph, rule_id))
        
        return {
            'dependencies': predecessors,
            'dependents': successors
        }
    
    def save_dependency_graph(self, dependencies, output_path):
        """保存依赖关系图"""
        try:
            plt.figure(figsize=(12, 8))
            
            # 创建图形
            G = nx.DiGraph()
            
            # 添加节点和边
            for dep in dependencies['variable_dependencies']:
                G.add_edge(dep['source'], dep['target'], label=dep['variable'][:10] + '...' if len(dep['variable']) > 10 else dep['variable'])
            
            for dep in dependencies['marker_dependencies']:
                G.add_edge(dep['source'], dep['target'], label='marker:' + dep['marker'])
            
            # 设置布局
            pos = nx.spring_layout(G, k=3, iterations=50)
            
            # 绘制节点
            nx.draw_networkx_nodes(G, pos, node_size=1000, node_color='lightblue', alpha=0.8)
            
            # 绘制边
            nx.draw_networkx_edges(G, pos, edgelist=G.edges(), arrows=True, arrowstyle='->', alpha=0.6)
            
            # 绘制标签
            nx.draw_networkx_labels(G, pos, font_size=8)
            
            # 绘制边标签
            edge_labels = nx.get_edge_attributes(G, 'label')
            nx.draw_networkx_edge_labels(G, pos, edge_labels=edge_labels, font_size=6)
            
            plt.title('WAF Rule Dependency Graph', fontsize=16)
            plt.axis('off')
            plt.tight_layout()
            plt.savefig(output_path, dpi=300, bbox_inches='tight')
            plt.close()
            
            self.logger.info(f"依赖关系图已保存到: {output_path}")
            return output_path
            
        except Exception as e:
            self.logger.error(f"保存依赖关系图失败: {str(e)}", exc_info=True)
            raise

def main():
    """测试主函数"""
    import argparse
    from part2_rule_analysis.lib.parser.modsecurity_parser import ModSecurityParser
    
    parser = argparse.ArgumentParser(description='依赖分析器测试')
    parser.add_argument('file', help='ModSecurity规则文件路径')
    
    args = parser.parse_args()
    
    # 设置日志
    logging.basicConfig(level=logging.INFO)
    
    try:
        # 解析规则文件
        parser = ModSecurityParser()
        rules = parser.parse_file(args.file)
        
        if not rules:
            print("没有解析到任何规则")
            return
        
        # 进行依赖分析
        analyzer = DependencyAnalyzer()
        results = analyzer.analyze_dependencies(rules)
        
        # 显示结果
        print(f"\n=== 依赖分析结果 ===")
        print(f"变量依赖: {len(results['variable_dependencies'])}")
        print(f"标记依赖: {len(results['marker_dependencies'])}")
        print(f"包含依赖: {len(results['include_dependencies'])}")
        print(f"总依赖数: {results['total_dependencies']}")
        
        # 检查循环依赖
        cycles = analyzer.find_cyclic_dependencies()
        if cycles:
            print(f"\n发现循环依赖:")
            for cycle in cycles:
                print(f"  {' -> '.join(cycle)}")
        
        # 保存依赖图
        analyzer.save_dependency_graph(results, 'dependency_graph.png')
        print(f"\n依赖关系图已保存到: dependency_graph.png")
        
    except Exception as e:
        print(f"分析失败: {str(e)}")

if __name__ == '__main__':
    main()