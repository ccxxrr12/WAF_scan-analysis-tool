#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
AST可视化器
构建和可视化规则的抽象语法树
"""

import os
import logging
import json
import matplotlib.pyplot as plt
import matplotlib.patches as patches
from matplotlib.patches import FancyBboxPatch
import networkx as nx
from networkx.drawing.nx_agraph import graphviz_layout

class ASTVisualizer:
    """AST可视化器"""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.ast_root = None
        self.node_counter = 0
    
    def build_ast(self, parsed_rules):
        """构建AST"""
        try:
            self.logger.info(f"开始构建AST，共 {len(parsed_rules)} 条规则")
            
            # 创建根节点
            self.ast_root = self._create_node("Root", "WAF Rules File", 0, 0)
            
            # 为每条规则创建节点
            for rule in parsed_rules:
                rule_node = self._build_rule_ast(rule)
                self.ast_root.add_child(rule_node)
            
            self.logger.info("AST构建完成")
            return self.ast_root
            
        except Exception as e:
            self.logger.error(f"AST构建失败: {str(e)}", exc_info=True)
            raise
    
    def _build_rule_ast(self, rule):
        """为单条规则构建AST"""
        # 创建规则节点
        rule_node = self._create_node(rule.node_type, 
                                     rule.rule_id or f"Rule {rule.line_num}", 
                                     rule.line_num, rule.col_num)
        
        # 根据规则类型添加不同的子节点
        if rule.node_type == "SecRule":
            self._build_secrule_ast(rule, rule_node)
        elif rule.node_type == "SecAction":
            self._build_secaction_ast(rule, rule_node)
        elif rule.node_type == "SecMarker":
            self._build_secmarker_ast(rule, rule_node)
        elif rule.node_type == "Include":
            self._build_include_ast(rule, rule_node)
        
        return rule_node
    
    def _build_secrule_ast(self, rule, parent_node):
        """构建SecRule的AST"""
        rule.extract_rule_info()
        
        # 添加变量节点
        if rule.variables:
            var_node = self._create_node("Variables", ", ".join(rule.variables), 
                                        rule.line_num, rule.col_num)
            parent_node.add_child(var_node)
        
        # 添加运算符节点
        if rule.operator:
            op_node = self._create_node("Operator", rule.operator, 
                                       rule.line_num, rule.col_num)
            parent_node.add_child(op_node)
        
        # 添加模式节点
        if rule.pattern:
            pattern_display = rule.pattern[:50] + "..." if len(rule.pattern) > 50 else rule.pattern
            pattern_node = self._create_node("Pattern", pattern_display, 
                                           rule.line_num, rule.col_num)
            parent_node.add_child(pattern_node)
        
        # 添加动作节点
        if rule.actions:
            action_node = self._create_node("Actions", f"{len(rule.actions)} actions", 
                                          rule.line_num, rule.col_num)
            parent_node.add_child(action_node)
            
            # 添加具体动作子节点
            for action in rule.actions[:5]:  # 只显示前5个动作
                action_display = action[:30] + "..." if len(action) > 30 else action
                action_child = self._create_node("Action", action_display, 
                                               rule.line_num, rule.col_num)
                action_node.add_child(action_child)
            
            if len(rule.actions) > 5:
                more_node = self._create_node("Action", f"+{len(rule.actions)-5} more", 
                                             rule.line_num, rule.col_num)
                action_node.add_child(more_node)
    
    def _build_secaction_ast(self, rule, parent_node):
        """构建SecAction的AST"""
        rule.extract_rule_info()
        
        # 添加动作节点
        if rule.actions:
            action_node = self._create_node("Actions", f"{len(rule.actions)} actions", 
                                          rule.line_num, rule.col_num)
            parent_node.add_child(action_node)
            
            for action in rule.actions[:5]:
                action_display = action[:30] + "..." if len(action) > 30 else action
                action_child = self._create_node("Action", action_display, 
                                               rule.line_num, rule.col_num)
                action_node.add_child(action_child)
            
            if len(rule.actions) > 5:
                more_node = self._create_node("Action", f"+{len(rule.actions)-5} more", 
                                             rule.line_num, rule.col_num)
                action_node.add_child(more_node)
    
    def _build_secmarker_ast(self, rule, parent_node):
        """构建SecMarker的AST"""
        marker_node = rule.get_child_by_type("MarkerContent")
        if marker_node:
            marker_value = marker_node.node_value
            marker_child = self._create_node("MarkerContent", marker_value, 
                                           rule.line_num, rule.col_num)
            parent_node.add_child(marker_child)
    
    def _build_include_ast(self, rule, parent_node):
        """构建Include的AST"""
        include_node = rule.get_child_by_type("IncludePath")
        if include_node:
            include_path = include_node.node_value
            path_display = include_path[:50] + "..." if len(include_path) > 50 else include_path
            include_child = self._create_node("IncludePath", path_display, 
                                            rule.line_num, rule.col_num)
            parent_node.add_child(include_child)
    
    def _create_node(self, node_type, node_value, line_num, col_num):
        """创建节点"""
        from part2_rule_analysis.lib.parser.rule_node import Node
        node = Node(node_type, node_value, line_num, col_num)
        return node
    
    def save_ast_image(self, ast_root, output_path):
        """保存AST图像"""
        try:
            plt.figure(figsize=(16, 12))
            
            # 创建有向图
            G = nx.DiGraph()
            
            # 递归添加节点和边
            self._add_ast_to_graph(G, ast_root)
            
            # 使用graphviz布局
            pos = graphviz_layout(G, prog='dot')
            
            # 绘制节点
            node_colors = self._get_node_colors(G)
            nx.draw_networkx_nodes(G, pos, node_size=2000, node_color=node_colors, alpha=0.8)
            
            # 绘制边
            nx.draw_networkx_edges(G, pos, edgelist=G.edges(), arrows=True, 
                                  arrowstyle='->', alpha=0.6, width=1.5)
            
            # 绘制标签
            labels = {node: G.nodes[node]['label'] for node in G.nodes()}
            nx.draw_networkx_labels(G, pos, labels=labels, font_size=8, font_weight='bold')
            
            plt.title('WAF Rule Abstract Syntax Tree (AST)', fontsize=20, fontweight='bold', pad=20)
            plt.axis('off')
            plt.tight_layout()
            plt.savefig(output_path, dpi=300, bbox_inches='tight')
            plt.close()
            
            self.logger.info(f"AST图像已保存到: {output_path}")
            return output_path
            
        except Exception as e:
            self.logger.error(f"保存AST图像失败: {str(e)}", exc_info=True)
            raise
    
    def _add_ast_to_graph(self, G, node, parent_id=None, depth=0):
        """递归添加AST节点到图中"""
        node_id = f"{node.node_type}_{id(node)}"
        
        # 创建节点标签
        label = f"{node.node_type}\n{node.node_value}"
        if len(label) > 20:
            label = label[:17] + "..."
        
        # 添加节点
        G.add_node(node_id, label=label, type=node.node_type, depth=depth)
        
        # 添加边
        if parent_id:
            G.add_edge(parent_id, node_id)
        
        # 递归添加子节点
        for child in node.children[:3]:  # 限制子节点数量，避免图像过于复杂
            self._add_ast_to_graph(G, child, node_id, depth + 1)
        
        # 如果有更多子节点，添加一个"更多"节点
        if len(node.children) > 3:
            more_id = f"more_{id(node)}"
            G.add_node(more_id, label=f"+{len(node.children)-3} more", type="more", depth=depth + 1)
            G.add_edge(node_id, more_id)
    
    def _get_node_colors(self, G):
        """获取节点颜色"""
        colors = []
        color_map = {
            'Root': '#2E86AB',
            'SecRule': '#A23B72',
            'SecAction': '#F18F01',
            'SecMarker': '#C73E1D',
            'Include': '#3F88C5',
            'Variables': '#43AA8B',
            'Operator': '#F9844A',
            'Pattern': '#90A959',
            'Actions': '#F9C74F',
            'Action': '#9D8189',
            'MarkerContent': '#D8E2DC',
            'IncludePath': '#FFE5D9',
            'more': '#E5E5E5'
        }
        
        for node in G.nodes():
            node_type = G.nodes[node]['type']
            colors.append(color_map.get(node_type, '#888888'))
        
        return colors
    
    def export_ast_json(self, ast_root, output_path):
        """导出AST为JSON格式"""
        try:
            ast_dict = self._ast_to_dict(ast_root)
            
            with open(output_path, 'w', encoding='utf-8') as f:
                json.dump(ast_dict, f, indent=2, ensure_ascii=False)
            
            self.logger.info(f"AST JSON已保存到: {output_path}")
            return output_path
            
        except Exception as e:
            self.logger.error(f"导出AST JSON失败: {str(e)}", exc_info=True)
            raise
    
    def _ast_to_dict(self, node):
        """将AST转换为字典"""
        node_dict = {
            'type': node.node_type,
            'value': node.node_value,
            'line': node.line_num,
            'col': node.col_num,
            'children': []
        }
        
        for child in node.children:
            node_dict['children'].append(self._ast_to_dict(child))
        
        return node_dict
    
    def create_interactive_ast(self, ast_root, output_path):
        """创建交互式AST可视化HTML"""
        try:
            # 转换AST为字典
            ast_dict = self._ast_to_dict(ast_root)
            
            # 创建HTML内容
            html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Interactive WAF Rule AST</title>
    <script src="https:#cdn.tailwindcss.com"></script>
    <link href="https:#cdnjs.cloudflare.com/ajax/libs/font-awesome/6.7.2/css/all.min.css" rel="stylesheet">
    <script src="https:#cdn.jsdelivr.net/npm/d3@7"></script>
    
    <script>
        const astData = {json.dumps(ast_dict, indent=2)};
        
        # 颜色映射
        const colorMap = {{
            'Root': '#2E86AB',
            'SecRule': '#A23B72',
            'SecAction': '#F18F01',
            'SecMarker': '#C73E1D',
            'Include': '#3F88C5',
            'Variables': '#43AA8B',
            'Operator': '#F9844A',
            'Pattern': '#90A959',
            'Actions': '#F9C74F',
            'Action': '#9D8189',
            'MarkerContent': '#D8E2DC',
            'IncludePath': '#FFE5D9'
        }};
        
        document.addEventListener('DOMContentLoaded', function() {{
            createTreeVisualization();
        }});
        
        function createTreeVisualization() {{
            const width = window.innerWidth - 40;
            const height = window.innerHeight - 200;
            
            const svg = d3.select('#ast-container')
                .append('svg')
                .attr('width', width)
                .attr('height', height);
            
            const g = svg.append('g')
                .attr('transform', `translate(${{width/2}}, 50)`);
            
            # 创建树布局
            const tree = d3.tree()
                .size([2 * Math.PI, Math.min(width, height) / 2 - 120])
                .separation((a, b) => (a.parent == b.parent ? 1 : 2) / a.depth);
            
            # 转换数据为层次结构
            const root = d3.hierarchy(astData);
            
            # 计算节点位置
            const nodes = tree(root);
            const links = nodes.links();
            
            # 创建连接线
            const link = g.selectAll('.link')
                .data(links)
                .enter().append('path')
                .attr('class', 'link')
                .attr('d', d3.linkRadial()
                    .angle(d => d.x)
                    .radius(d => d.y))
                .style('fill', 'none')
                .style('stroke', '#ccc')
                .style('stroke-width', 2);
            
            # 创建节点
            const node = g.selectAll('.node')
                .data(nodes)
                .enter().append('g')
                .attr('class', 'node')
                .attr('transform', d => `
                    rotate(${{d.x * 180 / Math.PI - 90}})
                    translate(${{d.y}},0)
                `)
                .on('click', toggleNode);
            
            # 添加节点圆圈
            node.append('circle')
                .attr('r', 15)
                .style('fill', d => colorMap[d.data.type] || '#888888')
                .style('stroke', '#fff')
                .style('stroke-width', 2)
                .style('cursor', 'pointer');
            
            # 添加节点标签
            node.append('text')
                .attr('dy', '.31em')
                .attr('text-anchor', d => d.x < Math.PI ? 'start' : 'end')
                .attr('transform', d => d.x < Math.PI ? 'translate(20)' : 'rotate(180) translate(-20)')
                .style('font-size', '12px')
                .style('font-weight', 'bold')
                .style('fill', '#333')
                .text(d => {{
                    let label = d.data.type;
                    if (d.data.value && d.data.value.length > 10) {{
                        label += '\\n' + d.data.value.substring(0, 10) + '...';
                    }} else if (d.data.value) {{
                        label += '\\n' + d.data.value;
                    }}
                    return label;
                }});
        }}
        
        function toggleNode(event, d) {{
            if (d.children) {{
                d._children = d.children;
                d.children = null;
            }} else {{
                d.children = d._children;
                d._children = null;
            }}
            
            # 重新绘制
            d3.select('#ast-container').select('svg').remove();
            createTreeVisualization();
            
            # 显示节点信息
            showNodeInfo(d.data);
        }}
        
        function showNodeInfo(nodeData) {{
            const infoPanel = document.getElementById('node-info');
            let infoHtml = `
                <div class="bg-white rounded-lg shadow-md p-4">
                    <h3 class="text-lg font-bold text-gray-800 mb-2">
                        <i class="fas fa-info-circle mr-2"></i>Node Information
                    </h3>
                    <div class="space-y-2 text-sm">
                        <div><span class="font-semibold">Type:</span> {{nodeData.type}}</div>
                        <div><span class="font-semibold">Value:</span> {{nodeData.value || 'N/A'}}</div>
                        <div><span class="font-semibold">Position:</span> Line {{nodeData.line}}, Column {{nodeData.col}}</div>
                        <div><span class="font-semibold">Children:</span> {{nodeData.children.length}}</div>
                    </div>
                </div>
            `;
            
            # 格式化值显示
            if (nodeData.value && nodeData.value.length > 50) {{
                nodeData.value = nodeData.value.substring(0, 50) + '...';
            }}
            
            infoPanel.innerHTML = infoHtml.replace(/{{nodeData\\.(\\w+)}}/g, (match, prop) => {{
                return nodeData[prop] !== undefined ? nodeData[prop] : 'N/A';
            }});
        }}
    </script>
</head>
<body class="bg-gray-50 min-h-screen">
    <div class="container mx-auto px-4 py-8">
        <h1 class="text-3xl font-bold text-gray-800 mb-6 text-center">
            <i class="fas fa-sitemap mr-3"></i>WAF Rule Abstract Syntax Tree
        </h1>
        
        <div class="grid grid-cols-1 lg:grid-cols-4 gap-6">
            <div class="lg:col-span-3">
                <div id="ast-container" class="bg-white rounded-lg shadow-lg p-4">
                    <!-- SVG will be rendered here -->
                </div>
            </div>
            
            <div class="lg:col-span-1">
                <div id="node-info" class="bg-white rounded-lg shadow-lg p-4">
                    <div class="text-center text-gray-500 py-8">
                        <i class="fas fa-hand-pointer text-4xl mb-2"></i>
                        <p>Click on a node to see details</p>
                    </div>
                </div>
            </div>
        </div>
    </div>
</body>
</html>"""
            
            with open(output_path, 'w', encoding='utf-8') as f:
                f.write(html_content)
            
            self.logger.info(f"交互式AST可视化已保存到: {output_path}")
            return output_path
            
        except Exception as e:
            self.logger.error(f"创建交互式AST失败: {str(e)}", exc_info=True)
            raise

def main():
    """测试主函数"""
    import argparse
    from part2_rule_analysis.lib.parser.modsecurity_parser import ModSecurityParser
    
    parser = argparse.ArgumentParser(description='AST可视化器测试')
    parser.add_argument('file', help='ModSecurity规则文件路径')
    parser.add_argument('-o', '--output', help='输出目录', default='./ast_output')
    
    args = parser.parse_args()
    
    # 设置日志
    logging.basicConfig(level=logging.INFO)
    
    try:
        # 创建输出目录
        os.makedirs(args.output, exist_ok=True)
        
        # 解析规则文件
        parser = ModSecurityParser()
        rules = parser.parse_file(args.file)
        
        if not rules:
            print("没有解析到任何规则")
            return
        
        # 构建和可视化AST
        visualizer = ASTVisualizer()
        ast_root = visualizer.build_ast(rules)
        
        # 保存图像
        img_path = os.path.join(args.output, 'ast.png')
        visualizer.save_ast_image(ast_root, img_path)
        
        # 保存JSON
        json_path = os.path.join(args.output, 'ast.json')
        visualizer.export_ast_json(ast_root, json_path)
        
        # 创建交互式HTML
        html_path = os.path.join(args.output, 'interactive_ast.html')
        visualizer.create_interactive_ast(ast_root, html_path)
        
        print(f"\n=== AST可视化完成 ===")
        print(f"AST图像: {img_path}")
        print(f"AST JSON: {json_path}")
        print(f"交互式AST: {html_path}")
        
    except Exception as e:
        print(f"可视化失败: {str(e)}")

if __name__ == '__main__':
    main()