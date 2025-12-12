#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
AST可视化器
构建和可视化规则的抽象语法树
"""

import os
import logging
import json
import networkx as nx
import html
try:
    from pyvis.network import Network
except Exception:
    Network = None

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
            # 使用 networkx 构建图，然后用 pyvis 导出为交互式 HTML
            if Network is None:
                raise RuntimeError('pyvis 未安装，请安装 pyvis (pip install pyvis) 以生成交互式可视化')

            # 创建有向图
            G = nx.DiGraph()
            # 递归添加节点和边（会在 G 的节点属性中保留 label/type）
            self._add_ast_to_graph(G, ast_root)

            # 创建 pyvis Network
            # 关闭物理模拟以加快渲染并稳定布局（交互仍然可用）
            net = Network(height='800px', width='100%', directed=True, notebook=False)
            try:
                net.toggle_physics(False)
            except Exception:
                # 如果 toggle_physics 不可用，忽略
                pass

            # 添加节点到 pyvis（保留 label, type, title）
            for node in G.nodes():
                ndata = G.nodes[node]
                label = ndata.get('label', str(node))
                ntype = ndata.get('type', '')
                # 构建丰富的 HTML tooltip（title）
                full_value = ndata.get('full_value', '')
                line = ndata.get('line', '')
                col = ndata.get('col', '')
                children_vals = ndata.get('children_values', []) or []

                # 安全转义
                esc_type = html.escape(str(ntype))
                esc_value = html.escape(str(full_value))
                esc_line = html.escape(str(line))
                esc_col = html.escape(str(col))

                children_html = ''
                if children_vals:
                    # 限制展示数量
                    max_show = 10
                    show_list = [html.escape(str(v)) for v in children_vals[:max_show]]
                    children_html = '<br>'.join(show_list)
                    if len(children_vals) > max_show:
                        children_html += f"<br>+{len(children_vals)-max_show} more..."

                title = f"<div style=\"max-width:300px;word-wrap:break-word;\">"
                title += f"<b>Type:</b> {esc_type}<br>"
                title += f"<b>Value:</b> {esc_value}<br>"
                title += f"<b>Position:</b> Line {esc_line}, Col {esc_col}<br>"
                if children_html:
                    title += f"<b>Children:</b><br>{children_html}<br>"
                title += "</div>"

                color = self._get_color_for_type(ntype)
                # pyvis 接受任意 hashable id
                net.add_node(node, label=label, title=title, color=color)

            # 添加边
            for src, dst in G.edges():
                net.add_edge(src, dst)

            # 保存为 HTML
            # 如果用户传入的是非 html 扩展名，强制转换为 .html
            out_path = output_path
            if not out_path.lower().endswith('.html'):
                out_path = output_path + '.html'

            # 直接生成 HTML 字符串并写入目标路径，避免 pyvis 的 write_html 对路径的限制
            # 生成 HTML 时使用 CDN 资源（local=False），避免 pyvis 复制本地 lib 目录并出现 /lib/* 404 问题
            # 将 name 设为文件名，以便模板内部校验通过
            html_content = net.generate_html(name=os.path.basename(out_path), local=False)

            # 确保目录存在
            os.makedirs(os.path.dirname(out_path), exist_ok=True)
            with open(out_path, 'w', encoding='utf-8') as f:
                                # 在 pyvis 生成的 HTML 末尾追加父子页面通信脚本：
                                # - 在加载完成后向父窗口发送页面高度
                                # - 在节点被点击时将节点信息 postMessage 给父窗口
                                # - 监听父窗口发来的高亮/选择请求
                                # 改进的通信脚本：
                                # - 在首次稳定时发送 'pyvis_ready' 和高度
                                # - 对高度发送做去抖/节流，只有在高度变化较大时才发送，避免和父窗口形成无限调整循环
                                # - 标记 source='ast'，以便父窗口区分不同可视化
                                comm_script = """
                        <script>
                            (function(){
                                var lastSentHeight = 0;
                                var sendTimer = null;
                                var maxHeight = 8000; // 限制单页最大高度，避免无限膨胀

                                function safePost(msg){
                                    try{ window.parent.postMessage(msg, '*'); }catch(e){}
                                }

                                function postHeightDebounced(){
                                    if(sendTimer) return;
                                    sendTimer = setTimeout(function(){
                                        sendTimer = null;
                                        try{
                                            var h = Math.min(document.body.scrollHeight || 0, maxHeight);
                                            // 只有当高度变化超过阈值时才发送
                                            if(Math.abs(h - lastSentHeight) > 30){
                                                lastSentHeight = h;
                                                safePost({type: 'pyvis_height', height: h, source: 'ast'});
                                            }
                                        }catch(e){}
                                    }, 300);
                                }

                                // 发送 ready 事件，通知父窗口 iframe 已准备好
                                function postReady(){
                                    safePost({type: 'pyvis_ready', source: 'ast'});
                                    postHeightDebounced();
                                    // 再次发送以覆盖可能的延迟布局
                                    setTimeout(postHeightDebounced, 700);
                                    setTimeout(postHeightDebounced, 1500);
                                }

                                window.addEventListener('load', function(){
                                    try{ postReady(); }catch(e){}
                                });

                                // 在内部布局/尺寸变化时节流发送高度
                                var resizeObserver = null;
                                try{
                                    if(window.ResizeObserver){
                                        resizeObserver = new ResizeObserver(function(){ postHeightDebounced(); });
                                        resizeObserver.observe(document.body);
                                    } else {
                                        window.addEventListener('resize', postHeightDebounced);
                                    }
                                }catch(e){ window.addEventListener('resize', postHeightDebounced); }

                                // wait for network variable from pyvis and attach click handler
                                function attachClick(){
                                    try{
                                        if(typeof network !== 'undefined' && typeof nodes !== 'undefined'){
                                            // notify parent that network is available
                                            try{ safePost({type: 'pyvis_ready', source: 'ast'}); }catch(e){}

                                            network.on('click', function(params){
                                                try{
                                                    if(params.nodes && params.nodes.length > 0){
                                                        var nodeId = params.nodes[0];
                                                        var nodeData = null;
                                                        try{ nodeData = nodes.find(function(n){ return n.id == nodeId; }) || {id: nodeId}; }catch(e){ nodeData = {id: nodeId}; }
                                                        safePost({type:'pyvis_node_click', node: nodeData, source: 'ast'});
                                                        // 在节点点击后可能会触发展开/详情，稍后再测量高度并发送
                                                        setTimeout(postHeightDebounced, 300);
                                                    }
                                                }catch(e){ }
                                            });
                                        } else {
                                            setTimeout(attachClick, 200);
                                        }
                                    }catch(e){ setTimeout(attachClick, 200); }
                                }
                                attachClick();

                                // 监听父窗口消息（高亮等）
                                window.addEventListener('message', function(event){
                                    try{
                                        var data = event.data || {};
                                        if(data && data.type === 'pyvis_highlight' && typeof network !== 'undefined'){
                                            try{ network.selectNodes([data.nodeId]); }catch(e){}
                                        }
                                    }catch(e){}
                                });
                            })();
                        </script>
                        """

                                f.write(html_content)
                                f.write(comm_script)

            self.logger.info(f"AST交互式可视化已保存到: {out_path}")
            return out_path
            
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

        # 准备子节点值列表（用于 tooltip）
        children_values = [child.node_value for child in node.children]

        # 添加节点（保存短 label 及完整字段）
        G.add_node(node_id, label=label, type=node.node_type, depth=depth,
                   full_value=node.node_value, line=node.line_num, col=node.col_num,
                   children_values=children_values)
        
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

    def _get_color_for_type(self, node_type):
        """根据节点类型返回颜色"""
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
        return color_map.get(node_type, '#888888')

    def _ast_to_dict(self, node):
        """将AST节点递归转为字典（供导出或调用）"""
        node_dict = {
            'type': getattr(node, 'node_type', None),
            'value': getattr(node, 'node_value', None),
            'line': getattr(node, 'line_num', None),
            'col': getattr(node, 'col_num', None),
            'children': []
        }

        for child in getattr(node, 'children', []) or []:
            node_dict['children'].append(self._ast_to_dict(child))

        return node_dict
    
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

    def create_interactive_ast(self, ast_root, output_path):
        """创建交互式AST可视化HTML（使用 pyvis）"""
        try:
            return self.save_ast_image(ast_root, output_path)
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