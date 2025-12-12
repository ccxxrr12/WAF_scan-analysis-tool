import os
import logging
import json
import html
import networkx as nx
try:
    from pyvis.network import Network
except Exception:
    Network = None

logger = logging.getLogger(__name__)

# PyVis 依赖说明
_PYVIS_DEPENDENCY_NOTE = """
# PyVis 依赖说明

## 安装指南

### Python 依赖
```bash
pip install pyvis networkx
```

## 常见问题

**错误**: ModuleNotFoundError: No module named 'pyvis'
**解决**: 运行 `pip install pyvis networkx` 安装依赖

**错误**: JavaScript 相关错误
**解决**: 确保使用的浏览器支持现代 JavaScript
"""

class ASTVisualizer:
    """AST可视化器"""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.node_counter = 0
    
    def get_pyvis_dependency_note(self):
        """获取PyVis依赖说明"""
        return _PYVIS_DEPENDENCY_NOTE
    
    def build_ast(self, rule):
        """构建AST"""
        try:
            self.logger.info(f"开始构建AST")
            
            # 创建根节点
            ast_root = Node("Root", "ModSecurity Rule", 0, 0)
            
            # 为规则创建AST节点
            rule_node = self._build_rule_ast(rule)
            ast_root.add_child(rule_node)
            
            self.logger.info("AST构建完成")
            return ast_root
            
        except Exception as e:
            self.logger.error(f"AST构建失败: {str(e)}", exc_info=True)
            raise
    
    def _build_rule_ast(self, rule):
        """为单条规则构建AST"""
        # 创建规则节点
        rule_type = rule.get('type', 'Unknown')
        rule_id = rule.get('rule_info', {}).get('id', 'Unknown')
        rule_node = Node(rule_type, rule_id, 0, 0)
        
        # 添加规则信息
        rule_info = rule.get('rule_info', {})
        
        # 添加变量节点
        variables = rule_info.get('variables', [])
        if variables:
            var_node = Node("Variables", ", ".join(variables), 0, 0)
            rule_node.add_child(var_node)
        
        # 添加操作符节点
        operator = rule_info.get('operator', '')
        if operator:
            op_node = Node("Operator", operator, 0, 0)
            rule_node.add_child(op_node)
        
        # 添加模式节点
        pattern = rule_info.get('pattern', '')
        if pattern:
            pattern_display = pattern[:50] + "..." if len(pattern) > 50 else pattern
            pattern_node = Node("Pattern", pattern_display, 0, 0)
            rule_node.add_child(pattern_node)
        
        # 添加动作节点
        actions = rule_info.get('actions', [])
        if actions:
            action_node = Node("Actions", f"{len(actions)} actions", 0, 0)
            rule_node.add_child(action_node)
            
            # 添加具体动作
            for i, action in enumerate(actions[:5]):  # 只显示前5个动作
                action_display = action[:30] + "..." if len(action) > 30 else action
                action_child = Node("Action", action_display, 0, 0)
                action_node.add_child(action_child)
            
            if len(actions) > 5:
                more_node = Node("Action", f"+{len(actions)-5} more", 0, 0)
                action_node.add_child(more_node)
        
        return rule_node
    
    def save_ast_file(self, rule, output_path):
        """保存AST图像"""
        try:
            if Network is None:
                raise RuntimeError('pyvis 未安装，请安装 pyvis (pip install pyvis) 以生成交互式可视化')

            # 构建AST
            ast_root = self.build_ast(rule)
            
            # 创建有向图
            G = nx.DiGraph()
            # 递归添加节点和边
            self._add_ast_to_graph(G, ast_root)

            # 创建 pyvis Network
            net = Network(height='800px', width='100%', directed=True, notebook=False)
            try:
                net.toggle_physics(False)
            except Exception:
                pass

            # 添加节点到 pyvis
            for node in G.nodes():
                ndata = G.nodes[node]
                label = ndata.get('label', str(node))
                ntype = ndata.get('type', '')
                
                # 构建丰富的 HTML tooltip
                full_value = ndata.get('full_value', '')
                children_vals = ndata.get('children_values', []) or []

                # 安全转义
                esc_type = html.escape(str(ntype))
                esc_value = html.escape(str(full_value))

                children_html = ''
                if children_vals:
                    max_show = 10
                    show_list = [html.escape(str(v)) for v in children_vals[:max_show]]
                    children_html = '<br>'.join(show_list)
                    if len(children_vals) > max_show:
                        children_html += f"<br>+{len(children_vals)-max_show} more..."

                title = f"<div style=\"max-width:300px;word-wrap:break-word;\">"
                title += f"<b>Type:</b> {esc_type}<br>"
                title += f"<b>Value:</b> {esc_value}<br>"
                if children_html:
                    title += f"<b>Children:</b><br>{children_html}<br>"
                title += "</div>"

                color = self._get_color_for_type(ntype)
                net.add_node(node, label=label, title=title, color=color)

            # 添加边
            for src, dst in G.edges():
                net.add_edge(src, dst)

            # 保存为 HTML
            # 如果用户传入的是非 html 扩展名，强制转换为 .html
            out_path = output_path
            if not out_path.lower().endswith('.html'):
                out_path = output_path + '.html'

            # 生成 HTML
            html_content = net.generate_html(name=os.path.basename(out_path), local=False)
            
            # 添加通信脚本
            comm_script = """
            <script>
                (function(){
                    var lastSentHeight = 0;
                    var sendTimer = null;
                    var maxHeight = 8000;

                    function safePost(msg){
                        try{ window.parent.postMessage(msg, '*'); }catch(e){}
                    }

                    function postHeightDebounced(){
                        if(sendTimer) return;
                        sendTimer = setTimeout(function(){
                            sendTimer = null;
                            try{
                                var h = Math.min(document.body.scrollHeight || 0, maxHeight);
                                if(Math.abs(h - lastSentHeight) > 30){
                                    lastSentHeight = h;
                                    safePost({type: 'pyvis_height', height: h, source: 'ast'});
                                }
                            }catch(e){}
                        }, 300);
                    }

                    function postReady(){
                        safePost({type: 'pyvis_ready', source: 'ast'});
                        postHeightDebounced();
                        setTimeout(postHeightDebounced, 700);
                        setTimeout(postHeightDebounced, 1500);
                    }

                    window.addEventListener('load', function(){
                        try{ postReady(); }catch(e){}
                    });

                    var resizeObserver = null;
                    try{
                        if(window.ResizeObserver){
                            resizeObserver = new ResizeObserver(function(){ postHeightDebounced(); });
                            resizeObserver.observe(document.body);
                        } else {
                            window.addEventListener('resize', postHeightDebounced);
                        }
                    }catch(e){ window.addEventListener('resize', postHeightDebounced); }

                    function attachClick(){
                        try{
                            if(typeof network !== 'undefined' && typeof nodes !== 'undefined'){
                                try{ safePost({type: 'pyvis_ready', source: 'ast'}); }catch(e){}

                                network.on('click', function(params){
                                    try{
                                        if(params.nodes && params.nodes.length > 0){
                                            var nodeId = params.nodes[0];
                                            var nodeData = null;
                                            try{ nodeData = nodes.find(function(n){ return n.id == nodeId; }) || {id: nodeId}; }catch(e){ nodeData = {id: nodeId}; }
                                            safePost({type:'pyvis_node_click', node: nodeData, source: 'ast'});
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

            with open(out_path, 'w', encoding='utf-8') as f:
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

        # 准备子节点值列表
        children_values = [child.node_value for child in node.children]

        # 添加节点
        G.add_node(node_id, label=label, type=node.node_type, depth=depth,
                   full_value=node.node_value, line=node.line_num, col=node.col_num,
                   children_values=children_values)
        
        # 添加边
        if parent_id:
            G.add_edge(parent_id, node_id)
        
        # 递归添加子节点
        for child in node.children[:3]:  # 限制子节点数量
            self._add_ast_to_graph(G, child, node_id, depth + 1)
        
        # 如果有更多子节点，添加一个"更多"节点
        if len(node.children) > 3:
            more_id = f"more_{id(node)}"
            G.add_node(more_id, label=f"+{len(node.children)-3} more", type="more", depth=depth + 1)
            G.add_edge(node_id, more_id)
    
    def _get_color_for_type(self, node_type):
        """根据节点类型返回颜色"""
        color_map = {
            'Root': '#2E86AB',
            'T_CONFIG_DIRECTIVE_SECRULE': '#A23B72',
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
            'more': '#E5E5E5',
            'Unknown': '#888888'
        }
        return color_map.get(node_type, '#888888')
    
    def export_ast_json(self, rule, output_path):
        """导出AST为JSON格式"""
        try:
            # 构建AST
            ast_root = self.build_ast(rule)
            ast_dict = self._ast_to_dict(ast_root)
            
            with open(output_path, 'w', encoding='utf-8') as f:
                json.dump(ast_dict, f, indent=2, ensure_ascii=False)
            
            self.logger.info(f"AST JSON已保存到: {output_path}")
            return output_path
        
        except Exception as e:
            self.logger.error(f"导出AST JSON失败: {str(e)}", exc_info=True)
            raise
    
    def _ast_to_dict(self, node):
        """将AST节点递归转为字典"""
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

# 辅助节点类
class Node:
    """AST节点类"""
    def __init__(self, node_type, node_value, line_num, col_num):
        self.node_type = node_type
        self.node_value = node_value
        self.line_num = line_num
        self.col_num = col_num
        self.children = []
    
    def add_child(self, child):
        """添加子节点"""
        self.children.append(child)
    
    def get_child_by_type(self, node_type):
        """根据类型获取子节点"""
        for child in self.children:
            if child.node_type == node_type:
                return child
        return None

class DependencyVisualizer:
    """依赖关系可视化工具"""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
    
    def save_dependency_file(self, rule, output_path, show_full_details=True):
        """保存依赖关系可视化到文件"""
        try:
            if Network is None:
                raise RuntimeError('pyvis 未安装，请安装 pyvis (pip install pyvis) 以生成交互式可视化')

            # 创建有向图
            G = nx.DiGraph()
            
            # 获取规则信息
            rule_info = rule.get('rule_info', {})
            rule_id = rule_info.get('id', 'unknown')
            message = rule_info.get('message', '')
            
            # 规则节点标签
            rule_label = f"Rule {rule_id}"
            if show_full_details and message:
                rule_label = f"Rule {rule_id}\n{message[:50]}{'...' if len(message) > 50 else ''}"
            
            # 添加规则节点
            rule_node_id = f'rule_{rule_id}'
            G.add_node(rule_node_id, label=rule_label, type='Rule', full_value=rule_label, children_values=[])
            
            # 添加依赖分析
            dependency_analysis = rule.get('dependency_analysis', {})
            
            # 添加变量依赖
            variable_dependencies = dependency_analysis.get('variable_dependencies', [])
            if variable_dependencies:
                var_group_id = f'var_group_{rule_id}'
                G.add_node(var_group_id, label='Variable Dependencies', type='VariableDependencies', full_value='Variable Dependencies', children_values=variable_dependencies)
                G.add_edge(rule_node_id, var_group_id)
                
                for var_dep in variable_dependencies:
                    var_id = f'var_{rule_id}_{hash(var_dep)}'
                    G.add_node(var_id, label=f'Variable: {var_dep}', type='Variable', full_value=var_dep, children_values=[])
                    G.add_edge(var_group_id, var_id, label='uses')
            
            # 添加标记依赖
            marker_dependencies = dependency_analysis.get('marker_dependencies', [])
            if marker_dependencies:
                marker_group_id = f'marker_group_{rule_id}'
                G.add_node(marker_group_id, label='Marker Dependencies', type='MarkerDependencies', full_value='Marker Dependencies', children_values=marker_dependencies)
                G.add_edge(rule_node_id, marker_group_id)
                
                for marker_dep in marker_dependencies:
                    marker_id = f'marker_{rule_id}_{hash(marker_dep)}'
                    G.add_node(marker_id, label=f'Marker: {marker_dep}', type='Marker', full_value=marker_dep, children_values=[])
                    G.add_edge(marker_group_id, marker_id, label='relies on')
            
            # 添加包含依赖
            include_dependencies = dependency_analysis.get('include_dependencies', [])
            if include_dependencies:
                include_group_id = f'include_group_{rule_id}'
                G.add_node(include_group_id, label='Include Dependencies', type='IncludeDependencies', full_value='Include Dependencies', children_values=include_dependencies)
                G.add_edge(rule_node_id, include_group_id)
                
                for include_dep in include_dependencies:
                    include_id = f'include_{rule_id}_{hash(include_dep)}'
                    G.add_node(include_id, label=f'Include: {include_dep}', type='Include', full_value=include_dep, children_values=[])
                    G.add_edge(include_group_id, include_id, label='includes')
            
            # 创建 pyvis Network
            net = Network(height='800px', width='100%', directed=True, notebook=False)
            try:
                net.toggle_physics(False)
            except Exception:
                pass
            
            # 添加节点到 pyvis
            for node in G.nodes():
                ndata = G.nodes[node]
                label = ndata.get('label', str(node))
                ntype = ndata.get('type', '')
                
                # 构建tooltip
                full_value = ndata.get('full_value', '')
                children_vals = ndata.get('children_values', []) or []
                
                esc_type = html.escape(str(ntype))
                esc_value = html.escape(str(full_value))
                
                children_html = ''
                if children_vals:
                    max_show = 10
                    show_list = [html.escape(str(v)) for v in children_vals[:max_show]]
                    children_html = '<br>'.join(show_list)
                    if len(children_vals) > max_show:
                        children_html += f"<br>+{len(children_vals)-max_show} more..."
                
                title = f"<div style=\"max-width:300px;word-wrap:break-word;\">"
                title += f"<b>Type:</b> {esc_type}<br>"
                title += f"<b>Value:</b> {esc_value}<br>"
                if children_html:
                    title += f"<b>Children:</b><br>{children_html}<br>"
                title += "</div>"
                
                # 根据节点类型设置颜色
                color_map = {
                    'Rule': '#2E86AB',
                    'VariableDependencies': '#43AA8B',
                    'Variable': '#70C1B3',
                    'MarkerDependencies': '#F3FFBD',
                    'Marker': '#FF1654',
                    'IncludeDependencies': '#FFD166',
                    'Include': '#06D6A0'
                }
                color = color_map.get(ntype, '#888888')
                
                net.add_node(node, label=label, title=title, color=color)
            
            # 添加边
            for src, dst in G.edges():
                edge_data = G.edges[src, dst]
                label = edge_data.get('label', '')
                net.add_edge(src, dst, label=label)
            
            # 保存为 HTML
            out_path = output_path
            if not out_path.lower().endswith('.html'):
                out_path = output_path + '.html'
            
            # 生成 HTML
            html_content = net.generate_html(name=os.path.basename(out_path), local=False)
            
            # 添加通信脚本
            comm_script = """
            <script>
                (function(){
                    var lastSentHeight = 0;
                    var sendTimer = null;
                    var maxHeight = 8000;
                    
                    function safePost(msg){
                        try{ window.parent.postMessage(msg, '*'); }catch(e){}
                    }
                    
                    function postHeightDebounced(){
                        if(sendTimer) return;
                        sendTimer = setTimeout(function(){
                            sendTimer = null;
                            try{
                                var h = Math.min(document.body.scrollHeight || 0, maxHeight);
                                if(Math.abs(h - lastSentHeight) > 30){
                                    lastSentHeight = h;
                                    safePost({type: 'pyvis_height', height: h, source: 'dependency'});
                                }
                            }catch(e){}
                        }, 300);
                    }
                    
                    function postReady(){
                        safePost({type: 'pyvis_ready', source: 'dependency'});
                        postHeightDebounced();
                        setTimeout(postHeightDebounced, 700);
                        setTimeout(postHeightDebounced, 1500);
                    }
                    
                    window.addEventListener('load', function(){
                        try{ postReady(); }catch(e){}
                    });
                    
                    var resizeObserver = null;
                    try{
                        if(window.ResizeObserver){
                            resizeObserver = new ResizeObserver(function(){ postHeightDebounced(); });
                            resizeObserver.observe(document.body);
                        } else {
                            window.addEventListener('resize', postHeightDebounced);
                        }
                    }catch(e){ window.addEventListener('resize', postHeightDebounced); }
                    
                    function attachClick(){
                        try{
                            if(typeof network !== 'undefined' && typeof nodes !== 'undefined'){
                                try{ safePost({type: 'pyvis_ready', source: 'dependency'}); }catch(e){}
                                
                                network.on('click', function(params){
                                    try{
                                        if(params.nodes && params.nodes.length > 0){
                                            var nodeId = params.nodes[0];
                                            var nodeData = null;
                                            try{ nodeData = nodes.find(function(n){ return n.id == nodeId; }) || {id: nodeId}; }catch(e){ nodeData = {id: nodeId}; }
                                            safePost({type:'pyvis_node_click', node: nodeData, source: 'dependency'});
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
            
            with open(out_path, 'w', encoding='utf-8') as f:
                f.write(html_content)
                f.write(comm_script)
            
            self.logger.info(f"依赖关系交互式可视化已保存到: {out_path}")
            return out_path
            
        except Exception as e:
            self.logger.error(f"保存依赖关系可视化失败: {str(e)}", exc_info=True)
            raise

class ConflictVisualizer:
    """冲突检测可视化工具"""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
    
    def save_conflict_file(self, conflicts, output_path):
        """保存冲突检测可视化到文件"""
        try:
            if Network is None:
                raise RuntimeError('pyvis 未安装，请安装 pyvis (pip install pyvis) 以生成交互式可视化')

            # 创建有向图
            G = nx.DiGraph()
            
            # 添加标题节点
            G.add_node('title', label='Rule Conflict Analysis', type='Title', full_value='Rule Conflict Analysis', children_values=[])
            
            if not conflicts:
                # 没有冲突
                G.add_node('no_conflict', label='No conflicts detected', type='NoConflict', full_value='No conflicts detected', children_values=[])
                G.add_edge('title', 'no_conflict')
            else:
                # 按严重程度分组冲突
                conflicts_by_severity = {
                    'high': [],
                    'medium': [],
                    'low': []
                }
                for conflict in conflicts:
                    severity = conflict.get('severity', 'low')
                    conflicts_by_severity[severity].append(conflict)
                
                # 统计冲突数量
                total_conflicts = len(conflicts)
                high_count = len(conflicts_by_severity['high'])
                medium_count = len(conflicts_by_severity['medium'])
                low_count = len(conflicts_by_severity['low'])
                
                # 添加统计节点
                stats_label = f"Conflict Statistics\nHigh: {high_count}\nMedium: {medium_count}\nLow: {low_count}\nTotal: {total_conflicts}"
                G.add_node('stats', label=stats_label, type='Statistics', full_value=stats_label, children_values=[])
                G.add_edge('title', 'stats')
                
                # 冲突类型到标签的映射
                conflict_type_labels = {
                    'logic_conflict': 'Logic Conflict',
                    'coverage_conflict': 'Coverage Conflict',
                    'priority_conflict': 'Priority Conflict',
                    'overlap_conflict': 'Overlap Conflict',
                    'dependency_conflict': 'Dependency Conflict',
                    'chain_conflict': 'Chain Conflict'
                }
                
                # 按严重程度从高到低添加冲突节点
                for severity in ['high', 'medium', 'low']:
                    if not conflicts_by_severity[severity]:
                        continue
                    
                    # 添加严重程度组节点
                    severity_node_id = f'severity_{severity}'
                    severity_label = f"{severity.capitalize()} Conflicts ({len(conflicts_by_severity[severity])})"
                    G.add_node(severity_node_id, label=severity_label, type='SeverityGroup', full_value=severity_label, children_values=[])
                    G.add_edge('stats', severity_node_id)
                    
                    # 添加该严重程度下的冲突节点
                    for i, conflict in enumerate(conflicts_by_severity[severity]):
                        conflict_id = f'conflict_{severity}_{i}'
                        conflict_type = conflict.get('conflict_type', 'Unknown')
                        rule_ids = conflict.get('rule_ids', [])
                        reason = conflict.get('reason', '')
                        
                        # 冲突节点标签
                        conflict_label = f"{conflict_type_labels.get(conflict_type, conflict_type)}\nRules: {', '.join(rule_ids)}\nReason: {reason[:60]}{'...' if len(reason) > 60 else ''}"
                        G.add_node(conflict_id, label=conflict_label, type='Conflict', full_value=conflict_label, children_values=rule_ids)
                        G.add_edge(severity_node_id, conflict_id)
            
            # 创建 pyvis Network
            net = Network(height='800px', width='100%', directed=True, notebook=False)
            try:
                net.toggle_physics(False)
            except Exception:
                pass
            
            # 添加节点到 pyvis
            for node in G.nodes():
                ndata = G.nodes[node]
                label = ndata.get('label', str(node))
                ntype = ndata.get('type', '')
                
                # 构建tooltip
                full_value = ndata.get('full_value', '')
                children_vals = ndata.get('children_values', []) or []
                
                esc_type = html.escape(str(ntype))
                esc_value = html.escape(str(full_value))
                
                children_html = ''
                if children_vals:
                    max_show = 10
                    show_list = [html.escape(str(v)) for v in children_vals[:max_show]]
                    children_html = '<br>'.join(show_list)
                    if len(children_vals) > max_show:
                        children_html += f"<br>+{len(children_vals)-max_show} more..."
                
                title = f"<div style=\"max-width:300px;word-wrap:break-word;\">"
                title += f"<b>Type:</b> {esc_type}<br>"
                title += f"<b>Value:</b> {esc_value}<br>"
                if children_html:
                    title += f"<b>Children:</b><br>{children_html}<br>"
                title += "</div>"
                
                # 根据节点类型设置颜色
                color_map = {
                    'Title': '#2E86AB',
                    'Statistics': '#43AA8B',
                    'NoConflict': '#52c41a',
                    'SeverityGroup': {
                        'high': '#ff4d4f',
                        'medium': '#ffec3d',
                        'low': '#ffffff'
                    },
                    'Conflict': {
                        'high': '#ff4d4f',
                        'medium': '#ffec3d',
                        'low': '#f0f0f0'
                    }
                }
                
                # 确定节点颜色
                if ntype == 'SeverityGroup' or ntype == 'Conflict':
                    # 从节点ID中提取严重程度
                    severity = 'low'
                    if 'high' in node:
                        severity = 'high'
                    elif 'medium' in node:
                        severity = 'medium'
                    color = color_map[ntype][severity]
                else:
                    color = color_map.get(ntype, '#888888')
                
                # 确定节点文字颜色
                font_color = '#333333'
                if color in ['#ff4d4f', '#2E86AB', '#43AA8B', '#52c41a']:
                    font_color = '#ffffff'
                
                net.add_node(node, label=label, title=title, color=color, font={'color': font_color})
            
            # 添加边
            for src, dst in G.edges():
                net.add_edge(src, dst)
            
            # 保存为 HTML
            out_path = output_path
            if not out_path.lower().endswith('.html'):
                out_path = output_path + '.html'
            
            # 生成 HTML
            html_content = net.generate_html(name=os.path.basename(out_path), local=False)
            
            # 添加通信脚本
            comm_script = """
            <script>
                (function(){
                    var lastSentHeight = 0;
                    var sendTimer = null;
                    var maxHeight = 8000;
                    
                    function safePost(msg){
                        try{ window.parent.postMessage(msg, '*'); }catch(e){}
                    }
                    
                    function postHeightDebounced(){
                        if(sendTimer) return;
                        sendTimer = setTimeout(function(){
                            sendTimer = null;
                            try{
                                var h = Math.min(document.body.scrollHeight || 0, maxHeight);
                                if(Math.abs(h - lastSentHeight) > 30){
                                    lastSentHeight = h;
                                    safePost({type: 'pyvis_height', height: h, source: 'conflict'});
                                }
                            }catch(e){}
                        }, 300);
                    }
                    
                    function postReady(){
                        safePost({type: 'pyvis_ready', source: 'conflict'});
                        postHeightDebounced();
                        setTimeout(postHeightDebounced, 700);
                        setTimeout(postHeightDebounced, 1500);
                    }
                    
                    window.addEventListener('load', function(){
                        try{ postReady(); }catch(e){}
                    });
                    
                    var resizeObserver = null;
                    try{
                        if(window.ResizeObserver){
                            resizeObserver = new ResizeObserver(function(){ postHeightDebounced(); });
                            resizeObserver.observe(document.body);
                        } else {
                            window.addEventListener('resize', postHeightDebounced);
                        }
                    }catch(e){ window.addEventListener('resize', postHeightDebounced); }
                    
                    function attachClick(){
                        try{
                            if(typeof network !== 'undefined' && typeof nodes !== 'undefined'){
                                try{ safePost({type: 'pyvis_ready', source: 'conflict'}); }catch(e){}
                                
                                network.on('click', function(params){
                                    try{
                                        if(params.nodes && params.nodes.length > 0){
                                            var nodeId = params.nodes[0];
                                            var nodeData = null;
                                            try{ nodeData = nodes.find(function(n){ return n.id == nodeId; }) || {id: nodeId}; }catch(e){ nodeData = {id: nodeId}; }
                                            safePost({type:'pyvis_node_click', node: nodeData, source: 'conflict'});
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
            
            with open(out_path, 'w', encoding='utf-8') as f:
                f.write(html_content)
                f.write(comm_script)
            
            self.logger.info(f"冲突检测交互式可视化已保存到: {out_path}")
            return out_path
            
        except Exception as e:
            self.logger.error(f"保存冲突检测可视化失败: {str(e)}", exc_info=True)
            raise

class AttackTypeVisualizer:
    """攻击类型可视化工具"""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
    
    def save_attack_type_file(self, rules, output_path, layout='radial'):
        """保存攻击类型可视化到文件"""
        try:
            if Network is None:
                raise RuntimeError('pyvis 未安装，请安装 pyvis (pip install pyvis) 以生成交互式可视化')

            # 创建有向图
            G = nx.DiGraph()
            
            # 添加根节点
            root_node_id = 'root'
            G.add_node(root_node_id, label='Attack Types Distribution', type='Root', full_value='Attack Types Distribution', children_values=[])
            
            # 统计攻击类型
            attack_types = {}
            total_rules = 0
            for rule in rules:
                semantic_analysis = rule.get('semantic_analysis', {})
                types = semantic_analysis.get('attack_types', [])
                total_rules += 1
                for attack_type in types:
                    attack_types[attack_type] = attack_types.get(attack_type, 0) + 1
            
            # 添加统计节点
            stats_label = f"Statistics\nTotal Rules: {total_rules}\nUnique Attack Types: {len(attack_types)}"
            stats_node_id = 'stats'
            G.add_node(stats_node_id, label=stats_label, type='Statistics', full_value=stats_label, children_values=[])
            G.add_edge(root_node_id, stats_node_id)
            
            if not attack_types:
                # 没有攻击类型数据
                no_data_node_id = 'no_data'
                G.add_node(no_data_node_id, label='No attack type data', type='NoData', full_value='No attack type data', children_values=[])
                G.add_edge(stats_node_id, no_data_node_id)
            else:
                # 按数量排序攻击类型
                sorted_attack_types = sorted(attack_types.items(), key=lambda x: x[1], reverse=True)
                
                # 为每种攻击类型添加节点
                for i, (attack_type, count) in enumerate(sorted_attack_types):
                    # 计算百分比
                    percentage = (count / total_rules) * 100
                    type_id = f'attack_{i}'
                    label = f"{attack_type}\n({count} rules, {percentage:.1f}%)"
                    
                    # 保存完整信息用于tooltip
                    full_info = f"Attack Type: {attack_type}\nCount: {count}\nPercentage: {percentage:.1f}%\nTotal Rules: {total_rules}"
                    
                    G.add_node(type_id, label=label, type='AttackType', full_value=full_info, children_values=[])
                    G.add_edge(stats_node_id, type_id)
            
            # 创建 pyvis Network
            net = Network(height='800px', width='100%', directed=True, notebook=False)
            try:
                net.toggle_physics(False)
            except Exception:
                pass
            
            # 添加节点到 pyvis
            for node in G.nodes():
                ndata = G.nodes[node]
                label = ndata.get('label', str(node))
                ntype = ndata.get('type', '')
                
                # 构建tooltip
                full_value = ndata.get('full_value', '')
                
                esc_type = html.escape(str(ntype))
                esc_value = html.escape(str(full_value))
                
                title = f"<div style=\"max-width:300px;word-wrap:break-word;\">"
                title += f"<b>Type:</b> {esc_type}<br>"
                title += f"<b>Details:</b><br>{esc_value}<br>"
                title += "</div>"
                
                # 根据节点类型设置颜色
                color_map = {
                    'Root': '#2E86AB',
                    'Statistics': '#43AA8B',
                    'NoData': '#999999',
                    'AttackType': '#70C1B3'
                }
                
                # 为AttackType节点根据百分比调整颜色
                if ntype == 'AttackType':
                    # 提取百分比信息
                    import re
                    percentage_match = re.search(r'\((\d+) rules, (\d+\.\d+)%\)', label)
                    if percentage_match:
                        percentage = float(percentage_match.group(2))
                        # 根据百分比设置颜色
                        if percentage > 30:
                            color = '#ff4d4f'
                        elif percentage > 15:
                            color = '#faad14'
                        elif percentage > 5:
                            color = '#1890ff'
                        else:
                            color = '#52c41a'
                    else:
                        color = color_map[ntype]
                else:
                    color = color_map.get(ntype, '#888888')
                
                # 确定文字颜色
                font_color = '#333333'
                if color in ['#ff4d4f', '#2E86AB', '#43AA8B', '#1890ff', '#52c41a']:
                    font_color = '#ffffff'
                
                net.add_node(node, label=label, title=title, color=color, font={'color': font_color})
            
            # 添加边
            for src, dst in G.edges():
                net.add_edge(src, dst)
            
            # 保存为 HTML
            out_path = output_path
            if not out_path.lower().endswith('.html'):
                out_path = output_path + '.html'
            
            # 生成 HTML
            html_content = net.generate_html(name=os.path.basename(out_path), local=False)
            
            # 添加通信脚本
            comm_script = """
            <script>
                (function(){
                    var lastSentHeight = 0;
                    var sendTimer = null;
                    var maxHeight = 8000;
                    
                    function safePost(msg){
                        try{ window.parent.postMessage(msg, '*'); }catch(e){}
                    }
                    
                    function postHeightDebounced(){
                        if(sendTimer) return;
                        sendTimer = setTimeout(function(){
                            sendTimer = null;
                            try{
                                var h = Math.min(document.body.scrollHeight || 0, maxHeight);
                                if(Math.abs(h - lastSentHeight) > 30){
                                    lastSentHeight = h;
                                    safePost({type: 'pyvis_height', height: h, source: 'attack_type'});
                                }
                            }catch(e){}
                        }, 300);
                    }
                    
                    function postReady(){
                        safePost({type: 'pyvis_ready', source: 'attack_type'});
                        postHeightDebounced();
                        setTimeout(postHeightDebounced, 700);
                        setTimeout(postHeightDebounced, 1500);
                    }
                    
                    window.addEventListener('load', function(){
                        try{ postReady(); }catch(e){}
                    });
                    
                    var resizeObserver = null;
                    try{
                        if(window.ResizeObserver){
                            resizeObserver = new ResizeObserver(function(){ postHeightDebounced(); });
                            resizeObserver.observe(document.body);
                        } else {
                            window.addEventListener('resize', postHeightDebounced);
                        }
                    }catch(e){ window.addEventListener('resize', postHeightDebounced); }
                    
                    function attachClick(){
                        try{
                            if(typeof network !== 'undefined' && typeof nodes !== 'undefined'){
                                try{ safePost({type: 'pyvis_ready', source: 'attack_type'}); }catch(e){}
                                
                                network.on('click', function(params){
                                    try{
                                        if(params.nodes && params.nodes.length > 0){
                                            var nodeId = params.nodes[0];
                                            var nodeData = null;
                                            try{ nodeData = nodes.find(function(n){ return n.id == nodeId; }) || {id: nodeId}; }catch(e){ nodeData = {id: nodeId}; }
                                            safePost({type:'pyvis_node_click', node: nodeData, source: 'attack_type'});
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
            
            with open(out_path, 'w', encoding='utf-8') as f:
                f.write(html_content)
                f.write(comm_script)
            
            self.logger.info(f"攻击类型交互式可视化已保存到: {out_path}")
            return out_path
            
        except Exception as e:
            self.logger.error(f"保存攻击类型可视化失败: {str(e)}", exc_info=True)
            raise

class RuleFlowVisualizer:
    """规则流可视化工具"""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
    
    def save_ruleflow_file(self, rules, output_path, max_rules_per_phase=10):
        """保存规则流可视化到文件"""
        try:
            if Network is None:
                raise RuntimeError('pyvis 未安装，请安装 pyvis (pip install pyvis) 以生成交互式可视化')

            # 创建有向图
            G = nx.DiGraph()
            
            # 添加标题节点
            title_node_id = 'title'
            G.add_node(title_node_id, label='Rule Processing Flow', type='Title', full_value='Rule Processing Flow', children_values=[])
            
            if not rules:
                # 没有规则数据
                no_rules_node_id = 'no_rules'
                G.add_node(no_rules_node_id, label='No rules to display', type='NoRules', full_value='No rules to display', children_values=[])
                G.add_edge(title_node_id, no_rules_node_id)
            else:
                # 按phase分组规则
                phases = {}
                for rule in rules:
                    rule_info = rule.get('rule_info', {})
                    phase = rule_info.get('phase', 'unknown')
                    rule_id = rule_info.get('id', 'unknown')
                    severity_val = rule_info.get('severity', 'LOW')
                    severity = (severity_val.upper() if severity_val else 'LOW') or 'LOW'
                    
                    if phase not in phases:
                        phases[phase] = []
                    phases[phase].append({
                        'id': rule_id,
                        'severity': severity
                    })
                
                # 按phase值排序，先按是否为数字分组，再分别排序
                sorted_phases = sorted(phases.items(), key=lambda x: (not x[0].isdigit(), int(x[0]) if x[0].isdigit() else x[0]))
                
                # 添加每个phase的节点
                prev_phase_node_id = title_node_id
                
                for phase, phase_rules in sorted_phases:
                    phase_id = f'phase_{phase}'
                    rule_count = len(phase_rules)
                    
                    # 统计严重程度分布
                    severity_counts = {
                        'CRITICAL': 0,
                        'HIGH': 0,
                        'MEDIUM': 0,
                        'LOW': 0,
                        'INFO': 0,
                        'WARNING': 0
                    }
                    for rule in phase_rules:
                        severity = rule['severity']
                        if severity not in severity_counts:
                            severity_counts[severity] = 0
                        severity_counts[severity] += 1
                    
                    # 创建阶段标签
                    severity_lines = []
                    for severity, count in severity_counts.items():
                        if count > 0:
                            severity_lines.append(f"{severity}: {count}")
                    
                    phase_label = f"Phase {phase}\n{rule_count} rules\n" + "\n".join(severity_lines)
                    
                    # 添加阶段节点
                    G.add_node(phase_id, label=phase_label, type='Phase', full_value=phase_label, children_values=[])
                    G.add_edge(prev_phase_node_id, phase_id)
                    prev_phase_node_id = phase_id
                    
                    # 添加该phase下的规则节点（限制显示数量）
                    display_count = min(rule_count, max_rules_per_phase)
                    
                    # 按规则ID排序
                    sorted_phase_rules = sorted(phase_rules, key=lambda x: x['id'])
                    
                    for i in range(display_count):
                        rule = sorted_phase_rules[i]
                        rule_id = rule['id']
                        severity = rule['severity']
                        
                        rule_label = f"Rule {rule_id}\n({severity})"
                        rule_node_id = f'rule_{rule_id}'
                        
                        # 保存完整信息用于tooltip
                        full_info = f"Rule ID: {rule_id}\nPhase: {phase}\nSeverity: {severity}"
                        
                        G.add_node(rule_node_id, label=rule_label, type='Rule', full_value=full_info, children_values=[])
                        G.add_edge(phase_id, rule_node_id)
                    
                    # 如果有更多规则，添加省略节点
                    if rule_count > display_count:
                        more_node_id = f'more_{phase}'
                        more_label = f"... {rule_count - display_count} more rules"
                        G.add_node(more_node_id, label=more_label, type='MoreRules', full_value=more_label, children_values=[])
                        G.add_edge(phase_id, more_node_id)
            
            # 创建 pyvis Network
            net = Network(height='800px', width='100%', directed=True, notebook=False)
            try:
                net.toggle_physics(False)
            except Exception:
                pass
            
            # 添加节点到 pyvis
            for node in G.nodes():
                ndata = G.nodes[node]
                label = ndata.get('label', str(node))
                ntype = ndata.get('type', '')
                
                # 构建tooltip
                full_value = ndata.get('full_value', '')
                
                esc_type = html.escape(str(ntype))
                esc_value = html.escape(str(full_value))
                
                title = f"<div style=\"max-width:300px;word-wrap:break-word;\">"
                title += f"<b>Type:</b> {esc_type}<br>"
                title += f"<b>Details:</b><br>{esc_value}<br>"
                title += "</div>"
                
                # 根据节点类型设置颜色
                color_map = {
                    'Title': '#2E86AB',
                    'NoRules': '#999999',
                    'Phase': '#1890ff',
                    'Rule': {
                        'CRITICAL': '#ff4d4f',
                        'HIGH': '#fa8c16',
                        'MEDIUM': '#ffec3d',
                        'LOW': '#52c41a',
                        'INFO': '#69c0ff',
                        '': '#d9d9d9'
                    },
                    'MoreRules': '#666666'
                }
                
                # 确定节点颜色
                if ntype == 'Rule':
                    # 从节点ID中提取规则ID
                    rule_id = node.split('_')[-1]
                    # 查找规则的严重程度
                    severity = 'LOW'
                    for phase_rules in phases.values():
                        for rule in phase_rules:
                            if rule['id'] == rule_id:
                                severity = rule['severity']
                                break
                        if severity != 'LOW':
                            break
                    color = color_map[ntype].get(severity, color_map[ntype][''])
                else:
                    color = color_map.get(ntype, '#888888')
                
                # 确定文字颜色
                font_color = '#333333'
                if color in ['#2E86AB', '#1890ff', '#ff4d4f', '#fa8c16', '#52c41a', '#69c0ff']:
                    font_color = '#ffffff'
                
                net.add_node(node, label=label, title=title, color=color, font={'color': font_color})
            
            # 添加边
            for src, dst in G.edges():
                net.add_edge(src, dst)
            
            # 保存为 HTML
            out_path = output_path
            if not out_path.lower().endswith('.html'):
                out_path = output_path + '.html'
            
            # 生成 HTML
            html_content = net.generate_html(name=os.path.basename(out_path), local=False)
            
            # 添加通信脚本
            comm_script = """
            <script>
                (function(){
                    var lastSentHeight = 0;
                    var sendTimer = null;
                    var maxHeight = 8000;
                    
                    function safePost(msg){
                        try{ window.parent.postMessage(msg, '*'); }catch(e){}
                    }
                    
                    function postHeightDebounced(){
                        if(sendTimer) return;
                        sendTimer = setTimeout(function(){
                            sendTimer = null;
                            try{
                                var h = Math.min(document.body.scrollHeight || 0, maxHeight);
                                if(Math.abs(h - lastSentHeight) > 30){
                                    lastSentHeight = h;
                                    safePost({type: 'pyvis_height', height: h, source: 'ruleflow'});
                                }
                            }catch(e){}
                        }, 300);
                    }
                    
                    function postReady(){
                        safePost({type: 'pyvis_ready', source: 'ruleflow'});
                        postHeightDebounced();
                        setTimeout(postHeightDebounced, 700);
                        setTimeout(postHeightDebounced, 1500);
                    }
                    
                    window.addEventListener('load', function(){
                        try{ postReady(); }catch(e){}
                    });
                    
                    var resizeObserver = null;
                    try{
                        if(window.ResizeObserver){
                            resizeObserver = new ResizeObserver(function(){ postHeightDebounced(); });
                            resizeObserver.observe(document.body);
                        } else {
                            window.addEventListener('resize', postHeightDebounced);
                        }
                    }catch(e){ window.addEventListener('resize', postHeightDebounced); }
                    
                    function attachClick(){
                        try{
                            if(typeof network !== 'undefined' && typeof nodes !== 'undefined'){
                                try{ safePost({type: 'pyvis_ready', source: 'ruleflow'}); }catch(e){}
                                
                                network.on('click', function(params){
                                    try{
                                        if(params.nodes && params.nodes.length > 0){
                                            var nodeId = params.nodes[0];
                                            var nodeData = null;
                                            try{ nodeData = nodes.find(function(n){ return n.id == nodeId; }) || {id: nodeId}; }catch(e){ nodeData = {id: nodeId}; }
                                            safePost({type:'pyvis_node_click', node: nodeData, source: 'ruleflow'});
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
            
            with open(out_path, 'w', encoding='utf-8') as f:
                f.write(html_content)
                f.write(comm_script)
            
            self.logger.info(f"规则流交互式可视化已保存到: {out_path}")
            return out_path
            
        except Exception as e:
            self.logger.error(f"保存规则流可视化失败: {str(e)}", exc_info=True)
            raise