#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ModSecurity规则解析器
基于ANTLR4实现的ModSecurity规则语法解析器
"""

import os
import logging
import tempfile
from pathlib import Path
from antlr4 import *
from antlr4.error.ErrorListener import ErrorListener

from part2_rule_analysis.lib.parser.grammar.ModSecurityLexer import ModSecurityLexer
# ANTLR生成的解析器，重命名以避免与本模块中的封装类冲突
from part2_rule_analysis.lib.parser.grammar.ModSecurityParser import ModSecurityParser as ANTLRModSecurityParser
from part2_rule_analysis.lib.parser.rule_node import RuleNode, Node
from common.utils.file_utils import read_file_content

class ParsingErrorListener(ErrorListener):
    """语法解析错误监听器"""
    
    def __init__(self):
        super().__init__()
        self.errors = []
    
    def syntaxError(self, recognizer, offendingSymbol, line, column, msg, e):
        error_msg = f"语法错误: 第{line}行第{column}列 - {msg}"
        self.errors.append({
            'type': 'syntax_error',
            'line': line,
            'column': column,
            'message': msg,
            'full_message': error_msg
        })
    
    def reportAmbiguity(self, recognizer, dfa, startIndex, stopIndex, exact, ambigAlts, configs):
        pass
    
    def reportAttemptingFullContext(self, recognizer, dfa, startIndex, stopIndex, conflictingAlts, configs):
        pass
    
    def reportContextSensitivity(self, recognizer, dfa, startIndex, stopIndex, prediction, configs):
        pass

class ModSecurityParser:
    """ModSecurity规则解析器"""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.error_listener = ParsingErrorListener()
        self.parsed_rules = []
        self.parse_errors = []
    
    def parse_file(self, file_path):
        """解析规则文件"""
        try:
            self.logger.info(f"开始解析文件: {file_path}")
            
            # 读取文件内容
            content = read_file_content(file_path)
            if not content:
                self.logger.warning("文件内容为空")
                return []
            
            return self.parse_content(content, file_path)
            
        except Exception as e:
            self.logger.error(f"解析文件失败: {str(e)}", exc_info=True)
            raise
    
    def parse_content(self, content, file_path=None):
        """解析规则内容"""
        try:
            self.logger.info(f"开始解析规则内容，长度: {len(content)}字符")
            
            # 重置状态
            self.parsed_rules = []
            self.parse_errors = []
            self.error_listener = ParsingErrorListener()
            
            # 创建ANTLR输入流
            # 预处理（针对 Core Rule Set 的常见特性）：
            # - 移除整行注释（以 # 开头）
            # - 合并以反斜杠结尾的续行
            # - 移除或忽略常见全局配置指令（可扩展）
            # - 对极少数会破坏词法的字符做最小转义
            import re

            # 移除以 # 开头的注释行（CRS 中大量注释）
            content = re.sub(r"^\s*#.*$\r?\n?", "", content, flags=re.MULTILINE)

            # 合并续行：把以反斜杠结尾的行与下一行连接为一个空格分隔的行
            content = re.sub(r"\\\s*\r?\n\s*", " ", content)

            # 移除不在当前语法中的全局指令（可根据需要扩展）
            content = re.sub(r"^\s*(SecRuleEngine|SecRequestBodyAccess|SecComponentSignature).*$\r?\n?", "", content, flags=re.MULTILINE)

            # 最小转义：反引号、未配对的内嵌双引号片段等
            content = content.replace('`', '\\`')
            content = content.replace('onclick="', 'onclick=\\"')

            input_stream = InputStream(content)
            
            # 创建词法分析器
            lexer = ModSecurityLexer(input_stream)
            lexer.removeErrorListeners()
            lexer.addErrorListener(self.error_listener)
            
            # 创建词法单元流
            token_stream = CommonTokenStream(lexer)
            
            # 创建语法分析器（使用 ANTLR 生成的解析器实例）
            antlr_parser = ANTLRModSecurityParser(token_stream)
            antlr_parser.removeErrorListeners()
            antlr_parser.addErrorListener(self.error_listener)

            # 设置自定义的树监听器并生成语法树
            # ANTLR生成的解析器入口函数为 rulesFile()
            tree = antlr_parser.rulesFile()
            
            # 检查解析错误
            if self.error_listener.errors:
                self.parse_errors.extend(self.error_listener.errors)
                self.logger.error(f"解析发现 {len(self.parse_errors)} 个错误")
                for error in self.parse_errors[:5]:  # 只显示前5个错误
                    self.logger.error(f"  {error['full_message']}")
            
            # 构建规则对象列表（传入 ANTLR 解析器以备后续使用）
            self._build_rule_objects(tree, antlr_parser)
            
            self.logger.info(f"解析完成，共解析到 {len(self.parsed_rules)} 条规则")

            # 如果 ANTLR 解析器未能成功构建规则（例如 CRS 中有大量宏/扩展语法），
            # 则使用一个轻量的启发式回退解析器从文本中抽取 SecRule/SecAction/Include 等信息，
            # 以便后续语义/依赖/索引能获得至少部分可用数据。
            if (not self.parsed_rules) and self.error_listener.errors:
                try:
                    self.logger.warning("ANTLR 解析失败，尝试使用启发式回退解析器提取规则")
                    fallback_rules = self._heuristic_parse_content(content, file_path)
                    if fallback_rules:
                        self.parse_errors.append({'type': 'fallback', 'message': '使用启发式解析器提取规则，原始解析存在语法错误'})
                        self.parsed_rules = fallback_rules
                        self.logger.info(f"启发式解析提取到 {len(fallback_rules)} 条规则")
                except Exception:
                    self.logger.exception('启发式回退解析失败')

            return self.parsed_rules
            
        except Exception as e:
            self.logger.error(f"解析内容失败: {str(e)}", exc_info=True)
            raise
    
    def _build_rule_objects(self, tree, parser):
        """构建规则对象列表"""
        try:
            # 遍历语法树，构建规则对象
            listener = RuleBuildingListener()
            walker = ParseTreeWalker()
            walker.walk(listener, tree)
            
            self.parsed_rules = listener.rules
            self.logger.debug(f"成功构建 {len(self.parsed_rules)} 条规则对象")
            
        except Exception as e:
            self.logger.error(f"构建规则对象失败: {str(e)}", exc_info=True)
            raise

    def _heuristic_parse_content(self, content, file_path=None):
        """启发式从文本中提取规则：

        - 查找以 SecRule/SecAction/SecMarker/SecDefaultAction/Include 开头的行（已合并续行）
        - 尽量提取 id、msg、tag、pattern 等信息，返回一组 RuleNode
        这是一个容错的备选解析路径，用于处理 CRS 中大量注释、宏或扩展语法导致的 ANTLR 失败。
        """
        import re
        from part2_rule_analysis.lib.parser.rule_node import RuleNode, Node

        rules = []
        try:
            # 预处理：移除连续空行，保持行号映射大致合理
            lines = content.splitlines()

            multi_line = []
            current = ''
            current_line_no = 0
            for idx, raw in enumerate(lines, start=1):
                line = raw.rstrip('\r\n')
                # 跳过注释
                if re.match(r'^\s*#', line):
                    continue
                # 合并以反斜杠结尾的续行（parse_content 已做过，但再保险）
                if line.endswith('\\'):
                    if not current:
                        current_line_no = idx
                    current += line[:-1] + ' '
                    continue
                if current:
                    current += line
                    merged = current
                    multi_line.append((current_line_no, merged))
                    current = ''
                    current_line_no = 0
                else:
                    multi_line.append((idx, line))

            # 正则匹配 SecRule 等指令
            secrule_re = re.compile(r'^\s*SecRule\s+(?P<vars>[^\s]+)\s+(?P<op>[^\s]+)(?:\s+(?P<rest>.*))?$', re.IGNORECASE)
            secaction_re = re.compile(r'^\s*SecAction\b(?:\s+(?P<rest>.*))?$', re.IGNORECASE)
            include_re = re.compile(r'^\s*Include\s+(?P<path>.+)$', re.IGNORECASE)

            for line_no, line in multi_line:
                m = secrule_re.match(line)
                if m:
                    vars_part = m.group('vars')
                    op_part = m.group('op')
                    rest = m.group('rest') or ''

                    node = RuleNode('SecRule', line_no, 0)
                    # 尝试提取 pattern（op_part 可能是 @rx 或直接以"开头）
                    pattern = None
                    if op_part.startswith('@'):
                        # op 可能后接字符串或带引号的模式
                        # 从 rest 中查找第一个引号包裹的字符串
                        q = re.search(r'"([^"]+)"|\'([^\']+)\'', rest)
                        if q:
                            pattern = q.group(1) or q.group(2)
                    else:
                        # op_part 可能就是一个简单模式
                        pattern = op_part

                    node.pattern = pattern

                    # 解析动作列表（rest），寻找 id/msg/tag/severity
                    actions = []
                    tags = []
                    rule_id = None
                    if rest:
                        # 动作通常以逗号分隔，可能包含引号
                        parts = [p.strip() for p in re.split(r',(?=(?:[^\"\']*[\"\'][^\"\']*[\"\'])*[^\"\']*$)', rest) if p.strip()]
                        for part in parts:
                            actions.append(part)
                            # 提取 id:数字
                            idm = re.search(r'id\s*:\s*(\d+)', part, re.IGNORECASE)
                            if idm and not rule_id:
                                rule_id = idm.group(1)
                            # 提取 tag
                            tagm = re.search(r'tag\s*:\s*"?([^",]+)"?', part, re.IGNORECASE)
                            if tagm:
                                tags.append(tagm.group(1))
                    node.actions = actions
                    node.tags = tags
                    node.rule_id = rule_id or f"heuristic_{line_no}_{abs(hash(line)) & 0xffffffff}"
                    # 增加 Pattern 子节点以兼容后续处理
                    if node.pattern:
                        pnode = Node('Pattern', node.pattern, line_no, 0)
                        node.add_child(pnode)
                    rules.append(node)
                    continue

                m2 = secaction_re.match(line)
                if m2:
                    rest = m2.group('rest') or ''
                    node = RuleNode('SecAction', line_no, 0)
                    actions = [p.strip() for p in rest.split(',') if p.strip()]
                    node.actions = actions
                    # try extract id
                    rule_id = None
                    for part in actions:
                        idm = re.search(r'id\s*:\s*(\d+)', part, re.IGNORECASE)
                        if idm:
                            rule_id = idm.group(1)
                            break
                    node.rule_id = rule_id or f"secaction_{line_no}_{abs(hash(line)) & 0xffffffff}"
                    rules.append(node)
                    continue

                m3 = include_re.match(line)
                if m3:
                    path = m3.group('path').strip().strip('"')
                    node = RuleNode('Include', line_no, 0)
                    node.add_child(Node('IncludePath', path, line_no, 0))
                    node.rule_id = f"include_{line_no}_{abs(hash(path)) & 0xffffffff}"
                    rules.append(node)

            return rules
        except Exception as e:
            self.logger.exception(f"启发式解析失败: {str(e)}")
            return []
    
    def get_parse_errors(self):
        """获取解析错误信息"""
        return self.parse_errors
    
    def save_parsed_results(self, output_dir):
        """保存解析结果"""
        try:
            os.makedirs(output_dir, exist_ok=True)
            
            # 保存解析的规则
            rules_path = os.path.join(output_dir, 'parsed_rules.json')
            with open(rules_path, 'w', encoding='utf-8') as f:
                import json
                json.dump([rule.to_dict() for rule in self.parsed_rules], f, indent=2, ensure_ascii=False)
            
            # 保存解析错误
            if self.parse_errors:
                errors_path = os.path.join(output_dir, 'parse_errors.json')
                with open(errors_path, 'w', encoding='utf-8') as f:
                    import json
                    json.dump(self.parse_errors, f, indent=2, ensure_ascii=False)
            
            self.logger.info(f"解析结果已保存到: {output_dir}")
            return output_dir
            
        except Exception as e:
            self.logger.error(f"保存解析结果失败: {str(e)}", exc_info=True)
            raise

    def parse_directory(self, dir_path):
        """批量解析目录中的规则文件。

        - 对于常规 ModSecurity/CRS 配置（.conf/.example/.conf.*）使用已有的 parse_content
        - 对于 .data 字典文件（每行一个模式），将每个非注释、非空行转换为一个简单的 RuleNode
        返回解析得到的规则对象列表（合并所有文件的结果）。
        """
        from pathlib import Path
        rules = []
        dir_path = Path(dir_path)
        if not dir_path.exists() or not dir_path.is_dir():
            raise Exception(f"指定的规则目录不存在: {dir_path}")

        for p in sorted(dir_path.iterdir()):
            if p.is_file():
                name = p.name.lower()
                try:
                    if name.endswith('.data'):
                        self.logger.info(f"解析 data 字典文件: {p}")
                        data_rules = self._parse_data_file(str(p))
                        rules.extend(data_rules)
                    elif name.endswith('.conf') or name.endswith('.example') or name.endswith('.conf.example') or name.endswith('.conf.disabled'):
                        self.logger.info(f"解析配置文件: {p}")
                        parsed = self.parse_file(str(p)) or []
                        rules.extend(parsed)
                    else:
                        # 对其他文件也尝试以文本方式解析（例如没有扩展名的规则文件）
                        try:
                            parsed = self.parse_file(str(p)) or []
                            rules.extend(parsed)
                        except Exception:
                            # 忽略非可解析文件
                            self.logger.debug(f"跳过无法解析的文件: {p}")
                except Exception:
                    self.logger.exception(f"解析文件失败: {p}")

        # 返回合并的规则列表
        return rules

    def _parse_data_file(self, file_path):
        """解析 .data 字典文件：每个非注释、非空行创建一个简单的 RuleNode（node_type='DataEntry'）。"""
        from part2_rule_analysis.lib.parser.rule_node import RuleNode, Node
        results = []
        try:
            content = read_file_content(file_path)
        except Exception:
            self.logger.exception(f"读取 data 文件失败: {file_path}")
            return results

        for i, raw_line in enumerate(content.splitlines(), start=1):
            line = raw_line.strip()
            if not line:
                continue
            if line.startswith('#'):
                continue

            # 构造一个最小的 RuleNode，便于后续分析器使用
            node = RuleNode('DataEntry', i, 0)
            node.pattern = line
            node.rule_id = f"data_{i}_{abs(hash(line)) & 0xffffffff}"
            # 添加一个 Pattern 子节点，保持结构一致
            pattern_node = Node('Pattern', line, i, 0)
            node.add_child(pattern_node)
            results.append(node)

        self.logger.info(f"从 data 文件 {file_path} 构建 {len(results)} 条 DataEntry 规则")
        return results

class RuleBuildingListener(ParseTreeListener):
    """规则构建监听器"""
    
    def __init__(self):
        self.rules = []
        self.current_rule = None
        self.current_node = None
    
    def enterSecRuleDirective(self, ctx):
        """进入SecRule指令"""
        line = ctx.SEC_RULE.line
        self.current_rule = RuleNode("SecRule", line, 0)
        self.rules.append(self.current_rule)
    
    def exitSecRuleDirective(self, ctx):
        """退出SecRule指令"""
        self.current_rule = None
    
    def enterSecActionDirective(self, ctx):
        """进入SecAction指令"""
        line = ctx.SEC_ACTION.line
        self.current_rule = RuleNode("SecAction", line, 0)
        self.rules.append(self.current_rule)
    
    def exitSecActionDirective(self, ctx):
        """退出SecAction指令"""
        self.current_rule = None
    
    def enterSecMarkerDirective(self, ctx):
        """进入SecMarker指令"""
        line = ctx.SEC_MARKER.line
        marker_rule = RuleNode("SecMarker", line, 0)
        
        # 获取标记内容
        if ctx.STRING_CONTENT():
            marker_content = ctx.STRING_CONTENT().getText()
        elif ctx.SINGLE_STRING_CONTENT():
            marker_content = ctx.SINGLE_STRING_CONTENT().getText()
        else:
            marker_content = ""
        
        marker_rule.add_child(Node("MarkerContent", marker_content, line, 0))
        self.rules.append(marker_rule)
    
    def enterSecDefaultActionDirective(self, ctx):
        """进入SecDefaultAction指令"""
        line = ctx.SEC_DEFAULT_ACTION.line
        self.current_rule = RuleNode("SecDefaultAction", line, 0)
        self.rules.append(self.current_rule)
    
    def exitSecDefaultActionDirective(self, ctx):
        """退出SecDefaultAction指令"""
        self.current_rule = None
    
    def enterVarList(self, ctx):
        """进入变量列表"""
        if self.current_rule:
            var_list_node = Node("VarList", "", ctx.start.line, ctx.start.column)
            self.current_rule.add_child(var_list_node)
            self.current_node = var_list_node
    
    def exitVarList(self, ctx):
        """退出变量列表"""
        self.current_node = self.current_node.parent if self.current_node else None
    
    def enterVar(self, ctx):
        """进入变量"""
        if self.current_node and self.current_node.node_type == "VarList":
            var_name = ctx.getText()
            var_node = Node("Variable", var_name, ctx.start.line, ctx.start.column)
            self.current_node.add_child(var_node)
    
    def enterOpMode(self, ctx):
        """进入运算符模式"""
        if self.current_rule:
            op_name = ctx.getText()
            op_node = Node("Operator", op_name, ctx.start.line, ctx.start.column)
            self.current_rule.add_child(op_node)
    
    def enterPattern(self, ctx):
        """进入模式"""
        if self.current_rule:
            if ctx.STRING_CONTENT():
                pattern_content = ctx.STRING_CONTENT().getText()
            elif ctx.SINGLE_STRING_CONTENT():
                pattern_content = ctx.SINGLE_STRING_CONTENT().getText()
            else:
                pattern_content = ""
            
            pattern_node = Node("Pattern", pattern_content, ctx.start.line, ctx.start.column)
            self.current_rule.add_child(pattern_node)
    
    def enterActionList(self, ctx):
        """进入动作列表"""
        if self.current_rule:
            action_list_node = Node("ActionList", "", ctx.start.line, ctx.start.column)
            self.current_rule.add_child(action_list_node)
            self.current_node = action_list_node
    
    def exitActionList(self, ctx):
        """退出动作列表"""
        self.current_node = self.current_node.parent if self.current_node else None
    
    def enterAction(self, ctx):
        """进入动作"""
        if self.current_node and self.current_node.node_type == "ActionList":
            action_content = ctx.getText()
            action_node = Node("Action", action_content, ctx.start.line, ctx.start.column)
            self.current_node.add_child(action_node)
    
    # 其他enter/exit方法
    def enterIncludeDirective(self, ctx):
        """进入Include指令"""
        include_path = ""
        if ctx.STRING_CONTENT():
            include_path = ctx.STRING_CONTENT().getText()
        elif ctx.SINGLE_STRING_CONTENT():
            include_path = ctx.SINGLE_STRING_CONTENT().getText()
        
        include_rule = RuleNode("Include", ctx.INCLUDE.line, ctx.INCLUDE.column)
        include_rule.add_child(Node("IncludePath", include_path, ctx.start.line, ctx.start.column))
        self.rules.append(include_rule)
    
    def visitTerminal(self, node):
        """访问终端节点"""
        pass
    
    def visitErrorNode(self, node):
        """访问错误节点"""
        pass
    
    def enterEveryRule(self, ctx):
        """进入每个规则"""
        pass
    
    def exitEveryRule(self, ctx):
        """退出每个规则"""
        pass

def main():
    """测试主函数"""
    import argparse
    parser = argparse.ArgumentParser(description='ModSecurity规则解析器测试')
    parser.add_argument('file', help='ModSecurity规则文件路径')
    parser.add_argument('-v', '--verbose', action='store_true', help='显示详细信息')
    
    args = parser.parse_args()
    
    # 设置日志
    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO)
    
    try:
        parser = ModSecurityParser()
        rules = parser.parse_file(args.file)
        
        print(f"\n=== 解析结果 ===")
        print(f"解析规则数量: {len(rules)}")
        
        if parser.get_parse_errors():
            print(f"\n发现 {len(parser.get_parse_errors())} 个解析错误:")
            for error in parser.get_parse_errors():
                print(f"  {error['full_message']}")
        
        print(f"\n规则详情:")
        for i, rule in enumerate(rules[:10]):  # 只显示前10个规则
            print(f"\n规则 {i+1}: {rule.node_type} (第{rule.line}行)")
            print(f"  结构: {rule.to_dict()}")
            
    except Exception as e:
        print(f"解析失败: {str(e)}")

if __name__ == '__main__':
    main()