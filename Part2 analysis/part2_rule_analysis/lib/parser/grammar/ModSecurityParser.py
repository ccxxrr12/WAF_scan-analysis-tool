# Generated from ModSecurityParser.g4 by ANTLR 4.13.2
# encoding: utf-8
from antlr4 import *
from io import StringIO
import sys
if sys.version_info[1] > 5:
	from typing import TextIO
else:
	from typing.io import TextIO

def serializedATN():
    return [
        4,1,100,122,2,0,7,0,2,1,7,1,2,2,7,2,2,3,7,3,2,4,7,4,2,5,7,5,2,6,
        7,6,2,7,7,7,2,8,7,8,2,9,7,9,2,10,7,10,2,11,7,11,2,12,7,12,2,13,7,
        13,1,0,4,0,30,8,0,11,0,12,0,31,1,0,1,0,1,1,1,1,1,1,1,1,1,1,3,1,41,
        8,1,1,2,1,2,1,2,1,2,1,2,3,2,48,8,2,1,3,1,3,1,3,1,4,1,4,3,4,55,8,
        4,1,5,1,5,1,5,1,6,1,6,1,6,1,7,1,7,1,7,5,7,66,8,7,10,7,12,7,69,9,
        7,1,8,1,8,1,8,1,8,1,8,1,8,1,8,1,8,1,8,1,8,1,8,1,8,1,8,1,8,1,8,1,
        8,1,8,1,8,1,8,1,8,1,8,3,8,92,8,8,1,9,1,9,1,10,1,10,1,11,1,11,1,12,
        1,12,1,12,5,12,103,8,12,10,12,12,12,106,9,12,1,13,1,13,1,13,1,13,
        1,13,1,13,1,13,1,13,1,13,1,13,3,13,118,8,13,3,13,120,8,13,1,13,0,
        0,14,0,2,4,6,8,10,12,14,16,18,20,22,24,26,0,3,1,0,11,31,1,0,95,98,
        1,0,95,96,138,0,29,1,0,0,0,2,40,1,0,0,0,4,42,1,0,0,0,6,49,1,0,0,
        0,8,52,1,0,0,0,10,56,1,0,0,0,12,59,1,0,0,0,14,62,1,0,0,0,16,91,1,
        0,0,0,18,93,1,0,0,0,20,95,1,0,0,0,22,97,1,0,0,0,24,99,1,0,0,0,26,
        119,1,0,0,0,28,30,3,2,1,0,29,28,1,0,0,0,30,31,1,0,0,0,31,29,1,0,
        0,0,31,32,1,0,0,0,32,33,1,0,0,0,33,34,5,0,0,1,34,1,1,0,0,0,35,41,
        3,4,2,0,36,41,3,6,3,0,37,41,3,8,4,0,38,41,3,10,5,0,39,41,3,12,6,
        0,40,35,1,0,0,0,40,36,1,0,0,0,40,37,1,0,0,0,40,38,1,0,0,0,40,39,
        1,0,0,0,41,3,1,0,0,0,42,43,5,1,0,0,43,44,3,14,7,0,44,45,3,18,9,0,
        45,47,3,20,10,0,46,48,3,22,11,0,47,46,1,0,0,0,47,48,1,0,0,0,48,5,
        1,0,0,0,49,50,5,2,0,0,50,51,3,22,11,0,51,7,1,0,0,0,52,54,5,3,0,0,
        53,55,5,95,0,0,54,53,1,0,0,0,54,55,1,0,0,0,55,9,1,0,0,0,56,57,5,
        4,0,0,57,58,3,22,11,0,58,11,1,0,0,0,59,60,5,8,0,0,60,61,5,95,0,0,
        61,13,1,0,0,0,62,67,3,16,8,0,63,64,5,76,0,0,64,66,3,16,8,0,65,63,
        1,0,0,0,66,69,1,0,0,0,67,65,1,0,0,0,67,68,1,0,0,0,68,15,1,0,0,0,
        69,67,1,0,0,0,70,92,5,39,0,0,71,92,5,42,0,0,72,92,5,43,0,0,73,92,
        5,44,0,0,74,92,5,45,0,0,75,92,5,46,0,0,76,92,5,47,0,0,77,92,5,48,
        0,0,78,92,5,49,0,0,79,80,5,50,0,0,80,92,5,98,0,0,81,82,5,51,0,0,
        82,92,5,98,0,0,83,84,5,52,0,0,84,92,5,98,0,0,85,86,5,53,0,0,86,92,
        5,98,0,0,87,88,5,40,0,0,88,92,5,98,0,0,89,90,5,41,0,0,90,92,5,98,
        0,0,91,70,1,0,0,0,91,71,1,0,0,0,91,72,1,0,0,0,91,73,1,0,0,0,91,74,
        1,0,0,0,91,75,1,0,0,0,91,76,1,0,0,0,91,77,1,0,0,0,91,78,1,0,0,0,
        91,79,1,0,0,0,91,81,1,0,0,0,91,83,1,0,0,0,91,85,1,0,0,0,91,87,1,
        0,0,0,91,89,1,0,0,0,92,17,1,0,0,0,93,94,7,0,0,0,94,19,1,0,0,0,95,
        96,7,1,0,0,96,21,1,0,0,0,97,98,7,2,0,0,98,23,1,0,0,0,99,104,3,26,
        13,0,100,101,5,60,0,0,101,103,3,26,13,0,102,100,1,0,0,0,103,106,
        1,0,0,0,104,102,1,0,0,0,104,105,1,0,0,0,105,25,1,0,0,0,106,104,1,
        0,0,0,107,120,5,32,0,0,108,120,5,33,0,0,109,120,5,34,0,0,110,120,
        5,35,0,0,111,120,5,36,0,0,112,120,5,37,0,0,113,120,5,38,0,0,114,
        117,5,98,0,0,115,116,5,63,0,0,116,118,7,1,0,0,117,115,1,0,0,0,117,
        118,1,0,0,0,118,120,1,0,0,0,119,107,1,0,0,0,119,108,1,0,0,0,119,
        109,1,0,0,0,119,110,1,0,0,0,119,111,1,0,0,0,119,112,1,0,0,0,119,
        113,1,0,0,0,119,114,1,0,0,0,120,27,1,0,0,0,9,31,40,47,54,67,91,104,
        117,119
    ]

class ModSecurityParser ( Parser ):

    grammarFileName = "ModSecurityParser.g4"

    atn = ATNDeserializer().deserialize(serializedATN())

    decisionsToDFA = [ DFA(ds, i) for i, ds in enumerate(atn.decisionToState) ]

    sharedContextCache = PredictionContextCache()

    literalNames = [ "<INVALID>", "'SecRule'", "'SecAction'", "'SecMarker'", 
                     "'SecDefaultAction'", "'SecRuleScript'", "'SecInitCollection'", 
                     "'SecCollection'", "'Include'", "'SecCompatibilityMode'", 
                     "'SecRewriteRule'", "'@rx'", "'@contains'", "'@beginsWith'", 
                     "'@endsWith'", "'@eq'", "'@ne'", "'@lt'", "'@gt'", 
                     "'@le'", "'@ge'", "'@ipMatch'", "'@geoLookup'", "'@hash'", 
                     "'@rbl'", "'@urlLen'", "'@length'", "'@digits'", "'@alpha'", 
                     "'@alphanum'", "'@hex'", "'@pregMatch'", "'deny'", 
                     "'pass'", "'drop'", "'allow'", "'log'", "'nolog'", 
                     "'chain'", "'REQUEST_URI'", "'REQUEST_HEADERS:'", "'RESPONSE_HEADERS:'", 
                     "'REMOTE_ADDR'", "'ARGS'", "'ARGS_GET'", "'ARGS_POST'", 
                     "'FILES'", "'FILES_NAMES'", "'FILES_SIZES'", "'FILES_TMP_CONTENT'", 
                     "'ENV:'", "'GEO:'", "'TX:'", "'IP:'", "'('", "')'", 
                     "'{'", "'}'", "'['", "']'", "','", "'.'", "';'", "':'", 
                     "'?'", "'*'", "'+'", "'-'", "'~'", "'!'", "'$'", "'@'", 
                     "'#'", "'%'", "'^'", "'&'", "'|'", "'\\'", "'/'", "'='", 
                     "'!='", "'=='", "'==='", "'<'", "'>'", "'<='", "'>='", 
                     "'+='", "'-='", "'*='", "'/='", "'%='", "'&='", "'|='", 
                     "'^='" ]

    symbolicNames = [ "<INVALID>", "SEC_RULE", "SEC_ACTION", "SEC_MARKER", 
                      "SEC_DEFAULT_ACTION", "SEC_RULE_SCRIPT", "SEC_INIT_COLLECTION", 
                      "SEC_COLLECTION", "INCLUDE", "SEC_COMPATIBILITY_MODE", 
                      "SEC_REWRITE_RULE", "OP_RX", "OP_CONTAINS", "OP_BEGINS_WITH", 
                      "OP_ENDS_WITH", "OP_EQ", "OP_NE", "OP_LT", "OP_GT", 
                      "OP_LE", "OP_GE", "OP_IP_MATCH", "OP_GEO_LOOKUP", 
                      "OP_HASH", "OP_RBL", "OP_URL_LEN", "OP_LENGTH", "OP_DIGITS", 
                      "OP_ALPHA", "OP_ALPHANUM", "OP_HEX", "OP_PREG_MATCH", 
                      "ACTION_DENY", "ACTION_PASS", "ACTION_DROP", "ACTION_ALLOW", 
                      "ACTION_LOG", "ACTION_NOLOG", "ACTION_CHAIN", "VAR_REQUEST_URI", 
                      "VAR_REQUEST_HEADERS", "VAR_RESPONSE_HEADERS", "VAR_REMOTE_ADDR", 
                      "VAR_ARGS", "VAR_ARGS_GET", "VAR_ARGS_POST", "VAR_FILES", 
                      "VAR_FILES_NAMES", "VAR_FILES_SIZES", "VAR_FILES_TMP_CONTENT", 
                      "VAR_ENV", "VAR_GEO", "VAR_TX", "VAR_IP", "LPAREN", 
                      "RPAREN", "LBRACE", "RBRACE", "LBRACKET", "RBRACKET", 
                      "COMMA", "DOT", "SEMICOLON", "COLON", "QUESTION", 
                      "STAR", "PLUS", "MINUS", "TILDE", "BANG", "DOLLAR", 
                      "AT", "HASH", "PERCENT", "CARET", "AMPERSAND", "PIPE", 
                      "BACKSLASH", "SLASH", "EQUALS", "EXCLAMATION_EQUALS", 
                      "DOUBLE_EQUALS", "TRIPLE_EQUALS", "LESS_THAN", "GREATER_THAN", 
                      "LESS_EQUALS", "GREATER_EQUALS", "PLUS_EQUALS", "MINUS_EQUALS", 
                      "STAR_EQUALS", "SLASH_EQUALS", "PERCENT_EQUALS", "AMPERSAND_EQUALS", 
                      "PIPE_EQUALS", "CARET_EQUALS", "STRING", "SINGLE_STRING", 
                      "NUMBER", "IDENTIFIER", "COMMENT", "WS" ]

    RULE_rulesFile = 0
    RULE_rule = 1
    RULE_secRule = 2
    RULE_secAction = 3
    RULE_secMarker = 4
    RULE_secDefaultAction = 5
    RULE_includeDirective = 6
    RULE_varList = 7
    RULE_var = 8
    RULE_opMode = 9
    RULE_pattern = 10
    RULE_quoteActionList = 11
    RULE_actionList = 12
    RULE_action = 13

    ruleNames =  [ "rulesFile", "rule", "secRule", "secAction", "secMarker", 
                   "secDefaultAction", "includeDirective", "varList", "var", 
                   "opMode", "pattern", "quoteActionList", "actionList", 
                   "action" ]

    EOF = Token.EOF
    SEC_RULE=1
    SEC_ACTION=2
    SEC_MARKER=3
    SEC_DEFAULT_ACTION=4
    SEC_RULE_SCRIPT=5
    SEC_INIT_COLLECTION=6
    SEC_COLLECTION=7
    INCLUDE=8
    SEC_COMPATIBILITY_MODE=9
    SEC_REWRITE_RULE=10
    OP_RX=11
    OP_CONTAINS=12
    OP_BEGINS_WITH=13
    OP_ENDS_WITH=14
    OP_EQ=15
    OP_NE=16
    OP_LT=17
    OP_GT=18
    OP_LE=19
    OP_GE=20
    OP_IP_MATCH=21
    OP_GEO_LOOKUP=22
    OP_HASH=23
    OP_RBL=24
    OP_URL_LEN=25
    OP_LENGTH=26
    OP_DIGITS=27
    OP_ALPHA=28
    OP_ALPHANUM=29
    OP_HEX=30
    OP_PREG_MATCH=31
    ACTION_DENY=32
    ACTION_PASS=33
    ACTION_DROP=34
    ACTION_ALLOW=35
    ACTION_LOG=36
    ACTION_NOLOG=37
    ACTION_CHAIN=38
    VAR_REQUEST_URI=39
    VAR_REQUEST_HEADERS=40
    VAR_RESPONSE_HEADERS=41
    VAR_REMOTE_ADDR=42
    VAR_ARGS=43
    VAR_ARGS_GET=44
    VAR_ARGS_POST=45
    VAR_FILES=46
    VAR_FILES_NAMES=47
    VAR_FILES_SIZES=48
    VAR_FILES_TMP_CONTENT=49
    VAR_ENV=50
    VAR_GEO=51
    VAR_TX=52
    VAR_IP=53
    LPAREN=54
    RPAREN=55
    LBRACE=56
    RBRACE=57
    LBRACKET=58
    RBRACKET=59
    COMMA=60
    DOT=61
    SEMICOLON=62
    COLON=63
    QUESTION=64
    STAR=65
    PLUS=66
    MINUS=67
    TILDE=68
    BANG=69
    DOLLAR=70
    AT=71
    HASH=72
    PERCENT=73
    CARET=74
    AMPERSAND=75
    PIPE=76
    BACKSLASH=77
    SLASH=78
    EQUALS=79
    EXCLAMATION_EQUALS=80
    DOUBLE_EQUALS=81
    TRIPLE_EQUALS=82
    LESS_THAN=83
    GREATER_THAN=84
    LESS_EQUALS=85
    GREATER_EQUALS=86
    PLUS_EQUALS=87
    MINUS_EQUALS=88
    STAR_EQUALS=89
    SLASH_EQUALS=90
    PERCENT_EQUALS=91
    AMPERSAND_EQUALS=92
    PIPE_EQUALS=93
    CARET_EQUALS=94
    STRING=95
    SINGLE_STRING=96
    NUMBER=97
    IDENTIFIER=98
    COMMENT=99
    WS=100

    def __init__(self, input:TokenStream, output:TextIO = sys.stdout):
        super().__init__(input, output)
        self.checkVersion("4.13.2")
        self._interp = ParserATNSimulator(self, self.atn, self.decisionsToDFA, self.sharedContextCache)
        self._predicates = None




    class RulesFileContext(ParserRuleContext):
        __slots__ = 'parser'

        def __init__(self, parser, parent:ParserRuleContext=None, invokingState:int=-1):
            super().__init__(parent, invokingState)
            self.parser = parser

        def EOF(self):
            return self.getToken(ModSecurityParser.EOF, 0)

        def rule_(self, i:int=None):
            if i is None:
                return self.getTypedRuleContexts(ModSecurityParser.RuleContext)
            else:
                return self.getTypedRuleContext(ModSecurityParser.RuleContext,i)


        def getRuleIndex(self):
            return ModSecurityParser.RULE_rulesFile

        def enterRule(self, listener:ParseTreeListener):
            if hasattr( listener, "enterRulesFile" ):
                listener.enterRulesFile(self)

        def exitRule(self, listener:ParseTreeListener):
            if hasattr( listener, "exitRulesFile" ):
                listener.exitRulesFile(self)




    def rulesFile(self):

        localctx = ModSecurityParser.RulesFileContext(self, self._ctx, self.state)
        self.enterRule(localctx, 0, self.RULE_rulesFile)
        self._la = 0 # Token type
        try:
            self.enterOuterAlt(localctx, 1)
            self.state = 29 
            self._errHandler.sync(self)
            _la = self._input.LA(1)
            while True:
                self.state = 28
                self.rule_()
                self.state = 31 
                self._errHandler.sync(self)
                _la = self._input.LA(1)
                if not ((((_la) & ~0x3f) == 0 and ((1 << _la) & 286) != 0)):
                    break

            self.state = 33
            self.match(ModSecurityParser.EOF)
        except RecognitionException as re:
            localctx.exception = re
            self._errHandler.reportError(self, re)
            self._errHandler.recover(self, re)
        finally:
            self.exitRule()
        return localctx


    class RuleContext(ParserRuleContext):
        __slots__ = 'parser'

        def __init__(self, parser, parent:ParserRuleContext=None, invokingState:int=-1):
            super().__init__(parent, invokingState)
            self.parser = parser

        def secRule(self):
            return self.getTypedRuleContext(ModSecurityParser.SecRuleContext,0)


        def secAction(self):
            return self.getTypedRuleContext(ModSecurityParser.SecActionContext,0)


        def secMarker(self):
            return self.getTypedRuleContext(ModSecurityParser.SecMarkerContext,0)


        def secDefaultAction(self):
            return self.getTypedRuleContext(ModSecurityParser.SecDefaultActionContext,0)


        def includeDirective(self):
            return self.getTypedRuleContext(ModSecurityParser.IncludeDirectiveContext,0)


        def getRuleIndex(self):
            return ModSecurityParser.RULE_rule

        def enterRule(self, listener:ParseTreeListener):
            if hasattr( listener, "enterRule" ):
                listener.enterRule(self)

        def exitRule(self, listener:ParseTreeListener):
            if hasattr( listener, "exitRule" ):
                listener.exitRule(self)




    def rule_(self):

        localctx = ModSecurityParser.RuleContext(self, self._ctx, self.state)
        self.enterRule(localctx, 2, self.RULE_rule)
        try:
            self.state = 40
            self._errHandler.sync(self)
            token = self._input.LA(1)
            if token in [1]:
                self.enterOuterAlt(localctx, 1)
                self.state = 35
                self.secRule()
                pass
            elif token in [2]:
                self.enterOuterAlt(localctx, 2)
                self.state = 36
                self.secAction()
                pass
            elif token in [3]:
                self.enterOuterAlt(localctx, 3)
                self.state = 37
                self.secMarker()
                pass
            elif token in [4]:
                self.enterOuterAlt(localctx, 4)
                self.state = 38
                self.secDefaultAction()
                pass
            elif token in [8]:
                self.enterOuterAlt(localctx, 5)
                self.state = 39
                self.includeDirective()
                pass
            else:
                raise NoViableAltException(self)

        except RecognitionException as re:
            localctx.exception = re
            self._errHandler.reportError(self, re)
            self._errHandler.recover(self, re)
        finally:
            self.exitRule()
        return localctx


    class SecRuleContext(ParserRuleContext):
        __slots__ = 'parser'

        def __init__(self, parser, parent:ParserRuleContext=None, invokingState:int=-1):
            super().__init__(parent, invokingState)
            self.parser = parser

        def SEC_RULE(self):
            return self.getToken(ModSecurityParser.SEC_RULE, 0)

        def varList(self):
            return self.getTypedRuleContext(ModSecurityParser.VarListContext,0)


        def opMode(self):
            return self.getTypedRuleContext(ModSecurityParser.OpModeContext,0)


        def pattern(self):
            return self.getTypedRuleContext(ModSecurityParser.PatternContext,0)


        def quoteActionList(self):
            return self.getTypedRuleContext(ModSecurityParser.QuoteActionListContext,0)


        def getRuleIndex(self):
            return ModSecurityParser.RULE_secRule

        def enterRule(self, listener:ParseTreeListener):
            if hasattr( listener, "enterSecRule" ):
                listener.enterSecRule(self)

        def exitRule(self, listener:ParseTreeListener):
            if hasattr( listener, "exitSecRule" ):
                listener.exitSecRule(self)




    def secRule(self):

        localctx = ModSecurityParser.SecRuleContext(self, self._ctx, self.state)
        self.enterRule(localctx, 4, self.RULE_secRule)
        self._la = 0 # Token type
        try:
            self.enterOuterAlt(localctx, 1)
            self.state = 42
            self.match(ModSecurityParser.SEC_RULE)
            self.state = 43
            self.varList()
            self.state = 44
            self.opMode()
            self.state = 45
            self.pattern()
            self.state = 47
            self._errHandler.sync(self)
            _la = self._input.LA(1)
            if _la==95 or _la==96:
                self.state = 46
                self.quoteActionList()


        except RecognitionException as re:
            localctx.exception = re
            self._errHandler.reportError(self, re)
            self._errHandler.recover(self, re)
        finally:
            self.exitRule()
        return localctx


    class SecActionContext(ParserRuleContext):
        __slots__ = 'parser'

        def __init__(self, parser, parent:ParserRuleContext=None, invokingState:int=-1):
            super().__init__(parent, invokingState)
            self.parser = parser

        def SEC_ACTION(self):
            return self.getToken(ModSecurityParser.SEC_ACTION, 0)

        def quoteActionList(self):
            return self.getTypedRuleContext(ModSecurityParser.QuoteActionListContext,0)


        def getRuleIndex(self):
            return ModSecurityParser.RULE_secAction

        def enterRule(self, listener:ParseTreeListener):
            if hasattr( listener, "enterSecAction" ):
                listener.enterSecAction(self)

        def exitRule(self, listener:ParseTreeListener):
            if hasattr( listener, "exitSecAction" ):
                listener.exitSecAction(self)




    def secAction(self):

        localctx = ModSecurityParser.SecActionContext(self, self._ctx, self.state)
        self.enterRule(localctx, 6, self.RULE_secAction)
        try:
            self.enterOuterAlt(localctx, 1)
            self.state = 49
            self.match(ModSecurityParser.SEC_ACTION)
            self.state = 50
            self.quoteActionList()
        except RecognitionException as re:
            localctx.exception = re
            self._errHandler.reportError(self, re)
            self._errHandler.recover(self, re)
        finally:
            self.exitRule()
        return localctx


    class SecMarkerContext(ParserRuleContext):
        __slots__ = 'parser'

        def __init__(self, parser, parent:ParserRuleContext=None, invokingState:int=-1):
            super().__init__(parent, invokingState)
            self.parser = parser

        def SEC_MARKER(self):
            return self.getToken(ModSecurityParser.SEC_MARKER, 0)

        def STRING(self):
            return self.getToken(ModSecurityParser.STRING, 0)

        def getRuleIndex(self):
            return ModSecurityParser.RULE_secMarker

        def enterRule(self, listener:ParseTreeListener):
            if hasattr( listener, "enterSecMarker" ):
                listener.enterSecMarker(self)

        def exitRule(self, listener:ParseTreeListener):
            if hasattr( listener, "exitSecMarker" ):
                listener.exitSecMarker(self)




    def secMarker(self):

        localctx = ModSecurityParser.SecMarkerContext(self, self._ctx, self.state)
        self.enterRule(localctx, 8, self.RULE_secMarker)
        self._la = 0 # Token type
        try:
            self.enterOuterAlt(localctx, 1)
            self.state = 52
            self.match(ModSecurityParser.SEC_MARKER)
            self.state = 54
            self._errHandler.sync(self)
            _la = self._input.LA(1)
            if _la==95:
                self.state = 53
                self.match(ModSecurityParser.STRING)


        except RecognitionException as re:
            localctx.exception = re
            self._errHandler.reportError(self, re)
            self._errHandler.recover(self, re)
        finally:
            self.exitRule()
        return localctx


    class SecDefaultActionContext(ParserRuleContext):
        __slots__ = 'parser'

        def __init__(self, parser, parent:ParserRuleContext=None, invokingState:int=-1):
            super().__init__(parent, invokingState)
            self.parser = parser

        def SEC_DEFAULT_ACTION(self):
            return self.getToken(ModSecurityParser.SEC_DEFAULT_ACTION, 0)

        def quoteActionList(self):
            return self.getTypedRuleContext(ModSecurityParser.QuoteActionListContext,0)


        def getRuleIndex(self):
            return ModSecurityParser.RULE_secDefaultAction

        def enterRule(self, listener:ParseTreeListener):
            if hasattr( listener, "enterSecDefaultAction" ):
                listener.enterSecDefaultAction(self)

        def exitRule(self, listener:ParseTreeListener):
            if hasattr( listener, "exitSecDefaultAction" ):
                listener.exitSecDefaultAction(self)




    def secDefaultAction(self):

        localctx = ModSecurityParser.SecDefaultActionContext(self, self._ctx, self.state)
        self.enterRule(localctx, 10, self.RULE_secDefaultAction)
        try:
            self.enterOuterAlt(localctx, 1)
            self.state = 56
            self.match(ModSecurityParser.SEC_DEFAULT_ACTION)
            self.state = 57
            self.quoteActionList()
        except RecognitionException as re:
            localctx.exception = re
            self._errHandler.reportError(self, re)
            self._errHandler.recover(self, re)
        finally:
            self.exitRule()
        return localctx


    class IncludeDirectiveContext(ParserRuleContext):
        __slots__ = 'parser'

        def __init__(self, parser, parent:ParserRuleContext=None, invokingState:int=-1):
            super().__init__(parent, invokingState)
            self.parser = parser

        def INCLUDE(self):
            return self.getToken(ModSecurityParser.INCLUDE, 0)

        def STRING(self):
            return self.getToken(ModSecurityParser.STRING, 0)

        def getRuleIndex(self):
            return ModSecurityParser.RULE_includeDirective

        def enterRule(self, listener:ParseTreeListener):
            if hasattr( listener, "enterIncludeDirective" ):
                listener.enterIncludeDirective(self)

        def exitRule(self, listener:ParseTreeListener):
            if hasattr( listener, "exitIncludeDirective" ):
                listener.exitIncludeDirective(self)




    def includeDirective(self):

        localctx = ModSecurityParser.IncludeDirectiveContext(self, self._ctx, self.state)
        self.enterRule(localctx, 12, self.RULE_includeDirective)
        try:
            self.enterOuterAlt(localctx, 1)
            self.state = 59
            self.match(ModSecurityParser.INCLUDE)
            self.state = 60
            self.match(ModSecurityParser.STRING)
        except RecognitionException as re:
            localctx.exception = re
            self._errHandler.reportError(self, re)
            self._errHandler.recover(self, re)
        finally:
            self.exitRule()
        return localctx


    class VarListContext(ParserRuleContext):
        __slots__ = 'parser'

        def __init__(self, parser, parent:ParserRuleContext=None, invokingState:int=-1):
            super().__init__(parent, invokingState)
            self.parser = parser

        def var(self, i:int=None):
            if i is None:
                return self.getTypedRuleContexts(ModSecurityParser.VarContext)
            else:
                return self.getTypedRuleContext(ModSecurityParser.VarContext,i)


        def PIPE(self, i:int=None):
            if i is None:
                return self.getTokens(ModSecurityParser.PIPE)
            else:
                return self.getToken(ModSecurityParser.PIPE, i)

        def getRuleIndex(self):
            return ModSecurityParser.RULE_varList

        def enterRule(self, listener:ParseTreeListener):
            if hasattr( listener, "enterVarList" ):
                listener.enterVarList(self)

        def exitRule(self, listener:ParseTreeListener):
            if hasattr( listener, "exitVarList" ):
                listener.exitVarList(self)




    def varList(self):

        localctx = ModSecurityParser.VarListContext(self, self._ctx, self.state)
        self.enterRule(localctx, 14, self.RULE_varList)
        self._la = 0 # Token type
        try:
            self.enterOuterAlt(localctx, 1)
            self.state = 62
            self.var()
            self.state = 67
            self._errHandler.sync(self)
            _la = self._input.LA(1)
            while _la==76:
                self.state = 63
                self.match(ModSecurityParser.PIPE)
                self.state = 64
                self.var()
                self.state = 69
                self._errHandler.sync(self)
                _la = self._input.LA(1)

        except RecognitionException as re:
            localctx.exception = re
            self._errHandler.reportError(self, re)
            self._errHandler.recover(self, re)
        finally:
            self.exitRule()
        return localctx


    class VarContext(ParserRuleContext):
        __slots__ = 'parser'

        def __init__(self, parser, parent:ParserRuleContext=None, invokingState:int=-1):
            super().__init__(parent, invokingState)
            self.parser = parser

        def VAR_REQUEST_URI(self):
            return self.getToken(ModSecurityParser.VAR_REQUEST_URI, 0)

        def VAR_REMOTE_ADDR(self):
            return self.getToken(ModSecurityParser.VAR_REMOTE_ADDR, 0)

        def VAR_ARGS(self):
            return self.getToken(ModSecurityParser.VAR_ARGS, 0)

        def VAR_ARGS_GET(self):
            return self.getToken(ModSecurityParser.VAR_ARGS_GET, 0)

        def VAR_ARGS_POST(self):
            return self.getToken(ModSecurityParser.VAR_ARGS_POST, 0)

        def VAR_FILES(self):
            return self.getToken(ModSecurityParser.VAR_FILES, 0)

        def VAR_FILES_NAMES(self):
            return self.getToken(ModSecurityParser.VAR_FILES_NAMES, 0)

        def VAR_FILES_SIZES(self):
            return self.getToken(ModSecurityParser.VAR_FILES_SIZES, 0)

        def VAR_FILES_TMP_CONTENT(self):
            return self.getToken(ModSecurityParser.VAR_FILES_TMP_CONTENT, 0)

        def VAR_ENV(self):
            return self.getToken(ModSecurityParser.VAR_ENV, 0)

        def IDENTIFIER(self):
            return self.getToken(ModSecurityParser.IDENTIFIER, 0)

        def VAR_GEO(self):
            return self.getToken(ModSecurityParser.VAR_GEO, 0)

        def VAR_TX(self):
            return self.getToken(ModSecurityParser.VAR_TX, 0)

        def VAR_IP(self):
            return self.getToken(ModSecurityParser.VAR_IP, 0)

        def VAR_REQUEST_HEADERS(self):
            return self.getToken(ModSecurityParser.VAR_REQUEST_HEADERS, 0)

        def VAR_RESPONSE_HEADERS(self):
            return self.getToken(ModSecurityParser.VAR_RESPONSE_HEADERS, 0)

        def getRuleIndex(self):
            return ModSecurityParser.RULE_var

        def enterRule(self, listener:ParseTreeListener):
            if hasattr( listener, "enterVar" ):
                listener.enterVar(self)

        def exitRule(self, listener:ParseTreeListener):
            if hasattr( listener, "exitVar" ):
                listener.exitVar(self)




    def var(self):

        localctx = ModSecurityParser.VarContext(self, self._ctx, self.state)
        self.enterRule(localctx, 16, self.RULE_var)
        try:
            self.state = 91
            self._errHandler.sync(self)
            token = self._input.LA(1)
            if token in [39]:
                self.enterOuterAlt(localctx, 1)
                self.state = 70
                self.match(ModSecurityParser.VAR_REQUEST_URI)
                pass
            elif token in [42]:
                self.enterOuterAlt(localctx, 2)
                self.state = 71
                self.match(ModSecurityParser.VAR_REMOTE_ADDR)
                pass
            elif token in [43]:
                self.enterOuterAlt(localctx, 3)
                self.state = 72
                self.match(ModSecurityParser.VAR_ARGS)
                pass
            elif token in [44]:
                self.enterOuterAlt(localctx, 4)
                self.state = 73
                self.match(ModSecurityParser.VAR_ARGS_GET)
                pass
            elif token in [45]:
                self.enterOuterAlt(localctx, 5)
                self.state = 74
                self.match(ModSecurityParser.VAR_ARGS_POST)
                pass
            elif token in [46]:
                self.enterOuterAlt(localctx, 6)
                self.state = 75
                self.match(ModSecurityParser.VAR_FILES)
                pass
            elif token in [47]:
                self.enterOuterAlt(localctx, 7)
                self.state = 76
                self.match(ModSecurityParser.VAR_FILES_NAMES)
                pass
            elif token in [48]:
                self.enterOuterAlt(localctx, 8)
                self.state = 77
                self.match(ModSecurityParser.VAR_FILES_SIZES)
                pass
            elif token in [49]:
                self.enterOuterAlt(localctx, 9)
                self.state = 78
                self.match(ModSecurityParser.VAR_FILES_TMP_CONTENT)
                pass
            elif token in [50]:
                self.enterOuterAlt(localctx, 10)
                self.state = 79
                self.match(ModSecurityParser.VAR_ENV)
                self.state = 80
                self.match(ModSecurityParser.IDENTIFIER)
                pass
            elif token in [51]:
                self.enterOuterAlt(localctx, 11)
                self.state = 81
                self.match(ModSecurityParser.VAR_GEO)
                self.state = 82
                self.match(ModSecurityParser.IDENTIFIER)
                pass
            elif token in [52]:
                self.enterOuterAlt(localctx, 12)
                self.state = 83
                self.match(ModSecurityParser.VAR_TX)
                self.state = 84
                self.match(ModSecurityParser.IDENTIFIER)
                pass
            elif token in [53]:
                self.enterOuterAlt(localctx, 13)
                self.state = 85
                self.match(ModSecurityParser.VAR_IP)
                self.state = 86
                self.match(ModSecurityParser.IDENTIFIER)
                pass
            elif token in [40]:
                self.enterOuterAlt(localctx, 14)
                self.state = 87
                self.match(ModSecurityParser.VAR_REQUEST_HEADERS)
                self.state = 88
                self.match(ModSecurityParser.IDENTIFIER)
                pass
            elif token in [41]:
                self.enterOuterAlt(localctx, 15)
                self.state = 89
                self.match(ModSecurityParser.VAR_RESPONSE_HEADERS)
                self.state = 90
                self.match(ModSecurityParser.IDENTIFIER)
                pass
            else:
                raise NoViableAltException(self)

        except RecognitionException as re:
            localctx.exception = re
            self._errHandler.reportError(self, re)
            self._errHandler.recover(self, re)
        finally:
            self.exitRule()
        return localctx


    class OpModeContext(ParserRuleContext):
        __slots__ = 'parser'

        def __init__(self, parser, parent:ParserRuleContext=None, invokingState:int=-1):
            super().__init__(parent, invokingState)
            self.parser = parser

        def OP_RX(self):
            return self.getToken(ModSecurityParser.OP_RX, 0)

        def OP_CONTAINS(self):
            return self.getToken(ModSecurityParser.OP_CONTAINS, 0)

        def OP_BEGINS_WITH(self):
            return self.getToken(ModSecurityParser.OP_BEGINS_WITH, 0)

        def OP_ENDS_WITH(self):
            return self.getToken(ModSecurityParser.OP_ENDS_WITH, 0)

        def OP_EQ(self):
            return self.getToken(ModSecurityParser.OP_EQ, 0)

        def OP_NE(self):
            return self.getToken(ModSecurityParser.OP_NE, 0)

        def OP_LT(self):
            return self.getToken(ModSecurityParser.OP_LT, 0)

        def OP_GT(self):
            return self.getToken(ModSecurityParser.OP_GT, 0)

        def OP_LE(self):
            return self.getToken(ModSecurityParser.OP_LE, 0)

        def OP_GE(self):
            return self.getToken(ModSecurityParser.OP_GE, 0)

        def OP_IP_MATCH(self):
            return self.getToken(ModSecurityParser.OP_IP_MATCH, 0)

        def OP_GEO_LOOKUP(self):
            return self.getToken(ModSecurityParser.OP_GEO_LOOKUP, 0)

        def OP_HASH(self):
            return self.getToken(ModSecurityParser.OP_HASH, 0)

        def OP_RBL(self):
            return self.getToken(ModSecurityParser.OP_RBL, 0)

        def OP_URL_LEN(self):
            return self.getToken(ModSecurityParser.OP_URL_LEN, 0)

        def OP_LENGTH(self):
            return self.getToken(ModSecurityParser.OP_LENGTH, 0)

        def OP_DIGITS(self):
            return self.getToken(ModSecurityParser.OP_DIGITS, 0)

        def OP_ALPHA(self):
            return self.getToken(ModSecurityParser.OP_ALPHA, 0)

        def OP_ALPHANUM(self):
            return self.getToken(ModSecurityParser.OP_ALPHANUM, 0)

        def OP_HEX(self):
            return self.getToken(ModSecurityParser.OP_HEX, 0)

        def OP_PREG_MATCH(self):
            return self.getToken(ModSecurityParser.OP_PREG_MATCH, 0)

        def getRuleIndex(self):
            return ModSecurityParser.RULE_opMode

        def enterRule(self, listener:ParseTreeListener):
            if hasattr( listener, "enterOpMode" ):
                listener.enterOpMode(self)

        def exitRule(self, listener:ParseTreeListener):
            if hasattr( listener, "exitOpMode" ):
                listener.exitOpMode(self)




    def opMode(self):

        localctx = ModSecurityParser.OpModeContext(self, self._ctx, self.state)
        self.enterRule(localctx, 18, self.RULE_opMode)
        self._la = 0 # Token type
        try:
            self.enterOuterAlt(localctx, 1)
            self.state = 93
            _la = self._input.LA(1)
            if not((((_la) & ~0x3f) == 0 and ((1 << _la) & 4294965248) != 0)):
                self._errHandler.recoverInline(self)
            else:
                self._errHandler.reportMatch(self)
                self.consume()
        except RecognitionException as re:
            localctx.exception = re
            self._errHandler.reportError(self, re)
            self._errHandler.recover(self, re)
        finally:
            self.exitRule()
        return localctx


    class PatternContext(ParserRuleContext):
        __slots__ = 'parser'

        def __init__(self, parser, parent:ParserRuleContext=None, invokingState:int=-1):
            super().__init__(parent, invokingState)
            self.parser = parser

        def STRING(self):
            return self.getToken(ModSecurityParser.STRING, 0)

        def SINGLE_STRING(self):
            return self.getToken(ModSecurityParser.SINGLE_STRING, 0)

        def NUMBER(self):
            return self.getToken(ModSecurityParser.NUMBER, 0)

        def IDENTIFIER(self):
            return self.getToken(ModSecurityParser.IDENTIFIER, 0)

        def getRuleIndex(self):
            return ModSecurityParser.RULE_pattern

        def enterRule(self, listener:ParseTreeListener):
            if hasattr( listener, "enterPattern" ):
                listener.enterPattern(self)

        def exitRule(self, listener:ParseTreeListener):
            if hasattr( listener, "exitPattern" ):
                listener.exitPattern(self)




    def pattern(self):

        localctx = ModSecurityParser.PatternContext(self, self._ctx, self.state)
        self.enterRule(localctx, 20, self.RULE_pattern)
        self._la = 0 # Token type
        try:
            self.enterOuterAlt(localctx, 1)
            self.state = 95
            _la = self._input.LA(1)
            if not(((((_la - 95)) & ~0x3f) == 0 and ((1 << (_la - 95)) & 15) != 0)):
                self._errHandler.recoverInline(self)
            else:
                self._errHandler.reportMatch(self)
                self.consume()
        except RecognitionException as re:
            localctx.exception = re
            self._errHandler.reportError(self, re)
            self._errHandler.recover(self, re)
        finally:
            self.exitRule()
        return localctx


    class QuoteActionListContext(ParserRuleContext):
        __slots__ = 'parser'

        def __init__(self, parser, parent:ParserRuleContext=None, invokingState:int=-1):
            super().__init__(parent, invokingState)
            self.parser = parser

        def STRING(self):
            return self.getToken(ModSecurityParser.STRING, 0)

        def SINGLE_STRING(self):
            return self.getToken(ModSecurityParser.SINGLE_STRING, 0)

        def getRuleIndex(self):
            return ModSecurityParser.RULE_quoteActionList

        def enterRule(self, listener:ParseTreeListener):
            if hasattr( listener, "enterQuoteActionList" ):
                listener.enterQuoteActionList(self)

        def exitRule(self, listener:ParseTreeListener):
            if hasattr( listener, "exitQuoteActionList" ):
                listener.exitQuoteActionList(self)




    def quoteActionList(self):

        localctx = ModSecurityParser.QuoteActionListContext(self, self._ctx, self.state)
        self.enterRule(localctx, 22, self.RULE_quoteActionList)
        self._la = 0 # Token type
        try:
            self.enterOuterAlt(localctx, 1)
            self.state = 97
            _la = self._input.LA(1)
            if not(_la==95 or _la==96):
                self._errHandler.recoverInline(self)
            else:
                self._errHandler.reportMatch(self)
                self.consume()
        except RecognitionException as re:
            localctx.exception = re
            self._errHandler.reportError(self, re)
            self._errHandler.recover(self, re)
        finally:
            self.exitRule()
        return localctx


    class ActionListContext(ParserRuleContext):
        __slots__ = 'parser'

        def __init__(self, parser, parent:ParserRuleContext=None, invokingState:int=-1):
            super().__init__(parent, invokingState)
            self.parser = parser

        def action(self, i:int=None):
            if i is None:
                return self.getTypedRuleContexts(ModSecurityParser.ActionContext)
            else:
                return self.getTypedRuleContext(ModSecurityParser.ActionContext,i)


        def COMMA(self, i:int=None):
            if i is None:
                return self.getTokens(ModSecurityParser.COMMA)
            else:
                return self.getToken(ModSecurityParser.COMMA, i)

        def getRuleIndex(self):
            return ModSecurityParser.RULE_actionList

        def enterRule(self, listener:ParseTreeListener):
            if hasattr( listener, "enterActionList" ):
                listener.enterActionList(self)

        def exitRule(self, listener:ParseTreeListener):
            if hasattr( listener, "exitActionList" ):
                listener.exitActionList(self)




    def actionList(self):

        localctx = ModSecurityParser.ActionListContext(self, self._ctx, self.state)
        self.enterRule(localctx, 24, self.RULE_actionList)
        self._la = 0 # Token type
        try:
            self.enterOuterAlt(localctx, 1)
            self.state = 99
            self.action()
            self.state = 104
            self._errHandler.sync(self)
            _la = self._input.LA(1)
            while _la==60:
                self.state = 100
                self.match(ModSecurityParser.COMMA)
                self.state = 101
                self.action()
                self.state = 106
                self._errHandler.sync(self)
                _la = self._input.LA(1)

        except RecognitionException as re:
            localctx.exception = re
            self._errHandler.reportError(self, re)
            self._errHandler.recover(self, re)
        finally:
            self.exitRule()
        return localctx


    class ActionContext(ParserRuleContext):
        __slots__ = 'parser'

        def __init__(self, parser, parent:ParserRuleContext=None, invokingState:int=-1):
            super().__init__(parent, invokingState)
            self.parser = parser

        def ACTION_DENY(self):
            return self.getToken(ModSecurityParser.ACTION_DENY, 0)

        def ACTION_PASS(self):
            return self.getToken(ModSecurityParser.ACTION_PASS, 0)

        def ACTION_DROP(self):
            return self.getToken(ModSecurityParser.ACTION_DROP, 0)

        def ACTION_ALLOW(self):
            return self.getToken(ModSecurityParser.ACTION_ALLOW, 0)

        def ACTION_LOG(self):
            return self.getToken(ModSecurityParser.ACTION_LOG, 0)

        def ACTION_NOLOG(self):
            return self.getToken(ModSecurityParser.ACTION_NOLOG, 0)

        def ACTION_CHAIN(self):
            return self.getToken(ModSecurityParser.ACTION_CHAIN, 0)

        def IDENTIFIER(self, i:int=None):
            if i is None:
                return self.getTokens(ModSecurityParser.IDENTIFIER)
            else:
                return self.getToken(ModSecurityParser.IDENTIFIER, i)

        def COLON(self):
            return self.getToken(ModSecurityParser.COLON, 0)

        def STRING(self):
            return self.getToken(ModSecurityParser.STRING, 0)

        def SINGLE_STRING(self):
            return self.getToken(ModSecurityParser.SINGLE_STRING, 0)

        def NUMBER(self):
            return self.getToken(ModSecurityParser.NUMBER, 0)

        def getRuleIndex(self):
            return ModSecurityParser.RULE_action

        def enterRule(self, listener:ParseTreeListener):
            if hasattr( listener, "enterAction" ):
                listener.enterAction(self)

        def exitRule(self, listener:ParseTreeListener):
            if hasattr( listener, "exitAction" ):
                listener.exitAction(self)




    def action(self):

        localctx = ModSecurityParser.ActionContext(self, self._ctx, self.state)
        self.enterRule(localctx, 26, self.RULE_action)
        self._la = 0 # Token type
        try:
            self.state = 119
            self._errHandler.sync(self)
            token = self._input.LA(1)
            if token in [32]:
                self.enterOuterAlt(localctx, 1)
                self.state = 107
                self.match(ModSecurityParser.ACTION_DENY)
                pass
            elif token in [33]:
                self.enterOuterAlt(localctx, 2)
                self.state = 108
                self.match(ModSecurityParser.ACTION_PASS)
                pass
            elif token in [34]:
                self.enterOuterAlt(localctx, 3)
                self.state = 109
                self.match(ModSecurityParser.ACTION_DROP)
                pass
            elif token in [35]:
                self.enterOuterAlt(localctx, 4)
                self.state = 110
                self.match(ModSecurityParser.ACTION_ALLOW)
                pass
            elif token in [36]:
                self.enterOuterAlt(localctx, 5)
                self.state = 111
                self.match(ModSecurityParser.ACTION_LOG)
                pass
            elif token in [37]:
                self.enterOuterAlt(localctx, 6)
                self.state = 112
                self.match(ModSecurityParser.ACTION_NOLOG)
                pass
            elif token in [38]:
                self.enterOuterAlt(localctx, 7)
                self.state = 113
                self.match(ModSecurityParser.ACTION_CHAIN)
                pass
            elif token in [98]:
                self.enterOuterAlt(localctx, 8)
                self.state = 114
                self.match(ModSecurityParser.IDENTIFIER)
                self.state = 117
                self._errHandler.sync(self)
                _la = self._input.LA(1)
                if _la==63:
                    self.state = 115
                    self.match(ModSecurityParser.COLON)
                    self.state = 116
                    _la = self._input.LA(1)
                    if not(((((_la - 95)) & ~0x3f) == 0 and ((1 << (_la - 95)) & 15) != 0)):
                        self._errHandler.recoverInline(self)
                    else:
                        self._errHandler.reportMatch(self)
                        self.consume()


                pass
            else:
                raise NoViableAltException(self)

        except RecognitionException as re:
            localctx.exception = re
            self._errHandler.reportError(self, re)
            self._errHandler.recover(self, re)
        finally:
            self.exitRule()
        return localctx





