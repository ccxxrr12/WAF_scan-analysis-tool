// ModSecurityParser.g4
parser grammar ModSecurityParser;

options { tokenVocab=ModSecurityLexer; }

// 规则文件
rulesFile: rule+ EOF;

// 规则类型
rule: secRule | secAction | secMarker | secDefaultAction | includeDirective;

// SecRule规则
// 支持两种形式：
// 1) SecRule VARS OP PATTERN "actions"
// 2) SecRule VARS "@op pattern" "actions"  （CRS 常见写法，将 operator+pattern 放在一个 STRING 中）
secRule: SEC_RULE varList (opMode pattern | STRING) (quoteActionList | actionList)?;

// SecAction规则
secAction: SEC_ACTION quoteActionList;

// SecMarker规则
secMarker: SEC_MARKER STRING?;

// SecDefaultAction规则
secDefaultAction: SEC_DEFAULT_ACTION quoteActionList;

// Include指令
includeDirective: INCLUDE STRING;

// 变量列表
varList: var (PIPE var)*;

// 单个变量
var: VAR_REQUEST_URI | VAR_REMOTE_ADDR | VAR_ARGS | VAR_ARGS_GET | VAR_ARGS_POST | VAR_FILES | VAR_FILES_NAMES | VAR_FILES_SIZES | VAR_FILES_TMP_CONTENT | VAR_ENV IDENTIFIER | VAR_GEO IDENTIFIER | VAR_TX IDENTIFIER | VAR_IP IDENTIFIER | VAR_REQUEST_HEADERS IDENTIFIER | VAR_RESPONSE_HEADERS IDENTIFIER;

// 运算符模式
opMode: OP_RX | OP_CONTAINS | OP_BEGINS_WITH | OP_ENDS_WITH | OP_EQ | OP_NE | OP_LT | OP_GT | OP_LE | OP_GE | OP_IP_MATCH | OP_GEO_LOOKUP | OP_HASH | OP_RBL | OP_URL_LEN | OP_LENGTH | OP_DIGITS | OP_ALPHA | OP_ALPHANUM | OP_HEX | OP_PREG_MATCH;

// 模式
pattern: STRING | SINGLE_STRING | NUMBER | IDENTIFIER;

// 带引号的动作列表
quoteActionList: STRING | SINGLE_STRING;

// 动作列表
actionList: action (COMMA action)*;

// 单个动作
action: ACTION_DENY | ACTION_PASS | ACTION_DROP | ACTION_ALLOW | ACTION_LOG | ACTION_NOLOG | ACTION_CHAIN | IDENTIFIER (COLON (STRING | SINGLE_STRING | NUMBER | IDENTIFIER))?;