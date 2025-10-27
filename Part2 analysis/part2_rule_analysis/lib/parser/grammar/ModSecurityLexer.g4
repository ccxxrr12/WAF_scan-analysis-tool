// ModSecurityLexer.g4
lexer grammar ModSecurityLexer;

// 关键字
SEC_RULE: 'SecRule';
SEC_ACTION: 'SecAction';
SEC_MARKER: 'SecMarker';
SEC_DEFAULT_ACTION: 'SecDefaultAction';
SEC_RULE_SCRIPT: 'SecRuleScript';
SEC_INIT_COLLECTION: 'SecInitCollection';
SEC_COLLECTION: 'SecCollection';
INCLUDE: 'Include';
SEC_COMPATIBILITY_MODE: 'SecCompatibilityMode';
SEC_REWRITE_RULE: 'SecRewriteRule';

// 运算符
OP_RX: '@rx';
OP_CONTAINS: '@contains';
OP_BEGINS_WITH: '@beginsWith';
OP_ENDS_WITH: '@endsWith';
OP_EQ: '@eq';
OP_NE: '@ne';
OP_LT: '@lt';
OP_GT: '@gt';
OP_LE: '@le';
OP_GE: '@ge';
OP_IP_MATCH: '@ipMatch';
OP_GEO_LOOKUP: '@geoLookup';
OP_HASH: '@hash';
OP_RBL: '@rbl';
OP_URL_LEN: '@urlLen';
OP_LENGTH: '@length';
OP_DIGITS: '@digits';
OP_ALPHA: '@alpha';
OP_ALPHANUM: '@alphanum';
OP_HEX: '@hex';
OP_PREG_MATCH: '@pregMatch';

// 通用 operator（例如 @detectSQLi 或其他自定义 operator）
OP_GENERIC: '@' [a-zA-Z_] [a-zA-Z0-9_]*;

// 动作
ACTION_DENY: 'deny';
ACTION_PASS: 'pass';
ACTION_DROP: 'drop';
ACTION_ALLOW: 'allow';
ACTION_LOG: 'log';
ACTION_NOLOG: 'nolog';
ACTION_CHAIN: 'chain';

// 变量
VAR_REQUEST_URI: 'REQUEST_URI';
VAR_REQUEST_HEADERS: 'REQUEST_HEADERS:';
VAR_RESPONSE_HEADERS: 'RESPONSE_HEADERS:';
VAR_REMOTE_ADDR: 'REMOTE_ADDR';
VAR_ARGS: 'ARGS';
VAR_ARGS_GET: 'ARGS_GET';
VAR_ARGS_POST: 'ARGS_POST';
VAR_FILES: 'FILES';
VAR_FILES_NAMES: 'FILES_NAMES';
VAR_FILES_SIZES: 'FILES_SIZES';
VAR_FILES_TMP_CONTENT: 'FILES_TMP_CONTENT';
VAR_ENV: 'ENV:';
VAR_GEO: 'GEO:';
VAR_TX: 'TX:';
VAR_IP: 'IP:';

// 特殊字符
LPAREN: '(';
RPAREN: ')';
LBRACE: '{';
RBRACE: '}';
LBRACKET: '[';
RBRACKET: ']';
COMMA: ',';
DOT: '.';
SEMICOLON: ';';
COLON: ':';
QUESTION: '?';
STAR: '*';
PLUS: '+';
MINUS: '-';
TILDE: '~';
BANG: '!';
DOLLAR: '$';
AT: '@';
HASH: '#';
PERCENT: '%';
CARET: '^';
AMPERSAND: '&';
PIPE: '|';
BACKSLASH: '\\';
SLASH: '/';
EQUALS: '=';
EXCLAMATION_EQUALS: '!=';
DOUBLE_EQUALS: '==';
TRIPLE_EQUALS: '===';
LESS_THAN: '<';
GREATER_THAN: '>';
LESS_EQUALS: '<=';
GREATER_EQUALS: '>=';
PLUS_EQUALS: '+=';
MINUS_EQUALS: '-=';
STAR_EQUALS: '*=';
SLASH_EQUALS: '/=';
PERCENT_EQUALS: '%=';
AMPERSAND_EQUALS: '&=';
PIPE_EQUALS: '|=';
CARET_EQUALS: '^=';

// 字符串
STRING: '"' (ESC | ~["\\])* '"';
SINGLE_STRING: '\'' (ESC | ~['\\])* '\'';

fragment ESC: '\\' (["\\/bfnrt] | UNICODE);
fragment UNICODE: 'u' HEX HEX HEX HEX;
fragment HEX: [0-9a-fA-F];

// 数字
NUMBER: [0-9]+ (DOT [0-9]+)?;

// 标识符
IDENTIFIER: [a-zA-Z_][a-zA-Z0-9_]*;

// 注释
COMMENT: '#' ~[\r\n]* -> skip;

// 空白字符
WS: [ \t\r\n]+ -> skip;