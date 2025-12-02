// ModSecurityParser.g4
parser grammar ModSecurityParser;

options { tokenVocab=ModSecurityLexer; }

// 规则文件
rulesFile: (directive | rule | includeDirective)* EOF;

// 指令类型
directive: 
    secRuleEngine | secRequestBodyAccess | secResponseBodyAccess | 
    secAuditEngine | secAuditLog | secAuditLogParts | secAuditLogType |
    secDebugLog | secDebugLogLevel | secRequestBodyLimit | secResponseBodyLimit |
    secArgumentsLimit | secWebAppId | secHashMethod | secHashKey |
    secUnicodeMap | secDefaultCharset | secContentInjection | secPcreMatchLimit |
    secCompatibilityMode | secDefaultAction | secMarker | secRuleRemoveById |
    secRuleRemoveByMsg | secRuleRemoveByTag | secRuleUpdateById | secRuleUpdateTargetById |
    secRuleInheritance | secCollection | secInitCollection | secGeoLookupDb |
    secDisableBackendCompression | secServerSignature | secConnectionEngine |
    secResponseBodyMimeType | secRequestBodyJsonDepthLimit | secStreamOutputBodyInspection |
    secStatusEngine | secRuleUpdate | secHttpBlKey | secStreamOutputBodyBuffer |
    secDisableForwardedProxyHeaders;

// 规则类型
rule: secRule | secAction | secRuleScript | secRewriteRule;

// SecRule规则
secRule: 
    SEC_RULE targets (operatorPattern | STRING)? 
    (actionString | actionList)? 
    (chainRule)*;

chainRule: ACTION_CHAIN targets (operatorPattern | STRING)? (actionString | actionList)?;

targets: transformationList (PIPE transformationList)*;
transformationList: variable (PIPE transformation)*;
transformation: T_LOWERCASE | T_UPPERCASE | T_URL_DECODE | T_HTML_ENTITY_DECODE | 
                T_BASE64_DECODE | T_BASE64_ENCODE | T_HEX_DECODE | T_HEX_ENCODE |
                T_MD5 | T_SHA1 | T_COMPRESS_WHITESPACE | T_CSS_DECODE | T_JS_DECODE |
                T_ESCAPE_SEQ_DECODE | T_REMOVE_WHITESPACE | T_REPLACE_COMMENTS |
                T_REMOVE_COMMENTS | T_REMOVE_NULLS | T_TRIM | T_TRIM_LEFT | T_TRIM_RIGHT |
                T_NORMALISE_PATH | T_NORMALISE_PATH_WIN | T_LENGTH | T_NONE |
                T_PARITY_EVEN_7BIT | T_PARITY_ODD_7BIT | T_PARITY_ZERO_7BIT |
                T_REMOVE_RANGE | T_REPLACE_NULLS | T_UTF8_TO_UNICODE;

operatorPattern: operator patternList;
operator: 
    OP_RX | OP_CONTAINS | OP_BEGINS_WITH | OP_ENDS_WITH | OP_EQ | OP_NE | 
    OP_LT | OP_GT | OP_LE | OP_GE | OP_IP_MATCH | OP_IP_MATCH_F | OP_GEO_LOOKUP | 
    OP_HASH | OP_RBL | OP_URL_LEN | OP_LENGTH | OP_DIGITS | OP_ALPHA | OP_ALPHANUM | 
    OP_HEX | OP_PREG_MATCH | OP_VALIDATE_BYTE_RANGE | OP_VALIDATE_URL_ENCODING |
    OP_VALIDATE_UTF8_ENCODING | OP_DETECT_XSS | OP_DETECT_SQLI | OP_VERIFY_CC |
    OP_CHECK_URL | OP_WITHIN | OP_STREQ | OP_STRMATCH | OP_VERIFY_SVN | OP_VERIFY_CPF |
    OP_INSPECT_FILE | OP_GSB_LOOKUP | OP_GENERIC;

patternList: pattern (PIPE pattern)*;
pattern: STRING | SINGLE_STRING | NUMBER | HEX_NUMBER | IDENTIFIER | VARIABLE_REF;

// SecAction规则
secAction: SEC_ACTION actionString;

// SecMarker规则
secMarker: SEC_MARKER (STRING | IDENTIFIER)?;

// SecRuleScript规则
secRuleScript: SEC_RULE_SCRIPT targets STRING (actionString | actionList)?;

// SecRewriteRule规则
secRewriteRule: SEC_REWRITE_RULE pattern pattern (flags)?;
flags: LBRACKET flag (COMMA flag)* RBRACKET;
flag: IDENTIFIER (EQUALS (STRING | NUMBER))?;

// 动作定义
actionString: STRING | SINGLE_STRING;
actionList: LBRACE action (COMMA action)* RBRACE;
action: 
    phaseAction | blockAction | allowAction | logAction | noLogAction |
    auditLogAction | noAuditLogAction | msgAction | tagAction | severityAction |
    idAction | revAction | verAction | multiMatchAction | captureAction |
    statusAction | redirectAction | execAction | setEnvAction | setVarAction |
    expireVarAction | initColAction | setSidAction | appendAction | prependAction |
    logDataAction | hashAction | ccAction | ctlAction | sanitiseArgAction |
    sanitiseMatchedAction | sanitiseMatchedBytesAction | skipAction | skipAfterAction |
    genericAction;

// 具体动作类型
phaseAction: ACTION_PHASE COLON phaseValue;
phaseValue: NUMBER | PHASE_REQUEST_HEADERS | PHASE_REQUEST_BODY | PHASE_RESPONSE_HEADERS | PHASE_RESPONSE_BODY | PHASE_LOGGING;

blockAction: ACTION_DENY | ACTION_DROP;
allowAction: ACTION_ALLOW | ACTION_PASS;
logAction: ACTION_LOG;
noLogAction: ACTION_NOLOG;
auditLogAction: ACTION_AUDITLOG;
noAuditLogAction: ACTION_NOAUDITLOG;
msgAction: ACTION_MSG COLON stringValue;
tagAction: ACTION_TAG COLON stringValue;
severityAction: ACTION_SEVERITY COLON (STRING | IDENTIFIER | NUMBER);
idAction: ACTION_ID COLON NUMBER;
revAction: ACTION_REV COLON stringValue;
verAction: ACTION_VER COLON stringValue;
multiMatchAction: ACTION_MULTIMATCH;
captureAction: ACTION_CAPTURE;
statusAction: ACTION_STATUS COLON NUMBER;
redirectAction: ACTION_REDIRECT COLON stringValue;
execAction: ACTION_EXEC COLON stringValue;
setEnvAction: ACTION_SETENV COLON varAssignment;
setVarAction: ACTION_SETVAR COLON varAssignment;
expireVarAction: ACTION_EXPIREVAR COLON varAssignment;
initColAction: ACTION_INITCOLL COLON varAssignment;
setSidAction: ACTION_SETSID COLON stringValue;
appendAction: ACTION_APPEND COLON stringValue;
prependAction: ACTION_PREPEND COLON stringValue;
logDataAction: ACTION_LOGDATA COLON stringValue;
hashAction: ACTION_HASH COLON stringValue;
ccAction: ACTION_CC COLON stringValue;
ctlAction: ACTION_CTL COLON ctlAssignment;
sanitiseArgAction: ACTION_SANITISE_ARG COLON stringValue;
sanitiseMatchedAction: ACTION_SANITISE_MATCHED;
sanitiseMatchedBytesAction: ACTION_SANITISE_MATCHED_BYTES COLON NUMBER;
skipAction: ACTION_SKIP COLON NUMBER;
skipAfterAction: ACTION_SKIP_AFTER COLON stringValue;
genericAction: IDENTIFIER (COLON actionValue)?;

varAssignment: variable (EQUALS expression)?;
ctlAssignment: IDENTIFIER (EQUALS expression)?;
actionValue: stringValue | NUMBER | IDENTIFIER | VARIABLE_REF;
stringValue: STRING | SINGLE_STRING | IDENTIFIER;

// 表达式
expression: 
    logicalOrExpression | 
    mathExpression | 
    stringExpression |
    variableExpression;

logicalOrExpression: logicalAndExpression (OR logicalAndExpression)*;
logicalAndExpression: equalityExpression (AND equalityExpression)*;
equalityExpression: relationalExpression ((EQUALS | EXCLAMATION_EQUALS) relationalExpression)*;
relationalExpression: mathExpression ((LESS_THAN | GREATER_THAN | LESS_EQUALS | GREATER_EQUALS) mathExpression)*;
mathExpression: term ((PLUS | MINUS) term)*;
term: factor ((STAR | SLASH | PERCENT) factor)*;
factor: (PLUS | MINUS)? (NUMBER | HEX_NUMBER | VARIABLE_REF | IDENTIFIER | LPAREN expression RPAREN);
stringExpression: stringValue (PLUS stringValue)*;
variableExpression: VARIABLE_REF;

// 变量定义
variable: 
    simpleVariable | indexedVariable | namedVariable | collectionVariable;

simpleVariable: 
    VAR_REQUEST_URI | VAR_REMOTE_ADDR | VAR_ARGS | VAR_ARGS_GET | VAR_ARGS_POST | 
    VAR_FILES | VAR_FILES_NAMES | VAR_FILES_SIZES | VAR_FILES_TMP_CONTENT | 
    VAR_REQUEST_METHOD | VAR_REQUEST_PROTOCOL | VAR_REQUEST_FILENAME | 
    VAR_REQUEST_BASENAME | VAR_REQUEST_LINE | VAR_REQUEST_BODY | 
    VAR_RESPONSE_BODY | VAR_RESPONSE_STATUS | VAR_QUERY_STRING | 
    VAR_RESPONSE_CONTENT_TYPE | VAR_RESPONSE_CONTENT_LENGTH | VAR_ARGS_NAMES |
    VAR_ARGS_COMBINED_SIZE | VAR_FILES_COMBINED_SIZE | VAR_DURATION |
    VAR_HIGHEST_SEVERITY | VAR_MATCHED_VAR | VAR_MATCHED_VAR_NAME |
    VAR_MATCHED_VARS | VAR_MATCHED_VARS_NAMES | VAR_MULTIPART_CRLF_LF_LINES |
    VAR_MULTIPART_STRICT_ERROR | VAR_MULTIPART_UNMATCHED_BOUNDARY |
    VAR_AUTH_TYPE | VAR_SCRIPT_BASENAME | VAR_SCRIPT_FILENAME |
    VAR_UNIQUE_ID | VAR_WEBAPPID | VAR_XML;

indexedVariable: 
    (VAR_REQUEST_HEADERS | VAR_RESPONSE_HEADERS | VAR_ENV | VAR_GEO | VAR_IP) 
    (LBRACKET stringValue RBRACKET)?;

namedVariable: 
    (VAR_REQUEST_HEADERS | VAR_RESPONSE_HEADERS | VAR_ENV | VAR_GEO | VAR_IP | 
     VAR_SESSION | VAR_USER | VAR_TIME) COLON IDENTIFIER;

collectionVariable: 
    VAR_TX (COLON IDENTIFIER)? | 
    collectionName (COLON fieldName)?;

collectionName: IDENTIFIER;
fieldName: IDENTIFIER;

// Include指令
includeDirective: SEC_INCLUDE filePath;
filePath: STRING | SINGLE_STRING;

// 配置指令
secRuleEngine: SEC_RULE_ENGINE engineMode;
engineMode: 'On' | 'Off' | 'DetectionOnly';

secRequestBodyAccess: SEC_REQUEST_BODY_ACCESS accessMode;
secResponseBodyAccess: SEC_RESPONSE_BODY_ACCESS accessMode;
accessMode: 'On' | 'Off';

secAuditEngine: SEC_AUDIT_ENGINE auditMode;
auditMode: 'On' | 'Off' | 'RelevantOnly';

secAuditLog: SEC_AUDIT_LOG filePath;
secAuditLogParts: SEC_AUDIT_LOG_PARTS partsList;
partsList: LETTER+;
LETTER: [A-Za-z];

secAuditLogType: SEC_AUDIT_LOG_TYPE auditLogType;
auditLogType: 'Serial' | 'Concurrent';

secDebugLog: SEC_DEBUG_LOG filePath;
secDebugLogLevel: SEC_DEBUG_LOG_LEVEL logLevel;
logLevel: NUMBER;

secRequestBodyLimit: SEC_REQUEST_BODY_LIMIT size;
secResponseBodyLimit: SEC_RESPONSE_BODY_LIMIT size;
secArgumentsLimit: SEC_ARGUMENTS_LIMIT size;
size: NUMBER ('K' | 'M' | 'G')?;

secRequestBodyLimitAction: SEC_REQUEST_BODY_LIMIT_ACTION limitAction;
secResponseBodyLimitAction: SEC_RESPONSE_BODY_LIMIT_ACTION limitAction;
limitAction: 'Reject' | 'ProcessPartial';

secWebAppId: SEC_WEB_APP_ID stringValue;
secHashMethod: SEC_HASH_METHOD hashMethod;
hashMethod: 'MD5' | 'SHA1' | 'SHA256' | 'SHA512';
secHashKey: SEC_HASH_KEY stringValue;
secUnicodeMap: SEC_UNICODE_MAP stringValue;
secDefaultCharset: SEC_DEFAULT_CHARSET stringValue;
secContentInjection: SEC_CONTENT_INJECTION injectionMode;
injectionMode: 'On' | 'Off';
secPcreMatchLimit: SEC_PCRE_MATCH_LIMIT NUMBER;
secCompatibilityMode: SEC_COMPATIBILITY_MODE compatibilityFlag;
compatibilityFlag: 'On' | 'Off';
secRuleRemoveById: SEC_RULE_REMOVE_BY_ID idList;
secRuleRemoveByMsg: SEC_RULE_REMOVE_BY_MSG stringValue;
secRuleRemoveByTag: SEC_RULE_REMOVE_BY_TAG stringValue;
secRuleUpdateById: SEC_RULE_UPDATE_BY_ID NUMBER updateAction;
secRuleUpdateTargetById: SEC_RULE_UPDATE_TARGET_BY_ID NUMBER updateTarget;
secRuleInheritance: SEC_RULE_INHERITANCE inheritanceMode;
inheritanceMode: 'On' | 'Off';
secCollection: SEC_COLLECTION collectionName COLON fieldName EQUALS expression;
secInitCollection: SEC_INIT_COLLECTION collectionName COLON fieldName EQUALS expression;
secGeoLookupDb: SEC_GEO_LOOKUP_DB filePath;
secDisableBackendCompression: SEC_DISABLE_BACKEND_COMPRESSION compressionMode;
compressionMode: 'On' | 'Off';
secServerSignature: SEC_SERVER_SIGNATURE stringValue;
secConnectionEngine: SEC_CONNECTION_ENGINE connectionMode;
connectionMode: 'On' | 'Off';
secResponseBodyMimeType: SEC_RESPONSE_BODY_MIME_TYPE mimeTypeList;
mimeTypeList: stringValue (PIPE stringValue)*;
secRequestBodyJsonDepthLimit: SEC_REQUEST_BODY_JSON_DEPTH_LIMIT NUMBER;
secStreamOutputBodyInspection: SEC_STREAM_OUTPUT_BODY_INSPECTION inspectionMode;
inspectionMode: 'On' | 'Off';
secStatusEngine: SEC_STATUS_ENGINE statusMode;
statusMode: 'On' | 'Off';
secRuleUpdate: SEC_RULE_UPDATE updateSpec;
updateSpec: stringValue;
secHttpBlKey: SEC_HTTP_BL_KEY stringValue;
secStreamOutputBodyBuffer: SEC_STREAM_OUTPUT_BODY_BUFFER size;
secDisableForwardedProxyHeaders: SEC_DISABLE_FORWARDED_PROXY_HEADERS proxyMode;
proxyMode: 'On' | 'Off';

idList: NUMBER (COMMA NUMBER)*;
updateAction: STRING;
updateTarget: STRING;

// 逻辑运算符（需要在词法分析器中定义）
OR: 'or' | '||';
AND: 'and' | '&&';
NOT: 'not' | '!';