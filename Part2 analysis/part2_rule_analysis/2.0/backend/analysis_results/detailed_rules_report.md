# Detailed ModSecurity Rules Parsing Report

Generated on: 2025-12-12 23:29:36
Rules directory: D:\github\Repository\WAF_scan-analysis-tool\Part2 analysis\part2_rule_analysis\2.0\rules
Total files: 26

====================================================================================================

## File: REQUEST-901-INITIALIZATION.conf

### File Summary
- Total rules: 32
- Chained rules: 3
- Non-chained rules: 29

### Detailed Rules

#### Rule 1: 901001
- **Phase**: 1
- **Variables**: TX:crs_setup_version
- **Operator**: @eq
- **Pattern**: 0
- **Is Chain**: False
- **Message**: CRS is deployed without configuration! Please copy the crs-setup.conf.example template to crs-setup.conf, and include the crs-setup.conf file in your webserver configuration before including the CRS rules. See the INSTALL file in the CRS directory for detailed instructions
- **Severity**: CRITICAL
- **Tags**: OWASP_CRS
- **Actions**: id:901001, phase:1, deny, status:500, log, auditlog, msg:CRS is deployed without configuration! Please copy the crs-setup.conf.example template to crs-setup.conf, and include the crs-setup.conf file in your webserver configuration before including the CRS rules. See the INSTALL file in the CRS directory for detailed instructions, tag:OWASP_CRS, ver:OWASP_CRS/4.22.0-dev, severity:CRITICAL

#### Rule 2: 901100
- **Phase**: 1
- **Variables**: TX:inbound_anomaly_score_threshold
- **Operator**: @eq
- **Pattern**: 0
- **Is Chain**: False
- **Message**: 
- **Severity**: 
- **Tags**: OWASP_CRS
- **Actions**: id:901100, phase:1, pass, nolog, tag:OWASP_CRS, ver:OWASP_CRS/4.22.0-dev, setvar:tx.inbound_anomaly_score_threshold=5

#### Rule 3: 901110
- **Phase**: 1
- **Variables**: TX:outbound_anomaly_score_threshold
- **Operator**: @eq
- **Pattern**: 0
- **Is Chain**: False
- **Message**: 
- **Severity**: 
- **Tags**: OWASP_CRS
- **Actions**: id:901110, phase:1, pass, nolog, tag:OWASP_CRS, ver:OWASP_CRS/4.22.0-dev, setvar:tx.outbound_anomaly_score_threshold=4

#### Rule 4: 901111
- **Phase**: 1
- **Variables**: TX:reporting_level
- **Operator**: @eq
- **Pattern**: 0
- **Is Chain**: False
- **Message**: 
- **Severity**: 
- **Tags**: OWASP_CRS
- **Actions**: id:901111, phase:1, pass, nolog, tag:OWASP_CRS, ver:OWASP_CRS/4.22.0-dev, setvar:tx.reporting_level=4

#### Rule 5: 901115
- **Phase**: 1
- **Variables**: TX:early_blocking
- **Operator**: @eq
- **Pattern**: 0
- **Is Chain**: False
- **Message**: 
- **Severity**: 
- **Tags**: OWASP_CRS
- **Actions**: id:901115, phase:1, pass, nolog, tag:OWASP_CRS, ver:OWASP_CRS/4.22.0-dev, setvar:tx.early_blocking=0

#### Rule 6: 901120
- **Phase**: 1
- **Variables**: TX:blocking_paranoia_level
- **Operator**: @eq
- **Pattern**: 0
- **Is Chain**: False
- **Message**: 
- **Severity**: 
- **Tags**: OWASP_CRS
- **Actions**: id:901120, phase:1, pass, nolog, tag:OWASP_CRS, ver:OWASP_CRS/4.22.0-dev, setvar:tx.blocking_paranoia_level=1

#### Rule 7: 901125
- **Phase**: 1
- **Variables**: TX:detection_paranoia_level
- **Operator**: @eq
- **Pattern**: 0
- **Is Chain**: False
- **Message**: 
- **Severity**: 
- **Tags**: OWASP_CRS
- **Actions**: id:901125, phase:1, pass, nolog, tag:OWASP_CRS, ver:OWASP_CRS/4.22.0-dev, setvar:tx.detection_paranoia_level=%{TX.blocking_paranoia_level}

#### Rule 8: 901130
- **Phase**: 1
- **Variables**: TX:sampling_percentage
- **Operator**: @eq
- **Pattern**: 0
- **Is Chain**: False
- **Message**: 
- **Severity**: 
- **Tags**: OWASP_CRS
- **Actions**: id:901130, phase:1, pass, nolog, tag:OWASP_CRS, ver:OWASP_CRS/4.22.0-dev, setvar:tx.sampling_percentage=100

#### Rule 9: 901140
- **Phase**: 1
- **Variables**: TX:critical_anomaly_score
- **Operator**: @eq
- **Pattern**: 0
- **Is Chain**: False
- **Message**: 
- **Severity**: 
- **Tags**: OWASP_CRS
- **Actions**: id:901140, phase:1, pass, nolog, tag:OWASP_CRS, ver:OWASP_CRS/4.22.0-dev, setvar:tx.critical_anomaly_score=5

#### Rule 10: 901141
- **Phase**: 1
- **Variables**: TX:error_anomaly_score
- **Operator**: @eq
- **Pattern**: 0
- **Is Chain**: False
- **Message**: 
- **Severity**: 
- **Tags**: OWASP_CRS
- **Actions**: id:901141, phase:1, pass, nolog, tag:OWASP_CRS, ver:OWASP_CRS/4.22.0-dev, setvar:tx.error_anomaly_score=4

#### Rule 11: 901142
- **Phase**: 1
- **Variables**: TX:warning_anomaly_score
- **Operator**: @eq
- **Pattern**: 0
- **Is Chain**: False
- **Message**: 
- **Severity**: 
- **Tags**: OWASP_CRS
- **Actions**: id:901142, phase:1, pass, nolog, tag:OWASP_CRS, ver:OWASP_CRS/4.22.0-dev, setvar:tx.warning_anomaly_score=3

#### Rule 12: 901143
- **Phase**: 1
- **Variables**: TX:notice_anomaly_score
- **Operator**: @eq
- **Pattern**: 0
- **Is Chain**: False
- **Message**: 
- **Severity**: 
- **Tags**: OWASP_CRS
- **Actions**: id:901143, phase:1, pass, nolog, tag:OWASP_CRS, ver:OWASP_CRS/4.22.0-dev, setvar:tx.notice_anomaly_score=2

#### Rule 13: 901160
- **Phase**: 1
- **Variables**: TX:allowed_methods
- **Operator**: @eq
- **Pattern**: 0
- **Is Chain**: False
- **Message**: 
- **Severity**: 
- **Tags**: OWASP_CRS
- **Actions**: id:901160, phase:1, pass, nolog, tag:OWASP_CRS, ver:OWASP_CRS/4.22.0-dev, setvar:tx.allowed_methods=GET HEAD POST OPTIONS

#### Rule 14: 901162
- **Phase**: 1
- **Variables**: TX:allowed_request_content_type
- **Operator**: @eq
- **Pattern**: 0
- **Is Chain**: False
- **Message**: 
- **Severity**: 
- **Tags**: OWASP_CRS
- **Actions**: id:901162, phase:1, pass, nolog, tag:OWASP_CRS, ver:OWASP_CRS/4.22.0-dev, setvar:tx.allowed_request_content_type=|application/x-www-form-urlencoded| |multipart/form-data| |text/xml| |application/xml| |application/soap+xml| |application/json| |application/reports+json| |application/csp-report|

#### Rule 15: 901168
- **Phase**: 1
- **Variables**: TX:allowed_request_content_type_charset
- **Operator**: @eq
- **Pattern**: 0
- **Is Chain**: False
- **Message**: 
- **Severity**: 
- **Tags**: OWASP_CRS
- **Actions**: id:901168, phase:1, pass, nolog, tag:OWASP_CRS, ver:OWASP_CRS/4.22.0-dev, setvar:tx.allowed_request_content_type_charset=|utf-8| |iso-8859-1| |iso-8859-15| |windows-1252|

#### Rule 16: 901163
- **Phase**: 1
- **Variables**: TX:allowed_http_versions
- **Operator**: @eq
- **Pattern**: 0
- **Is Chain**: False
- **Message**: 
- **Severity**: 
- **Tags**: OWASP_CRS
- **Actions**: id:901163, phase:1, pass, nolog, tag:OWASP_CRS, ver:OWASP_CRS/4.22.0-dev, setvar:tx.allowed_http_versions=HTTP/1.0 HTTP/1.1 HTTP/2 HTTP/2.0 HTTP/3 HTTP/3.0

#### Rule 17: 901164
- **Phase**: 1
- **Variables**: TX:restricted_extensions
- **Operator**: @eq
- **Pattern**: 0
- **Is Chain**: False
- **Message**: 
- **Severity**: 
- **Tags**: OWASP_CRS
- **Actions**: id:901164, phase:1, pass, nolog, tag:OWASP_CRS, ver:OWASP_CRS/4.22.0-dev, setvar:tx.restricted_extensions=.ani/ .asa/ .asax/ .ascx/ .back/ .backup/ .bak/ .bck/ .bk/ .bkp/ .bat/ .cdx/ .cer/ .cfg/ .cmd/ .cnf/ .com/ .compositefont/ .config/ .conf/ .copy/ .crt/ .cs/ .csproj/ .csr/ .dat/ .db/ .dbf/ .dist/ .dll/ .dos/ .dpkg-dist/ .drv/ .gadget/ .hta/ .htr/ .htw/ .ida/ .idc/ .idq/ .inc/ .inf/ .ini/ .jse/ .key/ .licx/ .lnk/ .log/ .mdb/ .msc/ .ocx/ .old/ .pass/ .pdb/ .pfx/ .pif/ .pem/ .pol/ .prf/ .printer/ .pwd/ .rdb/ .rdp/ .reg/ .resources/ .resx/ .sav/ .save/ .scr/ .sct/ .sh/ .shs/ .sql/ .sqlite/ .sqlite3/ .swp/ .sys/ .temp/ .tlb/ .tmp/ .vb/ .vbe/ .vbs/ .vbproj/ .vsdisco/ .vxd/ .webinfo/ .ws/ .wsc/ .wsf/ .wsh/ .xsd/ .xsx/

#### Rule 18: 901165
- **Phase**: 1
- **Variables**: TX:restricted_headers_basic
- **Operator**: @eq
- **Pattern**: 0
- **Is Chain**: False
- **Message**: 
- **Severity**: 
- **Tags**: OWASP_CRS
- **Actions**: id:901165, phase:1, pass, nolog, tag:OWASP_CRS, ver:OWASP_CRS/4.22.0-dev, setvar:tx.restricted_headers_basic=/content-encoding/ /proxy/ /lock-token/ /content-range/ /if/ /x-http-method-override/ /x-http-method/ /x-method-override/ /x-middleware-subrequest/ /expect/

#### Rule 19: 901171
- **Phase**: 1
- **Variables**: TX:restricted_headers_extended
- **Operator**: @eq
- **Pattern**: 0
- **Is Chain**: False
- **Message**: 
- **Severity**: 
- **Tags**: OWASP_CRS
- **Actions**: id:901171, phase:1, pass, nolog, tag:OWASP_CRS, ver:OWASP_CRS/4.22.0-dev, setvar:tx.restricted_headers_extended=/accept-charset/

#### Rule 20: 901167
- **Phase**: 1
- **Variables**: TX:enforce_bodyproc_urlencoded
- **Operator**: @eq
- **Pattern**: 0
- **Is Chain**: False
- **Message**: 
- **Severity**: 
- **Tags**: OWASP_CRS
- **Actions**: id:901167, phase:1, pass, nolog, tag:OWASP_CRS, ver:OWASP_CRS/4.22.0-dev, setvar:tx.enforce_bodyproc_urlencoded=0

#### Rule 21: 901169
- **Phase**: 1
- **Variables**: TX:crs_validate_utf8_encoding
- **Operator**: @eq
- **Pattern**: 0
- **Is Chain**: False
- **Message**: 
- **Severity**: 
- **Tags**: OWASP_CRS
- **Actions**: id:901169, phase:1, pass, nolog, tag:OWASP_CRS, ver:OWASP_CRS/4.22.0-dev, setvar:tx.crs_validate_utf8_encoding=0

#### Rule 22: 901170
- **Phase**: 1
- **Variables**: TX:crs_skip_response_analysis
- **Operator**: @eq
- **Pattern**: 0
- **Is Chain**: False
- **Message**: 
- **Severity**: 
- **Tags**: OWASP_CRS
- **Actions**: id:901170, phase:1, pass, nolog, tag:OWASP_CRS, ver:OWASP_CRS/4.22.0-dev, setvar:tx.crs_skip_response_analysis=0

#### Rule 23: 901320
- **Phase**: 1
- **Variables**: TX:ENABLE_DEFAULT_COLLECTIONS
- **Operator**: @eq
- **Pattern**: 1
- **Is Chain**: True
- **Message**: 
- **Severity**: 
- **Tags**: OWASP_CRS
- **Actions**: id:901320, phase:1, pass, nolog, tag:OWASP_CRS, ver:OWASP_CRS/4.22.0-dev, setvar:tx.ua_hash=%{REQUEST_HEADERS.User-Agent}, chain

#### Rule 24: Unknown
- **Phase**: Unknown
- **Variables**: TX:ENABLE_DEFAULT_COLLECTIONS
- **Operator**: @eq
- **Pattern**: 1
- **Is Chain**: True
- **Message**: 
- **Severity**: 
- **Actions**: chain

#### Rule 25: Unknown
- **Phase**: Unknown
- **Variables**: TX:ua_hash
- **Operator**: @unconditionalMatch
- **Pattern**: 
- **Is Chain**: False
- **Message**: 
- **Severity**: 
- **Actions**: t:none, t:sha1, t:hexEncode, initcol:global, initcol:ip

#### Rule 26: 901340
- **Phase**: 1
- **Variables**: REQBODY_PROCESSOR
- **Operator**: !@rx
- **Pattern**: (?:URLENCODED|MULTIPART|XML|JSON)
- **Is Chain**: False
- **Message**: Enabling body inspection
- **Severity**: 
- **Tags**: OWASP_CRS
- **Actions**: id:901340, phase:1, pass, nolog, noauditlog, msg:Enabling body inspection, tag:OWASP_CRS, ctl:forceRequestBodyVariable, ver:OWASP_CRS/4.22.0-dev

#### Rule 27: 901350
- **Phase**: 1
- **Variables**: TX:enforce_bodyproc_urlencoded
- **Operator**: @eq
- **Pattern**: 1
- **Is Chain**: True
- **Message**: Enabling forced body inspection for ASCII content
- **Severity**: 
- **Tags**: OWASP_CRS
- **Actions**: id:901350, phase:1, pass, t:none, t:urlDecodeUni, nolog, noauditlog, msg:Enabling forced body inspection for ASCII content, tag:OWASP_CRS, ver:OWASP_CRS/4.22.0-dev, chain

#### Rule 28: Unknown
- **Phase**: Unknown
- **Variables**: REQBODY_PROCESSOR
- **Operator**: !@rx
- **Pattern**: (?:URLENCODED|MULTIPART|XML|JSON)
- **Is Chain**: False
- **Message**: 
- **Severity**: 
- **Actions**: ctl:requestBodyProcessor

#### Rule 29: 901400
- **Phase**: 1
- **Variables**: TX:sampling_percentage
- **Operator**: @eq
- **Pattern**: 100
- **Is Chain**: False
- **Message**: 
- **Severity**: 
- **Tags**: OWASP_CRS
- **Actions**: id:901400, phase:1, pass, nolog, tag:OWASP_CRS, ver:OWASP_CRS/4.22.0-dev, skipAfter:END-SAMPLING

#### Rule 30: 901410
- **Phase**: 1
- **Variables**: UNIQUE_ID
- **Operator**: @rx
- **Pattern**: ^[a-f]*([0-9])[a-f]*([0-9])
- **Is Chain**: False
- **Message**: 
- **Severity**: 
- **Tags**: OWASP_CRS
- **Actions**: id:901410, phase:1, pass, capture, t:sha1, t:hexEncode, nolog, tag:OWASP_CRS, ver:OWASP_CRS/4.22.0-dev, setvar:TX.sampling_rnd100=%{TX.1}%{TX.2}

#### Rule 31: 901450
- **Phase**: 1
- **Variables**: TX:sampling_rnd100
- **Operator**: !@lt
- **Pattern**: %{tx.sampling_percentage}
- **Is Chain**: False
- **Message**: Sampling: Disable the rule engine based on sampling_percentage %{TX.sampling_percentage} and random number %{TX.sampling_rnd100}
- **Severity**: 
- **Tags**: OWASP_CRS
- **Actions**: id:901450, phase:1, pass, log, noauditlog, msg:Sampling: Disable the rule engine based on sampling_percentage %{TX.sampling_percentage} and random number %{TX.sampling_rnd100}, tag:OWASP_CRS, ctl:ruleRemoveByTag, ver:OWASP_CRS/4.22.0-dev

#### Rule 32: 901500
- **Phase**: 1
- **Variables**: TX:detection_paranoia_level
- **Operator**: @lt
- **Pattern**: %{tx.blocking_paranoia_level}
- **Is Chain**: False
- **Message**: Detection paranoia level configured is lower than the paranoia level itself. This is illegal. Blocking request. Aborting
- **Severity**: 
- **Tags**: OWASP_CRS
- **Actions**: id:901500, phase:1, deny, status:500, t:none, log, msg:Detection paranoia level configured is lower than the paranoia level itself. This is illegal. Blocking request. Aborting, tag:OWASP_CRS, ver:OWASP_CRS/4.22.0-dev


====================================================================================================

## File: REQUEST-905-COMMON-EXCEPTIONS.conf

### File Summary
- Total rules: 5
- Chained rules: 3
- Non-chained rules: 2

### Detailed Rules

#### Rule 1: 905100
- **Phase**: 1
- **Variables**: REQUEST_LINE
- **Operator**: @streq
- **Pattern**: GET /
- **Is Chain**: True
- **Message**: 
- **Severity**: 
- **Tags**: application-multi, language-multi, platform-apache, attack-generic, OWASP_CRS
- **Actions**: id:905100, phase:1, pass, t:none, nolog, tag:application-multi, tag:language-multi, tag:platform-apache, tag:attack-generic, tag:OWASP_CRS, ver:OWASP_CRS/4.22.0-dev, chain

#### Rule 2: Unknown
- **Phase**: Unknown
- **Variables**: REMOTE_ADDR
- **Operator**: @ipMatch
- **Pattern**: 127.0.0.1,::1
- **Is Chain**: False
- **Message**: 
- **Severity**: 
- **Actions**: t:none, ctl:ruleRemoveByTag, ctl:auditEngine

#### Rule 3: 905110
- **Phase**: 1
- **Variables**: REMOTE_ADDR
- **Operator**: @ipMatch
- **Pattern**: 127.0.0.1,::1
- **Is Chain**: True
- **Message**: 
- **Severity**: 
- **Tags**: application-multi, language-multi, platform-apache, attack-generic, OWASP_CRS
- **Actions**: id:905110, phase:1, pass, t:none, nolog, tag:application-multi, tag:language-multi, tag:platform-apache, tag:attack-generic, tag:OWASP_CRS, ver:OWASP_CRS/4.22.0-dev, chain

#### Rule 4: Unknown
- **Phase**: Unknown
- **Variables**: REQUEST_HEADERS:User-Agent
- **Operator**: @endsWith
- **Pattern**: (internal dummy connection)
- **Is Chain**: True
- **Message**: 
- **Severity**: 
- **Actions**: t:none, chain

#### Rule 5: Unknown
- **Phase**: Unknown
- **Variables**: REQUEST_LINE
- **Operator**: @rx
- **Pattern**: ^(?:GET /|OPTIONS \*) HTTP/[12]\.[01]$
- **Is Chain**: False
- **Message**: 
- **Severity**: 
- **Actions**: t:none, ctl:ruleRemoveByTag, ctl:auditEngine


====================================================================================================

## File: REQUEST-911-METHOD-ENFORCEMENT.conf

### File Summary
- Total rules: 9
- Chained rules: 0
- Non-chained rules: 9

### Detailed Rules

#### Rule 1: 911011
- **Phase**: 1
- **Variables**: TX:DETECTION_PARANOIA_LEVEL
- **Operator**: @lt
- **Pattern**: 1
- **Is Chain**: False
- **Message**: 
- **Severity**: 
- **Tags**: OWASP_CRS
- **Actions**: id:911011, phase:1, pass, nolog, tag:OWASP_CRS, ver:OWASP_CRS/4.22.0-dev, skipAfter:END-REQUEST-911-METHOD-ENFORCEMENT

#### Rule 2: 911012
- **Phase**: 2
- **Variables**: TX:DETECTION_PARANOIA_LEVEL
- **Operator**: @lt
- **Pattern**: 1
- **Is Chain**: False
- **Message**: 
- **Severity**: 
- **Tags**: OWASP_CRS
- **Actions**: id:911012, phase:2, pass, nolog, tag:OWASP_CRS, ver:OWASP_CRS/4.22.0-dev, skipAfter:END-REQUEST-911-METHOD-ENFORCEMENT

#### Rule 3: 911100
- **Phase**: 1
- **Variables**: REQUEST_METHOD
- **Operator**: !@within
- **Pattern**: %{tx.allowed_methods}
- **Is Chain**: False
- **Message**: Method is not allowed by policy
- **Severity**: CRITICAL
- **Tags**: application-multi, language-multi, platform-multi, attack-generic, paranoia-level/1, OWASP_CRS, OWASP_CRS/METHOD-ENFORCEMENT, capec/1000/210/272/220/274
- **Actions**: id:911100, phase:1, block, msg:Method is not allowed by policy, logdata:%{MATCHED_VAR}, tag:application-multi, tag:language-multi, tag:platform-multi, tag:attack-generic, tag:paranoia-level/1, tag:OWASP_CRS, tag:OWASP_CRS/METHOD-ENFORCEMENT, tag:capec/1000/210/272/220/274, ver:OWASP_CRS/4.22.0-dev, severity:CRITICAL, setvar:tx.inbound_anomaly_score_pl1=+%{tx.critical_anomaly_score}

#### Rule 4: 911013
- **Phase**: 1
- **Variables**: TX:DETECTION_PARANOIA_LEVEL
- **Operator**: @lt
- **Pattern**: 2
- **Is Chain**: False
- **Message**: 
- **Severity**: 
- **Tags**: OWASP_CRS
- **Actions**: id:911013, phase:1, pass, nolog, tag:OWASP_CRS, ver:OWASP_CRS/4.22.0-dev, skipAfter:END-REQUEST-911-METHOD-ENFORCEMENT

#### Rule 5: 911014
- **Phase**: 2
- **Variables**: TX:DETECTION_PARANOIA_LEVEL
- **Operator**: @lt
- **Pattern**: 2
- **Is Chain**: False
- **Message**: 
- **Severity**: 
- **Tags**: OWASP_CRS
- **Actions**: id:911014, phase:2, pass, nolog, tag:OWASP_CRS, ver:OWASP_CRS/4.22.0-dev, skipAfter:END-REQUEST-911-METHOD-ENFORCEMENT

#### Rule 6: 911015
- **Phase**: 1
- **Variables**: TX:DETECTION_PARANOIA_LEVEL
- **Operator**: @lt
- **Pattern**: 3
- **Is Chain**: False
- **Message**: 
- **Severity**: 
- **Tags**: OWASP_CRS
- **Actions**: id:911015, phase:1, pass, nolog, tag:OWASP_CRS, ver:OWASP_CRS/4.22.0-dev, skipAfter:END-REQUEST-911-METHOD-ENFORCEMENT

#### Rule 7: 911016
- **Phase**: 2
- **Variables**: TX:DETECTION_PARANOIA_LEVEL
- **Operator**: @lt
- **Pattern**: 3
- **Is Chain**: False
- **Message**: 
- **Severity**: 
- **Tags**: OWASP_CRS
- **Actions**: id:911016, phase:2, pass, nolog, tag:OWASP_CRS, ver:OWASP_CRS/4.22.0-dev, skipAfter:END-REQUEST-911-METHOD-ENFORCEMENT

#### Rule 8: 911017
- **Phase**: 1
- **Variables**: TX:DETECTION_PARANOIA_LEVEL
- **Operator**: @lt
- **Pattern**: 4
- **Is Chain**: False
- **Message**: 
- **Severity**: 
- **Tags**: OWASP_CRS
- **Actions**: id:911017, phase:1, pass, nolog, tag:OWASP_CRS, ver:OWASP_CRS/4.22.0-dev, skipAfter:END-REQUEST-911-METHOD-ENFORCEMENT

#### Rule 9: 911018
- **Phase**: 2
- **Variables**: TX:DETECTION_PARANOIA_LEVEL
- **Operator**: @lt
- **Pattern**: 4
- **Is Chain**: False
- **Message**: 
- **Severity**: 
- **Tags**: OWASP_CRS
- **Actions**: id:911018, phase:2, pass, nolog, tag:OWASP_CRS, ver:OWASP_CRS/4.22.0-dev, skipAfter:END-REQUEST-911-METHOD-ENFORCEMENT


====================================================================================================

## File: REQUEST-913-SCANNER-DETECTION.conf

### File Summary
- Total rules: 9
- Chained rules: 0
- Non-chained rules: 9

### Detailed Rules

#### Rule 1: 913011
- **Phase**: 1
- **Variables**: TX:DETECTION_PARANOIA_LEVEL
- **Operator**: @lt
- **Pattern**: 1
- **Is Chain**: False
- **Message**: 
- **Severity**: 
- **Tags**: OWASP_CRS
- **Actions**: id:913011, phase:1, pass, nolog, tag:OWASP_CRS, ver:OWASP_CRS/4.22.0-dev, skipAfter:END-REQUEST-913-SCANNER-DETECTION

#### Rule 2: 913012
- **Phase**: 2
- **Variables**: TX:DETECTION_PARANOIA_LEVEL
- **Operator**: @lt
- **Pattern**: 1
- **Is Chain**: False
- **Message**: 
- **Severity**: 
- **Tags**: OWASP_CRS
- **Actions**: id:913012, phase:2, pass, nolog, tag:OWASP_CRS, ver:OWASP_CRS/4.22.0-dev, skipAfter:END-REQUEST-913-SCANNER-DETECTION

#### Rule 3: 913100
- **Phase**: 1
- **Variables**: REQUEST_HEADERS:User-Agent
- **Operator**: @pmFromFile
- **Pattern**: scanners-user-agents.data
- **Is Chain**: False
- **Message**: Found User-Agent associated with security scanner
- **Severity**: CRITICAL
- **Tags**: application-multi, language-multi, platform-multi, attack-reputation-scanner, paranoia-level/1, OWASP_CRS, OWASP_CRS/SCANNER-DETECTION, capec/1000/118/224/541/310
- **Actions**: id:913100, phase:1, block, capture, t:none, msg:Found User-Agent associated with security scanner, logdata:Matched Data: %{TX.0} found within %{MATCHED_VAR_NAME}: %{MATCHED_VAR}, tag:application-multi, tag:language-multi, tag:platform-multi, tag:attack-reputation-scanner, tag:paranoia-level/1, tag:OWASP_CRS, tag:OWASP_CRS/SCANNER-DETECTION, tag:capec/1000/118/224/541/310, ver:OWASP_CRS/4.22.0-dev, severity:CRITICAL, setvar:tx.inbound_anomaly_score_pl1=+%{tx.critical_anomaly_score}

#### Rule 4: 913013
- **Phase**: 1
- **Variables**: TX:DETECTION_PARANOIA_LEVEL
- **Operator**: @lt
- **Pattern**: 2
- **Is Chain**: False
- **Message**: 
- **Severity**: 
- **Tags**: OWASP_CRS
- **Actions**: id:913013, phase:1, pass, nolog, tag:OWASP_CRS, ver:OWASP_CRS/4.22.0-dev, skipAfter:END-REQUEST-913-SCANNER-DETECTION

#### Rule 5: 913014
- **Phase**: 2
- **Variables**: TX:DETECTION_PARANOIA_LEVEL
- **Operator**: @lt
- **Pattern**: 2
- **Is Chain**: False
- **Message**: 
- **Severity**: 
- **Tags**: OWASP_CRS
- **Actions**: id:913014, phase:2, pass, nolog, tag:OWASP_CRS, ver:OWASP_CRS/4.22.0-dev, skipAfter:END-REQUEST-913-SCANNER-DETECTION

#### Rule 6: 913015
- **Phase**: 1
- **Variables**: TX:DETECTION_PARANOIA_LEVEL
- **Operator**: @lt
- **Pattern**: 3
- **Is Chain**: False
- **Message**: 
- **Severity**: 
- **Tags**: OWASP_CRS
- **Actions**: id:913015, phase:1, pass, nolog, tag:OWASP_CRS, ver:OWASP_CRS/4.22.0-dev, skipAfter:END-REQUEST-913-SCANNER-DETECTION

#### Rule 7: 913016
- **Phase**: 2
- **Variables**: TX:DETECTION_PARANOIA_LEVEL
- **Operator**: @lt
- **Pattern**: 3
- **Is Chain**: False
- **Message**: 
- **Severity**: 
- **Tags**: OWASP_CRS
- **Actions**: id:913016, phase:2, pass, nolog, tag:OWASP_CRS, ver:OWASP_CRS/4.22.0-dev, skipAfter:END-REQUEST-913-SCANNER-DETECTION

#### Rule 8: 913017
- **Phase**: 1
- **Variables**: TX:DETECTION_PARANOIA_LEVEL
- **Operator**: @lt
- **Pattern**: 4
- **Is Chain**: False
- **Message**: 
- **Severity**: 
- **Tags**: OWASP_CRS
- **Actions**: id:913017, phase:1, pass, nolog, tag:OWASP_CRS, ver:OWASP_CRS/4.22.0-dev, skipAfter:END-REQUEST-913-SCANNER-DETECTION

#### Rule 9: 913018
- **Phase**: 2
- **Variables**: TX:DETECTION_PARANOIA_LEVEL
- **Operator**: @lt
- **Pattern**: 4
- **Is Chain**: False
- **Message**: 
- **Severity**: 
- **Tags**: OWASP_CRS
- **Actions**: id:913018, phase:2, pass, nolog, tag:OWASP_CRS, ver:OWASP_CRS/4.22.0-dev, skipAfter:END-REQUEST-913-SCANNER-DETECTION


====================================================================================================

## File: REQUEST-920-PROTOCOL-ENFORCEMENT.conf

### File Summary
- Total rules: 99
- Chained rules: 35
- Non-chained rules: 64

### Detailed Rules

#### Rule 1: 920011
- **Phase**: 1
- **Variables**: TX:DETECTION_PARANOIA_LEVEL
- **Operator**: @lt
- **Pattern**: 1
- **Is Chain**: False
- **Message**: 
- **Severity**: 
- **Tags**: OWASP_CRS
- **Actions**: id:920011, phase:1, pass, nolog, tag:OWASP_CRS, ver:OWASP_CRS/4.22.0-dev, skipAfter:END-REQUEST-920-PROTOCOL-ENFORCEMENT

#### Rule 2: 920012
- **Phase**: 2
- **Variables**: TX:DETECTION_PARANOIA_LEVEL
- **Operator**: @lt
- **Pattern**: 1
- **Is Chain**: False
- **Message**: 
- **Severity**: 
- **Tags**: OWASP_CRS
- **Actions**: id:920012, phase:2, pass, nolog, tag:OWASP_CRS, ver:OWASP_CRS/4.22.0-dev, skipAfter:END-REQUEST-920-PROTOCOL-ENFORCEMENT

#### Rule 3: 920100
- **Phase**: 1
- **Variables**: REQUEST_LINE
- **Operator**: !@rx
- **Pattern**: (?i)^(?:get /[^#\?]*(?:\?[^\s\x0b#]*)?(?:#[^\s\x0b]*)?|(?:connect (?:(?:[0-9]{1,3}\.){3}[0-9]{1,3}\.?(?::[0-9]+)?|[\--9A-Z_a-z]+:[0-9]+)|options \*|[a-z]{3,10}[\s\x0b]+(?:[0-9A-Z_a-z]{3,7}?://[\--9A-Z_a-z]*(?::[0-9]+)?)?/[^#\?]*(?:\?[^\s\x0b#]*)?(?:#[^\s\x0b]*)?)[\s\x0b]+[\.-9A-Z_a-z]+)$
- **Is Chain**: False
- **Message**: Invalid HTTP Request Line
- **Severity**: WARNING
- **Tags**: application-multi, language-multi, platform-multi, attack-protocol, paranoia-level/1, OWASP_CRS, OWASP_CRS/PROTOCOL-ENFORCEMENT, capec/1000/210/272
- **Actions**: id:920100, phase:1, block, t:none, msg:Invalid HTTP Request Line, logdata:%{request_line}, tag:application-multi, tag:language-multi, tag:platform-multi, tag:attack-protocol, tag:paranoia-level/1, tag:OWASP_CRS, tag:OWASP_CRS/PROTOCOL-ENFORCEMENT, tag:capec/1000/210/272, ver:OWASP_CRS/4.22.0-dev, severity:WARNING, setvar:tx.inbound_anomaly_score_pl1=+%{tx.warning_anomaly_score}

#### Rule 4: 920120
- **Phase**: 2
- **Variables**: FILES, FILES_NAMES
- **Operator**: !@rx
- **Pattern**: (?i)^(?:&(?:(?:[acegilnorsuz]acut|[aeiou]grav|[aino]tild)e|[c-elnr-tz]caron|(?:[cgklnr-t]cedi|[aeiouy]um)l|[aceg-josuwy]circ|[au]ring|a(?:mp|pos)|nbsp|oslash);|[^\"';=\x5c])*$
- **Is Chain**: False
- **Message**: Attempted multipart/form-data bypass
- **Severity**: CRITICAL
- **Tags**: application-multi, language-multi, platform-multi, attack-protocol, paranoia-level/1, OWASP_CRS, OWASP_CRS/PROTOCOL-ENFORCEMENT, capec/1000/210/272
- **Actions**: id:920120, phase:2, block, t:none, t:urlDecodeUni, msg:Attempted multipart/form-data bypass, logdata:%{MATCHED_VAR}, tag:application-multi, tag:language-multi, tag:platform-multi, tag:attack-protocol, tag:paranoia-level/1, tag:OWASP_CRS, tag:OWASP_CRS/PROTOCOL-ENFORCEMENT, tag:capec/1000/210/272, ver:OWASP_CRS/4.22.0-dev, severity:CRITICAL, setvar:tx.inbound_anomaly_score_pl1=+%{tx.critical_anomaly_score}

#### Rule 5: 920160
- **Phase**: 1
- **Variables**: REQUEST_HEADERS:Content-Length
- **Operator**: !@rx
- **Pattern**: ^\d+$
- **Is Chain**: False
- **Message**: Content-Length HTTP header is not numeric
- **Severity**: CRITICAL
- **Tags**: application-multi, language-multi, platform-multi, attack-protocol, paranoia-level/1, OWASP_CRS, OWASP_CRS/PROTOCOL-ENFORCEMENT, capec/1000/210/272
- **Actions**: id:920160, phase:1, block, t:none, msg:Content-Length HTTP header is not numeric, logdata:%{MATCHED_VAR}, tag:application-multi, tag:language-multi, tag:platform-multi, tag:attack-protocol, tag:paranoia-level/1, tag:OWASP_CRS, tag:OWASP_CRS/PROTOCOL-ENFORCEMENT, tag:capec/1000/210/272, ver:OWASP_CRS/4.22.0-dev, severity:CRITICAL, setvar:tx.inbound_anomaly_score_pl1=+%{tx.critical_anomaly_score}

#### Rule 6: 920170
- **Phase**: 1
- **Variables**: REQUEST_METHOD
- **Operator**: @rx
- **Pattern**: ^(?:GET|HEAD)$
- **Is Chain**: True
- **Message**: GET or HEAD Request with Body Content
- **Severity**: CRITICAL
- **Tags**: application-multi, language-multi, platform-multi, attack-protocol, paranoia-level/1, OWASP_CRS, OWASP_CRS/PROTOCOL-ENFORCEMENT, capec/1000/210/272
- **Actions**: id:920170, phase:1, block, t:none, msg:GET or HEAD Request with Body Content, logdata:%{MATCHED_VAR}, tag:application-multi, tag:language-multi, tag:platform-multi, tag:attack-protocol, tag:paranoia-level/1, tag:OWASP_CRS, tag:OWASP_CRS/PROTOCOL-ENFORCEMENT, tag:capec/1000/210/272, ver:OWASP_CRS/4.22.0-dev, severity:CRITICAL, chain

#### Rule 7: Unknown
- **Phase**: Unknown
- **Variables**: REQUEST_HEADERS:Content-Length
- **Operator**: !@rx
- **Pattern**: ^0?$
- **Is Chain**: False
- **Message**: 
- **Severity**: 
- **Actions**: t:none, setvar:tx.inbound_anomaly_score_pl1=+%{tx.critical_anomaly_score}

#### Rule 8: 920171
- **Phase**: 1
- **Variables**: REQUEST_METHOD
- **Operator**: @rx
- **Pattern**: ^(?:GET|HEAD)$
- **Is Chain**: True
- **Message**: GET or HEAD Request with Transfer-Encoding
- **Severity**: CRITICAL
- **Tags**: application-multi, language-multi, platform-multi, attack-protocol, paranoia-level/1, OWASP_CRS, OWASP_CRS/PROTOCOL-ENFORCEMENT, capec/1000/210/272
- **Actions**: id:920171, phase:1, block, t:none, msg:GET or HEAD Request with Transfer-Encoding, logdata:%{MATCHED_VAR}, tag:application-multi, tag:language-multi, tag:platform-multi, tag:attack-protocol, tag:paranoia-level/1, tag:OWASP_CRS, tag:OWASP_CRS/PROTOCOL-ENFORCEMENT, tag:capec/1000/210/272, ver:OWASP_CRS/4.22.0-dev, severity:CRITICAL, chain

#### Rule 9: Unknown
- **Phase**: Unknown
- **Variables**: REQUEST_HEADERS:Transfer-Encoding
- **Operator**: !@eq
- **Pattern**: 0
- **Is Chain**: False
- **Message**: 
- **Severity**: 
- **Actions**: t:none, setvar:tx.inbound_anomaly_score_pl1=+%{tx.critical_anomaly_score}

#### Rule 10: 920180
- **Phase**: 1
- **Variables**: REQUEST_PROTOCOL
- **Operator**: !@within
- **Pattern**: HTTP/2 HTTP/2.0 HTTP/3 HTTP/3.0
- **Is Chain**: True
- **Message**: POST without Content-Length and Transfer-Encoding headers
- **Severity**: WARNING
- **Tags**: application-multi, language-multi, platform-multi, attack-protocol, paranoia-level/1, OWASP_CRS, OWASP_CRS/PROTOCOL-ENFORCEMENT, capec/1000/210/272
- **Actions**: id:920180, phase:1, block, t:none, msg:POST without Content-Length and Transfer-Encoding headers, logdata:%{MATCHED_VAR}, tag:application-multi, tag:language-multi, tag:platform-multi, tag:attack-protocol, tag:paranoia-level/1, tag:OWASP_CRS, tag:OWASP_CRS/PROTOCOL-ENFORCEMENT, tag:capec/1000/210/272, ver:OWASP_CRS/4.22.0-dev, severity:WARNING, chain

#### Rule 11: Unknown
- **Phase**: Unknown
- **Variables**: REQUEST_METHOD
- **Operator**: @streq
- **Pattern**: POST
- **Is Chain**: True
- **Message**: 
- **Severity**: 
- **Actions**: chain

#### Rule 12: Unknown
- **Phase**: Unknown
- **Variables**: REQUEST_HEADERS:Content-Length
- **Operator**: @eq
- **Pattern**: 0
- **Is Chain**: True
- **Message**: 
- **Severity**: 
- **Actions**: chain

#### Rule 13: Unknown
- **Phase**: Unknown
- **Variables**: REQUEST_HEADERS:Transfer-Encoding
- **Operator**: @eq
- **Pattern**: 0
- **Is Chain**: False
- **Message**: 
- **Severity**: 
- **Actions**: setvar:tx.inbound_anomaly_score_pl1=+%{tx.warning_anomaly_score}

#### Rule 14: 920181
- **Phase**: 1
- **Variables**: REQUEST_HEADERS:Transfer-Encoding
- **Operator**: !@eq
- **Pattern**: 0
- **Is Chain**: True
- **Message**: Content-Length and Transfer-Encoding headers present
- **Severity**: WARNING
- **Tags**: application-multi, language-multi, platform-multi, attack-protocol, paranoia-level/1, OWASP_CRS, OWASP_CRS/PROTOCOL-ENFORCEMENT, capec/1000/210/272
- **Actions**: id:920181, phase:1, block, t:none, msg:Content-Length and Transfer-Encoding headers present, tag:application-multi, tag:language-multi, tag:platform-multi, tag:attack-protocol, tag:paranoia-level/1, tag:OWASP_CRS, tag:OWASP_CRS/PROTOCOL-ENFORCEMENT, tag:capec/1000/210/272, ver:OWASP_CRS/4.22.0-dev, severity:WARNING, chain

#### Rule 15: Unknown
- **Phase**: Unknown
- **Variables**: REQUEST_HEADERS:Content-Length
- **Operator**: !@eq
- **Pattern**: 0
- **Is Chain**: False
- **Message**: 
- **Severity**: 
- **Actions**: t:none, setvar:tx.inbound_anomaly_score_pl1=+%{tx.warning_anomaly_score}

#### Rule 16: 920190
- **Phase**: 1
- **Variables**: REQUEST_HEADERS:Range, REQUEST_HEADERS:Request-Range
- **Operator**: @rx
- **Pattern**: (\d+)-(\d+)
- **Is Chain**: True
- **Message**: Range: Invalid Last Byte Value
- **Severity**: WARNING
- **Tags**: application-multi, language-multi, platform-multi, attack-protocol, paranoia-level/1, OWASP_CRS, OWASP_CRS/PROTOCOL-ENFORCEMENT, capec/1000/210/272
- **Actions**: id:920190, phase:1, block, capture, t:none, msg:Range: Invalid Last Byte Value, logdata:%{MATCHED_VAR}, tag:application-multi, tag:language-multi, tag:platform-multi, tag:attack-protocol, tag:paranoia-level/1, tag:OWASP_CRS, tag:OWASP_CRS/PROTOCOL-ENFORCEMENT, tag:capec/1000/210/272, ver:OWASP_CRS/4.22.0-dev, severity:WARNING, chain

#### Rule 17: Unknown
- **Phase**: Unknown
- **Variables**: TX:2
- **Operator**: @lt
- **Pattern**: %{tx.1}
- **Is Chain**: False
- **Message**: 
- **Severity**: 
- **Actions**: setvar:tx.inbound_anomaly_score_pl1=+%{tx.warning_anomaly_score}

#### Rule 18: 920210
- **Phase**: 1
- **Variables**: REQUEST_HEADERS:Connection
- **Operator**: @rx
- **Pattern**: \b(?:keep-alive|close),\s?(?:keep-alive|close)\b
- **Is Chain**: False
- **Message**: Multiple/Conflicting Connection Header Data Found
- **Severity**: WARNING
- **Tags**: application-multi, language-multi, platform-multi, attack-protocol, paranoia-level/1, OWASP_CRS, OWASP_CRS/PROTOCOL-ENFORCEMENT, capec/1000/210/272
- **Actions**: id:920210, phase:1, block, t:none, msg:Multiple/Conflicting Connection Header Data Found, logdata:%{MATCHED_VAR}, tag:application-multi, tag:language-multi, tag:platform-multi, tag:attack-protocol, tag:paranoia-level/1, tag:OWASP_CRS, tag:OWASP_CRS/PROTOCOL-ENFORCEMENT, tag:capec/1000/210/272, ver:OWASP_CRS/4.22.0-dev, severity:WARNING, setvar:tx.inbound_anomaly_score_pl1=+%{tx.warning_anomaly_score}

#### Rule 19: 920250
- **Phase**: 2
- **Variables**: TX:CRS_VALIDATE_UTF8_ENCODING
- **Operator**: @eq
- **Pattern**: 1
- **Is Chain**: True
- **Message**: UTF8 Encoding Abuse Attack Attempt
- **Severity**: WARNING
- **Tags**: application-multi, language-multi, platform-multi, attack-protocol, paranoia-level/1, OWASP_CRS, OWASP_CRS/PROTOCOL-ENFORCEMENT, capec/1000/255/153/267
- **Actions**: id:920250, phase:2, block, t:none, msg:UTF8 Encoding Abuse Attack Attempt, logdata:%{MATCHED_VAR}, tag:application-multi, tag:language-multi, tag:platform-multi, tag:attack-protocol, tag:paranoia-level/1, tag:OWASP_CRS, tag:OWASP_CRS/PROTOCOL-ENFORCEMENT, tag:capec/1000/255/153/267, ver:OWASP_CRS/4.22.0-dev, severity:WARNING, chain

#### Rule 20: Unknown
- **Phase**: Unknown
- **Variables**: REQUEST_FILENAME, ARGS, ARGS_NAMES
- **Operator**: @validateUtf8Encoding
- **Pattern**: 
- **Is Chain**: False
- **Message**: 
- **Severity**: 
- **Actions**: setvar:tx.inbound_anomaly_score_pl1=+%{tx.warning_anomaly_score}

#### Rule 21: 920260
- **Phase**: 2
- **Variables**: REQUEST_URI, REQUEST_BODY
- **Operator**: @rx
- **Pattern**: (?i)%uff[0-9a-f]{2}
- **Is Chain**: False
- **Message**: Unicode Full/Half Width Abuse Attack Attempt
- **Severity**: WARNING
- **Tags**: application-multi, language-multi, platform-iis, platform-windows, attack-protocol, paranoia-level/1, OWASP_CRS, OWASP_CRS/PROTOCOL-ENFORCEMENT, capec/1000/255/153/267/72
- **Actions**: id:920260, phase:2, block, t:none, msg:Unicode Full/Half Width Abuse Attack Attempt, logdata:%{MATCHED_VAR_NAME}=%{MATCHED_VAR}, tag:application-multi, tag:language-multi, tag:platform-iis, tag:platform-windows, tag:attack-protocol, tag:paranoia-level/1, tag:OWASP_CRS, tag:OWASP_CRS/PROTOCOL-ENFORCEMENT, tag:capec/1000/255/153/267/72, ver:OWASP_CRS/4.22.0-dev, severity:WARNING, setvar:tx.inbound_anomaly_score_pl1=+%{tx.warning_anomaly_score}

#### Rule 22: 920270
- **Phase**: 2
- **Variables**: REQUEST_URI_RAW, REQUEST_HEADERS, ARGS, ARGS_NAMES
- **Operator**: @validateByteRange
- **Pattern**: 1-255
- **Is Chain**: False
- **Message**: Invalid character in request (null character)
- **Severity**: CRITICAL
- **Tags**: application-multi, language-multi, platform-multi, attack-protocol, paranoia-level/1, OWASP_CRS, OWASP_CRS/PROTOCOL-ENFORCEMENT, capec/1000/210/272
- **Actions**: id:920270, phase:2, block, t:none, t:urlDecodeUni, msg:Invalid character in request (null character), logdata:%{MATCHED_VAR_NAME}=%{MATCHED_VAR}, tag:application-multi, tag:language-multi, tag:platform-multi, tag:attack-protocol, tag:paranoia-level/1, tag:OWASP_CRS, tag:OWASP_CRS/PROTOCOL-ENFORCEMENT, tag:capec/1000/210/272, ver:OWASP_CRS/4.22.0-dev, severity:CRITICAL, setvar:tx.inbound_anomaly_score_pl1=+%{tx.critical_anomaly_score}

#### Rule 23: 920280
- **Phase**: 1
- **Variables**: REQUEST_HEADERS:Host
- **Operator**: @eq
- **Pattern**: 0
- **Is Chain**: False
- **Message**: Request Missing a Host Header
- **Severity**: CRITICAL
- **Tags**: application-multi, language-multi, platform-multi, attack-protocol, paranoia-level/1, OWASP_CRS, OWASP_CRS/PROTOCOL-ENFORCEMENT, capec/1000/210/272
- **Actions**: id:920280, phase:1, block, t:none, msg:Request Missing a Host Header, tag:application-multi, tag:language-multi, tag:platform-multi, tag:attack-protocol, tag:paranoia-level/1, tag:OWASP_CRS, tag:OWASP_CRS/PROTOCOL-ENFORCEMENT, tag:capec/1000/210/272, ver:OWASP_CRS/4.22.0-dev, severity:CRITICAL, setvar:tx.inbound_anomaly_score_pl1=+%{tx.critical_anomaly_score}, skipAfter:END-HOST-CHECK

#### Rule 24: 920290
- **Phase**: 1
- **Variables**: REQUEST_HEADERS:Host
- **Operator**: @rx
- **Pattern**: ^$
- **Is Chain**: False
- **Message**: Empty Host Header
- **Severity**: CRITICAL
- **Tags**: application-multi, language-multi, platform-multi, attack-protocol, paranoia-level/1, OWASP_CRS, OWASP_CRS/PROTOCOL-ENFORCEMENT, capec/1000/210/272
- **Actions**: id:920290, phase:1, block, t:none, msg:Empty Host Header, tag:application-multi, tag:language-multi, tag:platform-multi, tag:attack-protocol, tag:paranoia-level/1, tag:OWASP_CRS, tag:OWASP_CRS/PROTOCOL-ENFORCEMENT, tag:capec/1000/210/272, ver:OWASP_CRS/4.22.0-dev, severity:CRITICAL, setvar:tx.inbound_anomaly_score_pl1=+%{tx.critical_anomaly_score}

#### Rule 25: 920310
- **Phase**: 1
- **Variables**: REQUEST_HEADERS:Accept
- **Operator**: @rx
- **Pattern**: ^$
- **Is Chain**: True
- **Message**: Request Has an Empty Accept Header
- **Severity**: NOTICE
- **Tags**: application-multi, language-multi, platform-multi, attack-protocol, paranoia-level/1, OWASP_CRS, OWASP_CRS/PROTOCOL-ENFORCEMENT, capec/1000/210/272
- **Actions**: id:920310, phase:1, block, t:none, msg:Request Has an Empty Accept Header, tag:application-multi, tag:language-multi, tag:platform-multi, tag:attack-protocol, tag:paranoia-level/1, tag:OWASP_CRS, tag:OWASP_CRS/PROTOCOL-ENFORCEMENT, tag:capec/1000/210/272, ver:OWASP_CRS/4.22.0-dev, severity:NOTICE, chain

#### Rule 26: Unknown
- **Phase**: Unknown
- **Variables**: REQUEST_METHOD
- **Operator**: !@rx
- **Pattern**: ^OPTIONS$
- **Is Chain**: True
- **Message**: 
- **Severity**: 
- **Actions**: chain

#### Rule 27: Unknown
- **Phase**: Unknown
- **Variables**: REQUEST_HEADERS:User-Agent
- **Operator**: !@pm
- **Pattern**: AppleWebKit Android Business Enterprise Entreprise
- **Is Chain**: False
- **Message**: 
- **Severity**: 
- **Actions**: t:none, setvar:tx.inbound_anomaly_score_pl1=+%{tx.notice_anomaly_score}

#### Rule 28: 920311
- **Phase**: 1
- **Variables**: REQUEST_HEADERS:Accept
- **Operator**: @rx
- **Pattern**: ^$
- **Is Chain**: True
- **Message**: Request Has an Empty Accept Header
- **Severity**: NOTICE
- **Tags**: application-multi, language-multi, platform-multi, attack-protocol, paranoia-level/1, OWASP_CRS, OWASP_CRS/PROTOCOL-ENFORCEMENT, capec/1000/210/272
- **Actions**: id:920311, phase:1, block, t:none, msg:Request Has an Empty Accept Header, tag:application-multi, tag:language-multi, tag:platform-multi, tag:attack-protocol, tag:paranoia-level/1, tag:OWASP_CRS, tag:OWASP_CRS/PROTOCOL-ENFORCEMENT, tag:capec/1000/210/272, ver:OWASP_CRS/4.22.0-dev, severity:NOTICE, chain

#### Rule 29: Unknown
- **Phase**: Unknown
- **Variables**: REQUEST_METHOD
- **Operator**: !@rx
- **Pattern**: ^OPTIONS$
- **Is Chain**: True
- **Message**: 
- **Severity**: 
- **Actions**: chain

#### Rule 30: Unknown
- **Phase**: Unknown
- **Variables**: REQUEST_HEADERS:User-Agent
- **Operator**: @eq
- **Pattern**: 0
- **Is Chain**: False
- **Message**: 
- **Severity**: 
- **Actions**: t:none, setvar:tx.inbound_anomaly_score_pl1=+%{tx.notice_anomaly_score}

#### Rule 31: 920330
- **Phase**: 1
- **Variables**: REQUEST_HEADERS:User-Agent
- **Operator**: @rx
- **Pattern**: ^$
- **Is Chain**: False
- **Message**: Empty User Agent Header
- **Severity**: NOTICE
- **Tags**: application-multi, language-multi, platform-multi, attack-protocol, paranoia-level/1, OWASP_CRS, OWASP_CRS/PROTOCOL-ENFORCEMENT, capec/1000/210/272
- **Actions**: id:920330, phase:1, block, t:none, msg:Empty User Agent Header, tag:application-multi, tag:language-multi, tag:platform-multi, tag:attack-protocol, tag:paranoia-level/1, tag:OWASP_CRS, tag:OWASP_CRS/PROTOCOL-ENFORCEMENT, tag:capec/1000/210/272, ver:OWASP_CRS/4.22.0-dev, severity:NOTICE, setvar:tx.inbound_anomaly_score_pl1=+%{tx.notice_anomaly_score}

#### Rule 32: 920340
- **Phase**: 1
- **Variables**: REQUEST_HEADERS:Content-Length
- **Operator**: !@rx
- **Pattern**: ^0$
- **Is Chain**: True
- **Message**: Request Containing Content, but Missing Content-Type header
- **Severity**: CRITICAL
- **Tags**: application-multi, language-multi, platform-multi, attack-protocol, paranoia-level/1, OWASP_CRS, OWASP_CRS/PROTOCOL-ENFORCEMENT, capec/1000/210/272
- **Actions**: id:920340, phase:1, block, t:none, msg:Request Containing Content, but Missing Content-Type header, tag:application-multi, tag:language-multi, tag:platform-multi, tag:attack-protocol, tag:paranoia-level/1, tag:OWASP_CRS, tag:OWASP_CRS/PROTOCOL-ENFORCEMENT, tag:capec/1000/210/272, ver:OWASP_CRS/4.22.0-dev, severity:CRITICAL, chain

#### Rule 33: Unknown
- **Phase**: Unknown
- **Variables**: REQUEST_HEADERS:Content-Type
- **Operator**: @eq
- **Pattern**: 0
- **Is Chain**: False
- **Message**: 
- **Severity**: 
- **Actions**: t:none, setvar:tx.inbound_anomaly_score_pl1=+%{tx.critical_anomaly_score}

#### Rule 34: 920350
- **Phase**: 1
- **Variables**: REQUEST_HEADERS:Host
- **Operator**: @rx
- **Pattern**: (?:^([\d.]+|\[[\da-f:]+\]|[\da-f:]+)(:[\d]+)?$)
- **Is Chain**: False
- **Message**: Host header is a numeric IP address
- **Severity**: WARNING
- **Tags**: application-multi, language-multi, platform-multi, attack-protocol, paranoia-level/1, OWASP_CRS, OWASP_CRS/PROTOCOL-ENFORCEMENT, capec/1000/210/272
- **Actions**: id:920350, phase:1, block, t:none, msg:Host header is a numeric IP address, logdata:%{MATCHED_VAR}, tag:application-multi, tag:language-multi, tag:platform-multi, tag:attack-protocol, tag:paranoia-level/1, tag:OWASP_CRS, tag:OWASP_CRS/PROTOCOL-ENFORCEMENT, tag:capec/1000/210/272, ver:OWASP_CRS/4.22.0-dev, severity:WARNING, setvar:tx.inbound_anomaly_score_pl1=+%{tx.warning_anomaly_score}

#### Rule 35: 920380
- **Phase**: 2
- **Variables**: TX:MAX_NUM_ARGS
- **Operator**: @eq
- **Pattern**: 1
- **Is Chain**: True
- **Message**: Too many arguments in request
- **Severity**: CRITICAL
- **Tags**: application-multi, language-multi, platform-multi, attack-protocol, paranoia-level/1, OWASP_CRS, OWASP_CRS/PROTOCOL-ENFORCEMENT, capec/1000/210/272
- **Actions**: id:920380, phase:2, block, t:none, msg:Too many arguments in request, logdata:%{MATCHED_VAR_NAME}=%{MATCHED_VAR}, tag:application-multi, tag:language-multi, tag:platform-multi, tag:attack-protocol, tag:paranoia-level/1, tag:OWASP_CRS, tag:OWASP_CRS/PROTOCOL-ENFORCEMENT, tag:capec/1000/210/272, ver:OWASP_CRS/4.22.0-dev, severity:CRITICAL, chain

#### Rule 36: Unknown
- **Phase**: Unknown
- **Variables**: ARGS
- **Operator**: @gt
- **Pattern**: %{tx.max_num_args}
- **Is Chain**: False
- **Message**: 
- **Severity**: 
- **Actions**: t:none, setvar:tx.inbound_anomaly_score_pl1=+%{tx.critical_anomaly_score}

#### Rule 37: 920360
- **Phase**: 2
- **Variables**: TX:ARG_NAME_LENGTH
- **Operator**: @eq
- **Pattern**: 1
- **Is Chain**: True
- **Message**: Argument name too long
- **Severity**: CRITICAL
- **Tags**: application-multi, language-multi, platform-multi, attack-protocol, paranoia-level/1, OWASP_CRS, OWASP_CRS/PROTOCOL-ENFORCEMENT, capec/1000/210/272
- **Actions**: id:920360, phase:2, block, t:none, msg:Argument name too long, logdata:%{MATCHED_VAR_NAME}=%{MATCHED_VAR}, tag:application-multi, tag:language-multi, tag:platform-multi, tag:attack-protocol, tag:paranoia-level/1, tag:OWASP_CRS, tag:OWASP_CRS/PROTOCOL-ENFORCEMENT, tag:capec/1000/210/272, ver:OWASP_CRS/4.22.0-dev, severity:CRITICAL, chain

#### Rule 38: Unknown
- **Phase**: Unknown
- **Variables**: ARGS_NAMES
- **Operator**: @gt
- **Pattern**: %{tx.arg_name_length}
- **Is Chain**: False
- **Message**: 
- **Severity**: 
- **Actions**: t:none, t:length, setvar:tx.inbound_anomaly_score_pl1=+%{tx.critical_anomaly_score}

#### Rule 39: 920370
- **Phase**: 2
- **Variables**: TX:ARG_LENGTH
- **Operator**: @eq
- **Pattern**: 1
- **Is Chain**: True
- **Message**: Argument value too long
- **Severity**: CRITICAL
- **Tags**: application-multi, language-multi, platform-multi, attack-protocol, paranoia-level/1, OWASP_CRS, OWASP_CRS/PROTOCOL-ENFORCEMENT, capec/1000/210/272
- **Actions**: id:920370, phase:2, block, t:none, msg:Argument value too long, logdata:%{MATCHED_VAR_NAME}=%{MATCHED_VAR}, tag:application-multi, tag:language-multi, tag:platform-multi, tag:attack-protocol, tag:paranoia-level/1, tag:OWASP_CRS, tag:OWASP_CRS/PROTOCOL-ENFORCEMENT, tag:capec/1000/210/272, ver:OWASP_CRS/4.22.0-dev, severity:CRITICAL, chain

#### Rule 40: Unknown
- **Phase**: Unknown
- **Variables**: ARGS
- **Operator**: @gt
- **Pattern**: %{tx.arg_length}
- **Is Chain**: False
- **Message**: 
- **Severity**: 
- **Actions**: t:none, t:length, setvar:tx.inbound_anomaly_score_pl1=+%{tx.critical_anomaly_score}

#### Rule 41: 920390
- **Phase**: 2
- **Variables**: TX:TOTAL_ARG_LENGTH
- **Operator**: @eq
- **Pattern**: 1
- **Is Chain**: True
- **Message**: Total arguments size exceeded
- **Severity**: CRITICAL
- **Tags**: application-multi, language-multi, platform-multi, attack-protocol, paranoia-level/1, OWASP_CRS, OWASP_CRS/PROTOCOL-ENFORCEMENT, capec/1000/210/272
- **Actions**: id:920390, phase:2, block, t:none, msg:Total arguments size exceeded, logdata:%{MATCHED_VAR_NAME}=%{MATCHED_VAR}, tag:application-multi, tag:language-multi, tag:platform-multi, tag:attack-protocol, tag:paranoia-level/1, tag:OWASP_CRS, tag:OWASP_CRS/PROTOCOL-ENFORCEMENT, tag:capec/1000/210/272, ver:OWASP_CRS/4.22.0-dev, severity:CRITICAL, chain

#### Rule 42: Unknown
- **Phase**: Unknown
- **Variables**: ARGS_COMBINED_SIZE
- **Operator**: @gt
- **Pattern**: %{tx.total_arg_length}
- **Is Chain**: False
- **Message**: 
- **Severity**: 
- **Actions**: t:none, setvar:tx.inbound_anomaly_score_pl1=+%{tx.critical_anomaly_score}

#### Rule 43: 920400
- **Phase**: 1
- **Variables**: TX:MAX_FILE_SIZE
- **Operator**: @eq
- **Pattern**: 1
- **Is Chain**: True
- **Message**: Uploaded file size too large
- **Severity**: CRITICAL
- **Tags**: application-multi, language-multi, platform-multi, attack-protocol, paranoia-level/1, OWASP_CRS, OWASP_CRS/PROTOCOL-ENFORCEMENT, capec/1000/210/272
- **Actions**: id:920400, phase:1, block, t:none, msg:Uploaded file size too large, tag:application-multi, tag:language-multi, tag:platform-multi, tag:attack-protocol, tag:paranoia-level/1, tag:OWASP_CRS, tag:OWASP_CRS/PROTOCOL-ENFORCEMENT, tag:capec/1000/210/272, ver:OWASP_CRS/4.22.0-dev, severity:CRITICAL, chain

#### Rule 44: Unknown
- **Phase**: Unknown
- **Variables**: REQUEST_HEADERS:Content-Type
- **Operator**: @rx
- **Pattern**: ^(?i)multipart/form-data
- **Is Chain**: True
- **Message**: 
- **Severity**: 
- **Actions**: chain

#### Rule 45: Unknown
- **Phase**: Unknown
- **Variables**: REQUEST_HEADERS:Content-Length
- **Operator**: @gt
- **Pattern**: %{tx.max_file_size}
- **Is Chain**: False
- **Message**: 
- **Severity**: 
- **Actions**: t:none, setvar:tx.inbound_anomaly_score_pl1=+%{tx.critical_anomaly_score}

#### Rule 46: 920410
- **Phase**: 2
- **Variables**: TX:COMBINED_FILE_SIZES
- **Operator**: @eq
- **Pattern**: 1
- **Is Chain**: True
- **Message**: Total uploaded files size too large
- **Severity**: CRITICAL
- **Tags**: application-multi, language-multi, platform-multi, attack-protocol, paranoia-level/1, OWASP_CRS, OWASP_CRS/PROTOCOL-ENFORCEMENT, capec/1000/210/272
- **Actions**: id:920410, phase:2, block, t:none, msg:Total uploaded files size too large, logdata:%{MATCHED_VAR_NAME}=%{MATCHED_VAR}, tag:application-multi, tag:language-multi, tag:platform-multi, tag:attack-protocol, tag:paranoia-level/1, tag:OWASP_CRS, tag:OWASP_CRS/PROTOCOL-ENFORCEMENT, tag:capec/1000/210/272, ver:OWASP_CRS/4.22.0-dev, severity:CRITICAL, chain

#### Rule 47: Unknown
- **Phase**: Unknown
- **Variables**: FILES_COMBINED_SIZE
- **Operator**: @gt
- **Pattern**: %{tx.combined_file_sizes}
- **Is Chain**: False
- **Message**: 
- **Severity**: 
- **Actions**: t:none, setvar:tx.inbound_anomaly_score_pl1=+%{tx.critical_anomaly_score}

#### Rule 48: 920470
- **Phase**: 1
- **Variables**: REQUEST_HEADERS:Content-Type
- **Operator**: !@rx
- **Pattern**: ^[\w/.+*-]+(?:\s?;\s*(?:action|boundary|charset|component|start(?:-info)?|type|version)\s?=\s?['\"\w.()+,/:=?<>@#*-]+)*$
- **Is Chain**: False
- **Message**: Illegal Content-Type header
- **Severity**: CRITICAL
- **Tags**: application-multi, language-multi, platform-multi, attack-protocol, paranoia-level/1, OWASP_CRS, OWASP_CRS/PROTOCOL-ENFORCEMENT, capec/1000/255/153
- **Actions**: id:920470, phase:1, block, t:none, t:lowercase, msg:Illegal Content-Type header, logdata:%{MATCHED_VAR}, tag:application-multi, tag:language-multi, tag:platform-multi, tag:attack-protocol, tag:paranoia-level/1, tag:OWASP_CRS, tag:OWASP_CRS/PROTOCOL-ENFORCEMENT, tag:capec/1000/255/153, ver:OWASP_CRS/4.22.0-dev, severity:CRITICAL, setvar:tx.inbound_anomaly_score_pl1=+%{tx.critical_anomaly_score}

#### Rule 49: 920420
- **Phase**: 1
- **Variables**: REQUEST_HEADERS:Content-Type
- **Operator**: @rx
- **Pattern**: ^[^;\s]+
- **Is Chain**: True
- **Message**: Request content type is not allowed by policy
- **Severity**: CRITICAL
- **Tags**: application-multi, language-multi, platform-multi, attack-protocol, paranoia-level/1, OWASP_CRS, OWASP_CRS/PROTOCOL-ENFORCEMENT, capec/1000/255/153
- **Actions**: id:920420, phase:1, block, capture, t:none, msg:Request content type is not allowed by policy, logdata:%{MATCHED_VAR}, tag:application-multi, tag:language-multi, tag:platform-multi, tag:attack-protocol, tag:paranoia-level/1, tag:OWASP_CRS, tag:OWASP_CRS/PROTOCOL-ENFORCEMENT, tag:capec/1000/255/153, ver:OWASP_CRS/4.22.0-dev, severity:CRITICAL, setvar:tx.content_type=|%{tx.0}|, chain

#### Rule 50: Unknown
- **Phase**: Unknown
- **Variables**: TX:content_type
- **Operator**: !@within
- **Pattern**: %{tx.allowed_request_content_type}
- **Is Chain**: False
- **Message**: 
- **Severity**: 
- **Actions**: t:lowercase, setvar:tx.inbound_anomaly_score_pl1=+%{tx.critical_anomaly_score}

#### Rule 51: 920480
- **Phase**: 1
- **Variables**: REQUEST_HEADERS:Content-Type
- **Operator**: @rx
- **Pattern**: charset\s*=\s*[\"']?([^;\"'\s]+)
- **Is Chain**: True
- **Message**: Request content type charset is not allowed by policy
- **Severity**: CRITICAL
- **Tags**: application-multi, language-multi, platform-multi, attack-protocol, paranoia-level/1, OWASP_CRS, OWASP_CRS/PROTOCOL-ENFORCEMENT, capec/1000/255/153
- **Actions**: id:920480, phase:1, block, capture, t:none, msg:Request content type charset is not allowed by policy, logdata:%{MATCHED_VAR}, tag:application-multi, tag:language-multi, tag:platform-multi, tag:attack-protocol, tag:paranoia-level/1, tag:OWASP_CRS, tag:OWASP_CRS/PROTOCOL-ENFORCEMENT, tag:capec/1000/255/153, ver:OWASP_CRS/4.22.0-dev, severity:CRITICAL, setvar:tx.content_type_charset=|%{tx.1}|, chain

#### Rule 52: Unknown
- **Phase**: Unknown
- **Variables**: TX:content_type_charset
- **Operator**: !@within
- **Pattern**: %{tx.allowed_request_content_type_charset}
- **Is Chain**: False
- **Message**: 
- **Severity**: 
- **Actions**: t:lowercase, ctl:forceRequestBodyVariable, setvar:tx.inbound_anomaly_score_pl1=+%{tx.critical_anomaly_score}

#### Rule 53: 920530
- **Phase**: 1
- **Variables**: REQUEST_HEADERS:Content-Type
- **Operator**: @rx
- **Pattern**: charset.*?charset
- **Is Chain**: False
- **Message**: Multiple charsets detected in content type header
- **Severity**: CRITICAL
- **Tags**: application-multi, language-multi, platform-multi, attack-protocol, paranoia-level/1, OWASP_CRS, OWASP_CRS/PROTOCOL-ENFORCEMENT, capec/1000/255/153
- **Actions**: id:920530, phase:1, block, t:none, t:lowercase, msg:Multiple charsets detected in content type header, logdata:%{MATCHED_VAR}, tag:application-multi, tag:language-multi, tag:platform-multi, tag:attack-protocol, tag:paranoia-level/1, tag:OWASP_CRS, tag:OWASP_CRS/PROTOCOL-ENFORCEMENT, tag:capec/1000/255/153, ver:OWASP_CRS/4.22.0-dev, severity:CRITICAL, setvar:tx.inbound_anomaly_score_pl1=+%{tx.critical_anomaly_score}

#### Rule 54: 920430
- **Phase**: 1
- **Variables**: REQUEST_PROTOCOL
- **Operator**: !@within
- **Pattern**: %{tx.allowed_http_versions}
- **Is Chain**: False
- **Message**: HTTP protocol version is not allowed by policy
- **Severity**: CRITICAL
- **Tags**: application-multi, language-multi, platform-multi, attack-protocol, paranoia-level/1, OWASP_CRS, OWASP_CRS/PROTOCOL-ENFORCEMENT, capec/1000/210/272
- **Actions**: id:920430, phase:1, block, t:none, msg:HTTP protocol version is not allowed by policy, logdata:%{MATCHED_VAR}, tag:application-multi, tag:language-multi, tag:platform-multi, tag:attack-protocol, tag:paranoia-level/1, tag:OWASP_CRS, tag:OWASP_CRS/PROTOCOL-ENFORCEMENT, tag:capec/1000/210/272, ver:OWASP_CRS/4.22.0-dev, severity:CRITICAL, setvar:tx.inbound_anomaly_score_pl1=+%{tx.critical_anomaly_score}

#### Rule 55: 920440
- **Phase**: 1
- **Variables**: REQUEST_BASENAME
- **Operator**: @rx
- **Pattern**: \.([^.]+)$
- **Is Chain**: True
- **Message**: URL file extension is restricted by policy
- **Severity**: CRITICAL
- **Tags**: application-multi, language-multi, platform-multi, attack-protocol, paranoia-level/1, OWASP_CRS, OWASP_CRS/PROTOCOL-ENFORCEMENT, capec/1000/210/272
- **Actions**: id:920440, phase:1, block, capture, t:none, t:urlDecodeUni, msg:URL file extension is restricted by policy, logdata:%{TX.0}, tag:application-multi, tag:language-multi, tag:platform-multi, tag:attack-protocol, tag:paranoia-level/1, tag:OWASP_CRS, tag:OWASP_CRS/PROTOCOL-ENFORCEMENT, tag:capec/1000/210/272, ver:OWASP_CRS/4.22.0-dev, severity:CRITICAL, setvar:tx.extension=.%{tx.1}/, chain

#### Rule 56: Unknown
- **Phase**: Unknown
- **Variables**: TX:EXTENSION
- **Operator**: @within
- **Pattern**: %{tx.restricted_extensions}
- **Is Chain**: False
- **Message**: 
- **Severity**: 
- **Actions**: t:none, t:lowercase, setvar:tx.inbound_anomaly_score_pl1=+%{tx.critical_anomaly_score}

#### Rule 57: 920500
- **Phase**: 1
- **Variables**: REQUEST_FILENAME
- **Operator**: @rx
- **Pattern**: \.[^.~]+~(?:/.*|)$
- **Is Chain**: False
- **Message**: Attempt to access a backup or working file
- **Severity**: CRITICAL
- **Tags**: application-multi, language-multi, platform-multi, attack-protocol, paranoia-level/1, OWASP_CRS, OWASP_CRS/PROTOCOL-ENFORCEMENT, capec/1000/210/272
- **Actions**: id:920500, phase:1, block, capture, t:none, t:urlDecodeUni, msg:Attempt to access a backup or working file, logdata:%{TX.0}, tag:application-multi, tag:language-multi, tag:platform-multi, tag:attack-protocol, tag:paranoia-level/1, tag:OWASP_CRS, tag:OWASP_CRS/PROTOCOL-ENFORCEMENT, tag:capec/1000/210/272, ver:OWASP_CRS/4.22.0-dev, severity:CRITICAL, setvar:tx.inbound_anomaly_score_pl1=+%{tx.critical_anomaly_score}

#### Rule 58: 920450
- **Phase**: 1
- **Variables**: REQUEST_HEADERS_NAMES
- **Operator**: @rx
- **Pattern**: ^.*$
- **Is Chain**: True
- **Message**: HTTP header is restricted by policy (%{MATCHED_VAR})
- **Severity**: CRITICAL
- **Tags**: application-multi, language-multi, platform-multi, attack-protocol, paranoia-level/1, OWASP_CRS, OWASP_CRS/PROTOCOL-ENFORCEMENT, capec/1000/210/272
- **Actions**: id:920450, phase:1, block, capture, t:none, t:lowercase, msg:HTTP header is restricted by policy (%{MATCHED_VAR}), logdata:Restricted header detected: %{MATCHED_VAR}, tag:application-multi, tag:language-multi, tag:platform-multi, tag:attack-protocol, tag:paranoia-level/1, tag:OWASP_CRS, tag:OWASP_CRS/PROTOCOL-ENFORCEMENT, tag:capec/1000/210/272, ver:OWASP_CRS/4.22.0-dev, severity:CRITICAL, setvar:tx.header_name_920450_%{tx.0}=/%{tx.0}/, chain

#### Rule 59: Unknown
- **Phase**: Unknown
- **Variables**: TX:/^header_name_920450_/
- **Operator**: @within
- **Pattern**: %{tx.restricted_headers_basic}
- **Is Chain**: False
- **Message**: 
- **Severity**: 
- **Actions**: setvar:tx.inbound_anomaly_score_pl1=+%{tx.critical_anomaly_score}

#### Rule 60: 920520
- **Phase**: 1
- **Variables**: REQUEST_HEADERS:Accept-Encoding
- **Operator**: @gt
- **Pattern**: 100
- **Is Chain**: False
- **Message**: Accept-Encoding header exceeded sensible length
- **Severity**: CRITICAL
- **Tags**: application-multi, language-multi, platform-multi, attack-protocol, paranoia-level/1, OWASP_CRS, OWASP_CRS/PROTOCOL-ENFORCEMENT, capec/1000/255/153
- **Actions**: id:920520, phase:1, block, t:none, t:lowercase, t:length, msg:Accept-Encoding header exceeded sensible length, logdata:%{MATCHED_VAR}, tag:application-multi, tag:language-multi, tag:platform-multi, tag:attack-protocol, tag:paranoia-level/1, tag:OWASP_CRS, tag:OWASP_CRS/PROTOCOL-ENFORCEMENT, tag:capec/1000/255/153, ver:OWASP_CRS/4.22.0-dev, severity:CRITICAL, setvar:tx.inbound_anomaly_score_pl1=+%{tx.critical_anomaly_score}

#### Rule 61: 920600
- **Phase**: 1
- **Variables**: REQUEST_HEADERS:Accept
- **Operator**: !@rx
- **Pattern**: ^(?:(?:\*|[^!\"\(\),/:-\?\[-\]\{\}]+)/(?:\*|[^!\"\(\),/:-\?\[-\]\{\}]+)|\*)(?:[\s\x0b]*;[\s\x0b]*(?:charset[\s\x0b]*=[\s\x0b]*\"?(?:iso-8859-15?|utf-8|windows-1252)\b\"?|(?:[^\s\x0b-\"\(\),/:-\?\[-\]c\{\}]|c(?:[^!\"\(\),/:-\?\[-\]h\{\}]|h(?:[^!\"\(\),/:-\?\[-\]a\{\}]|a(?:[^!\"\(\),/:-\?\[-\]r\{\}]|r(?:[^!\"\(\),/:-\?\[-\]s\{\}]|s(?:[^!\"\(\),/:-\?\[-\]e\{\}]|e[^!\"\(\),/:-\?\[-\]t\{\}]))))))[^!\"\(\),/:-\?\[-\]\{\}]*[\s\x0b]*=[\s\x0b]*[^!\(\),/:-\?\[-\]\{\}]+);?)*(?:[\s\x0b]*,[\s\x0b]*(?:(?:\*|[^!\"\(\),/:-\?\[-\]\{\}]+)/(?:\*|[^!\"\(\),/:-\?\[-\]\{\}]+)|\*)(?:[\s\x0b]*;[\s\x0b]*(?:charset[\s\x0b]*=[\s\x0b]*\"?(?:iso-8859-15?|utf-8|windows-1252)\b\"?|(?:[^\s\x0b-\"\(\),/:-\?\[-\]c\{\}]|c(?:[^!\"\(\),/:-\?\[-\]h\{\}]|h(?:[^!\"\(\),/:-\?\[-\]a\{\}]|a(?:[^!\"\(\),/:-\?\[-\]r\{\}]|r(?:[^!\"\(\),/:-\?\[-\]s\{\}]|s(?:[^!\"\(\),/:-\?\[-\]e\{\}]|e[^!\"\(\),/:-\?\[-\]t\{\}]))))))[^!\"\(\),/:-\?\[-\]\{\}]*[\s\x0b]*=[\s\x0b]*[^!\(\),/:-\?\[-\]\{\}]+);?)*)*$
- **Is Chain**: False
- **Message**: Illegal Accept header: charset parameter
- **Severity**: CRITICAL
- **Tags**: application-multi, language-multi, platform-multi, attack-protocol, paranoia-level/1, OWASP_CRS, OWASP_CRS/PROTOCOL-ENFORCEMENT
- **Actions**: id:920600, phase:1, block, t:none, t:lowercase, msg:Illegal Accept header: charset parameter, logdata:%{MATCHED_VAR}, tag:application-multi, tag:language-multi, tag:platform-multi, tag:attack-protocol, tag:paranoia-level/1, tag:OWASP_CRS, tag:OWASP_CRS/PROTOCOL-ENFORCEMENT, ver:OWASP_CRS/4.22.0-dev, severity:CRITICAL, setvar:tx.inbound_anomaly_score_pl1=+%{tx.critical_anomaly_score}

#### Rule 62: 920540
- **Phase**: 2
- **Variables**: REQBODY_PROCESSOR
- **Operator**: !@streq
- **Pattern**: JSON
- **Is Chain**: True
- **Message**: Possible Unicode character bypass detected
- **Severity**: CRITICAL
- **Tags**: application-multi, language-multi, platform-multi, attack-protocol, paranoia-level/1, OWASP_CRS, OWASP_CRS/PROTOCOL-ENFORCEMENT, capec/1000/255/153/267/72
- **Actions**: id:920540, phase:2, block, t:none, msg:Possible Unicode character bypass detected, logdata:%{MATCHED_VAR_NAME}=%{MATCHED_VAR}, tag:application-multi, tag:language-multi, tag:platform-multi, tag:attack-protocol, tag:paranoia-level/1, tag:OWASP_CRS, tag:OWASP_CRS/PROTOCOL-ENFORCEMENT, tag:capec/1000/255/153/267/72, ver:OWASP_CRS/4.22.0-dev, severity:CRITICAL, chain

#### Rule 63: Unknown
- **Phase**: Unknown
- **Variables**: REQUEST_URI, REQUEST_HEADERS, ARGS, ARGS_NAMES
- **Operator**: @rx
- **Pattern**: (?i)\x5cu[0-9a-f]{4}
- **Is Chain**: False
- **Message**: 
- **Severity**: 
- **Actions**: setvar:tx.inbound_anomaly_score_pl1=+%{tx.critical_anomaly_score}

#### Rule 64: 920610
- **Phase**: 1
- **Variables**: REQUEST_URI_RAW
- **Operator**: @contains
- **Pattern**: #
- **Is Chain**: False
- **Message**: Raw (unencoded) fragment in request URI
- **Severity**: CRITICAL
- **Tags**: application-multi, language-multi, platform-multi, attack-protocol, paranoia-level/1, OWASP_CRS, OWASP_CRS/PROTOCOL-ENFORCEMENT
- **Actions**: id:920610, phase:1, block, t:none, msg:Raw (unencoded) fragment in request URI, logdata:%{MATCHED_VAR}, tag:application-multi, tag:language-multi, tag:platform-multi, tag:attack-protocol, tag:paranoia-level/1, tag:OWASP_CRS, tag:OWASP_CRS/PROTOCOL-ENFORCEMENT, ver:OWASP_CRS/4.22.0-dev, severity:CRITICAL, setvar:tx.inbound_anomaly_score_pl1=+%{tx.critical_anomaly_score}

#### Rule 65: 920620
- **Phase**: 1
- **Variables**: REQUEST_HEADERS:Content-Type
- **Operator**: @gt
- **Pattern**: 1
- **Is Chain**: False
- **Message**: Multiple Content-Type Request Headers
- **Severity**: CRITICAL
- **Tags**: application-multi, language-multi, platform-multi, attack-protocol, paranoia-level/1, OWASP_CRS, OWASP_CRS/PROTOCOL-ENFORCEMENT
- **Actions**: id:920620, phase:1, block, t:none, msg:Multiple Content-Type Request Headers, logdata:%{MATCHED_VAR}, tag:application-multi, tag:language-multi, tag:platform-multi, tag:attack-protocol, tag:paranoia-level/1, tag:OWASP_CRS, tag:OWASP_CRS/PROTOCOL-ENFORCEMENT, ver:OWASP_CRS/4.22.0-dev, severity:CRITICAL, setvar:tx.inbound_anomaly_score_pl1=+%{tx.critical_anomaly_score}

#### Rule 66: 920013
- **Phase**: 1
- **Variables**: TX:DETECTION_PARANOIA_LEVEL
- **Operator**: @lt
- **Pattern**: 2
- **Is Chain**: False
- **Message**: 
- **Severity**: 
- **Tags**: OWASP_CRS
- **Actions**: id:920013, phase:1, pass, nolog, tag:OWASP_CRS, ver:OWASP_CRS/4.22.0-dev, skipAfter:END-REQUEST-920-PROTOCOL-ENFORCEMENT

#### Rule 67: 920014
- **Phase**: 2
- **Variables**: TX:DETECTION_PARANOIA_LEVEL
- **Operator**: @lt
- **Pattern**: 2
- **Is Chain**: False
- **Message**: 
- **Severity**: 
- **Tags**: OWASP_CRS
- **Actions**: id:920014, phase:2, pass, nolog, tag:OWASP_CRS, ver:OWASP_CRS/4.22.0-dev, skipAfter:END-REQUEST-920-PROTOCOL-ENFORCEMENT

#### Rule 68: 920200
- **Phase**: 1
- **Variables**: REQUEST_HEADERS:Range, REQUEST_HEADERS:Request-Range
- **Operator**: @rx
- **Pattern**: ^bytes=(?:(?:\d+)?-(?:\d+)?\s*,?\s*){6}
- **Is Chain**: True
- **Message**: Range: Too many fields (6 or more)
- **Severity**: WARNING
- **Tags**: application-multi, language-multi, platform-multi, attack-protocol, paranoia-level/2, OWASP_CRS, OWASP_CRS/PROTOCOL-ENFORCEMENT, capec/1000/210/272
- **Actions**: id:920200, phase:1, block, t:none, msg:Range: Too many fields (6 or more), logdata:%{MATCHED_VAR}, tag:application-multi, tag:language-multi, tag:platform-multi, tag:attack-protocol, tag:paranoia-level/2, tag:OWASP_CRS, tag:OWASP_CRS/PROTOCOL-ENFORCEMENT, tag:capec/1000/210/272, ver:OWASP_CRS/4.22.0-dev, severity:WARNING, chain

#### Rule 69: Unknown
- **Phase**: Unknown
- **Variables**: REQUEST_BASENAME
- **Operator**: !@endsWith
- **Pattern**: .pdf
- **Is Chain**: False
- **Message**: 
- **Severity**: 
- **Actions**: setvar:tx.inbound_anomaly_score_pl2=+%{tx.warning_anomaly_score}

#### Rule 70: 920201
- **Phase**: 1
- **Variables**: REQUEST_BASENAME
- **Operator**: @endsWith
- **Pattern**: .pdf
- **Is Chain**: True
- **Message**: Range: Too many fields for pdf request (63 or more)
- **Severity**: WARNING
- **Tags**: application-multi, language-multi, platform-multi, attack-protocol, paranoia-level/2, OWASP_CRS, OWASP_CRS/PROTOCOL-ENFORCEMENT, capec/1000/210/272
- **Actions**: id:920201, phase:1, block, t:none, t:urlDecodeUni, msg:Range: Too many fields for pdf request (63 or more), logdata:%{MATCHED_VAR}, tag:application-multi, tag:language-multi, tag:platform-multi, tag:attack-protocol, tag:paranoia-level/2, tag:OWASP_CRS, tag:OWASP_CRS/PROTOCOL-ENFORCEMENT, tag:capec/1000/210/272, ver:OWASP_CRS/4.22.0-dev, severity:WARNING, chain

#### Rule 71: Unknown
- **Phase**: Unknown
- **Variables**: REQUEST_HEADERS:Range, REQUEST_HEADERS:Request-Range
- **Operator**: @rx
- **Pattern**: ^bytes=(?:(?:\d+)?-(?:\d+)?\s*,?\s*){63}
- **Is Chain**: False
- **Message**: 
- **Severity**: 
- **Actions**: setvar:tx.inbound_anomaly_score_pl2=+%{tx.warning_anomaly_score}

#### Rule 72: 920230
- **Phase**: 2
- **Variables**: ARGS
- **Operator**: @rx
- **Pattern**: %[0-9a-fA-F]{2}
- **Is Chain**: False
- **Message**: Multiple URL Encoding Detected
- **Severity**: WARNING
- **Tags**: application-multi, language-multi, platform-multi, attack-protocol, paranoia-level/2, OWASP_CRS, OWASP_CRS/PROTOCOL-ENFORCEMENT, capec/1000/255/153/267/120
- **Actions**: id:920230, phase:2, block, t:none, msg:Multiple URL Encoding Detected, logdata:%{MATCHED_VAR}, tag:application-multi, tag:language-multi, tag:platform-multi, tag:attack-protocol, tag:paranoia-level/2, tag:OWASP_CRS, tag:OWASP_CRS/PROTOCOL-ENFORCEMENT, tag:capec/1000/255/153/267/120, ver:OWASP_CRS/4.22.0-dev, severity:WARNING, setvar:tx.inbound_anomaly_score_pl2=+%{tx.warning_anomaly_score}

#### Rule 73: 920271
- **Phase**: 2
- **Variables**: REQUEST_URI_RAW, REQUEST_HEADERS, ARGS, ARGS_NAMES
- **Operator**: @validateByteRange
- **Pattern**: 9,10,13,32-126,128-255
- **Is Chain**: False
- **Message**: Invalid character in request (non printable characters)
- **Severity**: CRITICAL
- **Tags**: application-multi, language-multi, platform-multi, attack-protocol, paranoia-level/2, OWASP_CRS, OWASP_CRS/PROTOCOL-ENFORCEMENT, capec/1000/210/272
- **Actions**: id:920271, phase:2, block, t:none, t:urlDecodeUni, msg:Invalid character in request (non printable characters), logdata:%{MATCHED_VAR_NAME}=%{MATCHED_VAR}, tag:application-multi, tag:language-multi, tag:platform-multi, tag:attack-protocol, tag:paranoia-level/2, tag:OWASP_CRS, tag:OWASP_CRS/PROTOCOL-ENFORCEMENT, tag:capec/1000/210/272, ver:OWASP_CRS/4.22.0-dev, severity:CRITICAL, setvar:tx.inbound_anomaly_score_pl2=+%{tx.critical_anomaly_score}

#### Rule 74: 920320
- **Phase**: 1
- **Variables**: REQUEST_HEADERS:User-Agent
- **Operator**: @eq
- **Pattern**: 0
- **Is Chain**: False
- **Message**: Missing User Agent Header
- **Severity**: NOTICE
- **Tags**: application-multi, language-multi, platform-multi, attack-protocol, paranoia-level/2, OWASP_CRS, OWASP_CRS/PROTOCOL-ENFORCEMENT, capec/1000/210/272
- **Actions**: id:920320, phase:1, block, t:none, msg:Missing User Agent Header, tag:application-multi, tag:language-multi, tag:platform-multi, tag:attack-protocol, tag:paranoia-level/2, tag:OWASP_CRS, tag:OWASP_CRS/PROTOCOL-ENFORCEMENT, tag:capec/1000/210/272, ver:OWASP_CRS/4.22.0-dev, severity:NOTICE, setvar:tx.inbound_anomaly_score_pl2=+%{tx.notice_anomaly_score}

#### Rule 75: 920121
- **Phase**: 2
- **Variables**: FILES_NAMES, FILES
- **Operator**: @rx
- **Pattern**: ['\";=\x5c]
- **Is Chain**: False
- **Message**: Attempted multipart/form-data bypass
- **Severity**: CRITICAL
- **Tags**: application-multi, language-multi, platform-multi, attack-protocol, paranoia-level/2, OWASP_CRS, OWASP_CRS/PROTOCOL-ENFORCEMENT, capec/1000/210/272
- **Actions**: id:920121, phase:2, block, t:none, t:urlDecodeUni, msg:Attempted multipart/form-data bypass, logdata:%{MATCHED_VAR}, tag:application-multi, tag:language-multi, tag:platform-multi, tag:attack-protocol, tag:paranoia-level/2, tag:OWASP_CRS, tag:OWASP_CRS/PROTOCOL-ENFORCEMENT, tag:capec/1000/210/272, ver:OWASP_CRS/4.22.0-dev, severity:CRITICAL, setvar:tx.inbound_anomaly_score_pl2=+%{tx.critical_anomaly_score}

#### Rule 76: 920451
- **Phase**: 1
- **Variables**: REQUEST_HEADERS_NAMES
- **Operator**: @rx
- **Pattern**: ^.*$
- **Is Chain**: True
- **Message**: HTTP header is restricted by policy (%{MATCHED_VAR})
- **Severity**: CRITICAL
- **Tags**: application-multi, language-multi, platform-multi, attack-protocol, paranoia-level/2, OWASP_CRS, OWASP_CRS/PROTOCOL-ENFORCEMENT, capec/1000/210/272
- **Actions**: id:920451, phase:1, block, capture, t:none, t:lowercase, msg:HTTP header is restricted by policy (%{MATCHED_VAR}), logdata:Restricted header detected: %{MATCHED_VAR}, tag:application-multi, tag:language-multi, tag:platform-multi, tag:attack-protocol, tag:paranoia-level/2, tag:OWASP_CRS, tag:OWASP_CRS/PROTOCOL-ENFORCEMENT, tag:capec/1000/210/272, ver:OWASP_CRS/4.22.0-dev, severity:CRITICAL, setvar:tx.header_name_920451_%{tx.0}=/%{tx.0}/, chain

#### Rule 77: Unknown
- **Phase**: Unknown
- **Variables**: TX:/^header_name_920451_/
- **Operator**: @within
- **Pattern**: %{tx.restricted_headers_extended}
- **Is Chain**: False
- **Message**: 
- **Severity**: 
- **Actions**: setvar:tx.inbound_anomaly_score_pl2=+%{tx.critical_anomaly_score}

#### Rule 78: 920240
- **Phase**: 2
- **Variables**: REQUEST_HEADERS:Content-Type
- **Operator**: @rx
- **Pattern**: ^(?i)application/x-www-form-urlencoded
- **Is Chain**: True
- **Message**: URL Encoding Abuse Attack Attempt
- **Severity**: WARNING
- **Tags**: application-multi, language-multi, platform-multi, attack-protocol, paranoia-level/2, OWASP_CRS, OWASP_CRS/PROTOCOL-ENFORCEMENT, capec/1000/255/153/267/72
- **Actions**: id:920240, phase:2, block, t:none, msg:URL Encoding Abuse Attack Attempt, logdata:%{MATCHED_VAR}, tag:application-multi, tag:language-multi, tag:platform-multi, tag:attack-protocol, tag:paranoia-level/2, tag:OWASP_CRS, tag:OWASP_CRS/PROTOCOL-ENFORCEMENT, tag:capec/1000/255/153/267/72, ver:OWASP_CRS/4.22.0-dev, severity:WARNING, chain

#### Rule 79: Unknown
- **Phase**: Unknown
- **Variables**: REQUEST_BODY
- **Operator**: @rx
- **Pattern**: \x25
- **Is Chain**: True
- **Message**: 
- **Severity**: 
- **Actions**: chain

#### Rule 80: Unknown
- **Phase**: Unknown
- **Variables**: REQUEST_BODY
- **Operator**: @validateUrlEncoding
- **Pattern**: 
- **Is Chain**: False
- **Message**: 
- **Severity**: 
- **Actions**: setvar:tx.inbound_anomaly_score_pl2=+%{tx.warning_anomaly_score}

#### Rule 81: 920015
- **Phase**: 1
- **Variables**: TX:DETECTION_PARANOIA_LEVEL
- **Operator**: @lt
- **Pattern**: 3
- **Is Chain**: False
- **Message**: 
- **Severity**: 
- **Tags**: OWASP_CRS
- **Actions**: id:920015, phase:1, pass, nolog, tag:OWASP_CRS, ver:OWASP_CRS/4.22.0-dev, skipAfter:END-REQUEST-920-PROTOCOL-ENFORCEMENT

#### Rule 82: 920016
- **Phase**: 2
- **Variables**: TX:DETECTION_PARANOIA_LEVEL
- **Operator**: @lt
- **Pattern**: 3
- **Is Chain**: False
- **Message**: 
- **Severity**: 
- **Tags**: OWASP_CRS
- **Actions**: id:920016, phase:2, pass, nolog, tag:OWASP_CRS, ver:OWASP_CRS/4.22.0-dev, skipAfter:END-REQUEST-920-PROTOCOL-ENFORCEMENT

#### Rule 83: 920272
- **Phase**: 2
- **Variables**: REQUEST_URI_RAW, REQUEST_HEADERS, ARGS, ARGS_NAMES, REQUEST_BODY
- **Operator**: @validateByteRange
- **Pattern**: 32-36,38-126
- **Is Chain**: False
- **Message**: Invalid character in request (outside of printable chars below ascii 127)
- **Severity**: CRITICAL
- **Tags**: application-multi, language-multi, platform-multi, attack-protocol, paranoia-level/3, OWASP_CRS, OWASP_CRS/PROTOCOL-ENFORCEMENT, capec/1000/210/272
- **Actions**: id:920272, phase:2, block, t:none, t:urlDecodeUni, msg:Invalid character in request (outside of printable chars below ascii 127), logdata:%{MATCHED_VAR_NAME}=%{MATCHED_VAR}, tag:application-multi, tag:language-multi, tag:platform-multi, tag:attack-protocol, tag:paranoia-level/3, tag:OWASP_CRS, tag:OWASP_CRS/PROTOCOL-ENFORCEMENT, tag:capec/1000/210/272, ver:OWASP_CRS/4.22.0-dev, severity:CRITICAL, setvar:tx.inbound_anomaly_score_pl3=+%{tx.critical_anomaly_score}

#### Rule 84: 920300
- **Phase**: 1
- **Variables**: REQUEST_HEADERS:Accept
- **Operator**: @eq
- **Pattern**: 0
- **Is Chain**: True
- **Message**: Request Missing an Accept Header
- **Severity**: NOTICE
- **Tags**: application-multi, language-multi, platform-multi, attack-protocol, paranoia-level/3, OWASP_CRS, OWASP_CRS/PROTOCOL-ENFORCEMENT, capec/1000/210/272
- **Actions**: id:920300, phase:1, block, t:none, msg:Request Missing an Accept Header, tag:application-multi, tag:language-multi, tag:platform-multi, tag:attack-protocol, tag:paranoia-level/3, tag:OWASP_CRS, tag:OWASP_CRS/PROTOCOL-ENFORCEMENT, tag:capec/1000/210/272, ver:OWASP_CRS/4.22.0-dev, severity:NOTICE, chain

#### Rule 85: Unknown
- **Phase**: Unknown
- **Variables**: REQUEST_METHOD
- **Operator**: !@rx
- **Pattern**: ^(?:OPTIONS|CONNECT)$
- **Is Chain**: True
- **Message**: 
- **Severity**: 
- **Actions**: chain

#### Rule 86: Unknown
- **Phase**: Unknown
- **Variables**: REQUEST_HEADERS:User-Agent
- **Operator**: !@pm
- **Pattern**: AppleWebKit Android
- **Is Chain**: False
- **Message**: 
- **Severity**: 
- **Actions**: t:none, setvar:tx.inbound_anomaly_score_pl3=+%{tx.notice_anomaly_score}

#### Rule 87: 920490
- **Phase**: 1
- **Variables**: REQUEST_HEADERS:x-up-devcap-post-charset
- **Operator**: @ge
- **Pattern**: 1
- **Is Chain**: True
- **Message**: Request header x-up-devcap-post-charset detected in combination with prefix \'UP\' to User-Agent
- **Severity**: CRITICAL
- **Tags**: language-aspnet, platform-windows, attack-protocol, paranoia-level/3, OWASP_CRS, OWASP_CRS/PROTOCOL-ENFORCEMENT, capec/1000/210/272
- **Actions**: id:920490, phase:1, block, t:none, msg:Request header x-up-devcap-post-charset detected in combination with prefix \'UP\' to User-Agent, logdata:%{MATCHED_VAR_NAME}=%{MATCHED_VAR}, tag:language-aspnet, tag:platform-windows, tag:attack-protocol, tag:paranoia-level/3, tag:OWASP_CRS, tag:OWASP_CRS/PROTOCOL-ENFORCEMENT, tag:capec/1000/210/272, ver:OWASP_CRS/4.22.0-dev, severity:CRITICAL, chain

#### Rule 88: Unknown
- **Phase**: Unknown
- **Variables**: REQUEST_HEADERS:User-Agent
- **Operator**: @rx
- **Pattern**: ^(?i)up
- **Is Chain**: False
- **Message**: 
- **Severity**: 
- **Actions**: t:none, setvar:tx.inbound_anomaly_score_pl3=+%{tx.critical_anomaly_score}

#### Rule 89: 920510
- **Phase**: 1
- **Variables**: REQUEST_HEADERS:Cache-Control
- **Operator**: @gt
- **Pattern**: 0
- **Is Chain**: True
- **Message**: Invalid Cache-Control request header
- **Severity**: CRITICAL
- **Tags**: application-multi, language-multi, platform-multi, attack-protocol, header-allowlist, paranoia-level/3, OWASP_CRS, OWASP_CRS/PROTOCOL-ENFORCEMENT, capec/1000/210/272
- **Actions**: id:920510, phase:1, block, t:none, msg:Invalid Cache-Control request header, logdata:Invalid Cache-Control value in request found within %{MATCHED_VAR_NAME}: %{MATCHED_VAR}, tag:application-multi, tag:language-multi, tag:platform-multi, tag:attack-protocol, tag:header-allowlist, tag:paranoia-level/3, tag:OWASP_CRS, tag:OWASP_CRS/PROTOCOL-ENFORCEMENT, tag:capec/1000/210/272, ver:OWASP_CRS/4.22.0-dev, severity:CRITICAL, chain

#### Rule 90: Unknown
- **Phase**: Unknown
- **Variables**: REQUEST_HEADERS:Cache-Control
- **Operator**: !@rx
- **Pattern**: ^(?:(?:max-age=[0-9]+|min-fresh=[0-9]+|no-cache|no-store|no-transform|only-if-cached|max-stale(?:=[0-9]+)?)(?:\s*\,\s*|$)){1,7}$
- **Is Chain**: False
- **Message**: 
- **Severity**: 
- **Actions**: setvar:tx.inbound_anomaly_score_pl3=+%{tx.critical_anomaly_score}

#### Rule 91: 920521
- **Phase**: 1
- **Variables**: REQUEST_HEADERS:Accept-Encoding
- **Operator**: !@rx
- **Pattern**: br|compress|deflate|(?:pack200-)?gzip|identity|\*|^$|aes128gcm|exi|zstd|x-(?:compress|gzip)
- **Is Chain**: False
- **Message**: Illegal Accept-Encoding header
- **Severity**: CRITICAL
- **Tags**: application-multi, language-multi, platform-multi, attack-protocol, paranoia-level/3, OWASP_CRS, OWASP_CRS/PROTOCOL-ENFORCEMENT, capec/1000/255/153
- **Actions**: id:920521, phase:1, block, t:none, t:lowercase, msg:Illegal Accept-Encoding header, logdata:%{MATCHED_VAR}, tag:application-multi, tag:language-multi, tag:platform-multi, tag:attack-protocol, tag:paranoia-level/3, tag:OWASP_CRS, tag:OWASP_CRS/PROTOCOL-ENFORCEMENT, tag:capec/1000/255/153, ver:OWASP_CRS/4.22.0-dev, severity:CRITICAL, setvar:tx.inbound_anomaly_score_pl3=+%{tx.critical_anomaly_score}

#### Rule 92: 920017
- **Phase**: 1
- **Variables**: TX:DETECTION_PARANOIA_LEVEL
- **Operator**: @lt
- **Pattern**: 4
- **Is Chain**: False
- **Message**: 
- **Severity**: 
- **Tags**: OWASP_CRS
- **Actions**: id:920017, phase:1, pass, nolog, tag:OWASP_CRS, ver:OWASP_CRS/4.22.0-dev, skipAfter:END-REQUEST-920-PROTOCOL-ENFORCEMENT

#### Rule 93: 920018
- **Phase**: 2
- **Variables**: TX:DETECTION_PARANOIA_LEVEL
- **Operator**: @lt
- **Pattern**: 4
- **Is Chain**: False
- **Message**: 
- **Severity**: 
- **Tags**: OWASP_CRS
- **Actions**: id:920018, phase:2, pass, nolog, tag:OWASP_CRS, ver:OWASP_CRS/4.22.0-dev, skipAfter:END-REQUEST-920-PROTOCOL-ENFORCEMENT

#### Rule 94: 920202
- **Phase**: 1
- **Variables**: REQUEST_BASENAME
- **Operator**: @endsWith
- **Pattern**: .pdf
- **Is Chain**: True
- **Message**: Range: Too many fields for pdf request (6 or more)
- **Severity**: WARNING
- **Tags**: application-multi, language-multi, platform-multi, attack-protocol, paranoia-level/4, OWASP_CRS, OWASP_CRS/PROTOCOL-ENFORCEMENT, capec/1000/210/272
- **Actions**: id:920202, phase:1, block, t:none, t:urlDecodeUni, msg:Range: Too many fields for pdf request (6 or more), logdata:%{MATCHED_VAR}, tag:application-multi, tag:language-multi, tag:platform-multi, tag:attack-protocol, tag:paranoia-level/4, tag:OWASP_CRS, tag:OWASP_CRS/PROTOCOL-ENFORCEMENT, tag:capec/1000/210/272, ver:OWASP_CRS/4.22.0-dev, severity:WARNING, chain

#### Rule 95: Unknown
- **Phase**: Unknown
- **Variables**: REQUEST_HEADERS:Range, REQUEST_HEADERS:Request-Range
- **Operator**: @rx
- **Pattern**: ^bytes=(?:(?:\d+)?-(?:\d+)?\s*,?\s*){6}
- **Is Chain**: False
- **Message**: 
- **Severity**: 
- **Actions**: setvar:tx.inbound_anomaly_score_pl4=+%{tx.warning_anomaly_score}

#### Rule 96: 920273
- **Phase**: 2
- **Variables**: ARGS, ARGS_NAMES, REQUEST_BODY
- **Operator**: @validateByteRange
- **Pattern**: 38,44-46,48-58,61,65-90,95,97-122
- **Is Chain**: False
- **Message**: Invalid character in request (outside of very strict set)
- **Severity**: CRITICAL
- **Tags**: application-multi, language-multi, platform-multi, attack-protocol, paranoia-level/4, OWASP_CRS, OWASP_CRS/PROTOCOL-ENFORCEMENT, capec/1000/210/272
- **Actions**: id:920273, phase:2, block, t:none, t:urlDecodeUni, msg:Invalid character in request (outside of very strict set), logdata:%{MATCHED_VAR_NAME}=%{MATCHED_VAR}, tag:application-multi, tag:language-multi, tag:platform-multi, tag:attack-protocol, tag:paranoia-level/4, tag:OWASP_CRS, tag:OWASP_CRS/PROTOCOL-ENFORCEMENT, tag:capec/1000/210/272, ver:OWASP_CRS/4.22.0-dev, severity:CRITICAL, setvar:tx.inbound_anomaly_score_pl4=+%{tx.critical_anomaly_score}

#### Rule 97: 920274
- **Phase**: 1
- **Variables**: REQUEST_HEADERS, REQUEST_HEADERS:User-Agent, REQUEST_HEADERS:Referer, REQUEST_HEADERS:Cookie, REQUEST_HEADERS:Sec-Fetch-User, REQUEST_HEADERS:Sec-CH-UA, REQUEST_HEADERS:Sec-CH-UA-Mobile
- **Operator**: @validateByteRange
- **Pattern**: 32,34,38,42-59,61,65-90,95,97-122
- **Is Chain**: False
- **Message**: Invalid character in request headers (outside of very strict set)
- **Severity**: CRITICAL
- **Tags**: application-multi, language-multi, platform-multi, attack-protocol, paranoia-level/4, OWASP_CRS, OWASP_CRS/PROTOCOL-ENFORCEMENT, capec/1000/210/272
- **Actions**: id:920274, phase:1, block, t:none, t:urlDecodeUni, msg:Invalid character in request headers (outside of very strict set), logdata:%{MATCHED_VAR_NAME}=%{MATCHED_VAR}, tag:application-multi, tag:language-multi, tag:platform-multi, tag:attack-protocol, tag:paranoia-level/4, tag:OWASP_CRS, tag:OWASP_CRS/PROTOCOL-ENFORCEMENT, tag:capec/1000/210/272, ver:OWASP_CRS/4.22.0-dev, severity:CRITICAL, setvar:tx.inbound_anomaly_score_pl4=+%{tx.critical_anomaly_score}

#### Rule 98: 920275
- **Phase**: 1
- **Variables**: REQUEST_HEADERS:Sec-Fetch-User, REQUEST_HEADERS:Sec-CH-UA-Mobile
- **Operator**: !@rx
- **Pattern**: ^(?:\?[01])?$
- **Is Chain**: False
- **Message**: Invalid character in request headers (outside of very strict set)
- **Severity**: CRITICAL
- **Tags**: application-multi, language-multi, platform-multi, attack-protocol, paranoia-level/4, OWASP_CRS, OWASP_CRS/PROTOCOL-ENFORCEMENT, capec/1000/210/272
- **Actions**: id:920275, phase:1, block, t:none, t:urlDecodeUni, msg:Invalid character in request headers (outside of very strict set), logdata:%{MATCHED_VAR_NAME}=%{MATCHED_VAR}, tag:application-multi, tag:language-multi, tag:platform-multi, tag:attack-protocol, tag:paranoia-level/4, tag:OWASP_CRS, tag:OWASP_CRS/PROTOCOL-ENFORCEMENT, tag:capec/1000/210/272, ver:OWASP_CRS/4.22.0-dev, severity:CRITICAL, setvar:tx.inbound_anomaly_score_pl4=+%{tx.critical_anomaly_score}

#### Rule 99: 920460
- **Phase**: 2
- **Variables**: REQUEST_URI, REQUEST_HEADERS, ARGS, ARGS_NAMES
- **Operator**: @rx
- **Pattern**: (?:^|[^\x5c])\x5c[cdeghijklmpqwxyz123456789]
- **Is Chain**: False
- **Message**: Abnormal character escapes in request
- **Severity**: CRITICAL
- **Tags**: application-multi, language-multi, platform-multi, attack-protocol, paranoia-level/4, OWASP_CRS, OWASP_CRS/PROTOCOL-ENFORCEMENT, capec/1000/153/267
- **Actions**: id:920460, phase:2, block, capture, t:none, t:htmlEntityDecode, t:lowercase, msg:Abnormal character escapes in request, logdata:Matched Data: %{TX.0} found within %{MATCHED_VAR_NAME}: %{MATCHED_VAR}, tag:application-multi, tag:language-multi, tag:platform-multi, tag:attack-protocol, tag:paranoia-level/4, tag:OWASP_CRS, tag:OWASP_CRS/PROTOCOL-ENFORCEMENT, tag:capec/1000/153/267, ver:OWASP_CRS/4.22.0-dev, severity:CRITICAL, setvar:tx.http_violation_score=+%{tx.critical_anomaly_score}, setvar:tx.inbound_anomaly_score_pl4=+%{tx.critical_anomaly_score}


====================================================================================================

## File: REQUEST-921-PROTOCOL-ATTACK.conf

### File Summary
- Total rules: 26
- Chained rules: 0
- Non-chained rules: 26

### Detailed Rules

#### Rule 1: 921011
- **Phase**: 1
- **Variables**: TX:DETECTION_PARANOIA_LEVEL
- **Operator**: @lt
- **Pattern**: 1
- **Is Chain**: False
- **Message**: 
- **Severity**: 
- **Tags**: OWASP_CRS
- **Actions**: id:921011, phase:1, pass, nolog, tag:OWASP_CRS, ver:OWASP_CRS/4.22.0-dev, skipAfter:END-REQUEST-921-PROTOCOL-ATTACK

#### Rule 2: 921012
- **Phase**: 2
- **Variables**: TX:DETECTION_PARANOIA_LEVEL
- **Operator**: @lt
- **Pattern**: 1
- **Is Chain**: False
- **Message**: 
- **Severity**: 
- **Tags**: OWASP_CRS
- **Actions**: id:921012, phase:2, pass, nolog, tag:OWASP_CRS, ver:OWASP_CRS/4.22.0-dev, skipAfter:END-REQUEST-921-PROTOCOL-ATTACK

#### Rule 3: 921110
- **Phase**: 2
- **Variables**: ARGS_NAMES, ARGS, REQUEST_BODY, XML:/*
- **Operator**: @rx
- **Pattern**: (?:get|post|head|options|connect|put|delete|trace|track|patch|propfind|propatch|mkcol|copy|move|lock|unlock)\s+[^\s]+\s+http/\d
- **Is Chain**: False
- **Message**: HTTP Request Smuggling Attack
- **Severity**: CRITICAL
- **Tags**: application-multi, language-multi, platform-multi, attack-protocol, paranoia-level/1, OWASP_CRS, OWASP_CRS/PROTOCOL-ATTACK, capec/1000/210/272/220/33
- **Actions**: id:921110, phase:2, block, capture, t:none, t:htmlEntityDecode, t:lowercase, msg:HTTP Request Smuggling Attack, logdata:Matched Data: %{TX.0} found within %{MATCHED_VAR_NAME}: %{MATCHED_VAR}, tag:application-multi, tag:language-multi, tag:platform-multi, tag:attack-protocol, tag:paranoia-level/1, tag:OWASP_CRS, tag:OWASP_CRS/PROTOCOL-ATTACK, tag:capec/1000/210/272/220/33, ver:OWASP_CRS/4.22.0-dev, severity:CRITICAL, setvar:tx.http_violation_score=+%{tx.critical_anomaly_score}, setvar:tx.inbound_anomaly_score_pl1=+%{tx.critical_anomaly_score}

#### Rule 4: 921120
- **Phase**: 2
- **Variables**: REQUEST_COOKIES, REQUEST_COOKIES_NAMES, ARGS_NAMES, ARGS, XML:/*
- **Operator**: @rx
- **Pattern**: [\r\n]\W*?(?:content-(?:type|length)|set-cookie|location):\s*\w
- **Is Chain**: False
- **Message**: HTTP Response Splitting Attack
- **Severity**: CRITICAL
- **Tags**: application-multi, language-multi, platform-multi, attack-protocol, paranoia-level/1, OWASP_CRS, OWASP_CRS/PROTOCOL-ATTACK, capec/1000/210/272/220/34
- **Actions**: id:921120, phase:2, block, capture, t:none, t:lowercase, msg:HTTP Response Splitting Attack, logdata:Matched Data: %{TX.0} found within %{MATCHED_VAR_NAME}: %{MATCHED_VAR}, tag:application-multi, tag:language-multi, tag:platform-multi, tag:attack-protocol, tag:paranoia-level/1, tag:OWASP_CRS, tag:OWASP_CRS/PROTOCOL-ATTACK, tag:capec/1000/210/272/220/34, ver:OWASP_CRS/4.22.0-dev, severity:CRITICAL, setvar:tx.http_violation_score=+%{tx.critical_anomaly_score}, setvar:tx.inbound_anomaly_score_pl1=+%{tx.critical_anomaly_score}

#### Rule 5: 921130
- **Phase**: 2
- **Variables**: REQUEST_COOKIES, REQUEST_COOKIES_NAMES, ARGS_NAMES, ARGS, XML:/*
- **Operator**: @rx
- **Pattern**: (?:\bhttp/\d|<(?:html|meta)\b)
- **Is Chain**: False
- **Message**: HTTP Response Splitting Attack
- **Severity**: CRITICAL
- **Tags**: application-multi, language-multi, platform-multi, attack-protocol, paranoia-level/1, OWASP_CRS, OWASP_CRS/PROTOCOL-ATTACK, capec/1000/210/272/220/34
- **Actions**: id:921130, phase:2, block, capture, t:none, t:htmlEntityDecode, t:lowercase, msg:HTTP Response Splitting Attack, logdata:Matched Data: %{TX.0} found within %{MATCHED_VAR_NAME}: %{MATCHED_VAR}, tag:application-multi, tag:language-multi, tag:platform-multi, tag:attack-protocol, tag:paranoia-level/1, tag:OWASP_CRS, tag:OWASP_CRS/PROTOCOL-ATTACK, tag:capec/1000/210/272/220/34, ver:OWASP_CRS/4.22.0-dev, severity:CRITICAL, setvar:tx.http_violation_score=+%{tx.critical_anomaly_score}, setvar:tx.inbound_anomaly_score_pl1=+%{tx.critical_anomaly_score}

#### Rule 6: 921140
- **Phase**: 1
- **Variables**: REQUEST_HEADERS_NAMES, REQUEST_HEADERS
- **Operator**: @rx
- **Pattern**: [\n\r]
- **Is Chain**: False
- **Message**: HTTP Header Injection Attack via headers
- **Severity**: CRITICAL
- **Tags**: application-multi, language-multi, platform-multi, attack-protocol, paranoia-level/1, OWASP_CRS, OWASP_CRS/PROTOCOL-ATTACK, capec/1000/210/272/220/273
- **Actions**: id:921140, phase:1, block, capture, t:none, t:urlDecodeUni, msg:HTTP Header Injection Attack via headers, logdata:Matched Data: %{TX.0} found within %{MATCHED_VAR_NAME}: %{MATCHED_VAR}, tag:application-multi, tag:language-multi, tag:platform-multi, tag:attack-protocol, tag:paranoia-level/1, tag:OWASP_CRS, tag:OWASP_CRS/PROTOCOL-ATTACK, tag:capec/1000/210/272/220/273, ver:OWASP_CRS/4.22.0-dev, severity:CRITICAL, setvar:tx.http_violation_score=+%{tx.critical_anomaly_score}, setvar:tx.inbound_anomaly_score_pl1=+%{tx.critical_anomaly_score}

#### Rule 7: 921150
- **Phase**: 2
- **Variables**: ARGS_NAMES
- **Operator**: @rx
- **Pattern**: [\n\r]
- **Is Chain**: False
- **Message**: HTTP Header Injection Attack via payload (CR/LF detected)
- **Severity**: CRITICAL
- **Tags**: application-multi, language-multi, platform-multi, attack-protocol, paranoia-level/1, OWASP_CRS, OWASP_CRS/PROTOCOL-ATTACK, capec/1000/210/272/220/33
- **Actions**: id:921150, phase:2, block, capture, t:none, msg:HTTP Header Injection Attack via payload (CR/LF detected), logdata:Matched Data: %{TX.0} found within %{MATCHED_VAR_NAME}: %{MATCHED_VAR}, tag:application-multi, tag:language-multi, tag:platform-multi, tag:attack-protocol, tag:paranoia-level/1, tag:OWASP_CRS, tag:OWASP_CRS/PROTOCOL-ATTACK, tag:capec/1000/210/272/220/33, ver:OWASP_CRS/4.22.0-dev, severity:CRITICAL, setvar:tx.http_violation_score=+%{tx.critical_anomaly_score}, setvar:tx.inbound_anomaly_score_pl1=+%{tx.critical_anomaly_score}

#### Rule 8: 921160
- **Phase**: 1
- **Variables**: ARGS_GET_NAMES, ARGS_GET
- **Operator**: @rx
- **Pattern**: [\n\r]+(?:\s|location|refresh|(?:set-)?cookie|(?:x-)?(?:forwarded-(?:for|host|server)|host|via|remote-ip|remote-addr|originating-IP))\s*:
- **Is Chain**: False
- **Message**: HTTP Header Injection Attack via payload (CR/LF and header-name detected)
- **Severity**: CRITICAL
- **Tags**: application-multi, language-multi, platform-multi, attack-protocol, paranoia-level/1, OWASP_CRS, OWASP_CRS/PROTOCOL-ATTACK, capec/1000/210/272/220/33
- **Actions**: id:921160, phase:1, block, capture, t:none, t:lowercase, msg:HTTP Header Injection Attack via payload (CR/LF and header-name detected), logdata:Matched Data: %{TX.0} found within %{MATCHED_VAR_NAME}: %{MATCHED_VAR}, tag:application-multi, tag:language-multi, tag:platform-multi, tag:attack-protocol, tag:paranoia-level/1, tag:OWASP_CRS, tag:OWASP_CRS/PROTOCOL-ATTACK, tag:capec/1000/210/272/220/33, ver:OWASP_CRS/4.22.0-dev, severity:CRITICAL, setvar:tx.http_violation_score=+%{tx.critical_anomaly_score}, setvar:tx.inbound_anomaly_score_pl1=+%{tx.critical_anomaly_score}

#### Rule 9: 921190
- **Phase**: 1
- **Variables**: REQUEST_FILENAME
- **Operator**: @rx
- **Pattern**: [\n\r]
- **Is Chain**: False
- **Message**: HTTP Splitting (CR/LF in request filename detected)
- **Severity**: CRITICAL
- **Tags**: application-multi, language-multi, platform-multi, attack-protocol, paranoia-level/1, OWASP_CRS, OWASP_CRS/PROTOCOL-ATTACK, capec/1000/210/272/220/34
- **Actions**: id:921190, phase:1, block, capture, t:none, t:urlDecodeUni, msg:HTTP Splitting (CR/LF in request filename detected), logdata:Matched Data: %{TX.0} found within %{MATCHED_VAR_NAME}: %{MATCHED_VAR}, tag:application-multi, tag:language-multi, tag:platform-multi, tag:attack-protocol, tag:paranoia-level/1, tag:OWASP_CRS, tag:OWASP_CRS/PROTOCOL-ATTACK, tag:capec/1000/210/272/220/34, ver:OWASP_CRS/4.22.0-dev, severity:CRITICAL, setvar:tx.http_violation_score=+%{tx.critical_anomaly_score}, setvar:tx.inbound_anomaly_score_pl1=+%{tx.critical_anomaly_score}

#### Rule 10: 921200
- **Phase**: 2
- **Variables**: REQUEST_COOKIES, REQUEST_COOKIES_NAMES, ARGS_NAMES, ARGS, XML:/*
- **Operator**: @rx
- **Pattern**: ^[^:\(\)\&\|\!\<\>\~]*\)\s*(?:\((?:[^,\(\)\=\&\|\!\<\>\~]+[><~]?=|\s*[&!|]\s*(?:\)|\()?\s*)|\)\s*\(\s*[\&\|\!]\s*|[&!|]\s*\([^\(\)\=\&\|\!\<\>\~]+[><~]?=[^:\(\)\&\|\!\<\>\~]*)
- **Is Chain**: False
- **Message**: LDAP Injection Attack
- **Severity**: CRITICAL
- **Tags**: application-multi, language-ldap, platform-multi, paranoia-level/1, OWASP_CRS, OWASP_CRS/PROTOCOL-ATTACK, capec/1000/152/248/136
- **Actions**: id:921200, phase:2, block, capture, t:none, t:htmlEntityDecode, msg:LDAP Injection Attack, logdata:Matched Data: %{TX.0} found within %{MATCHED_VAR_NAME}: %{MATCHED_VAR}, tag:application-multi, tag:language-ldap, tag:platform-multi, tag:paranoia-level/1, tag:OWASP_CRS, tag:OWASP_CRS/PROTOCOL-ATTACK, tag:capec/1000/152/248/136, ver:OWASP_CRS/4.22.0-dev, severity:CRITICAL, setvar:tx.inbound_anomaly_score_pl1=+%{tx.critical_anomaly_score}

#### Rule 11: 921421
- **Phase**: 1
- **Variables**: REQUEST_HEADERS:Content-Type
- **Operator**: @rx
- **Pattern**: ^[^\s\x0b,;]+[\s\x0b,;].*?(?:application/(?:.+\+)?json|(?:application/(?:soap\+)?|text/)xml)
- **Is Chain**: False
- **Message**: Content-Type header: Dangerous content type outside the mime type declaration
- **Severity**: CRITICAL
- **Tags**: application-multi, language-multi, platform-multi, attack-protocol, paranoia-level/1, OWASP_CRS, OWASP_CRS/PROTOCOL-ATTACK, capec/1000/255/153
- **Actions**: id:921421, phase:1, block, capture, t:none, t:lowercase, msg:Content-Type header: Dangerous content type outside the mime type declaration, logdata:Matched Data: %{TX.0} found within %{MATCHED_VAR_NAME}: %{MATCHED_VAR}, tag:application-multi, tag:language-multi, tag:platform-multi, tag:attack-protocol, tag:paranoia-level/1, tag:OWASP_CRS, tag:OWASP_CRS/PROTOCOL-ATTACK, tag:capec/1000/255/153, ver:OWASP_CRS/4.22.0-dev, severity:CRITICAL, setvar:tx.inbound_anomaly_score_pl1=+%{tx.critical_anomaly_score}

#### Rule 12: 921240
- **Phase**: 1
- **Variables**: REQUEST_URI_RAW
- **Operator**: @rx
- **Pattern**: unix:[^|]*\|
- **Is Chain**: False
- **Message**: mod_proxy attack attempt detected
- **Severity**: CRITICAL
- **Tags**: application-multi, language-multi, platform-apache, attack-protocol, paranoia-level/1, OWASP_CRS, OWASP_CRS/PROTOCOL-ATTACK, capec/1000/210/272/220/33
- **Actions**: id:921240, phase:1, block, capture, t:none, t:urlDecodeUni, t:lowercase, msg:mod_proxy attack attempt detected, logdata:Matched Data: %{TX.0} found within %{MATCHED_VAR_NAME}: %{MATCHED_VAR}, tag:application-multi, tag:language-multi, tag:platform-apache, tag:attack-protocol, tag:paranoia-level/1, tag:OWASP_CRS, tag:OWASP_CRS/PROTOCOL-ATTACK, tag:capec/1000/210/272/220/33, ver:OWASP_CRS/4.22.0-dev, severity:CRITICAL, setvar:tx.inbound_anomaly_score_pl1=+%{tx.critical_anomaly_score}

#### Rule 13: 921250
- **Phase**: 1
- **Variables**: REQUEST_COOKIES:/\x22?\x24Version/
- **Operator**: @streq
- **Pattern**: 1
- **Is Chain**: False
- **Message**: Old Cookies V1 usage attempt detected
- **Severity**: CRITICAL
- **Tags**: application-multi, language-multi, attack-protocol, paranoia-level/1, OWASP_CRS, OWASP_CRS/PROTOCOL-ATTACK, capec/1000/210/272/220/33
- **Actions**: id:921250, phase:1, block, capture, t:none, t:lowercase, msg:Old Cookies V1 usage attempt detected, logdata:Matched Data: %{TX.0} found within %{MATCHED_VAR_NAME}: %{MATCHED_VAR}, tag:application-multi, tag:language-multi, tag:attack-protocol, tag:paranoia-level/1, tag:OWASP_CRS, tag:OWASP_CRS/PROTOCOL-ATTACK, tag:capec/1000/210/272/220/33, ver:OWASP_CRS/4.22.0-dev, severity:CRITICAL, setvar:tx.inbound_anomaly_score_pl1=+%{tx.critical_anomaly_score}

#### Rule 14: 921013
- **Phase**: 1
- **Variables**: TX:DETECTION_PARANOIA_LEVEL
- **Operator**: @lt
- **Pattern**: 2
- **Is Chain**: False
- **Message**: 
- **Severity**: 
- **Tags**: OWASP_CRS
- **Actions**: id:921013, phase:1, pass, nolog, tag:OWASP_CRS, ver:OWASP_CRS/4.22.0-dev, skipAfter:END-REQUEST-921-PROTOCOL-ATTACK

#### Rule 15: 921014
- **Phase**: 2
- **Variables**: TX:DETECTION_PARANOIA_LEVEL
- **Operator**: @lt
- **Pattern**: 2
- **Is Chain**: False
- **Message**: 
- **Severity**: 
- **Tags**: OWASP_CRS
- **Actions**: id:921014, phase:2, pass, nolog, tag:OWASP_CRS, ver:OWASP_CRS/4.22.0-dev, skipAfter:END-REQUEST-921-PROTOCOL-ATTACK

#### Rule 16: 921151
- **Phase**: 1
- **Variables**: ARGS_GET
- **Operator**: @rx
- **Pattern**: [\n\r]
- **Is Chain**: False
- **Message**: HTTP Header Injection Attack via payload (CR/LF detected)
- **Severity**: CRITICAL
- **Tags**: application-multi, language-multi, platform-multi, attack-protocol, paranoia-level/2, OWASP_CRS, OWASP_CRS/PROTOCOL-ATTACK, capec/1000/210/272/220/33
- **Actions**: id:921151, phase:1, block, capture, t:none, msg:HTTP Header Injection Attack via payload (CR/LF detected), logdata:Matched Data: %{TX.0} found within %{MATCHED_VAR_NAME}: %{MATCHED_VAR}, tag:application-multi, tag:language-multi, tag:platform-multi, tag:attack-protocol, tag:paranoia-level/2, tag:OWASP_CRS, tag:OWASP_CRS/PROTOCOL-ATTACK, tag:capec/1000/210/272/220/33, ver:OWASP_CRS/4.22.0-dev, severity:CRITICAL, setvar:tx.http_violation_score=+%{tx.critical_anomaly_score}, setvar:tx.inbound_anomaly_score_pl2=+%{tx.critical_anomaly_score}

#### Rule 17: 921422
- **Phase**: 1
- **Variables**: REQUEST_HEADERS:Content-Type
- **Operator**: @rx
- **Pattern**: ^[^\s\x0b,;]+[\s\x0b,;].*?\b(?:((?:tex|multipar)t|application)|((?:audi|vide)o|image|cs[sv]|(?:vn|relate)d|p(?:df|lain)|json|(?:soa|cs)p|x(?:ml|-www-form-urlencoded)|form-data|x-amf|(?:octe|repor)t|stream)|([\+/]))\b
- **Is Chain**: False
- **Message**: Content-Type header: Dangerous content type outside the mime type declaration
- **Severity**: CRITICAL
- **Tags**: application-multi, language-multi, platform-multi, attack-protocol, paranoia-level/2, OWASP_CRS, OWASP_CRS/PROTOCOL-ATTACK, capec/1000/255/153
- **Actions**: id:921422, phase:1, block, capture, t:none, t:lowercase, msg:Content-Type header: Dangerous content type outside the mime type declaration, logdata:Matched Data: %{TX.0} found within %{MATCHED_VAR_NAME}: %{MATCHED_VAR}, tag:application-multi, tag:language-multi, tag:platform-multi, tag:attack-protocol, tag:paranoia-level/2, tag:OWASP_CRS, tag:OWASP_CRS/PROTOCOL-ATTACK, tag:capec/1000/255/153, ver:OWASP_CRS/4.22.0-dev, severity:CRITICAL, setvar:tx.inbound_anomaly_score_pl2=+%{tx.critical_anomaly_score}

#### Rule 18: 921015
- **Phase**: 1
- **Variables**: TX:DETECTION_PARANOIA_LEVEL
- **Operator**: @lt
- **Pattern**: 3
- **Is Chain**: False
- **Message**: 
- **Severity**: 
- **Tags**: OWASP_CRS
- **Actions**: id:921015, phase:1, pass, nolog, tag:OWASP_CRS, ver:OWASP_CRS/4.22.0-dev, skipAfter:END-REQUEST-921-PROTOCOL-ATTACK

#### Rule 19: 921016
- **Phase**: 2
- **Variables**: TX:DETECTION_PARANOIA_LEVEL
- **Operator**: @lt
- **Pattern**: 3
- **Is Chain**: False
- **Message**: 
- **Severity**: 
- **Tags**: OWASP_CRS
- **Actions**: id:921016, phase:2, pass, nolog, tag:OWASP_CRS, ver:OWASP_CRS/4.22.0-dev, skipAfter:END-REQUEST-921-PROTOCOL-ATTACK

#### Rule 20: 921230
- **Phase**: 1
- **Variables**: REQUEST_HEADERS:Range
- **Operator**: @gt
- **Pattern**: 0
- **Is Chain**: False
- **Message**: HTTP Range Header detected
- **Severity**: CRITICAL
- **Tags**: application-multi, language-multi, platform-multi, attack-protocol, paranoia-level/3, OWASP_CRS, OWASP_CRS/PROTOCOL-ATTACK, capec/1000/210/272/220
- **Actions**: id:921230, phase:1, block, t:none, msg:HTTP Range Header detected, logdata:Matched Data: Header %{MATCHED_VAR_NAME}: %{MATCHED_VAR}, tag:application-multi, tag:language-multi, tag:platform-multi, tag:attack-protocol, tag:paranoia-level/3, tag:OWASP_CRS, tag:OWASP_CRS/PROTOCOL-ATTACK, tag:capec/1000/210/272/220, ver:OWASP_CRS/4.22.0-dev, severity:CRITICAL, setvar:tx.inbound_anomaly_score_pl3=+%{tx.critical_anomaly_score}

#### Rule 21: 921170
- **Phase**: 2
- **Variables**: ARGS_NAMES
- **Operator**: @rx
- **Pattern**: .
- **Is Chain**: False
- **Message**: 
- **Severity**: 
- **Tags**: application-multi, language-multi, platform-multi, attack-protocol, OWASP_CRS, OWASP_CRS/PROTOCOL-ATTACK, capec/1000/152/137/15/460
- **Actions**: id:921170, phase:2, pass, nolog, tag:application-multi, tag:language-multi, tag:platform-multi, tag:attack-protocol, tag:OWASP_CRS, tag:OWASP_CRS/PROTOCOL-ATTACK, tag:capec/1000/152/137/15/460, ver:OWASP_CRS/4.22.0-dev, setvar:TX.paramcounter_%{MATCHED_VAR_NAME}=+1

#### Rule 22: 921180
- **Phase**: 2
- **Variables**: TX:/paramcounter_.*/
- **Operator**: @gt
- **Pattern**: 1
- **Is Chain**: False
- **Message**: HTTP Parameter Pollution (%{MATCHED_VAR_NAME})
- **Severity**: CRITICAL
- **Tags**: application-multi, language-multi, platform-multi, attack-protocol, paranoia-level/3, OWASP_CRS, OWASP_CRS/PROTOCOL-ATTACK, capec/1000/152/137/15/460
- **Actions**: id:921180, phase:2, block, msg:HTTP Parameter Pollution (%{MATCHED_VAR_NAME}), logdata:Matched Data: %{MATCHED_VAR} found within %{MATCHED_VAR_NAME}: %{MATCHED_VAR}, tag:application-multi, tag:language-multi, tag:platform-multi, tag:attack-protocol, tag:paranoia-level/3, tag:OWASP_CRS, tag:OWASP_CRS/PROTOCOL-ATTACK, tag:capec/1000/152/137/15/460, ver:OWASP_CRS/4.22.0-dev, severity:CRITICAL, setvar:tx.http_violation_score=+%{tx.critical_anomaly_score}, setvar:tx.inbound_anomaly_score_pl3=+%{tx.critical_anomaly_score}

#### Rule 23: 921210
- **Phase**: 2
- **Variables**: ARGS_NAMES
- **Operator**: @rx
- **Pattern**: (][^\]]+$|][^\]]+\[)
- **Is Chain**: False
- **Message**: HTTP Parameter Pollution after detecting bogus char after parameter array
- **Severity**: CRITICAL
- **Tags**: application-multi, language-multi, platform-multi, attack-protocol, paranoia-level/3, OWASP_CRS, OWASP_CRS/PROTOCOL-ATTACK, capec/1000/152/137/15/460
- **Actions**: id:921210, phase:2, block, capture, log, msg:HTTP Parameter Pollution after detecting bogus char after parameter array, logdata:Matched Data: %{TX.0} found within %{MATCHED_VAR_NAME}: %{MATCHED_VAR}, tag:application-multi, tag:language-multi, tag:platform-multi, tag:attack-protocol, tag:paranoia-level/3, tag:OWASP_CRS, tag:OWASP_CRS/PROTOCOL-ATTACK, tag:capec/1000/152/137/15/460, ver:OWASP_CRS/4.22.0-dev, severity:CRITICAL, setvar:tx.http_violation_score=+%{tx.critical_anomaly_score}, setvar:tx.inbound_anomaly_score_pl3=+%{tx.critical_anomaly_score}

#### Rule 24: 921017
- **Phase**: 1
- **Variables**: TX:DETECTION_PARANOIA_LEVEL
- **Operator**: @lt
- **Pattern**: 4
- **Is Chain**: False
- **Message**: 
- **Severity**: 
- **Tags**: OWASP_CRS
- **Actions**: id:921017, phase:1, pass, nolog, tag:OWASP_CRS, ver:OWASP_CRS/4.22.0-dev, skipAfter:END-REQUEST-921-PROTOCOL-ATTACK

#### Rule 25: 921018
- **Phase**: 2
- **Variables**: TX:DETECTION_PARANOIA_LEVEL
- **Operator**: @lt
- **Pattern**: 4
- **Is Chain**: False
- **Message**: 
- **Severity**: 
- **Tags**: OWASP_CRS
- **Actions**: id:921018, phase:2, pass, nolog, tag:OWASP_CRS, ver:OWASP_CRS/4.22.0-dev, skipAfter:END-REQUEST-921-PROTOCOL-ATTACK

#### Rule 26: 921220
- **Phase**: 2
- **Variables**: ARGS_NAMES
- **Operator**: @rx
- **Pattern**: \[
- **Is Chain**: False
- **Message**: HTTP Parameter Pollution possible via array notation
- **Severity**: CRITICAL
- **Tags**: application-multi, language-multi, platform-multi, attack-protocol, paranoia-level/4, OWASP_CRS, OWASP_CRS/PROTOCOL-ATTACK, capec/1000/152/137/15/460
- **Actions**: id:921220, phase:2, block, capture, log, msg:HTTP Parameter Pollution possible via array notation, logdata:Matched Data: %{TX.0} found within %{MATCHED_VAR_NAME}: %{MATCHED_VAR}, tag:application-multi, tag:language-multi, tag:platform-multi, tag:attack-protocol, tag:paranoia-level/4, tag:OWASP_CRS, tag:OWASP_CRS/PROTOCOL-ATTACK, tag:capec/1000/152/137/15/460, ver:OWASP_CRS/4.22.0-dev, severity:CRITICAL, setvar:tx.http_violation_score=+%{tx.critical_anomaly_score}, setvar:tx.inbound_anomaly_score_pl4=+%{tx.critical_anomaly_score}


====================================================================================================

## File: REQUEST-922-MULTIPART-ATTACK.conf

### File Summary
- Total rules: 6
- Chained rules: 2
- Non-chained rules: 4

### Detailed Rules

#### Rule 1: 922100
- **Phase**: 2
- **Variables**: MULTIPART_PART_HEADERS:_charset_
- **Operator**: !@eq
- **Pattern**: 0
- **Is Chain**: True
- **Message**: Multipart content type global _charset_ definition is not allowed by policy
- **Severity**: CRITICAL
- **Tags**: application-multi, language-multi, platform-multi, attack-multipart-header, paranoia-level/1, OWASP_CRS, OWASP_CRS/MULTIPART-ATTACK, capec/1000/255/153
- **Actions**: id:922100, phase:2, block, t:none, msg:Multipart content type global _charset_ definition is not allowed by policy, logdata:Matched Data: %{ARGS._charset_}, tag:application-multi, tag:language-multi, tag:platform-multi, tag:attack-multipart-header, tag:paranoia-level/1, tag:OWASP_CRS, tag:OWASP_CRS/MULTIPART-ATTACK, tag:capec/1000/255/153, ver:OWASP_CRS/4.22.0-dev, severity:CRITICAL, setvar:tx.922100_charset=|%{ARGS._charset_}|, chain

#### Rule 2: Unknown
- **Phase**: Unknown
- **Variables**: TX:922100_CHARSET
- **Operator**: !@within
- **Pattern**: %{tx.allowed_request_content_type_charset}
- **Is Chain**: False
- **Message**: 
- **Severity**: 
- **Actions**: t:lowercase, setvar:tx.inbound_anomaly_score_pl1=+%{tx.critical_anomaly_score}

#### Rule 3: 922110
- **Phase**: 2
- **Variables**: MULTIPART_PART_HEADERS
- **Operator**: @rx
- **Pattern**: ^content-type\s*:\s*(.*)$
- **Is Chain**: True
- **Message**: Illegal MIME Multipart Header content-type: charset parameter
- **Severity**: CRITICAL
- **Tags**: application-multi, language-multi, platform-multi, attack-multipart-header, attack-protocol, paranoia-level/1, OWASP_CRS, OWASP_CRS/MULTIPART-ATTACK, capec/272/220
- **Actions**: id:922110, phase:2, block, capture, t:none, t:lowercase, msg:Illegal MIME Multipart Header content-type: charset parameter, logdata:Matched Data: %{TX.1} found within Content-Type multipart form, tag:application-multi, tag:language-multi, tag:platform-multi, tag:attack-multipart-header, tag:attack-protocol, tag:paranoia-level/1, tag:OWASP_CRS, tag:OWASP_CRS/MULTIPART-ATTACK, tag:capec/272/220, ver:OWASP_CRS/4.22.0-dev, severity:CRITICAL, chain

#### Rule 4: Unknown
- **Phase**: Unknown
- **Variables**: TX:1
- **Operator**: !@rx
- **Pattern**: ^(?:(?:\*|[^!\"\(\),/:-\?\[-\]\{\}]+)/(?:\*|[^!\"\(\),/:-\?\[-\]\{\}]+)|\*)(?:[\s\x0b]*;[\s\x0b]*(?:charset[\s\x0b]*=[\s\x0b]*\"?(?:iso-8859-15?|utf-8|windows-1252)\b\"?|(?:[^\s\x0b-\"\(\),/:-\?\[-\]c\{\}]|c(?:[^!\"\(\),/:-\?\[-\]h\{\}]|h(?:[^!\"\(\),/:-\?\[-\]a\{\}]|a(?:[^!\"\(\),/:-\?\[-\]r\{\}]|r(?:[^!\"\(\),/:-\?\[-\]s\{\}]|s(?:[^!\"\(\),/:-\?\[-\]e\{\}]|e[^!\"\(\),/:-\?\[-\]t\{\}]))))))[^!\"\(\),/:-\?\[-\]\{\}]*[\s\x0b]*=[\s\x0b]*[^!\(\),/:-\?\[-\]\{\}]+);?)*(?:[\s\x0b]*,[\s\x0b]*(?:(?:\*|[^!\"\(\),/:-\?\[-\]\{\}]+)/(?:\*|[^!\"\(\),/:-\?\[-\]\{\}]+)|\*)(?:[\s\x0b]*;[\s\x0b]*(?:charset[\s\x0b]*=[\s\x0b]*\"?(?:iso-8859-15?|utf-8|windows-1252)\b\"?|(?:[^\s\x0b-\"\(\),/:-\?\[-\]c\{\}]|c(?:[^!\"\(\),/:-\?\[-\]h\{\}]|h(?:[^!\"\(\),/:-\?\[-\]a\{\}]|a(?:[^!\"\(\),/:-\?\[-\]r\{\}]|r(?:[^!\"\(\),/:-\?\[-\]s\{\}]|s(?:[^!\"\(\),/:-\?\[-\]e\{\}]|e[^!\"\(\),/:-\?\[-\]t\{\}]))))))[^!\"\(\),/:-\?\[-\]\{\}]*[\s\x0b]*=[\s\x0b]*[^!\(\),/:-\?\[-\]\{\}]+);?)*)*$
- **Is Chain**: False
- **Message**: 
- **Severity**: 
- **Actions**: setvar:tx.inbound_anomaly_score_pl1=+%{tx.critical_anomaly_score}

#### Rule 5: 922120
- **Phase**: 2
- **Variables**: MULTIPART_PART_HEADERS
- **Operator**: @rx
- **Pattern**: content-transfer-encoding:(.*)
- **Is Chain**: False
- **Message**: Content-Transfer-Encoding was deprecated by rfc7578 in 2015 and should not be used
- **Severity**: CRITICAL
- **Tags**: application-multi, language-multi, platform-multi, attack-multipart-header, attack-deprecated-header, paranoia-level/1, OWASP_CRS, OWASP_CRS/MULTIPART-ATTACK, capec/272/220
- **Actions**: id:922120, phase:2, block, capture, t:none, t:lowercase, msg:Content-Transfer-Encoding was deprecated by rfc7578 in 2015 and should not be used, logdata:Matched Data: %{TX.0}, tag:application-multi, tag:language-multi, tag:platform-multi, tag:attack-multipart-header, tag:attack-deprecated-header, tag:paranoia-level/1, tag:OWASP_CRS, tag:OWASP_CRS/MULTIPART-ATTACK, tag:capec/272/220, ver:OWASP_CRS/4.22.0-dev, severity:CRITICAL, setvar:tx.inbound_anomaly_score_pl1=+%{tx.critical_anomaly_score}

#### Rule 6: 922130
- **Phase**: 2
- **Variables**: MULTIPART_PART_HEADERS
- **Operator**: @rx
- **Pattern**: [^\x21-\x7E][\x21-\x39\x3B-\x7E]*:
- **Is Chain**: False
- **Message**: Multipart header contains characters outside of valid range
- **Severity**: CRITICAL
- **Tags**: application-multi, language-multi, platform-multi, attack-multipart-header, paranoia-level/1, OWASP_CRS, OWASP_CRS/MULTIPART-ATTACK, capec/272/220
- **Actions**: id:922130, phase:2, block, capture, t:none, t:lowercase, msg:Multipart header contains characters outside of valid range, logdata:Matched Data: %{TX.0}, tag:application-multi, tag:language-multi, tag:platform-multi, tag:attack-multipart-header, tag:paranoia-level/1, tag:OWASP_CRS, tag:OWASP_CRS/MULTIPART-ATTACK, tag:capec/272/220, ver:OWASP_CRS/4.22.0-dev, severity:CRITICAL, setvar:tx.inbound_anomaly_score_pl1=+%{tx.critical_anomaly_score}


====================================================================================================

## File: REQUEST-930-APPLICATION-ATTACK-LFI.conf

### File Summary
- Total rules: 13
- Chained rules: 0
- Non-chained rules: 13

### Detailed Rules

#### Rule 1: 930011
- **Phase**: 1
- **Variables**: TX:DETECTION_PARANOIA_LEVEL
- **Operator**: @lt
- **Pattern**: 1
- **Is Chain**: False
- **Message**: 
- **Severity**: 
- **Tags**: OWASP_CRS
- **Actions**: id:930011, phase:1, pass, nolog, tag:OWASP_CRS, ver:OWASP_CRS/4.22.0-dev, skipAfter:END-REQUEST-930-APPLICATION-ATTACK-LFI

#### Rule 2: 930012
- **Phase**: 2
- **Variables**: TX:DETECTION_PARANOIA_LEVEL
- **Operator**: @lt
- **Pattern**: 1
- **Is Chain**: False
- **Message**: 
- **Severity**: 
- **Tags**: OWASP_CRS
- **Actions**: id:930012, phase:2, pass, nolog, tag:OWASP_CRS, ver:OWASP_CRS/4.22.0-dev, skipAfter:END-REQUEST-930-APPLICATION-ATTACK-LFI

#### Rule 3: 930100
- **Phase**: 2
- **Variables**: REQUEST_URI_RAW, ARGS, REQUEST_HEADERS, REQUEST_HEADERS:Referer, FILES, XML:/*
- **Operator**: @rx
- **Pattern**: (?i)(?:[/\x5c]|%(?:2(?:f|5(?:2f|5c|c(?:1%259c|0%25af))|%46)|5c|c(?:0%(?:[2aq]f|5c|9v)|1%(?:[19p]c|8s|af))|(?:bg%q|(?:e|f(?:8%8)?0%8)0%80%a)f|u(?:221[56]|EFC8|F025|002f)|%3(?:2(?:%(?:%6|4)6|F)|5%%63)|1u)|0x(?:2f|5c))(?:\.(?:%0[01]|\?)?|\?\.?|%(?:2(?:(?:5(?:2|c0%25a))?e|%45)|c0(?:\.|%[256aef]e)|u(?:(?:ff0|002)e|2024)|%32(?:%(?:%6|4)5|E)|(?:e|f(?:(?:8|c%80)%8)?0%8)0%80%ae)|0x2e){2,3}(?:[/\x5c]|%(?:2(?:f|5(?:2f|5c|c(?:1%259c|0%25af))|%46)|5c|c(?:0%(?:[2aq]f|5c|9v)|1%(?:[19p]c|8s|af))|(?:bg%q|(?:e|f(?:8%8)?0%8)0%80%a)f|u(?:221[56]|EFC8|F025|002f)|%3(?:2(?:%(?:%6|4)6|F)|5%%63)|1u)|0x(?:2f|5c))
- **Is Chain**: False
- **Message**: Path Traversal Attack (/../) or (/.../)
- **Severity**: CRITICAL
- **Tags**: application-multi, language-multi, platform-multi, attack-lfi, paranoia-level/1, OWASP_CRS, OWASP_CRS/ATTACK-LFI, capec/1000/255/153/126
- **Actions**: id:930100, phase:2, block, capture, t:none, msg:Path Traversal Attack (/../) or (/.../), logdata:Matched Data: %{TX.0} found within %{MATCHED_VAR_NAME}: %{MATCHED_VAR}, tag:application-multi, tag:language-multi, tag:platform-multi, tag:attack-lfi, tag:paranoia-level/1, tag:OWASP_CRS, tag:OWASP_CRS/ATTACK-LFI, tag:capec/1000/255/153/126, ver:OWASP_CRS/4.22.0-dev, severity:CRITICAL, setvar:tx.inbound_anomaly_score_pl1=+%{tx.critical_anomaly_score}, setvar:tx.lfi_score=+%{tx.critical_anomaly_score}

#### Rule 4: 930110
- **Phase**: 2
- **Variables**: REQUEST_URI_RAW, ARGS, REQUEST_HEADERS, REQUEST_HEADERS:Referer, FILES, XML:/*
- **Operator**: @rx
- **Pattern**: (?:(?:^|[\x5c/;])\.{2,3}[\x5c/;]|[\x5c/;]\.{2,3}[\x5c/;])
- **Is Chain**: False
- **Message**: Path Traversal Attack (/../) or (/.../)
- **Severity**: CRITICAL
- **Tags**: application-multi, language-multi, platform-multi, attack-lfi, paranoia-level/1, OWASP_CRS, OWASP_CRS/ATTACK-LFI, capec/1000/255/153/126
- **Actions**: id:930110, phase:2, block, capture, t:none, t:utf8toUnicode, t:urlDecodeUni, t:removeNulls, t:cmdLine, msg:Path Traversal Attack (/../) or (/.../), logdata:Matched Data: %{TX.0} found within %{MATCHED_VAR_NAME}: %{MATCHED_VAR}, tag:application-multi, tag:language-multi, tag:platform-multi, tag:attack-lfi, tag:paranoia-level/1, tag:OWASP_CRS, tag:OWASP_CRS/ATTACK-LFI, tag:capec/1000/255/153/126, ver:OWASP_CRS/4.22.0-dev, severity:CRITICAL, multiMatch, setvar:tx.inbound_anomaly_score_pl1=+%{tx.critical_anomaly_score}, setvar:tx.lfi_score=+%{tx.critical_anomaly_score}

#### Rule 5: 930120
- **Phase**: 2
- **Variables**: REQUEST_COOKIES, REQUEST_COOKIES_NAMES, ARGS_NAMES, ARGS, XML:/*
- **Operator**: @pmFromFile
- **Pattern**: lfi-os-files.data
- **Is Chain**: False
- **Message**: OS File Access Attempt
- **Severity**: CRITICAL
- **Tags**: application-multi, language-multi, platform-multi, attack-lfi, paranoia-level/1, OWASP_CRS, OWASP_CRS/ATTACK-LFI, capec/1000/255/153/126
- **Actions**: id:930120, phase:2, block, capture, t:none, t:utf8toUnicode, t:urlDecodeUni, t:normalizePathWin, msg:OS File Access Attempt, logdata:Matched Data: %{TX.0} found within %{MATCHED_VAR_NAME}: %{MATCHED_VAR}, tag:application-multi, tag:language-multi, tag:platform-multi, tag:attack-lfi, tag:paranoia-level/1, tag:OWASP_CRS, tag:OWASP_CRS/ATTACK-LFI, tag:capec/1000/255/153/126, ver:OWASP_CRS/4.22.0-dev, severity:CRITICAL, setvar:tx.lfi_score=+%{tx.critical_anomaly_score}, setvar:tx.inbound_anomaly_score_pl1=+%{tx.critical_anomaly_score}

#### Rule 6: 930130
- **Phase**: 1
- **Variables**: REQUEST_FILENAME
- **Operator**: @pmFromFile
- **Pattern**: restricted-files.data
- **Is Chain**: False
- **Message**: Restricted File Access Attempt
- **Severity**: CRITICAL
- **Tags**: application-multi, language-multi, platform-multi, attack-lfi, paranoia-level/1, OWASP_CRS, OWASP_CRS/ATTACK-LFI, capec/1000/255/153/126
- **Actions**: id:930130, phase:1, block, capture, t:none, t:utf8toUnicode, t:urlDecodeUni, t:normalizePathWin, msg:Restricted File Access Attempt, logdata:Matched Data: %{TX.0} found within %{MATCHED_VAR_NAME}: %{MATCHED_VAR}, tag:application-multi, tag:language-multi, tag:platform-multi, tag:attack-lfi, tag:paranoia-level/1, tag:OWASP_CRS, tag:OWASP_CRS/ATTACK-LFI, tag:capec/1000/255/153/126, ver:OWASP_CRS/4.22.0-dev, severity:CRITICAL, setvar:tx.lfi_score=+%{tx.critical_anomaly_score}, setvar:tx.inbound_anomaly_score_pl1=+%{tx.critical_anomaly_score}

#### Rule 7: 930013
- **Phase**: 1
- **Variables**: TX:DETECTION_PARANOIA_LEVEL
- **Operator**: @lt
- **Pattern**: 2
- **Is Chain**: False
- **Message**: 
- **Severity**: 
- **Tags**: OWASP_CRS
- **Actions**: id:930013, phase:1, pass, nolog, tag:OWASP_CRS, ver:OWASP_CRS/4.22.0-dev, skipAfter:END-REQUEST-930-APPLICATION-ATTACK-LFI

#### Rule 8: 930014
- **Phase**: 2
- **Variables**: TX:DETECTION_PARANOIA_LEVEL
- **Operator**: @lt
- **Pattern**: 2
- **Is Chain**: False
- **Message**: 
- **Severity**: 
- **Tags**: OWASP_CRS
- **Actions**: id:930014, phase:2, pass, nolog, tag:OWASP_CRS, ver:OWASP_CRS/4.22.0-dev, skipAfter:END-REQUEST-930-APPLICATION-ATTACK-LFI

#### Rule 9: 930121
- **Phase**: 1
- **Variables**: REQUEST_HEADERS:Referer, REQUEST_HEADERS:User-Agent
- **Operator**: @pmFromFile
- **Pattern**: lfi-os-files.data
- **Is Chain**: False
- **Message**: OS File Access Attempt in REQUEST_HEADERS
- **Severity**: CRITICAL
- **Tags**: application-multi, language-multi, platform-multi, attack-lfi, paranoia-level/2, OWASP_CRS, OWASP_CRS/ATTACK-LFI, capec/1000/255/153/126
- **Actions**: id:930121, phase:1, block, capture, t:none, t:utf8toUnicode, t:urlDecodeUni, t:normalizePathWin, msg:OS File Access Attempt in REQUEST_HEADERS, logdata:Matched Data: %{TX.0} found within %{MATCHED_VAR_NAME}: %{MATCHED_VAR}, tag:application-multi, tag:language-multi, tag:platform-multi, tag:attack-lfi, tag:paranoia-level/2, tag:OWASP_CRS, tag:OWASP_CRS/ATTACK-LFI, tag:capec/1000/255/153/126, ver:OWASP_CRS/4.22.0-dev, severity:CRITICAL, setvar:tx.lfi_score=+%{tx.critical_anomaly_score}, setvar:tx.inbound_anomaly_score_pl2=+%{tx.critical_anomaly_score}

#### Rule 10: 930015
- **Phase**: 1
- **Variables**: TX:DETECTION_PARANOIA_LEVEL
- **Operator**: @lt
- **Pattern**: 3
- **Is Chain**: False
- **Message**: 
- **Severity**: 
- **Tags**: OWASP_CRS
- **Actions**: id:930015, phase:1, pass, nolog, tag:OWASP_CRS, ver:OWASP_CRS/4.22.0-dev, skipAfter:END-REQUEST-930-APPLICATION-ATTACK-LFI

#### Rule 11: 930016
- **Phase**: 2
- **Variables**: TX:DETECTION_PARANOIA_LEVEL
- **Operator**: @lt
- **Pattern**: 3
- **Is Chain**: False
- **Message**: 
- **Severity**: 
- **Tags**: OWASP_CRS
- **Actions**: id:930016, phase:2, pass, nolog, tag:OWASP_CRS, ver:OWASP_CRS/4.22.0-dev, skipAfter:END-REQUEST-930-APPLICATION-ATTACK-LFI

#### Rule 12: 930017
- **Phase**: 1
- **Variables**: TX:DETECTION_PARANOIA_LEVEL
- **Operator**: @lt
- **Pattern**: 4
- **Is Chain**: False
- **Message**: 
- **Severity**: 
- **Tags**: OWASP_CRS
- **Actions**: id:930017, phase:1, pass, nolog, tag:OWASP_CRS, ver:OWASP_CRS/4.22.0-dev, skipAfter:END-REQUEST-930-APPLICATION-ATTACK-LFI

#### Rule 13: 930018
- **Phase**: 2
- **Variables**: TX:DETECTION_PARANOIA_LEVEL
- **Operator**: @lt
- **Pattern**: 4
- **Is Chain**: False
- **Message**: 
- **Severity**: 
- **Tags**: OWASP_CRS
- **Actions**: id:930018, phase:2, pass, nolog, tag:OWASP_CRS, ver:OWASP_CRS/4.22.0-dev, skipAfter:END-REQUEST-930-APPLICATION-ATTACK-LFI


====================================================================================================

## File: REQUEST-931-APPLICATION-ATTACK-RFI.conf

### File Summary
- Total rules: 15
- Chained rules: 2
- Non-chained rules: 13

### Detailed Rules

#### Rule 1: 931011
- **Phase**: 1
- **Variables**: TX:DETECTION_PARANOIA_LEVEL
- **Operator**: @lt
- **Pattern**: 1
- **Is Chain**: False
- **Message**: 
- **Severity**: 
- **Tags**: OWASP_CRS
- **Actions**: id:931011, phase:1, pass, nolog, tag:OWASP_CRS, ver:OWASP_CRS/4.22.0-dev, skipAfter:END-REQUEST-931-APPLICATION-ATTACK-RFI

#### Rule 2: 931012
- **Phase**: 2
- **Variables**: TX:DETECTION_PARANOIA_LEVEL
- **Operator**: @lt
- **Pattern**: 1
- **Is Chain**: False
- **Message**: 
- **Severity**: 
- **Tags**: OWASP_CRS
- **Actions**: id:931012, phase:2, pass, nolog, tag:OWASP_CRS, ver:OWASP_CRS/4.22.0-dev, skipAfter:END-REQUEST-931-APPLICATION-ATTACK-RFI

#### Rule 3: 931100
- **Phase**: 2
- **Variables**: ARGS, XML:/*
- **Operator**: @rx
- **Pattern**: (?i)^(file|ftps?|https?|ssh)://(?:\[?[a-f0-9]+:[a-f0-9:]+\]?|\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})
- **Is Chain**: False
- **Message**: Possible Remote File Inclusion (RFI) Attack: URL Parameter using IP Address
- **Severity**: CRITICAL
- **Tags**: application-multi, language-multi, platform-multi, attack-rfi, paranoia-level/1, OWASP_CRS, OWASP_CRS/ATTACK-RFI, capec/1000/152/175/253
- **Actions**: id:931100, phase:2, block, capture, t:none, t:urlDecodeUni, msg:Possible Remote File Inclusion (RFI) Attack: URL Parameter using IP Address, logdata:Matched Data: %{TX.0} found within %{MATCHED_VAR_NAME}: %{MATCHED_VAR}, tag:application-multi, tag:language-multi, tag:platform-multi, tag:attack-rfi, tag:paranoia-level/1, tag:OWASP_CRS, tag:OWASP_CRS/ATTACK-RFI, tag:capec/1000/152/175/253, ver:OWASP_CRS/4.22.0-dev, severity:CRITICAL, setvar:tx.rfi_score=+%{tx.critical_anomaly_score}, setvar:tx.inbound_anomaly_score_pl1=+%{tx.critical_anomaly_score}

#### Rule 4: 931110
- **Phase**: 2
- **Variables**: QUERY_STRING, REQUEST_BODY
- **Operator**: @rx
- **Pattern**: (?i)(?:\binclude\s*\([^)]*|mosConfig_absolute_path|_CONF\[path\]|_SERVER\[DOCUMENT_ROOT\]|GALLERY_BASEDIR|path\[docroot\]|appserv_root|config\[root_dir\])=(?:file|ftps?|https?)://
- **Is Chain**: False
- **Message**: Possible Remote File Inclusion (RFI) Attack: Common RFI Vulnerable Parameter Name used w/URL Payload
- **Severity**: CRITICAL
- **Tags**: application-multi, language-multi, platform-multi, attack-rfi, paranoia-level/1, OWASP_CRS, OWASP_CRS/ATTACK-RFI, capec/1000/152/175/253
- **Actions**: id:931110, phase:2, block, capture, t:none, t:urlDecodeUni, msg:Possible Remote File Inclusion (RFI) Attack: Common RFI Vulnerable Parameter Name used w/URL Payload, logdata:Matched Data: %{TX.0} found within %{MATCHED_VAR_NAME}: %{MATCHED_VAR}, tag:application-multi, tag:language-multi, tag:platform-multi, tag:attack-rfi, tag:paranoia-level/1, tag:OWASP_CRS, tag:OWASP_CRS/ATTACK-RFI, tag:capec/1000/152/175/253, ver:OWASP_CRS/4.22.0-dev, severity:CRITICAL, setvar:tx.rfi_score=+%{tx.critical_anomaly_score}, setvar:tx.inbound_anomaly_score_pl1=+%{tx.critical_anomaly_score}

#### Rule 5: 931120
- **Phase**: 2
- **Variables**: ARGS
- **Operator**: @rx
- **Pattern**: ^(?i:file|ftps?|https?).*?\?+$
- **Is Chain**: False
- **Message**: Possible Remote File Inclusion (RFI) Attack: URL Payload Used w/Trailing Question Mark Character (?)
- **Severity**: CRITICAL
- **Tags**: application-multi, language-multi, platform-multi, attack-rfi, paranoia-level/1, OWASP_CRS, OWASP_CRS/ATTACK-RFI, capec/1000/152/175/253
- **Actions**: id:931120, phase:2, block, capture, t:none, msg:Possible Remote File Inclusion (RFI) Attack: URL Payload Used w/Trailing Question Mark Character (?), logdata:Matched Data: %{TX.0} found within %{MATCHED_VAR_NAME}: %{MATCHED_VAR}, tag:application-multi, tag:language-multi, tag:platform-multi, tag:attack-rfi, tag:paranoia-level/1, tag:OWASP_CRS, tag:OWASP_CRS/ATTACK-RFI, tag:capec/1000/152/175/253, ver:OWASP_CRS/4.22.0-dev, severity:CRITICAL, setvar:tx.rfi_score=+%{tx.critical_anomaly_score}, setvar:tx.inbound_anomaly_score_pl1=+%{tx.critical_anomaly_score}

#### Rule 6: 931013
- **Phase**: 1
- **Variables**: TX:DETECTION_PARANOIA_LEVEL
- **Operator**: @lt
- **Pattern**: 2
- **Is Chain**: False
- **Message**: 
- **Severity**: 
- **Tags**: OWASP_CRS
- **Actions**: id:931013, phase:1, pass, nolog, tag:OWASP_CRS, ver:OWASP_CRS/4.22.0-dev, skipAfter:END-REQUEST-931-APPLICATION-ATTACK-RFI

#### Rule 7: 931014
- **Phase**: 2
- **Variables**: TX:DETECTION_PARANOIA_LEVEL
- **Operator**: @lt
- **Pattern**: 2
- **Is Chain**: False
- **Message**: 
- **Severity**: 
- **Tags**: OWASP_CRS
- **Actions**: id:931014, phase:2, pass, nolog, tag:OWASP_CRS, ver:OWASP_CRS/4.22.0-dev, skipAfter:END-REQUEST-931-APPLICATION-ATTACK-RFI

#### Rule 8: 931130
- **Phase**: 2
- **Variables**: ARGS
- **Operator**: @rx
- **Pattern**: (?i)(?:(?:url|jar):)?(?:a(?:cap|f[ps]|ttachment)|b(?:eshare|itcoin|lob)|c(?:a(?:llto|p)|id|vs|ompress.(?:zlib|bzip2))|d(?:a(?:v|ta)|ict|n(?:s|tp))|e(?:d2k|xpect)|f(?:(?:ee)?d|i(?:le|nger|sh)|tps?)|g(?:it|o(?:pher)?|lob)|h(?:323|ttps?)|i(?:ax|cap|(?:ma|p)ps?|rc[6s]?)|ja(?:bbe)?r|l(?:dap[is]?|ocal_file)|m(?:a(?:ilto|ven)|ms|umble)|n(?:e(?:tdoc|ws)|fs|ntps?)|ogg|p(?:aparazzi|h(?:ar|p)|op(?:2|3s?)|r(?:es|oxy)|syc)|r(?:mi|sync|tm(?:f?p)?|ar)|s(?:3|ftp|ips?|m(?:[bs]|tps?)|n(?:ews|mp)|sh(?:2(?:.(?:s(?:hell|(?:ft|c)p)|exec|tunnel))?)?|vn(?:\+ssh)?)|t(?:e(?:amspeak|lnet)|ftp|urns?)|u(?:dp|nreal|t2004)|v(?:entrilo|iew-source|nc)|w(?:ebcal|ss?)|x(?:mpp|ri)|zip)://?(?:[^@]+@)?([^/]*)
- **Is Chain**: True
- **Message**: Possible Remote File Inclusion (RFI) Attack: Off-Domain Reference/Link
- **Severity**: CRITICAL
- **Tags**: application-multi, language-multi, platform-multi, attack-rfi, paranoia-level/2, OWASP_CRS, OWASP_CRS/ATTACK-RFI, capec/1000/152/175/253
- **Actions**: id:931130, phase:2, block, capture, t:none, msg:Possible Remote File Inclusion (RFI) Attack: Off-Domain Reference/Link, logdata:Matched Data: %{TX.0} found within %{MATCHED_VAR_NAME}: %{MATCHED_VAR}, tag:application-multi, tag:language-multi, tag:platform-multi, tag:attack-rfi, tag:paranoia-level/2, tag:OWASP_CRS, tag:OWASP_CRS/ATTACK-RFI, tag:capec/1000/152/175/253, ver:OWASP_CRS/4.22.0-dev, severity:CRITICAL, setvar:tx.rfi_parameter_%{MATCHED_VAR_NAME}=.%{tx.1}, chain

#### Rule 9: Unknown
- **Phase**: Unknown
- **Variables**: TX:/rfi_parameter_.*/
- **Operator**: !@endsWith
- **Pattern**: .%{request_headers.host}
- **Is Chain**: False
- **Message**: 
- **Severity**: 
- **Actions**: setvar:tx.rfi_score=+%{tx.critical_anomaly_score}, setvar:tx.inbound_anomaly_score_pl2=+%{tx.critical_anomaly_score}

#### Rule 10: 931131
- **Phase**: 1
- **Variables**: REQUEST_FILENAME
- **Operator**: @rx
- **Pattern**: (?i)(?:(?:url|jar):)?(?:a(?:cap|f[ps]|ttachment)|b(?:eshare|itcoin|lob)|c(?:a(?:llto|p)|id|vs|ompress.(?:zlib|bzip2))|d(?:a(?:v|ta)|ict|n(?:s|tp))|e(?:d2k|xpect)|f(?:(?:ee)?d|i(?:le|nger|sh)|tps?)|g(?:it|o(?:pher)?|lob)|h(?:323|ttps?)|i(?:ax|cap|(?:ma|p)ps?|rc[6s]?)|ja(?:bbe)?r|l(?:dap[is]?|ocal_file)|m(?:a(?:ilto|ven)|ms|umble)|n(?:e(?:tdoc|ws)|fs|ntps?)|ogg|p(?:aparazzi|h(?:ar|p)|op(?:2|3s?)|r(?:es|oxy)|syc)|r(?:mi|sync|tm(?:f?p)?|ar)|s(?:3|ftp|ips?|m(?:[bs]|tps?)|n(?:ews|mp)|sh(?:2(?:.(?:s(?:hell|(?:ft|c)p)|exec|tunnel))?)?|vn(?:\+ssh)?)|t(?:e(?:amspeak|lnet)|ftp|urns?)|u(?:dp|nreal|t2004)|v(?:entrilo|iew-source|nc)|w(?:ebcal|ss?)|x(?:mpp|ri)|zip)://(?:[^@]+@)?([^/]*)
- **Is Chain**: True
- **Message**: Possible Remote File Inclusion (RFI) Attack: Off-Domain Reference/Link
- **Severity**: CRITICAL
- **Tags**: application-multi, language-multi, platform-multi, attack-rfi, paranoia-level/2, OWASP_CRS, OWASP_CRS/ATTACK-RFI, capec/1000/152/175/253
- **Actions**: id:931131, phase:1, block, capture, t:none, t:urlDecodeUni, msg:Possible Remote File Inclusion (RFI) Attack: Off-Domain Reference/Link, logdata:Matched Data: %{TX.0} found within %{MATCHED_VAR_NAME}: %{MATCHED_VAR}, tag:application-multi, tag:language-multi, tag:platform-multi, tag:attack-rfi, tag:paranoia-level/2, tag:OWASP_CRS, tag:OWASP_CRS/ATTACK-RFI, tag:capec/1000/152/175/253, ver:OWASP_CRS/4.22.0-dev, severity:CRITICAL, setvar:tx.rfi_parameter_%{MATCHED_VAR_NAME}=.%{tx.1}, chain

#### Rule 11: Unknown
- **Phase**: Unknown
- **Variables**: TX:/rfi_parameter_.*/
- **Operator**: !@endsWith
- **Pattern**: .%{request_headers.host}
- **Is Chain**: False
- **Message**: 
- **Severity**: 
- **Actions**: setvar:tx.rfi_score=+%{tx.critical_anomaly_score}, setvar:tx.inbound_anomaly_score_pl2=+%{tx.critical_anomaly_score}

#### Rule 12: 931015
- **Phase**: 1
- **Variables**: TX:DETECTION_PARANOIA_LEVEL
- **Operator**: @lt
- **Pattern**: 3
- **Is Chain**: False
- **Message**: 
- **Severity**: 
- **Tags**: OWASP_CRS
- **Actions**: id:931015, phase:1, pass, nolog, tag:OWASP_CRS, ver:OWASP_CRS/4.22.0-dev, skipAfter:END-REQUEST-931-APPLICATION-ATTACK-RFI

#### Rule 13: 931016
- **Phase**: 2
- **Variables**: TX:DETECTION_PARANOIA_LEVEL
- **Operator**: @lt
- **Pattern**: 3
- **Is Chain**: False
- **Message**: 
- **Severity**: 
- **Tags**: OWASP_CRS
- **Actions**: id:931016, phase:2, pass, nolog, tag:OWASP_CRS, ver:OWASP_CRS/4.22.0-dev, skipAfter:END-REQUEST-931-APPLICATION-ATTACK-RFI

#### Rule 14: 931017
- **Phase**: 1
- **Variables**: TX:DETECTION_PARANOIA_LEVEL
- **Operator**: @lt
- **Pattern**: 4
- **Is Chain**: False
- **Message**: 
- **Severity**: 
- **Tags**: OWASP_CRS
- **Actions**: id:931017, phase:1, pass, nolog, tag:OWASP_CRS, ver:OWASP_CRS/4.22.0-dev, skipAfter:END-REQUEST-931-APPLICATION-ATTACK-RFI

#### Rule 15: 931018
- **Phase**: 2
- **Variables**: TX:DETECTION_PARANOIA_LEVEL
- **Operator**: @lt
- **Pattern**: 4
- **Is Chain**: False
- **Message**: 
- **Severity**: 
- **Tags**: OWASP_CRS
- **Actions**: id:931018, phase:2, pass, nolog, tag:OWASP_CRS, ver:OWASP_CRS/4.22.0-dev, skipAfter:END-REQUEST-931-APPLICATION-ATTACK-RFI


====================================================================================================

## File: REQUEST-932-APPLICATION-ATTACK-RCE.conf

### File Summary
- Total rules: 65
- Chained rules: 13
- Non-chained rules: 52

### Detailed Rules

#### Rule 1: 932011
- **Phase**: 1
- **Variables**: TX:DETECTION_PARANOIA_LEVEL
- **Operator**: @lt
- **Pattern**: 1
- **Is Chain**: False
- **Message**: 
- **Severity**: 
- **Tags**: OWASP_CRS
- **Actions**: id:932011, phase:1, pass, nolog, tag:OWASP_CRS, ver:OWASP_CRS/4.22.0-dev, skipAfter:END-REQUEST-932-APPLICATION-ATTACK-RCE

#### Rule 2: 932012
- **Phase**: 2
- **Variables**: TX:DETECTION_PARANOIA_LEVEL
- **Operator**: @lt
- **Pattern**: 1
- **Is Chain**: False
- **Message**: 
- **Severity**: 
- **Tags**: OWASP_CRS
- **Actions**: id:932012, phase:2, pass, nolog, tag:OWASP_CRS, ver:OWASP_CRS/4.22.0-dev, skipAfter:END-REQUEST-932-APPLICATION-ATTACK-RCE

#### Rule 3: 932230
- **Phase**: 2
- **Variables**: REQUEST_COOKIES, REQUEST_COOKIES_NAMES, ARGS_NAMES, ARGS, XML:/*
- **Operator**: @rx
- **Pattern**: (?i)(?:b[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?u[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?s[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?y[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?b[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?o[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?x|(?:c[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?o[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?m[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?m[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?a[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?n[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?d|e[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?(?:n[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?v|v[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?a[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?l)|w[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?a[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?t[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?c[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?h)[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?(?:[\s\x0b&\),<>\|]|$).*|[ls][\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?t[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?r[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?a[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?c[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?e|n[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?o[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?h[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?u[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?p|t[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?i[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?m[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?e[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?(?:(?:[\s\x0b&\),<>\|]|$).*|o[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?u[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?t)|[\n\r;=`\{]|\|\|?|&&?|\$(?:\(\(?|[\[\{])|<(?:\(|<<)|>\(|\([\s\x0b]*\))[\s\x0b]*(?:[\$\{]|(?:[\s\x0b]*\(|!)[\s\x0b]*|[0-9A-Z_a-z]+=(?:[^\s\x0b]*|\$(?:.*|.*)|[<>].*|'[^']*'|\"[^\"]*\")[\s\x0b]+)*[\s\x0b]*[\"']*(?:[\"'-\+\--9\?A-\]_a-z\|]+/)?[\"'\x5c]*(?:(?:7[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?z[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?(?:[arx][\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?)?|(?:b[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?z[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?z|c[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?(?:[89][\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?9|m[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?p|s[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?h)|d[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?(?:n[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?)?f|e[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?(?:n[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?v|q[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?n|s[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?h)|f[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?(?:[dg]|m[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?t)|(?:h[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?u|u[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?d)[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?p|i[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?r[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?b|j[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?(?:j[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?s|q)|[kz][\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?s[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?h|m[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?t[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?r|p[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?(?:d[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?b|k[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?g|t[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?x|x[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?z)|r[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?(?:c[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?p|m[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?t)|s[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?(?:c[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?p|e[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?d|(?:s[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?)?h|v[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?n)|t[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?(?:a[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?c|b[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?l)|w[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?(?:3[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?m|c)|x[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?(?:x[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?d|z)|y[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?u[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?m)[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?|l[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?(?:s[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?|z[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?(?:4[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?)?))(?:[\s\x0b&\),<>\|]|$).*|a[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?(?:a[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?-[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?(?:(?:[&\),<>\|]|$){1,10}|(?:[\-\.0-9A-Z_a-z][\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?){1,10}(?:[\s\x0b&\),<>\|\}]|$){1,10})|r[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?j[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?(?:[\s\x0b&\),<>\|]|$).*)|g[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?(?:c[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?c[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?(?:(?:[&\),<>\|]|$){1,10}|(?:[\-\.0-9A-Z_a-z][\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?){1,10}(?:[\s\x0b&\),<>\|\}]|$){1,10})|(?:d[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?b|[hr][\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?c|p[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?g)[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?(?:[\s\x0b&\),<>\|]|$).*))\b
- **Is Chain**: False
- **Message**: Remote Command Execution: Unix Command Injection (2-3 chars)
- **Severity**: CRITICAL
- **Tags**: application-multi, language-shell, platform-unix, attack-rce, paranoia-level/1, OWASP_CRS, OWASP_CRS/ATTACK-RCE, capec/1000/152/248/88
- **Actions**: id:932230, phase:2, block, capture, t:none, msg:Remote Command Execution: Unix Command Injection (2-3 chars), logdata:Matched Data: %{TX.0} found within %{MATCHED_VAR_NAME}: %{MATCHED_VAR}, tag:application-multi, tag:language-shell, tag:platform-unix, tag:attack-rce, tag:paranoia-level/1, tag:OWASP_CRS, tag:OWASP_CRS/ATTACK-RCE, tag:capec/1000/152/248/88, ver:OWASP_CRS/4.22.0-dev, severity:CRITICAL, setvar:tx.rce_score=+%{tx.critical_anomaly_score}, setvar:tx.inbound_anomaly_score_pl1=+%{tx.critical_anomaly_score}

#### Rule 4: 932235
- **Phase**: 2
- **Variables**: REQUEST_COOKIES, REQUEST_COOKIES_NAMES, ARGS_NAMES, ARGS, XML:/*
- **Operator**: @rx
- **Pattern**: (?i)(?:b[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?u[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?s[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?y[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?b[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?o[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?x|(?:c[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?o[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?m[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?m[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?a[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?n[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?d|e[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?(?:n[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?v|v[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?a[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?l)|w[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?a[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?t[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?c[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?h)[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?(?:[\s\x0b&\),<>\|]|$).*|[ls][\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?t[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?r[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?a[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?c[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?e|n[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?o[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?h[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?u[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?p|t[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?i[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?m[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?e[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?(?:(?:[\s\x0b&\),<>\|]|$).*|o[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?u[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?t)|[\n\r;=`\{]|\|\|?|&&?|\$(?:\(\(?|[\[\{])|<(?:\(|<<)|>\(|\([\s\x0b]*\))[\s\x0b]*(?:[\$\{]|(?:[\s\x0b]*\(|!)[\s\x0b]*|[0-9A-Z_a-z]+=(?:[^\s\x0b]*|\$(?:.*|.*)|[<>].*|'[^']*'|\"[^\"]*\")[\s\x0b]+)*[\s\x0b]*[\"']*(?:[\"'-\+\--9\?A-\]_a-z\|]+/)?[\"'\x5c]*(?:(?:HEAD|POST|y(?:arn|elp))(?:[\s\x0b&\),<>\|]|$)|a(?:dd(?:group|user)|getty|(?:l(?:ias|pine)|tobm|xel)(?:[\s\x0b&\),<>\|]|$)|nsible|p(?:parmor_[^\s\x0b]{1,10}\b|t(?:-get|itude(?:[\s\x0b&\),<>\|]|$)))|r(?:ch(?:[\s\x0b&\),<>\|]|$)|ia2c|j(?:-register|disp))|s(?:cii(?:-xfr|85)|pell)|u(?:ditctl|repot|search))|b(?:a(?:s(?:e(?:32|64|n(?:ame(?:[\s\x0b&\),<>\|]|$)|c))|h(?:[\s\x0b&\),<>\|]|$))|tch(?:[\s\x0b&\),<>\|]|$))|lkid(?:[\s\x0b&\),<>\|]|$)|pftrace|r(?:eaksw|(?:idge|wap)(?:[\s\x0b&\),<>\|]|$))|sd(?:cat|iff|tar)|u(?:iltin|n(?:dler(?:[\s\x0b&\),<>\|]|$)|zip2)|s(?:ctl|ybox))|y(?:ebug|obu(?:[\s\x0b&\),<>\|]|$))|z(?:c(?:at|mp)(?:[\s\x0b&\),<>\|]|$)|diff|e(?:grep|xe(?:[\s\x0b&\),<>\|]|$))|f?grep|ip2(?:[\s\x0b&\),<>\|]|$|recover)|less|more))|c(?:[89]9-gcc|a(?:ncel|psh)(?:[\s\x0b&\),<>\|]|$)|ertbot|h(?:(?:(?:att|di)r|mod|o(?:om|wn)|root|sh)(?:[\s\x0b&\),<>\|]|$)|e(?:ck_(?:by_ssh|cups|log|memory|raid|s(?:sl_cert|tatusfile))|f(?:[\s\x0b&\),\-<>\|]|$))|(?:flag|pas)s|g(?:passwd|rp(?:[\s\x0b&\),<>\|]|$)))|lang(?:\+\+|[\s\x0b&\),<>\|]|$)|o(?:bc(?:[\s\x0b&\),<>\|]|$|run)|lumn(?:[\s\x0b&\),<>\|]|$)|m(?:m(?:[\s\x0b&\),<>\|]|$|and(?:[\s\x0b&\),<>\|]|$))|p(?:oser|ress)(?:[\s\x0b&\),<>\|]|$))|proc|w(?:say|think))|p(?:(?:an|io)(?:[\s\x0b&\),<>\|]|$)|ulimit)|r(?:ash(?:[\s\x0b&\),<>\|]|$)|on(?:[\s\x0b&\),<>\|]|$|tab))|s(?:cli(?:[\s\x0b&\),<>\|]|$)|plit|vtool)|u(?:psfilter|rl(?:[\s\x0b&\),<>\|]|$)))|d(?:(?:ash|i(?:alog|ff)|vips)(?:[\s\x0b&\),<>\|]|$)|hclient|m(?:esg(?:[\s\x0b&\),<>\|]|$)|idecode|setup)|o(?:(?:as|ne)(?:[\s\x0b&\),<>\|]|$)|cker(?:[\s\x0b&\),\-<>\|]|$)|sbox)|pkg(?:[\s\x0b&\),\-<>\|]|$))|e(?:2fsck|asy_install|(?:cho|fax|grep|macs|sac|val)(?:[\s\x0b&\),<>\|]|$)|n(?:d(?:if|sw)(?:[\s\x0b&\),<>\|]|$)|v-update)|x(?:(?:ec|p(?:and|(?:ec|or)t|r))(?:[\s\x0b&\),<>\|]|$)|iftool))|f(?:acter|d(?:(?:find|isk)(?:[\s\x0b&\),<>\|]|$)|u?mount)|(?:etch|grep|lock|unction)(?:[\s\x0b&\),<>\|]|$)|i(?:le(?:[\s\x0b&\),<>\|]|$|test)|(?:n(?:d|ger)|sh)(?:[\s\x0b&\),<>\|]|$))|o(?:ld(?:[\s\x0b&\),<>\|]|$)|reach)|ping(?:[\s\x0b&\),6<>\|]|$)|tp(?:stats|who))|g(?:(?:awk|core|i(?:mp|nsh)|z(?:cat|exe|ip))(?:[\s\x0b&\),<>\|]|$)|e(?:ni(?:e(?:[\s\x0b&\),<>\|]|$)|soimage)|t(?:cap|facl(?:[\s\x0b&\),<>\|]|$)))|hc(?:-(?:[\s\x0b&\),<>\|]|$)|i(?:[\s\x0b&\),\-<>\|]|$))|r(?:(?:cat|ep)(?:[\s\x0b&\),<>\|]|$)|oupmod)|tester|unzip)|h(?:(?:ash|i(?:ghlight|story))(?:[\s\x0b&\),<>\|]|$)|e(?:ad(?:[\s\x0b&\),<>\|]|$)|xdump)|ost(?:id|name)|ping3|t(?:digest|op(?:[\s\x0b&\),<>\|]|$)|passwd))|i(?:(?:conv|nstall)(?:[\s\x0b&\),<>\|]|$)|f(?:config|top(?:[\s\x0b&\),<>\|]|$))|onice|p(?:6?tables|config|p(?:eveprinter|find|tool))|spell)|j(?:(?:ava|exec)(?:[\s\x0b&\),<>\|]|$)|o(?:in(?:[\s\x0b&\),<>\|]|$)|urnalctl)|runscript)|k(?:ill(?:[\s\x0b&\),<>\|]|$|all)|nife(?:[\s\x0b&\),<>\|]|$)|sshell)|l(?:a(?:st(?:comm(?:[\s\x0b&\),<>\|]|$)|log(?:in)?)|tex(?:[\s\x0b&\),<>\|]|$))|dconfig|ess(?:echo|(?:fil|pip)e)|ftp(?:[\s\x0b&\),<>\|]|$|get)|o(?:(?:cate|ok)(?:[\s\x0b&\),<>\|]|$)|g(?:inctl|(?:nam|sav)e)|setup)|s(?:(?:-F|cpu|hw|mod|of|pci|usb)(?:[\s\x0b&\),<>\|]|$)|b_release)|trace|ua(?:la)?tex|wp-(?:d(?:ownload|ump)|mirror|request)|ynx(?:[\s\x0b&\),<>\|]|$)|z(?:4c(?:[\s\x0b&\),<>\|]|$|at)|c(?:at|mp)(?:[\s\x0b&\),<>\|]|$)|diff|[ef]?grep|less|m(?:a(?:[\s\x0b&\),<>\|]|$|dec|info)|ore)))|m(?:a(?:il(?:[\s\x0b&\),<>\|]|$|[qx](?:[\s\x0b&\),<>\|]|$))|(?:ke|wk)(?:[\s\x0b&\),<>\|]|$)|ster\.passwd)|k(?:(?:dir|nod)(?:[\s\x0b&\),<>\|]|$)|fifo|temp)|locate|o(?:squitto|unt(?:[\s\x0b&\),<>\|]|$))|sg(?:attrib|c(?:at|onv)|filter|merge|uniq)|utt(?:[\s\x0b&\),<>\|]|$)|ysql(?:[\s\x0b&\),<>\|]|$|admin|dump(?:slow)?|hotcopy|show))|n(?:(?:a(?:no|sm|wk)|ice|map|o(?:de|hup)|ping|roff|ull)(?:[\s\x0b&\),<>\|]|$)|c(?:\.(?:openbsd|traditional)|at(?:[\s\x0b&\),<>\|]|$))|e(?:ofetch|t(?:(?:c|st)at|kit-ftp|plan))|s(?:enter|lookup|tat(?:[\s\x0b&\),<>\|]|$)))|o(?:ctave(?:[\s\x0b&\),<>\|]|$)|nintr|p(?:en(?:ssl|v(?:pn|t))|kg(?:[\s\x0b&\),<>\|]|$)))|p(?:a(?:(?:cman|rted|tch)(?:[\s\x0b&\),<>\|]|$)|s(?:swd|te(?:[\s\x0b&\),<>\|]|$)))|d(?:b(?:2mb|3(?:[\s\x0b&\),\.<>\|]|$))|f(?:la)?tex|ksh(?:[\s\x0b&\),<>\|]|$))|er(?:(?:f|ms)(?:[\s\x0b&\),<>\|]|$)|l(?:5?(?:[\s\x0b&\),<>\|]|$)|sh))|(?:(?:ft|gre)p|opd|u(?:ppet|shd))(?:[\s\x0b&\),<>\|]|$)|hp(?:-cgi|[57](?:[\s\x0b&\),<>\|]|$))|i(?:(?:co|gz|ng6?)(?:[\s\x0b&\),<>\|]|$)|dstat)|k(?:exec|g_?info|ill(?:[\s\x0b&\),<>\|]|$))|rint(?:env|f(?:[\s\x0b&\),<>\|]|$))|s(?:(?:ed|ql)(?:[\s\x0b&\),<>\|]|$)|ftp)|tar(?:[\s\x0b&\),<>\|]|$|diff|grep)|wd\.db|y(?:3?versions|thon(?:[23]|[^\s\x0b]{1,10}\b)))|r(?:(?:ak[eu]|bash|nano|oute|vi(?:ew|m))(?:[\s\x0b&\),<>\|]|$)|e(?:a(?:delf|lpath)|(?:(?:boo|dcarpe)t|name|p(?:eat|lace))(?:[\s\x0b&\),<>\|]|$)|stic)|l(?:ogin|wrap)|m(?:dir(?:[\s\x0b&\),<>\|]|$)|t-(?:dump|tar)|user)|pm(?:db(?:[\s\x0b&\),<>\|]|$)|(?:quer|verif)y)|sync(?:-ssl|[\s\x0b&\),<>\|]|$)|u(?:by[^\s\x0b]{1,10}\b|n(?:-(?:mailcap|parts)|c(?:[\s\x0b&\),<>\|]|$))))|s(?:(?:ash|c(?:hed|r(?:een|ipt))|diff|(?:ft|na)p|l(?:eep|sh))(?:[\s\x0b&\),<>\|]|$)|e(?:(?:ndmail|rvice)(?:[\s\x0b&\),<>\|]|$)|t(?:arch|cap|env|facl(?:[\s\x0b&\),<>\|]|$)|sid))|h(?:\.distrib|(?:adow|ells|u(?:f|tdown))(?:[\s\x0b&\),<>\|]|$))|mbclient|o(?:(?:ca|r)t(?:[\s\x0b&\),<>\|]|$)|elim)|p(?:lit(?:[\s\x0b&\),<>\|]|$)|wd\.db)|qlite3|sh(?:-(?:a(?:dd|gent)|copy-id|key(?:ge|sca)n)|pass)|t(?:art-stop-daemon|d(?:buf|err|in(?:[\s\x0b&\),<>\|]|$)|out)|r(?:ace|ings(?:[\s\x0b&\),<>\|]|$)))|udo(?:-rs|[\s\x0b&\),<>_\|]|$|edit|replay)|vn(?:a(?:dmin|uthz)|bench|dumpfilter|fsfs|look|mucc|rdump|s(?:erve|ync)|version)|ys(?:ctl|tem(?:ctl|d-resolve)))|t(?:a(?:il(?:[\s\x0b&\),<>\|]|$|f(?:[\s\x0b&\),<>\|]|$))|sk(?:[\s\x0b&\),<>\|]|$|set))|c(?:l?sh(?:[\s\x0b&\),<>\|]|$)|p(?:dump|ing|traceroute))|elnet|(?:ftp|mux|ouch)(?:[\s\x0b&\),<>\|]|$)|ime(?:datectl|out(?:[\s\x0b&\),<>\|]|$))|r(?:aceroute6?|off(?:[\s\x0b&\),<>\|]|$))|shark)|u(?:limit(?:[\s\x0b&\),<>\|]|$)|n(?:(?:ame|compress|iq|rar|s(?:et|hare)|xz)(?:[\s\x0b&\),<>\|]|$)|expand|l(?:ink(?:[\s\x0b&\),<>\|]|$)|z(?:4(?:[\s\x0b&\),<>\|]|$)|ma))|pigz|z(?:ip(?:[\s\x0b&\),<>\|]|$)|std))|p(?:2date(?:[\s\x0b&\),<>\|]|$)|date-alternatives)|ser(?:(?:ad|mo)d|del)|u(?:de|en)code)|v(?:algrind|i(?:(?:[ep]w|gr|rsh)(?:[\s\x0b&\),<>\|]|$)|mdiff|sudo(?:-rs)?)|olatility(?:[\s\x0b&\),<>\|]|$))|w(?:(?:all|get)(?:[\s\x0b&\),<>\|]|$)|h(?:iptail(?:[\s\x0b&\),<>\|]|$)|o(?:ami|is(?:[\s\x0b&\),<>\|]|$)))|i(?:reshark|sh(?:[\s\x0b&\),<>\|]|$)))|x(?:(?:args|pad|term)(?:[\s\x0b&\),<>\|]|$)|e(?:latex|tex(?:[\s\x0b&\),<>\|]|$))|mo(?:dmap|re(?:[\s\x0b&\),<>\|]|$))|z(?:c(?:at|mp)(?:[\s\x0b&\),<>\|]|$)|d(?:ec(?:[\s\x0b&\),<>\|]|$)|iff)|[ef]?grep|less|more))|z(?:athura|(?:c(?:at|mp)|diff|grep|less|run)(?:[\s\x0b&\),<>\|]|$)|e(?:grep|ro(?:[\s\x0b&\),<>\|]|$))|fgrep|ip(?:c(?:loak|mp)|details|grep|info|(?:merg|not)e|split|tool)|mo(?:dload|re(?:[\s\x0b&\),<>\|]|$))|s(?:oelim|td(?:[\s\x0b&\),<>\|]|$|(?:ca|m)t|grep|less))|ypper))
- **Is Chain**: False
- **Message**: Remote Command Execution: Unix Command Injection (command without evasion)
- **Severity**: CRITICAL
- **Tags**: application-multi, language-shell, platform-unix, attack-rce, paranoia-level/1, OWASP_CRS, OWASP_CRS/ATTACK-RCE, capec/1000/152/248/88
- **Actions**: id:932235, phase:2, block, capture, t:none, msg:Remote Command Execution: Unix Command Injection (command without evasion), logdata:Matched Data: %{TX.0} found within %{MATCHED_VAR_NAME}: %{MATCHED_VAR}, tag:application-multi, tag:language-shell, tag:platform-unix, tag:attack-rce, tag:paranoia-level/1, tag:OWASP_CRS, tag:OWASP_CRS/ATTACK-RCE, tag:capec/1000/152/248/88, ver:OWASP_CRS/4.22.0-dev, severity:CRITICAL, setvar:tx.rce_score=+%{tx.critical_anomaly_score}, setvar:tx.inbound_anomaly_score_pl1=+%{tx.critical_anomaly_score}

#### Rule 5: 932120
- **Phase**: 2
- **Variables**: REQUEST_COOKIES, REQUEST_COOKIES_NAMES, ARGS_NAMES, ARGS, XML:/*
- **Operator**: @pmFromFile
- **Pattern**: windows-powershell-commands.data
- **Is Chain**: False
- **Message**: Remote Command Execution: Windows PowerShell Command Found
- **Severity**: CRITICAL
- **Tags**: application-multi, language-shell, language-powershell, platform-windows, attack-rce, paranoia-level/1, OWASP_CRS, OWASP_CRS/ATTACK-RCE, capec/1000/152/248/88
- **Actions**: id:932120, phase:2, block, capture, t:none, t:cmdLine, msg:Remote Command Execution: Windows PowerShell Command Found, logdata:Matched Data: %{TX.0} found within %{MATCHED_VAR_NAME}: %{MATCHED_VAR}, tag:application-multi, tag:language-shell, tag:language-powershell, tag:platform-windows, tag:attack-rce, tag:paranoia-level/1, tag:OWASP_CRS, tag:OWASP_CRS/ATTACK-RCE, tag:capec/1000/152/248/88, ver:OWASP_CRS/4.22.0-dev, severity:CRITICAL, setvar:tx.rce_score=+%{tx.critical_anomaly_score}, setvar:tx.inbound_anomaly_score_pl1=+%{tx.critical_anomaly_score}

#### Rule 6: 932125
- **Phase**: 2
- **Variables**: REQUEST_COOKIES, REQUEST_COOKIES_NAMES, ARGS_NAMES, ARGS, XML:/*
- **Operator**: @rx
- **Pattern**: (?i)(?:[\n\r;`\{]|\|\|?|&&?)[\s\x0b]*[\s\x0b\"'\(,@]*(?:[\"'\.-9A-Z_a-z]+/|(?:[\"'\x5c\^]*[0-9A-Z_a-z][\"'\x5c\^]*:.*|[ \"'\.-9A-Z\x5c\^_a-z]*)\x5c)?[\"\^]*(?:(?:a[\"\^]*(?:c|s[\"\^]*n[\"\^]*p)|e[\"\^]*(?:b[\"\^]*p|p[\"\^]*(?:a[\"\^]*l|c[\"\^]*s[\"\^]*v|s[\"\^]*n)|[tx][\"\^]*s[\"\^]*n)|f[\"\^]*(?:[cltw]|o[\"\^]*r[\"\^]*e[\"\^]*a[\"\^]*c[\"\^]*h)|i[\"\^]*(?:[cr][\"\^]*m|e[\"\^]*x|h[\"\^]*y|i|p[\"\^]*(?:a[\"\^]*l|c[\"\^]*s[\"\^]*v|m[\"\^]*o|s[\"\^]*n)|s[\"\^]*e|w[\"\^]*(?:m[\"\^]*i|r))|m[\"\^]*(?:[dpv]|o[\"\^]*u[\"\^]*n[\"\^]*t)|o[\"\^]*g[\"\^]*v|p[\"\^]*(?:o[\"\^]*p|u[\"\^]*s[\"\^]*h)[\"\^]*d|t[\"\^]*r[\"\^]*c[\"\^]*m|w[\"\^]*j[\"\^]*b)[\"\^]*[\s\x0b,\./;<>].*|c[\"\^]*(?:(?:(?:d|h[\"\^]*d[\"\^]*i[\"\^]*r|v[\"\^]*p[\"\^]*a)[\"\^]*|p[\"\^]*(?:[ip][\"\^]*)?)[\s\x0b,\./;<>].*|l[\"\^]*(?:(?:[cipv]|h[\"\^]*y)[\"\^]*[\s\x0b,\./;<>].*|s)|n[\"\^]*s[\"\^]*n)|d[\"\^]*(?:(?:b[\"\^]*p|e[\"\^]*l|i[\"\^]*(?:f[\"\^]*f|r))[\"\^]*[\s\x0b,\./;<>].*|n[\"\^]*s[\"\^]*n)|g[\"\^]*(?:(?:(?:(?:a[\"\^]*)?l|b[\"\^]*p|d[\"\^]*r|h[\"\^]*y|(?:w[\"\^]*m[\"\^]*)?i|j[\"\^]*b|[uv])[\"\^]*|c[\"\^]*(?:[ims][\"\^]*)?|m[\"\^]*(?:o[\"\^]*)?|s[\"\^]*(?:n[\"\^]*(?:p[\"\^]*)?|v[\"\^]*))[\s\x0b,\./;<>].*|e[\"\^]*r[\"\^]*r|p[\"\^]*(?:(?:s[\"\^]*)?[\s\x0b,\./;<>].*|v))|l[\"\^]*s|n[\"\^]*(?:(?:a[\"\^]*l|d[\"\^]*r|[iv]|m[\"\^]*o|s[\"\^]*n)[\"\^]*[\s\x0b,\./;<>].*|p[\"\^]*s[\"\^]*s[\"\^]*c)|r[\"\^]*(?:(?:(?:(?:b[\"\^]*)?p|e[\"\^]*n|(?:w[\"\^]*m[\"\^]*)?i|j[\"\^]*b|n[\"\^]*[ip])[\"\^]*|d[\"\^]*(?:r[\"\^]*)?|m[\"\^]*(?:(?:d[\"\^]*i[\"\^]*r|o)[\"\^]*)?|s[\"\^]*n[\"\^]*(?:p[\"\^]*)?|v[\"\^]*(?:p[\"\^]*a[\"\^]*)?)[\s\x0b,\./;<>].*|c[\"\^]*(?:j[\"\^]*b[\"\^]*[\s\x0b,\./;<>].*|s[\"\^]*n)|u[\"\^]*j[\"\^]*b)|s[\"\^]*(?:(?:(?:a[\"\^]*(?:j[\"\^]*b|l|p[\"\^]*s|s[\"\^]*v)|b[\"\^]*p|[cv]|w[\"\^]*m[\"\^]*i)[\"\^]*|l[\"\^]*(?:s[\"\^]*)?|p[\"\^]*(?:(?:j[\"\^]*b|p[\"\^]*s|s[\"\^]*v)[\"\^]*)?)[\s\x0b,\./;<>].*|h[\"\^]*c[\"\^]*m|u[\"\^]*j[\"\^]*b))(?:\.[\"\^]*[0-9A-Z_a-z]+)?\b
- **Is Chain**: False
- **Message**: Remote Command Execution: Windows Powershell Alias Command Injection
- **Severity**: CRITICAL
- **Tags**: application-multi, language-shell, platform-windows, attack-rce, paranoia-level/1, OWASP_CRS, OWASP_CRS/ATTACK-RCE, capec/1000/152/248/88
- **Actions**: id:932125, phase:2, block, capture, t:none, msg:Remote Command Execution: Windows Powershell Alias Command Injection, logdata:Matched Data: %{TX.0} found within %{MATCHED_VAR_NAME}: %{MATCHED_VAR}, tag:application-multi, tag:language-shell, tag:platform-windows, tag:attack-rce, tag:paranoia-level/1, tag:OWASP_CRS, tag:OWASP_CRS/ATTACK-RCE, tag:capec/1000/152/248/88, ver:OWASP_CRS/4.22.0-dev, severity:CRITICAL, setvar:tx.rce_score=+%{tx.critical_anomaly_score}, setvar:tx.inbound_anomaly_score_pl1=+%{tx.critical_anomaly_score}

#### Rule 7: 932130
- **Phase**: 2
- **Variables**: REQUEST_COOKIES, REQUEST_COOKIES_NAMES, ARGS_NAMES, ARGS, XML:/*
- **Operator**: @rx
- **Pattern**: \$(?:\((?:.*|\(.*\))\)|\{.*\}|\[.*\])|[<>]\(.*\)|/[0-9A-Z_a-z]*\[!?.+\]
- **Is Chain**: False
- **Message**: Remote Command Execution: Unix Shell Expression Found
- **Severity**: CRITICAL
- **Tags**: application-multi, language-shell, platform-unix, attack-rce, paranoia-level/1, OWASP_CRS, OWASP_CRS/ATTACK-RCE, capec/1000/152/248/88
- **Actions**: id:932130, phase:2, block, capture, t:none, t:cmdLine, msg:Remote Command Execution: Unix Shell Expression Found, logdata:Matched Data: %{TX.0} found within %{MATCHED_VAR_NAME}: %{MATCHED_VAR}, tag:application-multi, tag:language-shell, tag:platform-unix, tag:attack-rce, tag:paranoia-level/1, tag:OWASP_CRS, tag:OWASP_CRS/ATTACK-RCE, tag:capec/1000/152/248/88, ver:OWASP_CRS/4.22.0-dev, severity:CRITICAL, setvar:tx.rce_score=+%{tx.critical_anomaly_score}, setvar:tx.inbound_anomaly_score_pl1=+%{tx.critical_anomaly_score}

#### Rule 8: 932140
- **Phase**: 2
- **Variables**: REQUEST_COOKIES, REQUEST_COOKIES_NAMES, ARGS_NAMES, ARGS, XML:/*
- **Operator**: @rx
- **Pattern**: \b(?:for(?:/[dflr].*)? %+[^ ]+ in\(.*\)[\s\x0b]?do|if(?:/i)?(?: not)?(?: (?:e(?:xist|rrorlevel)|defined|cmdextversion)\b|[ \(].*(?:\b(?:g(?:eq|tr)|equ|neq|l(?:eq|ss))\b|==)))
- **Is Chain**: False
- **Message**: Remote Command Execution: Windows FOR/IF Command Found
- **Severity**: CRITICAL
- **Tags**: application-multi, language-shell, platform-windows, attack-rce, paranoia-level/1, OWASP_CRS, OWASP_CRS/ATTACK-RCE, capec/1000/152/248/88
- **Actions**: id:932140, phase:2, block, capture, t:none, t:cmdLine, msg:Remote Command Execution: Windows FOR/IF Command Found, logdata:Matched Data: %{TX.0} found within %{MATCHED_VAR_NAME}: %{MATCHED_VAR}, tag:application-multi, tag:language-shell, tag:platform-windows, tag:attack-rce, tag:paranoia-level/1, tag:OWASP_CRS, tag:OWASP_CRS/ATTACK-RCE, tag:capec/1000/152/248/88, ver:OWASP_CRS/4.22.0-dev, severity:CRITICAL, setvar:tx.rce_score=+%{tx.critical_anomaly_score}, setvar:tx.inbound_anomaly_score_pl1=+%{tx.critical_anomaly_score}

#### Rule 9: 932270
- **Phase**: 2
- **Variables**: REQUEST_COOKIES, REQUEST_COOKIES_NAMES, ARGS_NAMES, ARGS, XML:/*
- **Operator**: @rx
- **Pattern**: ~[\+\-](?:$|[0-9]+)
- **Is Chain**: False
- **Message**: Remote Command Execution: Unix Shell Expression Found
- **Severity**: CRITICAL
- **Tags**: application-multi, language-shell, platform-unix, attack-rce, paranoia-level/1, OWASP_CRS, OWASP_CRS/ATTACK-RCE, capec/1000/152/248/88
- **Actions**: id:932270, phase:2, block, capture, t:none, t:cmdLine, msg:Remote Command Execution: Unix Shell Expression Found, logdata:Matched Data: %{TX.0} found within %{MATCHED_VAR_NAME}: %{MATCHED_VAR}, tag:application-multi, tag:language-shell, tag:platform-unix, tag:attack-rce, tag:paranoia-level/1, tag:OWASP_CRS, tag:OWASP_CRS/ATTACK-RCE, tag:capec/1000/152/248/88, ver:OWASP_CRS/4.22.0-dev, severity:CRITICAL, setvar:tx.rce_score=+%{tx.critical_anomaly_score}, setvar:tx.inbound_anomaly_score_pl1=+%{tx.critical_anomaly_score}

#### Rule 10: 932280
- **Phase**: 2
- **Variables**: REQUEST_COOKIES, REQUEST_COOKIES_NAMES, ARGS_NAMES, ARGS, XML:/*
- **Operator**: @rx
- **Pattern**: \{[0-9A-Z_a-z]*,[,\-0-9A-Z_a-z]*\}
- **Is Chain**: False
- **Message**: Remote Command Execution: Brace Expansion Found
- **Severity**: CRITICAL
- **Tags**: application-multi, language-shell, platform-unix, attack-rce, paranoia-level/1, OWASP_CRS, OWASP_CRS/ATTACK-RCE, capec/1000/152/248/88
- **Actions**: id:932280, phase:2, block, capture, t:none, msg:Remote Command Execution: Brace Expansion Found, logdata:Matched Data: %{TX.0} found within %{MATCHED_VAR_NAME}: %{MATCHED_VAR}, tag:application-multi, tag:language-shell, tag:platform-unix, tag:attack-rce, tag:paranoia-level/1, tag:OWASP_CRS, tag:OWASP_CRS/ATTACK-RCE, tag:capec/1000/152/248/88, ver:OWASP_CRS/4.22.0-dev, severity:CRITICAL, setvar:tx.rce_score=+%{tx.critical_anomaly_score}, setvar:tx.inbound_anomaly_score_pl1=+%{tx.critical_anomaly_score}

#### Rule 11: 932250
- **Phase**: 2
- **Variables**: REQUEST_COOKIES, REQUEST_COOKIES_NAMES, ARGS_NAMES, ARGS, XML:/*
- **Operator**: @rx
- **Pattern**: (?i)(?:^|b[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?u[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?s[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?y[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?b[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?o[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?x|(?:c[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?o[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?m[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?m[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?a[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?n[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?d|e[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?(?:n[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?v|v[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?a[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?l)|w[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?a[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?t[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?c[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?h)[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?(?:[\s\x0b&\),<>\|]|$).*|[ls][\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?t[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?r[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?a[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?c[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?e|n[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?o[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?h[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?u[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?p|t[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?i[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?m[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?e[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?(?:(?:[\s\x0b&\),<>\|]|$).*|o[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?u[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?t)|[\n\r;=`\{]|\|\|?|&&?|\$(?:\(\(?|[\[\{])|<(?:\(|<<)|>\(|\([\s\x0b]*\))[\s\x0b]*(?:[\$\{]|(?:[\s\x0b]*\(|!)[\s\x0b]*|[0-9A-Z_a-z]+=(?:[^\s\x0b]*|\$(?:.*|.*)|[<>].*|'[^']*'|\"[^\"]*\")[\s\x0b]+)*[\s\x0b]*[\"']*(?:[\"'-\+\--9\?A-\]_a-z\|]+/)?[\"'\x5c]*(?:(?:7[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?z[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?(?:[arx][\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?)?|(?:b[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?z[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?z|c[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?(?:[89][\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?9|m[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?p|s[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?h)|d[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?(?:n[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?)?f|e[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?(?:n[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?v|q[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?n|s[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?h)|f[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?(?:[dg]|m[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?t)|(?:h[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?u|u[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?d)[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?p|i[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?r[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?b|j[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?(?:j[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?s|q)|[kz][\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?s[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?h|m[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?t[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?r|p[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?(?:d[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?b|k[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?g|t[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?x|x[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?z)|r[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?(?:c[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?p|m[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?t)|s[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?(?:c[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?p|e[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?d|(?:s[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?)?h|v[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?n)|t[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?(?:a[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?c|b[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?l)|w[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?(?:3[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?m|c)|x[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?(?:x[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?d|z)|y[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?u[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?m)[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?|l[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?(?:s[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?|z[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?(?:4[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?)?))(?:[\s\x0b&\),<>\|]|$).*|a[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?(?:a[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?-[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?(?:(?:[&\),<>\|]|$){1,10}|(?:[\-\.0-9A-Z_a-z][\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?){1,10}(?:[\s\x0b&\),<>\|\}]|$){1,10})|r[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?j[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?(?:[\s\x0b&\),<>\|]|$).*)|g[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?(?:c[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?c[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?(?:(?:[&\),<>\|]|$){1,10}|(?:[\-\.0-9A-Z_a-z][\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?){1,10}(?:[\s\x0b&\),<>\|\}]|$){1,10})|(?:d[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?b|[hr][\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?c|p[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?g)[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?(?:[\s\x0b&\),<>\|]|$).*))
- **Is Chain**: False
- **Message**: Remote Command Execution: Direct Unix Command Execution
- **Severity**: CRITICAL
- **Tags**: application-multi, language-shell, platform-unix, attack-rce, paranoia-level/1, OWASP_CRS, OWASP_CRS/ATTACK-RCE, capec/1000/152/248/88
- **Actions**: id:932250, phase:2, block, capture, t:none, msg:Remote Command Execution: Direct Unix Command Execution, logdata:Matched Data: %{TX.0} found within %{MATCHED_VAR_NAME}: %{MATCHED_VAR}, tag:application-multi, tag:language-shell, tag:platform-unix, tag:attack-rce, tag:paranoia-level/1, tag:OWASP_CRS, tag:OWASP_CRS/ATTACK-RCE, tag:capec/1000/152/248/88, ver:OWASP_CRS/4.22.0-dev, severity:CRITICAL, setvar:tx.rce_score=+%{tx.critical_anomaly_score}, setvar:tx.inbound_anomaly_score_pl1=+%{tx.critical_anomaly_score}

#### Rule 12: 932260
- **Phase**: 2
- **Variables**: REQUEST_COOKIES, REQUEST_COOKIES_NAMES, ARGS_NAMES, ARGS, XML:/*
- **Operator**: @rx
- **Pattern**: (?i)(?:^|b[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?u[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?s[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?y[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?b[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?o[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?x|(?:c[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?o[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?m[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?m[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?a[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?n[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?d|e[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?(?:n[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?v|v[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?a[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?l)|w[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?a[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?t[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?c[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?h)[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?(?:[\s\x0b&\),<>\|]|$).*|[ls][\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?t[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?r[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?a[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?c[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?e|n[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?o[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?h[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?u[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?p|t[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?i[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?m[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?e[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?(?:(?:[\s\x0b&\),<>\|]|$).*|o[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?u[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?t)|[\n\r;=`\{]|\|\|?|&&?|\$(?:\(\(?|[\[\{])|<(?:\(|<<)|>\(|\([\s\x0b]*\))[\s\x0b]*(?:[\$\{]|(?:[\s\x0b]*\(|!)[\s\x0b]*|[0-9A-Z_a-z]+=(?:[^\s\x0b]*|\$(?:.*|.*)|[<>].*|'[^']*'|\"[^\"]*\")[\s\x0b]+)*[\s\x0b]*[\"']*(?:[\"'-\+\--9\?A-\]_a-z\|]+/)?[\"'\x5c]*(?:a(?:ddgroup|nsible|pparmor_[^\s\x0b]{1,10}\b|rj(?:-register|disp)|tobm(?:[\s\x0b&\),<>\|]|$)|u(?:ditctl|repot|search))|b(?:ase(?:32|64|nc)|(?:lkid|rwap|yobu)(?:[\s\x0b&\),<>\|]|$)|sd(?:cat|iff|tar)|u(?:iltin|nzip2|sybox)|z(?:c(?:at|mp)(?:[\s\x0b&\),<>\|]|$)|diff|e(?:grep|xe(?:[\s\x0b&\),<>\|]|$))|f?grep|ip2(?:[\s\x0b&\),<>\|]|$|recover)|less|more))|c(?:[89]9-gcc|h(?:(?:attr|mod|o(?:om|wn)|sh)(?:[\s\x0b&\),<>\|]|$)|ef-|g(?:passwd|rp(?:[\s\x0b&\),<>\|]|$))|pass)|lang\+\+|o(?:bc(?:[\s\x0b&\),<>\|]|$|run)|mm(?:[\s\x0b&\),<>\|]|$)|proc)|(?:p(?:an|io)|scli)(?:[\s\x0b&\),<>\|]|$))|d(?:(?:iff|mesg|vips)(?:[\s\x0b&\),<>\|]|$)|o(?:as(?:[\s\x0b&\),<>\|]|$)|cker-)|pkg(?:[\s\x0b&\),\-<>\|]|$))|e(?:2fsck|(?:fax|grep|macs|nd(?:if|sw)|sac|xpr)(?:[\s\x0b&\),<>\|]|$))|f(?:d(?:(?:find|isk)(?:[\s\x0b&\),<>\|]|$)|u?mount)|grep(?:[\s\x0b&\),<>\|]|$)|iletest|ping(?:[\s\x0b&\),6<>\|]|$)|tp(?:stats|who))|g(?:(?:core|insh|z(?:cat|exe|ip))(?:[\s\x0b&\),<>\|]|$)|(?:etca|unzi)p|hc(?:-(?:[\s\x0b&\),<>\|]|$)|i(?:[\s\x0b&\),\-<>\|]|$))|r(?:(?:cat|ep)(?:[\s\x0b&\),<>\|]|$)|oupmod))|(?:htop|jexec)(?:[\s\x0b&\),<>\|]|$)|i(?:(?:conv|ftop)(?:[\s\x0b&\),<>\|]|$)|pp(?:eveprinter|find|tool))|l(?:ast(?:comm(?:[\s\x0b&\),<>\|]|$)|log(?:in)?)|ess(?:echo|(?:fil|pip)e)|ftp(?:[\s\x0b&\),<>\|]|$|get)|osetup|s(?:(?:-F|cpu|hw|mod|of|pci|usb)(?:[\s\x0b&\),<>\|]|$)|b_release)|wp-download|z(?:4c(?:[\s\x0b&\),<>\|]|$|at)|c(?:at|mp)(?:[\s\x0b&\),<>\|]|$)|diff|[ef]?grep|less|m(?:a(?:[\s\x0b&\),<>\|]|$|dec|info)|ore)))|m(?:a(?:(?:ilq|wk)(?:[\s\x0b&\),<>\|]|$)|ster\.passwd)|k(?:fifo|nod(?:[\s\x0b&\),<>\|]|$)|temp)|locate|ysql(?:[\s\x0b&\),<>\|]|$|admin|dump(?:slow)?|hotcopy|show))|n(?:(?:a(?:sm|wk)|(?:ma|ohu)p|ping|roff|stat)(?:[\s\x0b&\),<>\|]|$)|c(?:\.(?:openbsd|traditional)|at(?:[\s\x0b&\),<>\|]|$))|et(?:(?:c|st)at|kit-ftp|plan))|o(?:nintr|pkg(?:[\s\x0b&\),<>\|]|$))|p(?:d(?:b(?:2mb|3(?:[\s\x0b&\),\.<>\|]|$))|ksh(?:[\s\x0b&\),<>\|]|$))|(?:er(?:f|l5?)|(?:ft|gre)p|i(?:gz|ng6)|(?:op|ush)d|s(?:ed|ql))(?:[\s\x0b&\),<>\|]|$)|hp(?:-cgi|[57](?:[\s\x0b&\),<>\|]|$))|k(?:exec|ill(?:[\s\x0b&\),<>\|]|$))|rint(?:env|f(?:[\s\x0b&\),<>\|]|$))|tar(?:[\s\x0b&\),<>\|]|$|diff|grep)|wd\.db|y(?:3?versions|thon[23]))|r(?:(?:aku|bash|nano|pmdb|unc|vi(?:ew|m))(?:[\s\x0b&\),<>\|]|$)|e(?:alpath|boot(?:[\s\x0b&\),<>\|]|$))|m(?:dir(?:[\s\x0b&\),<>\|]|$)|t-(?:dump|tar)|user)|sync(?:-ssl|[\s\x0b&\),<>\|]|$))|s(?:(?:diff|ftp|lsh|ocat)(?:[\s\x0b&\),<>\|]|$)|e(?:ndmail(?:[\s\x0b&\),<>\|]|$)|t(?:cap|env|sid))|h(?:\.distrib|uf(?:[\s\x0b&\),<>\|]|$))|pwd\.db|sh-(?:a(?:dd|gent)|copy-id)|td(?:err|in(?:[\s\x0b&\),<>\|]|$)|out)|udo(?:-rs|[\s\x0b&\),<>_\|]|$|edit|replay)|vn(?:a(?:dmin|uthz)|bench|dumpfilter|fsfs|look|mucc|rdump|s(?:erve|ync)|version)|ysctl)|t(?:(?:ailf|ftp|mux)(?:[\s\x0b&\),<>\|]|$)|c(?:l?sh(?:[\s\x0b&\),<>\|]|$)|p(?:ing|traceroute))|elnet|r(?:aceroute6?|off(?:[\s\x0b&\),<>\|]|$)))|u(?:n(?:(?:iq|rar|xz)(?:[\s\x0b&\),<>\|]|$)|lz(?:4(?:[\s\x0b&\),<>\|]|$)|ma)|pigz|zstd)|ser(?:(?:ad|mo)d|del))|vi(?:(?:gr|pw|rsh)(?:[\s\x0b&\),<>\|]|$)|sudo(?:-rs)?)|w(?:get(?:[\s\x0b&\),<>\|]|$)|hoami)|x(?:(?:args|etex|more|pad|term)(?:[\s\x0b&\),<>\|]|$)|z(?:c(?:at|mp)(?:[\s\x0b&\),<>\|]|$)|d(?:ec(?:[\s\x0b&\),<>\|]|$)|iff)|[ef]?grep|less|more))|z(?:(?:c(?:at|mp)|diff|grep|less|run)(?:[\s\x0b&\),<>\|]|$)|[ef]grep|ip(?:c(?:loak|mp)|details|grep|info|(?:merg|not)e|split|tool)|mo(?:dload|re(?:[\s\x0b&\),<>\|]|$))|std(?:[\s\x0b&\),<>\|]|$|(?:ca|m)t|grep|less)))
- **Is Chain**: False
- **Message**: Remote Command Execution: Direct Unix Command Execution
- **Severity**: CRITICAL
- **Tags**: application-multi, language-shell, platform-unix, attack-rce, paranoia-level/1, OWASP_CRS, OWASP_CRS/ATTACK-RCE, capec/1000/152/248/88
- **Actions**: id:932260, phase:2, block, capture, t:none, msg:Remote Command Execution: Direct Unix Command Execution, logdata:Matched Data: %{TX.0} found within %{MATCHED_VAR_NAME}: %{MATCHED_VAR}, tag:application-multi, tag:language-shell, tag:platform-unix, tag:attack-rce, tag:paranoia-level/1, tag:OWASP_CRS, tag:OWASP_CRS/ATTACK-RCE, tag:capec/1000/152/248/88, ver:OWASP_CRS/4.22.0-dev, severity:CRITICAL, setvar:tx.rce_score=+%{tx.critical_anomaly_score}, setvar:tx.inbound_anomaly_score_pl1=+%{tx.critical_anomaly_score}

#### Rule 13: 932330
- **Phase**: 2
- **Variables**: REQUEST_COOKIES, REQUEST_COOKIES_NAMES, ARGS_NAMES, ARGS, XML:/*
- **Operator**: @rx
- **Pattern**: !-\d
- **Is Chain**: False
- **Message**: Remote Command Execution: Unix shell history invocation
- **Severity**: CRITICAL
- **Tags**: application-multi, language-shell, platform-unix, attack-rce, paranoia-level/1, OWASP_CRS, OWASP_CRS/ATTACK-RCE, capec/1000/152/248/88
- **Actions**: id:932330, phase:2, block, capture, t:none, msg:Remote Command Execution: Unix shell history invocation, logdata:Matched Data: %{TX.0} found within %{MATCHED_VAR_NAME}: %{MATCHED_VAR}, tag:application-multi, tag:language-shell, tag:platform-unix, tag:attack-rce, tag:paranoia-level/1, tag:OWASP_CRS, tag:OWASP_CRS/ATTACK-RCE, tag:capec/1000/152/248/88, ver:OWASP_CRS/4.22.0-dev, severity:CRITICAL, setvar:tx.rce_score=+%{tx.critical_anomaly_score}, setvar:tx.inbound_anomaly_score_pl1=+%{tx.critical_anomaly_score}

#### Rule 14: 932160
- **Phase**: 2
- **Variables**: REQUEST_COOKIES, REQUEST_COOKIES_NAMES, ARGS_NAMES, ARGS, XML:/*
- **Operator**: @pmFromFile
- **Pattern**: unix-shell.data
- **Is Chain**: False
- **Message**: Remote Command Execution: Unix Shell Code Found
- **Severity**: CRITICAL
- **Tags**: application-multi, language-shell, platform-unix, attack-rce, paranoia-level/1, OWASP_CRS, OWASP_CRS/ATTACK-RCE, capec/1000/152/248/88
- **Actions**: id:932160, phase:2, block, capture, t:none, t:cmdLine, t:normalizePath, msg:Remote Command Execution: Unix Shell Code Found, logdata:Matched Data: %{TX.0} found within %{MATCHED_VAR_NAME}: %{MATCHED_VAR}, tag:application-multi, tag:language-shell, tag:platform-unix, tag:attack-rce, tag:paranoia-level/1, tag:OWASP_CRS, tag:OWASP_CRS/ATTACK-RCE, tag:capec/1000/152/248/88, ver:OWASP_CRS/4.22.0-dev, severity:CRITICAL, setvar:tx.rce_score=+%{tx.critical_anomaly_score}, setvar:tx.inbound_anomaly_score_pl1=+%{tx.critical_anomaly_score}

#### Rule 15: 932170
- **Phase**: 1
- **Variables**: REQUEST_HEADERS, REQUEST_LINE
- **Operator**: @rx
- **Pattern**: ^\(\s*\)\s+{
- **Is Chain**: False
- **Message**: Remote Command Execution: Shellshock (CVE-2014-6271)
- **Severity**: CRITICAL
- **Tags**: application-multi, language-shell, platform-unix, attack-rce, paranoia-level/1, OWASP_CRS, OWASP_CRS/ATTACK-RCE, capec/1000/152/248/88
- **Actions**: id:932170, phase:1, block, capture, t:none, t:urlDecodeUni, msg:Remote Command Execution: Shellshock (CVE-2014-6271), logdata:Matched Data: %{TX.0} found within %{MATCHED_VAR_NAME}: %{MATCHED_VAR}, tag:application-multi, tag:language-shell, tag:platform-unix, tag:attack-rce, tag:paranoia-level/1, tag:OWASP_CRS, tag:OWASP_CRS/ATTACK-RCE, tag:capec/1000/152/248/88, ver:OWASP_CRS/4.22.0-dev, severity:CRITICAL, setvar:tx.rce_score=+%{tx.critical_anomaly_score}, setvar:tx.inbound_anomaly_score_pl1=+%{tx.critical_anomaly_score}

#### Rule 16: 932171
- **Phase**: 2
- **Variables**: ARGS_NAMES, ARGS, FILES_NAMES
- **Operator**: @rx
- **Pattern**: ^\(\s*\)\s+{
- **Is Chain**: False
- **Message**: Remote Command Execution: Shellshock (CVE-2014-6271)
- **Severity**: CRITICAL
- **Tags**: application-multi, language-shell, platform-unix, attack-rce, paranoia-level/1, OWASP_CRS, OWASP_CRS/ATTACK-RCE, capec/1000/152/248/88
- **Actions**: id:932171, phase:2, block, capture, t:none, t:urlDecodeUni, msg:Remote Command Execution: Shellshock (CVE-2014-6271), logdata:Matched Data: %{TX.0} found within %{MATCHED_VAR_NAME}: %{MATCHED_VAR}, tag:application-multi, tag:language-shell, tag:platform-unix, tag:attack-rce, tag:paranoia-level/1, tag:OWASP_CRS, tag:OWASP_CRS/ATTACK-RCE, tag:capec/1000/152/248/88, ver:OWASP_CRS/4.22.0-dev, severity:CRITICAL, setvar:tx.rce_score=+%{tx.critical_anomaly_score}, setvar:tx.inbound_anomaly_score_pl1=+%{tx.critical_anomaly_score}

#### Rule 17: 932175
- **Phase**: 2
- **Variables**: REQUEST_COOKIES, REQUEST_COOKIES_NAMES, ARGS_NAMES, ARGS, XML:/*
- **Operator**: @rx
- **Pattern**: \ba[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?l[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?i[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?a[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?s\b[\s\x0b]+(?:[\+\-][a-z]+\+?[\s\x0b]+)?[!\"%',-\.0-9@-Z_a-z]+=[^\s\x0b]
- **Is Chain**: False
- **Message**: Remote Command Execution: Unix shell alias invocation
- **Severity**: CRITICAL
- **Tags**: application-multi, language-shell, platform-unix, attack-rce, paranoia-level/1, OWASP_CRS, OWASP_CRS/ATTACK-RCE, capec/1000/152/248/88
- **Actions**: id:932175, phase:2, block, capture, t:none, msg:Remote Command Execution: Unix shell alias invocation, logdata:Matched Data: %{TX.0} found within %{MATCHED_VAR_NAME}: %{MATCHED_VAR}, tag:application-multi, tag:language-shell, tag:platform-unix, tag:attack-rce, tag:paranoia-level/1, tag:OWASP_CRS, tag:OWASP_CRS/ATTACK-RCE, tag:capec/1000/152/248/88, ver:OWASP_CRS/4.22.0-dev, severity:CRITICAL, setvar:tx.rce_score=+%{tx.critical_anomaly_score}, setvar:tx.inbound_anomaly_score_pl1=+%{tx.critical_anomaly_score}

#### Rule 18: 932180
- **Phase**: 2
- **Variables**: FILES, REQUEST_HEADERS:X-Filename, REQUEST_HEADERS:X_Filename, REQUEST_HEADERS:X-File-Name
- **Operator**: @pmFromFile
- **Pattern**: restricted-upload.data
- **Is Chain**: True
- **Message**: Restricted File Upload Attempt
- **Severity**: CRITICAL
- **Tags**: application-multi, language-multi, platform-multi, attack-rce, paranoia-level/1, OWASP_CRS, OWASP_CRS/ATTACK-RCE, capec/1000/152/248/88
- **Actions**: id:932180, phase:2, block, capture, t:none, msg:Restricted File Upload Attempt, logdata:Matched Data: %{TX.0} found within %{MATCHED_VAR_NAME}: %{MATCHED_VAR}, tag:application-multi, tag:language-multi, tag:platform-multi, tag:attack-rce, tag:paranoia-level/1, tag:OWASP_CRS, tag:OWASP_CRS/ATTACK-RCE, tag:capec/1000/152/248/88, ver:OWASP_CRS/4.22.0-dev, severity:CRITICAL, chain

#### Rule 19: Unknown
- **Phase**: Unknown
- **Variables**: MATCHED_VARS
- **Operator**: !@rx
- **Pattern**: (?i)(?:\.boto|buddyinfo|mtrr|acpi|zoneinfo)\B
- **Is Chain**: False
- **Message**: 
- **Severity**: 
- **Actions**: t:none, setvar:tx.rce_score=+%{tx.critical_anomaly_score}, setvar:tx.inbound_anomaly_score_pl1=+%{tx.critical_anomaly_score}

#### Rule 20: 932370
- **Phase**: 2
- **Variables**: REQUEST_COOKIES, REQUEST_COOKIES_NAMES, ARGS_NAMES, ARGS, XML:/*
- **Operator**: @rx
- **Pattern**: (?i)(?:[\n\r;`\{]|\|\|?|&&?)[\s\x0b]*[\s\x0b\"'\(,@]*(?:[\"'\.-9A-Z_a-z]+/|(?:[\"'\x5c\^]*[0-9A-Z_a-z][\"'\x5c\^]*:[^\x5c]*|[ \"'\.-9A-Z\x5c\^_a-z]*)\x5c)?[\"\^]*(?:a[\"\^]*(?:c[\"\^]*c[\"\^]*c[\"\^]*h[\"\^]*e[\"\^]*c[\"\^]*k[\"\^]*c[\"\^]*o[\"\^]*n[\"\^]*s[\"\^]*o[\"\^]*l[\"\^]*e|d[\"\^]*(?:p[\"\^]*l[\"\^]*u[\"\^]*s|v[\"\^]*p[\"\^]*a[\"\^]*c[\"\^]*k)|(?:g[\"\^]*e[\"\^]*n[\"\^]*t[\"\^]*e[\"\^]*x[\"\^]*e[\"\^]*c[\"\^]*u[\"\^]*t[\"\^]*o|(?:s[\"\^]*p[\"\^]*n[\"\^]*e[\"\^]*t[\"\^]*_[\"\^]*c[\"\^]*o[\"\^]*m[\"\^]*p[\"\^]*i[\"\^]*l|t[\"\^]*b[\"\^]*r[\"\^]*o[\"\^]*k)[\"\^]*e)[\"\^]*r|p[\"\^]*p[\"\^]*(?:i[\"\^]*n[\"\^]*s[\"\^]*t[\"\^]*a[\"\^]*l[\"\^]*l[\"\^]*e[\"\^]*r|v[\"\^]*l[\"\^]*p))|b[\"\^]*(?:a[\"\^]*s[\"\^]*h|g[\"\^]*i[\"\^]*n[\"\^]*f[\"\^]*o|i[\"\^]*t[\"\^]*s[\"\^]*a[\"\^]*d[\"\^]*m[\"\^]*i[\"\^]*n)|c[\"\^]*(?:d[\"\^]*b|e[\"\^]*r[\"\^]*t[\"\^]*(?:o[\"\^]*c|r[\"\^]*e[\"\^]*q|u[\"\^]*t[\"\^]*i[\"\^]*l)|l[\"\^]*_[\"\^]*(?:i[\"\^]*n[\"\^]*v[\"\^]*o[\"\^]*c[\"\^]*a[\"\^]*t[\"\^]*i[\"\^]*o[\"\^]*n|l[\"\^]*o[\"\^]*a[\"\^]*d[\"\^]*a[\"\^]*s[\"\^]*s[\"\^]*e[\"\^]*m[\"\^]*b[\"\^]*l[\"\^]*y|m[\"\^]*u[\"\^]*t[\"\^]*e[\"\^]*x[\"\^]*v[\"\^]*e[\"\^]*r[\"\^]*i[\"\^]*f[\"\^]*i[\"\^]*e[\"\^]*r[\"\^]*s)|m[\"\^]*(?:d(?:[\"\^]*(?:k[\"\^]*e[\"\^]*y|l[\"\^]*3[\"\^]*2))?|s[\"\^]*t[\"\^]*p)|o[\"\^]*(?:m[\"\^]*s[\"\^]*v[\"\^]*c[\"\^]*s|n[\"\^]*(?:f[\"\^]*i[\"\^]*g[\"\^]*s[\"\^]*e[\"\^]*c[\"\^]*u[\"\^]*r[\"\^]*i[\"\^]*t[\"\^]*y[\"\^]*p[\"\^]*o[\"\^]*l[\"\^]*i[\"\^]*c[\"\^]*y|h[\"\^]*o[\"\^]*s[\"\^]*t|t[\"\^]*r[\"\^]*o[\"\^]*l)|r[\"\^]*e[\"\^]*g[\"\^]*e[\"\^]*n)|r[\"\^]*e[\"\^]*a[\"\^]*t[\"\^]*e[\"\^]*d[\"\^]*u[\"\^]*m[\"\^]*p|s[\"\^]*(?:c(?:[\"\^]*r[\"\^]*i[\"\^]*p[\"\^]*t)?|i)|u[\"\^]*s[\"\^]*t[\"\^]*o[\"\^]*m[\"\^]*s[\"\^]*h[\"\^]*e[\"\^]*l[\"\^]*l[\"\^]*h[\"\^]*o[\"\^]*s[\"\^]*t)|d[\"\^]*(?:a[\"\^]*t[\"\^]*a[\"\^]*s[\"\^]*v[\"\^]*c[\"\^]*u[\"\^]*t[\"\^]*i[\"\^]*l|e[\"\^]*(?:f[\"\^]*a[\"\^]*u[\"\^]*l[\"\^]*t[\"\^]*p[\"\^]*a[\"\^]*c[\"\^]*k|s[\"\^]*k(?:[\"\^]*t[\"\^]*o[\"\^]*p[\"\^]*i[\"\^]*m[\"\^]*g[\"\^]*d[\"\^]*o[\"\^]*w[\"\^]*n[\"\^]*l[\"\^]*d[\"\^]*r)?|v[\"\^]*(?:i[\"\^]*c[\"\^]*e[\"\^]*c[\"\^]*r[\"\^]*e[\"\^]*d[\"\^]*e[\"\^]*n[\"\^]*t[\"\^]*i[\"\^]*a[\"\^]*l[\"\^]*d[\"\^]*e[\"\^]*p[\"\^]*l[\"\^]*o[\"\^]*y[\"\^]*m[\"\^]*e[\"\^]*n[\"\^]*t|t[\"\^]*o[\"\^]*o[\"\^]*l[\"\^]*s[\"\^]*l[\"\^]*a[\"\^]*u[\"\^]*n[\"\^]*c[\"\^]*h[\"\^]*e[\"\^]*r))|f[\"\^]*s[\"\^]*(?:h[\"\^]*i[\"\^]*m|v[\"\^]*c)|i[\"\^]*(?:a[\"\^]*n[\"\^]*t[\"\^]*z|s[\"\^]*k[\"\^]*s[\"\^]*h[\"\^]*a[\"\^]*d[\"\^]*o[\"\^]*w)|n[\"\^]*(?:s[\"\^]*c[\"\^]*m[\"\^]*d|x)|o[\"\^]*t[\"\^]*n[\"\^]*e[\"\^]*t|u[\"\^]*m[\"\^]*p[\"\^]*6[\"\^]*4|x[\"\^]*c[\"\^]*a[\"\^]*p)|e[\"\^]*(?:s[\"\^]*e[\"\^]*n[\"\^]*t[\"\^]*u[\"\^]*t[\"\^]*l|v[\"\^]*e[\"\^]*n[\"\^]*t[\"\^]*v[\"\^]*w[\"\^]*r|x[\"\^]*(?:c[\"\^]*e[\"\^]*l|p[\"\^]*(?:a[\"\^]*n[\"\^]*d|l[\"\^]*o[\"\^]*r[\"\^]*e[\"\^]*r)|t[\"\^]*(?:e[\"\^]*x[\"\^]*p[\"\^]*o[\"\^]*r[\"\^]*t|r[\"\^]*a[\"\^]*c[\"\^]*3[\"\^]*2)))|f[\"\^]*(?:i[\"\^]*n[\"\^]*(?:d[\"\^]*s[\"\^]*t|g[\"\^]*e)[\"\^]*r|l[\"\^]*t[\"\^]*m[\"\^]*c|o[\"\^]*r[\"\^]*f[\"\^]*i[\"\^]*l[\"\^]*e[\"\^]*s|s[\"\^]*(?:i(?:[\"\^]*a[\"\^]*n[\"\^]*y[\"\^]*c[\"\^]*p[\"\^]*u)?|u[\"\^]*t[\"\^]*i[\"\^]*l)|t[\"\^]*p)|g[\"\^]*(?:f[\"\^]*x[\"\^]*d[\"\^]*o[\"\^]*w[\"\^]*n[\"\^]*l[\"\^]*o[\"\^]*a[\"\^]*d[\"\^]*w[\"\^]*r[\"\^]*a[\"\^]*p[\"\^]*p[\"\^]*e[\"\^]*r|p[\"\^]*s[\"\^]*c[\"\^]*r[\"\^]*i[\"\^]*p[\"\^]*t)|h[\"\^]*h|i[\"\^]*(?:e[\"\^]*(?:4[\"\^]*u[\"\^]*i[\"\^]*n[\"\^]*i[\"\^]*t|a[\"\^]*d[\"\^]*v[\"\^]*p[\"\^]*a[\"\^]*c[\"\^]*k|e[\"\^]*x[\"\^]*e[\"\^]*c|f[\"\^]*r[\"\^]*a[\"\^]*m[\"\^]*e)|l[\"\^]*a[\"\^]*s[\"\^]*m|m[\"\^]*e[\"\^]*w[\"\^]*d[\"\^]*b[\"\^]*l[\"\^]*d|n[\"\^]*(?:f[\"\^]*d[\"\^]*e[\"\^]*f[\"\^]*a[\"\^]*u[\"\^]*l[\"\^]*t[\"\^]*i[\"\^]*n[\"\^]*s[\"\^]*t[\"\^]*a[\"\^]*l|s[\"\^]*t[\"\^]*a[\"\^]*l[\"\^]*l[\"\^]*u[\"\^]*t[\"\^]*i)[\"\^]*l)|j[\"\^]*s[\"\^]*c|l[\"\^]*(?:a[\"\^]*u[\"\^]*n[\"\^]*c[\"\^]*h[\"\^]*-[\"\^]*v[\"\^]*s[\"\^]*d[\"\^]*e[\"\^]*v[\"\^]*s[\"\^]*h[\"\^]*e[\"\^]*l[\"\^]*l|d[\"\^]*i[\"\^]*f[\"\^]*d[\"\^]*e)|m[\"\^]*(?:a[\"\^]*(?:k[\"\^]*e[\"\^]*c[\"\^]*a[\"\^]*b|n[\"\^]*a[\"\^]*g[\"\^]*e[\"\^]*-[\"\^]*b[\"\^]*d[\"\^]*e|v[\"\^]*i[\"\^]*n[\"\^]*j[\"\^]*e[\"\^]*c[\"\^]*t)|f[\"\^]*t[\"\^]*r[\"\^]*a[\"\^]*c[\"\^]*e|i[\"\^]*c[\"\^]*r[\"\^]*o[\"\^]*s[\"\^]*o[\"\^]*f[\"\^]*t|m[\"\^]*c|p[\"\^]*c[\"\^]*m[\"\^]*d[\"\^]*r[\"\^]*u[\"\^]*n|s[\"\^]*(?:(?:b[\"\^]*u[\"\^]*i[\"\^]*l|o[\"\^]*h[\"\^]*t[\"\^]*m[\"\^]*e)[\"\^]*d|c[\"\^]*o[\"\^]*n[\"\^]*f[\"\^]*i[\"\^]*g|d[\"\^]*(?:e[\"\^]*p[\"\^]*l[\"\^]*o[\"\^]*y|t)|h[\"\^]*t[\"\^]*(?:a|m[\"\^]*l)|i[\"\^]*e[\"\^]*x[\"\^]*e[\"\^]*c|p[\"\^]*u[\"\^]*b|x[\"\^]*s[\"\^]*l))|n[\"\^]*(?:e[\"\^]*t[\"\^]*s[\"\^]*h|t[\"\^]*d[\"\^]*s[\"\^]*u[\"\^]*t[\"\^]*i[\"\^]*l)|o[\"\^]*(?:d[\"\^]*b[\"\^]*c[\"\^]*c[\"\^]*o[\"\^]*n[\"\^]*f|f[\"\^]*f[\"\^]*l[\"\^]*i[\"\^]*n[\"\^]*e[\"\^]*s[\"\^]*c[\"\^]*a[\"\^]*n[\"\^]*n[\"\^]*e[\"\^]*r[\"\^]*s[\"\^]*h[\"\^]*e[\"\^]*l[\"\^]*l|n[\"\^]*e[\"\^]*d[\"\^]*r[\"\^]*i[\"\^]*v[\"\^]*e[\"\^]*s[\"\^]*t[\"\^]*a[\"\^]*n[\"\^]*d[\"\^]*a[\"\^]*l[\"\^]*o[\"\^]*n[\"\^]*e[\"\^]*u[\"\^]*p[\"\^]*d[\"\^]*a[\"\^]*t[\"\^]*e[\"\^]*r|p[\"\^]*e[\"\^]*n[\"\^]*c[\"\^]*o[\"\^]*n[\"\^]*s[\"\^]*o[\"\^]*l[\"\^]*e)|p[\"\^]*(?:c[\"\^]*(?:a[\"\^]*l[\"\^]*u[\"\^]*a|w[\"\^]*(?:r[\"\^]*u[\"\^]*n|u[\"\^]*t[\"\^]*l))|(?:e[\"\^]*s[\"\^]*t[\"\^]*e|s)[\"\^]*r|(?:k[\"\^]*t[\"\^]*m[\"\^]*o|u[\"\^]*b[\"\^]*p[\"\^]*r)[\"\^]*n|n[\"\^]*p[\"\^]*u[\"\^]*t[\"\^]*i[\"\^]*l|o[\"\^]*w[\"\^]*e[\"\^]*r[\"\^]*p[\"\^]*n[\"\^]*t|r[\"\^]*(?:e[\"\^]*s[\"\^]*e[\"\^]*n[\"\^]*t[\"\^]*a[\"\^]*t[\"\^]*i[\"\^]*o[\"\^]*n[\"\^]*h[\"\^]*o[\"\^]*s[\"\^]*t|i[\"\^]*n[\"\^]*t(?:[\"\^]*b[\"\^]*r[\"\^]*m)?|o[\"\^]*(?:c[\"\^]*d[\"\^]*u[\"\^]*m[\"\^]*p|t[\"\^]*o[\"\^]*c[\"\^]*o[\"\^]*l[\"\^]*h[\"\^]*a[\"\^]*n[\"\^]*d[\"\^]*l[\"\^]*e[\"\^]*r)))|r[\"\^]*(?:a[\"\^]*s[\"\^]*a[\"\^]*u[\"\^]*t[\"\^]*o[\"\^]*u|c[\"\^]*s[\"\^]*i|(?:d[\"\^]*r[\"\^]*l[\"\^]*e[\"\^]*a[\"\^]*k[\"\^]*d[\"\^]*i[\"\^]*a|p[\"\^]*c[\"\^]*p[\"\^]*i[\"\^]*n)[\"\^]*g|e[\"\^]*(?:g(?:[\"\^]*(?:a[\"\^]*s[\"\^]*m|e[\"\^]*d[\"\^]*i[\"\^]*t|i[\"\^]*(?:n[\"\^]*i|s[\"\^]*t[\"\^]*e[\"\^]*r[\"\^]*-[\"\^]*c[\"\^]*i[\"\^]*m[\"\^]*p[\"\^]*r[\"\^]*o[\"\^]*v[\"\^]*i[\"\^]*d[\"\^]*e[\"\^]*r)|s[\"\^]*v[\"\^]*(?:c[\"\^]*s|r[\"\^]*3[\"\^]*2)))?|(?:m[\"\^]*o[\"\^]*t|p[\"\^]*l[\"\^]*a[\"\^]*c)[\"\^]*e)|u[\"\^]*n[\"\^]*(?:d[\"\^]*l[\"\^]*l[\"\^]*3[\"\^]*2|(?:e[\"\^]*x[\"\^]*e|s[\"\^]*c[\"\^]*r[\"\^]*i[\"\^]*p[\"\^]*t)[\"\^]*h[\"\^]*e[\"\^]*l[\"\^]*p[\"\^]*e[\"\^]*r|o[\"\^]*n[\"\^]*c[\"\^]*e))|s[\"\^]*(?:c[\"\^]*(?:[\s\x0b,\./;<>].*|h[\"\^]*t[\"\^]*a[\"\^]*s[\"\^]*k[\"\^]*s|r[\"\^]*i[\"\^]*p[\"\^]*t[\"\^]*r[\"\^]*u[\"\^]*n[\"\^]*n[\"\^]*e[\"\^]*r)|e[\"\^]*t[\"\^]*(?:r[\"\^]*e[\"\^]*s|t[\"\^]*i[\"\^]*n[\"\^]*g[\"\^]*s[\"\^]*y[\"\^]*n[\"\^]*c[\"\^]*h[\"\^]*o[\"\^]*s[\"\^]*t|u[\"\^]*p[\"\^]*a[\"\^]*p[\"\^]*i)|h[\"\^]*(?:d[\"\^]*o[\"\^]*c[\"\^]*v[\"\^]*w|e[\"\^]*l[\"\^]*l[\"\^]*3[\"\^]*2)|q[\"\^]*(?:l[\"\^]*(?:d[\"\^]*u[\"\^]*m[\"\^]*p[\"\^]*e[\"\^]*r|(?:t[\"\^]*o[\"\^]*o[\"\^]*l[\"\^]*s[\"\^]*)?p[\"\^]*s)|u[\"\^]*i[\"\^]*r[\"\^]*r[\"\^]*e[\"\^]*l)|s[\"\^]*h|t[\"\^]*o[\"\^]*r[\"\^]*d[\"\^]*i[\"\^]*a[\"\^]*g|y[\"\^]*(?:n[\"\^]*c[\"\^]*a[\"\^]*p[\"\^]*p[\"\^]*v[\"\^]*p[\"\^]*u[\"\^]*b[\"\^]*l[\"\^]*i[\"\^]*s[\"\^]*h[\"\^]*i[\"\^]*n[\"\^]*g[\"\^]*s[\"\^]*e[\"\^]*r[\"\^]*v[\"\^]*e[\"\^]*r|s[\"\^]*s[\"\^]*e[\"\^]*t[\"\^]*u[\"\^]*p))|t[\"\^]*(?:e[\"\^]*[\s\x0b,\./;<>].*|r[\"\^]*a[\"\^]*c[\"\^]*k[\"\^]*e[\"\^]*r|t[\"\^]*(?:d[\"\^]*i[\"\^]*n[\"\^]*j[\"\^]*e[\"\^]*c[\"\^]*t|t[\"\^]*r[\"\^]*a[\"\^]*c[\"\^]*e[\"\^]*r))|u[\"\^]*(?:n[\"\^]*r[\"\^]*e[\"\^]*g[\"\^]*m[\"\^]*p[\"\^]*2|p[\"\^]*d[\"\^]*a[\"\^]*t[\"\^]*e|r[\"\^]*l|t[\"\^]*i[\"\^]*l[\"\^]*i[\"\^]*t[\"\^]*y[\"\^]*f[\"\^]*u[\"\^]*n[\"\^]*c[\"\^]*t[\"\^]*i[\"\^]*o[\"\^]*n[\"\^]*s)|v[\"\^]*(?:b[\"\^]*c|e[\"\^]*r[\"\^]*c[\"\^]*l[\"\^]*s[\"\^]*i[\"\^]*d|i[\"\^]*s[\"\^]*u[\"\^]*a[\"\^]*l[\"\^]*u[\"\^]*i[\"\^]*a[\"\^]*v[\"\^]*e[\"\^]*r[\"\^]*i[\"\^]*f[\"\^]*y[\"\^]*n[\"\^]*a[\"\^]*t[\"\^]*i[\"\^]*v[\"\^]*e|s[\"\^]*(?:i[\"\^]*i[\"\^]*s[\"\^]*e[\"\^]*x[\"\^]*e[\"\^]*l[\"\^]*a[\"\^]*u[\"\^]*n[\"\^]*c[\"\^]*h|j[\"\^]*i[\"\^]*t[\"\^]*d[\"\^]*e[\"\^]*b[\"\^]*u[\"\^]*g[\"\^]*g)[\"\^]*e[\"\^]*r)|w[\"\^]*(?:a[\"\^]*b|(?:f|m[\"\^]*i)[\"\^]*c|i[\"\^]*n[\"\^]*(?:g[\"\^]*e[\"\^]*t|r[\"\^]*m|w[\"\^]*o[\"\^]*r[\"\^]*d)|l[\"\^]*r[\"\^]*m[\"\^]*d[\"\^]*r|o[\"\^]*r[\"\^]*k[\"\^]*f[\"\^]*o[\"\^]*l[\"\^]*d[\"\^]*e[\"\^]*r[\"\^]*s|s[\"\^]*(?:(?:c[\"\^]*r[\"\^]*i[\"\^]*p|r[\"\^]*e[\"\^]*s[\"\^]*e)[\"\^]*t|l)|t[\"\^]*[\s\x0b,\./;<>].*|u[\"\^]*a[\"\^]*u[\"\^]*c[\"\^]*l[\"\^]*t)|x[\"\^]*w[\"\^]*i[\"\^]*z[\"\^]*a[\"\^]*r[\"\^]*d|z[\"\^]*i[\"\^]*p[\"\^]*f[\"\^]*l[\"\^]*d[\"\^]*r)(?:\.[\"\^]*[0-9A-Z_a-z]+)?\b
- **Is Chain**: False
- **Message**: Remote Command Execution: Windows Command Injection
- **Severity**: CRITICAL
- **Tags**: application-multi, language-shell, platform-windows, attack-rce, paranoia-level/1, OWASP_CRS, OWASP_CRS/ATTACK-RCE, capec/1000/152/248/88
- **Actions**: id:932370, phase:2, block, capture, t:none, msg:Remote Command Execution: Windows Command Injection, logdata:Matched Data: %{TX.0} found within %{MATCHED_VAR_NAME}: %{MATCHED_VAR}, tag:application-multi, tag:language-shell, tag:platform-windows, tag:attack-rce, tag:paranoia-level/1, tag:OWASP_CRS, tag:OWASP_CRS/ATTACK-RCE, tag:capec/1000/152/248/88, ver:OWASP_CRS/4.22.0-dev, severity:CRITICAL, setvar:tx.rce_score=+%{tx.critical_anomaly_score}, setvar:tx.inbound_anomaly_score_pl1=+%{tx.critical_anomaly_score}

#### Rule 21: 932380
- **Phase**: 2
- **Variables**: REQUEST_COOKIES, REQUEST_COOKIES_NAMES, ARGS_NAMES, ARGS, XML:/*
- **Operator**: @rx
- **Pattern**: (?i)(?:[\n\r;`\{]|\|\|?|&&?)[\s\x0b]*[\s\x0b\"'\(,@]*(?:[\"'\.-9A-Z_a-z]+/|(?:[\"'\x5c\^]*[0-9A-Z_a-z][\"'\x5c\^]*:[^\x5c]*|[ \"'\.-9A-Z\x5c\^_a-z]*)\x5c)?[\"\^]*(?:a[\"\^]*(?:s[\"\^]*s[\"\^]*o[\"\^]*c|t[\"\^]*(?:m[\"\^]*a[\"\^]*d[\"\^]*m|t[\"\^]*r[\"\^]*i[\"\^]*b)|u[\"\^]*(?:d[\"\^]*i[\"\^]*t[\"\^]*p[\"\^]*o[\"\^]*l|t[\"\^]*o[\"\^]*(?:c[\"\^]*(?:h[\"\^]*k|o[\"\^]*n[\"\^]*v)|(?:f[\"\^]*m|m[\"\^]*o[\"\^]*u[\"\^]*n)[\"\^]*t)))|b[\"\^]*(?:c[\"\^]*d[\"\^]*(?:b[\"\^]*o[\"\^]*o|e[\"\^]*d[\"\^]*i)[\"\^]*t|(?:d[\"\^]*e[\"\^]*h[\"\^]*d|o[\"\^]*o[\"\^]*t)[\"\^]*c[\"\^]*f[\"\^]*g|i[\"\^]*t[\"\^]*s[\"\^]*a[\"\^]*d[\"\^]*m[\"\^]*i[\"\^]*n)|c[\"\^]*(?:a[\"\^]*c[\"\^]*l[\"\^]*s|e[\"\^]*r[\"\^]*t[\"\^]*(?:r[\"\^]*e[\"\^]*q|u[\"\^]*t[\"\^]*i[\"\^]*l)|h[\"\^]*(?:c[\"\^]*p|d[\"\^]*i[\"\^]*r|g[\"\^]*(?:l[\"\^]*o[\"\^]*g[\"\^]*o[\"\^]*n|p[\"\^]*o[\"\^]*r[\"\^]*t|u[\"\^]*s[\"\^]*r)|k[\"\^]*(?:d[\"\^]*s[\"\^]*k|n[\"\^]*t[\"\^]*f[\"\^]*s))|l[\"\^]*e[\"\^]*a[\"\^]*n[\"\^]*m[\"\^]*g[\"\^]*r|m[\"\^]*(?:d(?:[\"\^]*k[\"\^]*e[\"\^]*y)?|s[\"\^]*t[\"\^]*p)|s[\"\^]*c[\"\^]*r[\"\^]*i[\"\^]*p[\"\^]*t)|d[\"\^]*(?:c[\"\^]*(?:d[\"\^]*i[\"\^]*a[\"\^]*g|g[\"\^]*p[\"\^]*o[\"\^]*f[\"\^]*i[\"\^]*x)|e[\"\^]*(?:f[\"\^]*r[\"\^]*a[\"\^]*g|l)|f[\"\^]*s[\"\^]*(?:d[\"\^]*i[\"\^]*a|r[\"\^]*m[\"\^]*i)[\"\^]*g|i[\"\^]*(?:a[\"\^]*n[\"\^]*t[\"\^]*z|r|s[\"\^]*(?:k[\"\^]*(?:c[\"\^]*o[\"\^]*(?:m[\"\^]*p|p[\"\^]*y)|p[\"\^]*(?:a[\"\^]*r[\"\^]*t|e[\"\^]*r[\"\^]*f)|r[\"\^]*a[\"\^]*i[\"\^]*d|s[\"\^]*h[\"\^]*a[\"\^]*d[\"\^]*o[\"\^]*w)|p[\"\^]*d[\"\^]*i[\"\^]*a[\"\^]*g))|n[\"\^]*s[\"\^]*c[\"\^]*m[\"\^]*d|(?:o[\"\^]*s[\"\^]*k[\"\^]*e|r[\"\^]*i[\"\^]*v[\"\^]*e[\"\^]*r[\"\^]*q[\"\^]*u[\"\^]*e[\"\^]*r)[\"\^]*y)|e[\"\^]*(?:n[\"\^]*d[\"\^]*l[\"\^]*o[\"\^]*c[\"\^]*a[\"\^]*l|v[\"\^]*e[\"\^]*n[\"\^]*t[\"\^]*c[\"\^]*r[\"\^]*e[\"\^]*a[\"\^]*t[\"\^]*e)|E[\"\^]*v[\"\^]*n[\"\^]*t[\"\^]*c[\"\^]*m[\"\^]*d|f[\"\^]*(?:c|i[\"\^]*(?:l[\"\^]*e[\"\^]*s[\"\^]*y[\"\^]*s[\"\^]*t[\"\^]*e[\"\^]*m[\"\^]*s|n[\"\^]*d[\"\^]*s[\"\^]*t[\"\^]*r)|l[\"\^]*a[\"\^]*t[\"\^]*t[\"\^]*e[\"\^]*m[\"\^]*p|o[\"\^]*r[\"\^]*f[\"\^]*i[\"\^]*l[\"\^]*e[\"\^]*s|r[\"\^]*e[\"\^]*e[\"\^]*d[\"\^]*i[\"\^]*s[\"\^]*k|s[\"\^]*u[\"\^]*t[\"\^]*i[\"\^]*l|(?:t[\"\^]*y[\"\^]*p|v[\"\^]*e[\"\^]*u[\"\^]*p[\"\^]*d[\"\^]*a[\"\^]*t)[\"\^]*e)|g[\"\^]*(?:e[\"\^]*t[\"\^]*(?:m[\"\^]*a[\"\^]*c|t[\"\^]*y[\"\^]*p[\"\^]*e)|o[\"\^]*t[\"\^]*o|p[\"\^]*(?:f[\"\^]*i[\"\^]*x[\"\^]*u[\"\^]*p|(?:r[\"\^]*e[\"\^]*s[\"\^]*u[\"\^]*l[\"\^]*)?t|u[\"\^]*p[\"\^]*d[\"\^]*a[\"\^]*t[\"\^]*e)|r[\"\^]*a[\"\^]*f[\"\^]*t[\"\^]*a[\"\^]*b[\"\^]*l)|h[\"\^]*(?:e[\"\^]*l[\"\^]*p[\"\^]*c[\"\^]*t[\"\^]*r|o[\"\^]*s[\"\^]*t[\"\^]*n[\"\^]*a[\"\^]*m[\"\^]*e)|i[\"\^]*(?:c[\"\^]*a[\"\^]*c[\"\^]*l[\"\^]*s|p[\"\^]*(?:c[\"\^]*o[\"\^]*n[\"\^]*f[\"\^]*i[\"\^]*g|x[\"\^]*r[\"\^]*o[\"\^]*u[\"\^]*t[\"\^]*e)|r[\"\^]*f[\"\^]*t[\"\^]*p)|j[\"\^]*e[\"\^]*t[\"\^]*p[\"\^]*a[\"\^]*c[\"\^]*k|k[\"\^]*(?:l[\"\^]*i[\"\^]*s[\"\^]*t|s[\"\^]*e[\"\^]*t[\"\^]*u[\"\^]*p|t[\"\^]*(?:m[\"\^]*u[\"\^]*t[\"\^]*i[\"\^]*l|p[\"\^]*a[\"\^]*s[\"\^]*s))|l[\"\^]*(?:o[\"\^]*(?:d[\"\^]*c[\"\^]*t[\"\^]*r|g[\"\^]*(?:m[\"\^]*a[\"\^]*n|o[\"\^]*f[\"\^]*f))|p[\"\^]*[qr])|m[\"\^]*(?:a[\"\^]*(?:c[\"\^]*f[\"\^]*i[\"\^]*l[\"\^]*e|k[\"\^]*e[\"\^]*c[\"\^]*a[\"\^]*b|p[\"\^]*a[\"\^]*d[\"\^]*m[\"\^]*i[\"\^]*n)|k[\"\^]*(?:d[\"\^]*i[\"\^]*r|l[\"\^]*i[\"\^]*n[\"\^]*k)|m[\"\^]*c|o[\"\^]*u[\"\^]*n[\"\^]*t[\"\^]*v[\"\^]*o[\"\^]*l|q[\"\^]*(?:b[\"\^]*k[\"\^]*u[\"\^]*p|(?:t[\"\^]*g[\"\^]*)?s[\"\^]*v[\"\^]*c)|s[\"\^]*(?:d[\"\^]*t|i[\"\^]*(?:e[\"\^]*x[\"\^]*e[\"\^]*c|n[\"\^]*f[\"\^]*o[\"\^]*3[\"\^]*2)|t[\"\^]*s[\"\^]*c))|n[\"\^]*(?:b[\"\^]*t[\"\^]*s[\"\^]*t[\"\^]*a[\"\^]*t|e[\"\^]*t[\"\^]*(?:c[\"\^]*f[\"\^]*g|d[\"\^]*o[\"\^]*m|s[\"\^]*(?:h|t[\"\^]*a[\"\^]*t))|f[\"\^]*s[\"\^]*(?:a[\"\^]*d[\"\^]*m[\"\^]*i[\"\^]*n|s[\"\^]*(?:h[\"\^]*a[\"\^]*r[\"\^]*e|t[\"\^]*a[\"\^]*t))|l[\"\^]*(?:b[\"\^]*m[\"\^]*g[\"\^]*r|t[\"\^]*e[\"\^]*s[\"\^]*t)|s[\"\^]*l[\"\^]*o[\"\^]*o[\"\^]*k[\"\^]*u[\"\^]*p|t[\"\^]*(?:b[\"\^]*a[\"\^]*c[\"\^]*k[\"\^]*u[\"\^]*p|c[\"\^]*m[\"\^]*d[\"\^]*p[\"\^]*r[\"\^]*o[\"\^]*m[\"\^]*p[\"\^]*t|f[\"\^]*r[\"\^]*s[\"\^]*u[\"\^]*t[\"\^]*l))|o[\"\^]*(?:f[\"\^]*f[\"\^]*l[\"\^]*i[\"\^]*n[\"\^]*e|p[\"\^]*e[\"\^]*n[\"\^]*f[\"\^]*i[\"\^]*l[\"\^]*e[\"\^]*s)|p[\"\^]*(?:a[\"\^]*(?:g[\"\^]*e[\"\^]*f[\"\^]*i[\"\^]*l[\"\^]*e[\"\^]*c[\"\^]*o[\"\^]*n[\"\^]*f[\"\^]*i|t[\"\^]*h[\"\^]*p[\"\^]*i[\"\^]*n)[\"\^]*g|(?:b[\"\^]*a[\"\^]*d[\"\^]*m[\"\^]*i|k[\"\^]*t[\"\^]*m[\"\^]*o)[\"\^]*n|e[\"\^]*(?:n[\"\^]*t[\"\^]*n[\"\^]*t|r[\"\^]*f[\"\^]*m[\"\^]*o[\"\^]*n)|n[\"\^]*p[\"\^]*u[\"\^]*(?:n[\"\^]*a[\"\^]*t[\"\^]*t[\"\^]*e[\"\^]*n[\"\^]*d|t[\"\^]*i[\"\^]*l)|o[\"\^]*(?:p[\"\^]*d|w[\"\^]*e[\"\^]*r[\"\^]*s[\"\^]*h[\"\^]*e[\"\^]*l[\"\^]*l)|r[\"\^]*n[\"\^]*(?:c[\"\^]*n[\"\^]*f[\"\^]*g|(?:d[\"\^]*r[\"\^]*v|m[\"\^]*n[\"\^]*g)[\"\^]*r|j[\"\^]*o[\"\^]*b[\"\^]*s|p[\"\^]*o[\"\^]*r[\"\^]*t|q[\"\^]*c[\"\^]*t[\"\^]*l)|u[\"\^]*(?:b[\"\^]*p[\"\^]*r[\"\^]*n|s[\"\^]*h[\"\^]*(?:d|p[\"\^]*r[\"\^]*i[\"\^]*n[\"\^]*t[\"\^]*e[\"\^]*r[\"\^]*c[\"\^]*o[\"\^]*n[\"\^]*n[\"\^]*e[\"\^]*c[\"\^]*t[\"\^]*i[\"\^]*o[\"\^]*n[\"\^]*s))|w[\"\^]*(?:l[\"\^]*a[\"\^]*u[\"\^]*n[\"\^]*c[\"\^]*h[\"\^]*e[\"\^]*r|s[\"\^]*h))|q[\"\^]*(?:a[\"\^]*p[\"\^]*p[\"\^]*s[\"\^]*r[\"\^]*v|p[\"\^]*r[\"\^]*o[\"\^]*c[\"\^]*e[\"\^]*s[\"\^]*s|u[\"\^]*s[\"\^]*e[\"\^]*r|w[\"\^]*i[\"\^]*n[\"\^]*s[\"\^]*t[\"\^]*a)|r[\"\^]*(?:d(?:[\"\^]*p[\"\^]*s[\"\^]*i[\"\^]*g[\"\^]*n)?|e[\"\^]*(?:f[\"\^]*s[\"\^]*u[\"\^]*t[\"\^]*i[\"\^]*l|g(?:[\"\^]*(?:i[\"\^]*n[\"\^]*i|s[\"\^]*v[\"\^]*r[\"\^]*3[\"\^]*2))?|l[\"\^]*o[\"\^]*g|(?:(?:p[\"\^]*a[\"\^]*d[\"\^]*m[\"\^]*i|s[\"\^]*c[\"\^]*a)[\"\^]*)?n|x[\"\^]*e[\"\^]*c)|i[\"\^]*s[\"\^]*e[\"\^]*t[\"\^]*u[\"\^]*p|m[\"\^]*d[\"\^]*i[\"\^]*r|o[\"\^]*b[\"\^]*o[\"\^]*c[\"\^]*o[\"\^]*p[\"\^]*y|p[\"\^]*c[\"\^]*(?:i[\"\^]*n[\"\^]*f[\"\^]*o|p[\"\^]*i[\"\^]*n[\"\^]*g)|s[\"\^]*h|u[\"\^]*n[\"\^]*d[\"\^]*l[\"\^]*l[\"\^]*3[\"\^]*2|w[\"\^]*i[\"\^]*n[\"\^]*s[\"\^]*t[\"\^]*a)|s[\"\^]*(?:a[\"\^]*n|c[\"\^]*(?:h[\"\^]*t[\"\^]*a[\"\^]*s[\"\^]*k[\"\^]*s|w[\"\^]*c[\"\^]*m[\"\^]*d)|e[\"\^]*(?:c[\"\^]*e[\"\^]*d[\"\^]*i[\"\^]*t|r[\"\^]*v[\"\^]*e[\"\^]*r[\"\^]*(?:(?:c[\"\^]*e[\"\^]*i[\"\^]*p|w[\"\^]*e[\"\^]*r)[\"\^]*o[\"\^]*p[\"\^]*t[\"\^]*i[\"\^]*n|m[\"\^]*a[\"\^]*n[\"\^]*a[\"\^]*g[\"\^]*e[\"\^]*r[\"\^]*c[\"\^]*m[\"\^]*d)|t[\"\^]*x)|f[\"\^]*c|(?:h[\"\^]*o[\"\^]*w[\"\^]*m[\"\^]*o[\"\^]*u[\"\^]*n|u[\"\^]*b[\"\^]*s)[\"\^]*t|x[\"\^]*s[\"\^]*t[\"\^]*r[\"\^]*a[\"\^]*c[\"\^]*e|y[\"\^]*s[\"\^]*(?:o[\"\^]*c[\"\^]*m[\"\^]*g[\"\^]*r|t[\"\^]*e[\"\^]*m[\"\^]*i[\"\^]*n[\"\^]*f[\"\^]*o))|t[\"\^]*(?:a[\"\^]*(?:k[\"\^]*e[\"\^]*o[\"\^]*w[\"\^]*n|p[\"\^]*i[\"\^]*c[\"\^]*f[\"\^]*g|s[\"\^]*k[\"\^]*(?:k[\"\^]*i[\"\^]*l[\"\^]*l|l[\"\^]*i[\"\^]*s[\"\^]*t))|(?:c[\"\^]*m[\"\^]*s[\"\^]*e[\"\^]*t[\"\^]*u|f[\"\^]*t)[\"\^]*p|(?:(?:e[\"\^]*l[\"\^]*n[\"\^]*e|i[\"\^]*m[\"\^]*e[\"\^]*o[\"\^]*u)[\"\^]*|r[\"\^]*a[\"\^]*c[\"\^]*e[\"\^]*r[\"\^]*(?:p[\"\^]*)?)t|l[\"\^]*n[\"\^]*t[\"\^]*a[\"\^]*d[\"\^]*m[\"\^]*n|p[\"\^]*m[\"\^]*(?:t[\"\^]*o[\"\^]*o[\"\^]*l|v[\"\^]*s[\"\^]*c[\"\^]*m[\"\^]*g[\"\^]*r)|s[\"\^]*(?:(?:d[\"\^]*i[\"\^]*s[\"\^]*)?c[\"\^]*o[\"\^]*n|e[\"\^]*c[\"\^]*i[\"\^]*m[\"\^]*p|k[\"\^]*i[\"\^]*l[\"\^]*l|p[\"\^]*r[\"\^]*o[\"\^]*f)|y[\"\^]*p[\"\^]*e[\"\^]*p[\"\^]*e[\"\^]*r[\"\^]*f|z[\"\^]*u[\"\^]*t[\"\^]*i[\"\^]*l)|u[\"\^]*n[\"\^]*(?:e[\"\^]*x[\"\^]*p[\"\^]*o[\"\^]*s[\"\^]*e|i[\"\^]*q[\"\^]*u[\"\^]*e[\"\^]*i[\"\^]*d|l[\"\^]*o[\"\^]*d[\"\^]*c[\"\^]*t[\"\^]*r)|v[\"\^]*s[\"\^]*s[\"\^]*a[\"\^]*d[\"\^]*m[\"\^]*i[\"\^]*n|w[\"\^]*(?:a[\"\^]*i[\"\^]*t[\"\^]*f[\"\^]*o[\"\^]*r|b[\"\^]*a[\"\^]*d[\"\^]*m[\"\^]*i[\"\^]*n|(?:d[\"\^]*s|e[\"\^]*(?:c|v[\"\^]*t))[\"\^]*u[\"\^]*t[\"\^]*i[\"\^]*l|h[\"\^]*o[\"\^]*a[\"\^]*m[\"\^]*i|i[\"\^]*n[\"\^]*(?:n[\"\^]*t(?:[\"\^]*3[\"\^]*2)?|r[\"\^]*s)|m[\"\^]*i[\"\^]*c|s[\"\^]*c[\"\^]*r[\"\^]*i[\"\^]*p[\"\^]*t)|x[\"\^]*c[\"\^]*o[\"\^]*p[\"\^]*y)(?:\.[\"\^]*[0-9A-Z_a-z]+)?\b
- **Is Chain**: False
- **Message**: Remote Command Execution: Windows Command Injection
- **Severity**: CRITICAL
- **Tags**: application-multi, language-shell, platform-windows, attack-rce, paranoia-level/1, OWASP_CRS, OWASP_CRS/ATTACK-RCE, capec/1000/152/248/88
- **Actions**: id:932380, phase:2, block, capture, t:none, msg:Remote Command Execution: Windows Command Injection, logdata:Matched Data: %{TX.0} found within %{MATCHED_VAR_NAME}: %{MATCHED_VAR}, tag:application-multi, tag:language-shell, tag:platform-windows, tag:attack-rce, tag:paranoia-level/1, tag:OWASP_CRS, tag:OWASP_CRS/ATTACK-RCE, tag:capec/1000/152/248/88, ver:OWASP_CRS/4.22.0-dev, severity:CRITICAL, setvar:tx.rce_score=+%{tx.critical_anomaly_score}, setvar:tx.inbound_anomaly_score_pl1=+%{tx.critical_anomaly_score}

#### Rule 22: 932013
- **Phase**: 1
- **Variables**: TX:DETECTION_PARANOIA_LEVEL
- **Operator**: @lt
- **Pattern**: 2
- **Is Chain**: False
- **Message**: 
- **Severity**: 
- **Tags**: OWASP_CRS
- **Actions**: id:932013, phase:1, pass, nolog, tag:OWASP_CRS, ver:OWASP_CRS/4.22.0-dev, skipAfter:END-REQUEST-932-APPLICATION-ATTACK-RCE

#### Rule 23: 932014
- **Phase**: 2
- **Variables**: TX:DETECTION_PARANOIA_LEVEL
- **Operator**: @lt
- **Pattern**: 2
- **Is Chain**: False
- **Message**: 
- **Severity**: 
- **Tags**: OWASP_CRS
- **Actions**: id:932014, phase:2, pass, nolog, tag:OWASP_CRS, ver:OWASP_CRS/4.22.0-dev, skipAfter:END-REQUEST-932-APPLICATION-ATTACK-RCE

#### Rule 24: 932371
- **Phase**: 2
- **Variables**: REQUEST_COOKIES, REQUEST_COOKIES_NAMES, ARGS_NAMES, ARGS, XML:/*
- **Operator**: @rx
- **Pattern**: (?i)(?:[\n\r;`\{]|\|\|?|&&?)[\s\x0b]*[\s\x0b\"'\(,@]*(?:[\"'\.-9A-Z_a-z]+/|(?:[\"'\x5c\^]*[0-9A-Z_a-z][\"'\x5c\^]*:[^\x5c]*|[ \"'\.-9A-Z\x5c\^_a-z]*)\x5c)?[\"\^]*a[\"\^]*t[\"\^]*[\s\x0b,\./;<>].*(?:\.[\"\^]*[0-9A-Z_a-z]+)?\b
- **Is Chain**: False
- **Message**: Remote Command Execution: Windows Command Injection
- **Severity**: CRITICAL
- **Tags**: application-multi, language-shell, platform-windows, attack-rce, paranoia-level/2, OWASP_CRS, OWASP_CRS/ATTACK-RCE, capec/1000/152/248/88
- **Actions**: id:932371, phase:2, block, capture, t:none, msg:Remote Command Execution: Windows Command Injection, logdata:Matched Data: %{TX.0} found within %{MATCHED_VAR_NAME}: %{MATCHED_VAR}, tag:application-multi, tag:language-shell, tag:platform-windows, tag:attack-rce, tag:paranoia-level/2, tag:OWASP_CRS, tag:OWASP_CRS/ATTACK-RCE, tag:capec/1000/152/248/88, ver:OWASP_CRS/4.22.0-dev, severity:CRITICAL, setvar:tx.rce_score=+%{tx.critical_anomaly_score}, setvar:tx.inbound_anomaly_score_pl2=+%{tx.critical_anomaly_score}

#### Rule 25: 932231
- **Phase**: 2
- **Variables**: REQUEST_COOKIES, REQUEST_COOKIES_NAMES, ARGS_NAMES, ARGS, XML:/*
- **Operator**: @rx
- **Pattern**: (?:b[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?u[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?s[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?y[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?b[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?o[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?x|(?:c[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?o[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?m[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?m[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?a[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?n[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?d|e[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?(?:n[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?v|v[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?a[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?l)|w[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?a[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?t[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?c[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?h)[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?(?:[\s\x0b&\),<>\|]|$).*|[ls][\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?t[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?r[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?a[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?c[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?e|n[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?o[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?h[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?u[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?p|t[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?i[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?m[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?e[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?(?:(?:[\s\x0b&\),<>\|]|$).*|o[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?u[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?t)|[\n\r;=`\{]|\|\|?|&&?|\$(?:\(\(?|[\[\{])|<(?:\(|<<)|>\(|\([\s\x0b]*\))[\s\x0b]*(?:[\$\{]|(?:[\s\x0b]*\(|!)[\s\x0b]*|[0-9A-Z_a-z]+=(?:[^\s\x0b]*|\$(?:.*|.*)|[<>].*|'[^']*'|\"[^\"]*\")[\s\x0b]+)*[\s\x0b]*[\"']*(?:[\"'-\+\--9\?A-\]_a-z\|]+/)?[\"'\x5c]*\.[\s\x0b].*\b
- **Is Chain**: False
- **Message**: Remote Command Execution: Unix Command Injection
- **Severity**: CRITICAL
- **Tags**: application-multi, language-shell, platform-unix, attack-rce, paranoia-level/2, OWASP_CRS, OWASP_CRS/ATTACK-RCE, capec/1000/152/248/88
- **Actions**: id:932231, phase:2, block, capture, t:none, msg:Remote Command Execution: Unix Command Injection, logdata:Matched Data: %{TX.0} found within %{MATCHED_VAR_NAME}: %{MATCHED_VAR}, tag:application-multi, tag:language-shell, tag:platform-unix, tag:attack-rce, tag:paranoia-level/2, tag:OWASP_CRS, tag:OWASP_CRS/ATTACK-RCE, tag:capec/1000/152/248/88, ver:OWASP_CRS/4.22.0-dev, severity:CRITICAL, setvar:tx.rce_score=+%{tx.critical_anomaly_score}, setvar:tx.inbound_anomaly_score_pl2=+%{tx.critical_anomaly_score}

#### Rule 26: 932131
- **Phase**: 1
- **Variables**: REQUEST_HEADERS:User-Agent, REQUEST_HEADERS:Referer
- **Operator**: @rx
- **Pattern**: \$(?:\((?:.*|\(.*\))\)|\{.*\}|\[.*\])|[<>]\(.*\)|/[0-9A-Z_a-z]*\[!?.+\]
- **Is Chain**: False
- **Message**: Remote Command Execution: Unix Shell Expression Found
- **Severity**: CRITICAL
- **Tags**: application-multi, language-shell, platform-unix, attack-rce, paranoia-level/2, OWASP_CRS, OWASP_CRS/ATTACK-RCE, capec/1000/152/248/88
- **Actions**: id:932131, phase:1, block, capture, t:none, t:cmdLine, msg:Remote Command Execution: Unix Shell Expression Found, logdata:Matched Data: %{TX.0} found within %{MATCHED_VAR_NAME}: %{MATCHED_VAR}, tag:application-multi, tag:language-shell, tag:platform-unix, tag:attack-rce, tag:paranoia-level/2, tag:OWASP_CRS, tag:OWASP_CRS/ATTACK-RCE, tag:capec/1000/152/248/88, ver:OWASP_CRS/4.22.0-dev, severity:CRITICAL, setvar:tx.rce_score=+%{tx.critical_anomaly_score}, setvar:tx.inbound_anomaly_score_pl2=+%{tx.critical_anomaly_score}

#### Rule 27: 932200
- **Phase**: 2
- **Variables**: REQUEST_COOKIES, REQUEST_COOKIES_NAMES, ARGS_NAMES, ARGS, XML:/*
- **Operator**: @rx
- **Pattern**: ['\*\?\x5c`][^\n/]+/|/[^/]+?['\*\?\x5c`]|\$[!#\$\(\*\-0-9\?-\[_a-\{]
- **Is Chain**: True
- **Message**: RCE Bypass Technique
- **Severity**: CRITICAL
- **Tags**: application-multi, language-multi, platform-multi, attack-rce, paranoia-level/2, OWASP_CRS, OWASP_CRS/ATTACK-RCE, capec/1000/152/248/88
- **Actions**: id:932200, phase:2, block, capture, t:none, t:lowercase, t:urlDecodeUni, msg:RCE Bypass Technique, logdata:Matched Data: %{TX.0} found within %{TX.932200_MATCHED_VAR_NAME}: %{MATCHED_VAR}, tag:application-multi, tag:language-multi, tag:platform-multi, tag:attack-rce, tag:paranoia-level/2, tag:OWASP_CRS, tag:OWASP_CRS/ATTACK-RCE, tag:capec/1000/152/248/88, ver:OWASP_CRS/4.22.0-dev, severity:CRITICAL, setvar:tx.932200_matched_var_name=%{matched_var_name}, chain

#### Rule 28: Unknown
- **Phase**: Unknown
- **Variables**: MATCHED_VARS
- **Operator**: @rx
- **Pattern**: /
- **Is Chain**: True
- **Message**: 
- **Severity**: 
- **Actions**: t:none, chain

#### Rule 29: Unknown
- **Phase**: Unknown
- **Variables**: MATCHED_VARS
- **Operator**: @rx
- **Pattern**: \s
- **Is Chain**: False
- **Message**: 
- **Severity**: 
- **Actions**: t:none, setvar:tx.rce_score=+%{tx.critical_anomaly_score}, setvar:tx.inbound_anomaly_score_pl2=+%{tx.critical_anomaly_score}

#### Rule 30: 932205
- **Phase**: 1
- **Variables**: REQUEST_HEADERS:Referer
- **Operator**: @rx
- **Pattern**: ^[^#]+
- **Is Chain**: True
- **Message**: RCE Bypass Technique
- **Severity**: CRITICAL
- **Tags**: application-multi, language-multi, platform-multi, attack-rce, paranoia-level/2, OWASP_CRS, OWASP_CRS/ATTACK-RCE, capec/1000/152/248/88
- **Actions**: id:932205, phase:1, block, capture, t:none, t:lowercase, t:urlDecodeUni, msg:RCE Bypass Technique, logdata:Matched Data: %{TX.2} found within %{TX.932205_MATCHED_VAR_NAME}: %{MATCHED_VAR}, tag:application-multi, tag:language-multi, tag:platform-multi, tag:attack-rce, tag:paranoia-level/2, tag:OWASP_CRS, tag:OWASP_CRS/ATTACK-RCE, tag:capec/1000/152/248/88, ver:OWASP_CRS/4.22.0-dev, severity:CRITICAL, setvar:tx.932205_matched_var_name=%{matched_var_name}, chain

#### Rule 31: Unknown
- **Phase**: Unknown
- **Variables**: TX:0
- **Operator**: @rx
- **Pattern**: ^[^\.]+\.[^;\?]+[;\?](.*(['\*\?\x5c`][^\n/]+/|/[^/]+?['\*\?\x5c`]|\$[!#\$\(\*\-0-9\?-\[_a-\{]))
- **Is Chain**: True
- **Message**: 
- **Severity**: 
- **Actions**: capture, t:none, chain

#### Rule 32: Unknown
- **Phase**: Unknown
- **Variables**: TX:1
- **Operator**: @rx
- **Pattern**: /
- **Is Chain**: True
- **Message**: 
- **Severity**: 
- **Actions**: t:none, chain

#### Rule 33: Unknown
- **Phase**: Unknown
- **Variables**: TX:1
- **Operator**: @rx
- **Pattern**: \s
- **Is Chain**: False
- **Message**: 
- **Severity**: 
- **Actions**: t:none, setvar:tx.rce_score=+%{tx.critical_anomaly_score}, setvar:tx.inbound_anomaly_score_pl2=+%{tx.critical_anomaly_score}

#### Rule 34: 932206
- **Phase**: 1
- **Variables**: REQUEST_HEADERS:Referer
- **Operator**: @rx
- **Pattern**: ^[^\.]*?(?:['\*\?\x5c`][^\n/]+/|/[^/]+?['\*\?\x5c`]|\$[!#\$\(\*\-0-9\?-\[_a-\{])
- **Is Chain**: True
- **Message**: RCE Bypass Technique
- **Severity**: CRITICAL
- **Tags**: application-multi, language-multi, platform-multi, attack-rce, paranoia-level/2, OWASP_CRS, OWASP_CRS/ATTACK-RCE, capec/1000/152/248/88
- **Actions**: id:932206, phase:1, block, capture, t:none, t:lowercase, t:urlDecodeUni, msg:RCE Bypass Technique, logdata:Matched Data: %{TX.0} found within %{TX.932206_MATCHED_VAR_NAME}: %{MATCHED_VAR}, tag:application-multi, tag:language-multi, tag:platform-multi, tag:attack-rce, tag:paranoia-level/2, tag:OWASP_CRS, tag:OWASP_CRS/ATTACK-RCE, tag:capec/1000/152/248/88, ver:OWASP_CRS/4.22.0-dev, severity:CRITICAL, setvar:tx.932206_matched_var_name=%{matched_var_name}, chain

#### Rule 35: Unknown
- **Phase**: Unknown
- **Variables**: MATCHED_VARS
- **Operator**: @rx
- **Pattern**: /
- **Is Chain**: True
- **Message**: 
- **Severity**: 
- **Actions**: t:none, chain

#### Rule 36: Unknown
- **Phase**: Unknown
- **Variables**: MATCHED_VARS
- **Operator**: @rx
- **Pattern**: \s
- **Is Chain**: False
- **Message**: 
- **Severity**: 
- **Actions**: t:none, setvar:tx.rce_score=+%{tx.critical_anomaly_score}, setvar:tx.inbound_anomaly_score_pl2=+%{tx.critical_anomaly_score}

#### Rule 37: 932207
- **Phase**: 1
- **Variables**: REQUEST_HEADERS:Referer
- **Operator**: @rx
- **Pattern**: #.*
- **Is Chain**: True
- **Message**: RCE Bypass Technique
- **Severity**: CRITICAL
- **Tags**: application-multi, language-multi, platform-multi, attack-rce, paranoia-level/2, OWASP_CRS, OWASP_CRS/ATTACK-RCE, capec/1000/152/248/88
- **Actions**: id:932207, phase:1, block, capture, t:none, t:lowercase, t:urlDecodeUni, msg:RCE Bypass Technique, logdata:Matched Data: %{TX.0} found within %{TX.932207_MATCHED_VAR_NAME}: %{MATCHED_VAR}, tag:application-multi, tag:language-multi, tag:platform-multi, tag:attack-rce, tag:paranoia-level/2, tag:OWASP_CRS, tag:OWASP_CRS/ATTACK-RCE, tag:capec/1000/152/248/88, ver:OWASP_CRS/4.22.0-dev, severity:CRITICAL, setvar:tx.932207_matched_var_name=%{matched_var_name}, chain

#### Rule 38: Unknown
- **Phase**: Unknown
- **Variables**: TX:0
- **Operator**: @rx
- **Pattern**: ['\*\?\x5c`][^\n/]+/|/[^/]+?['\*\?\x5c`]|\$[!#\$\(\*\-0-9\?-\[_a-\{]
- **Is Chain**: True
- **Message**: 
- **Severity**: 
- **Actions**: capture, t:none, chain

#### Rule 39: Unknown
- **Phase**: Unknown
- **Variables**: MATCHED_VAR
- **Operator**: @rx
- **Pattern**: /
- **Is Chain**: True
- **Message**: 
- **Severity**: 
- **Actions**: t:none, chain

#### Rule 40: Unknown
- **Phase**: Unknown
- **Variables**: MATCHED_VAR
- **Operator**: @rx
- **Pattern**: \s
- **Is Chain**: True
- **Message**: 
- **Severity**: 
- **Actions**: t:none, chain

#### Rule 41: Unknown
- **Phase**: Unknown
- **Variables**: MATCHED_VAR
- **Operator**: !@beginsWith
- **Pattern**: #:~:text=
- **Is Chain**: False
- **Message**: 
- **Severity**: 
- **Actions**: t:none, setvar:tx.rce_score=+%{tx.critical_anomaly_score}, setvar:tx.inbound_anomaly_score_pl2=+%{tx.critical_anomaly_score}

#### Rule 42: 932220
- **Phase**: 2
- **Variables**: REQUEST_COOKIES, REQUEST_COOKIES_NAMES, ARGS_NAMES, ARGS, XML:/*
- **Operator**: @rx
- **Pattern**: (?i).\|(?:[\s\x0b]*|b[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?u[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?s[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?y[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?b[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?o[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?x|(?:c[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?o[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?m[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?m[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?a[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?n[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?d|e[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?(?:n[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?v|v[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?a[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?l)|w[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?a[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?t[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?c[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?h)[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?(?:[\s\x0b&\),<>\|]|$).*|[ls][\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?t[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?r[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?a[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?c[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?e|n[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?o[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?h[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?u[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?p|t[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?i[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?m[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?e[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?(?:(?:[\s\x0b&\),<>\|]|$).*|o[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?u[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?t)|[\n\r;=`\{]|\|\|?|&&?|\$(?:\(\(?|[\[\{])|<(?:\(|<<)|>\(|\([\s\x0b]*\))[\s\x0b]*(?:[\$\{]|(?:[\s\x0b]*\(|!)[\s\x0b]*|[0-9A-Z_a-z]+=(?:[^\s\x0b]*|\$(?:.*|.*)|[<>].*|'[^']*'|\"[^\"]*\")[\s\x0b]+)*[\s\x0b]*[\"']*(?:[\"'-\+\--9\?A-\]_a-z\|]+/)?[\"'\x5c]*(?:(?:7[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?z[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?(?:[arx][\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?)?|(?:b[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?z[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?z|c[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?(?:[89][\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?9|[au][\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?t|c|(?:m[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?)?p|s[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?h)|d[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?(?:[dfu]|i[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?g)|f[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?(?:[cdgi]|m[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?t|t[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?p)|h[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?(?:d|u[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?p)|i[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?(?:p|r[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?b)|j[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?(?:j[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?s|q)|k[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?s[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?h|m[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?(?:a[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?n|t[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?r|v)|n[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?(?:[cl]|e[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?t|(?:p[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?)?m)|o[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?d|s[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?(?:c[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?p|e[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?[dt]|[gu]|(?:s[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?)?h|v[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?n)|t[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?(?:a[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?[cr]|b[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?l|[co][\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?p|e[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?[ex]|i[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?c)|u[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?(?:d[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?p|l)|(?:v[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?i|y[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?u)[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?m|w[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?(?:3[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?m|c)|x[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?(?:x[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?d|z)|z[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?(?:i[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?p|s[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?h))[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?|e[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?(?:(?:[bx]|n[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?v|q[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?n)[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?|s[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?(?:h[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?)?)|l[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?(?:d[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?(?:d[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?)?|(?:[nps]|u[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?a)[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?|z[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?(?:4[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?)?)|r[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?(?:(?:a[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?r|e[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?[dv]|p[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?m)[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?|c[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?(?:p[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?)?|m[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?(?:t[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?)?))(?:[\s\x0b&\),<>\|]|$).*|a[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?(?:a[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?-[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?(?:(?:[&\),<>\|]|$){1,10}|(?:[\-\.0-9A-Z_a-z][\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?){1,10}(?:[\s\x0b&\),<>\|\}]|$){1,10})|(?:(?:b|(?:p[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?)?t|w[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?[ks])[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?|r[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?(?:[jp][\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?)?|s[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?(?:h[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?)?)(?:[\s\x0b&\),<>\|]|$).*)|g[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?(?:c[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?c[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?(?:(?:[&\),<>\|]|$){1,10}|(?:[\-\.0-9A-Z_a-z][\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?){1,10}(?:[\s\x0b&\),<>\|\}]|$){1,10})|(?:d[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?b|e[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?m|[hr][\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?c|i[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?t|o|p[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?g)[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?(?:[\s\x0b&\),<>\|]|$).*)|p[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?(?:(?:(?:[at][\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?x|d[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?b|f|k[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?g|w[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?d|x[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?z)[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?|r[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?(?:y[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?)?)(?:[\s\x0b&\),<>\|]|$).*|i[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?(?:c[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?(?:[\s\x0b&\),<>\|]|$).*|p[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?(?:(?:[&\),<>\|]|$){1,10}|(?:[\-\.0-9A-Z_a-z][\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?){1,10}(?:[\s\x0b&\),<>\|\}]|$){1,10}|(?:[\s\x0b&\),<>\|]|$).*))))
- **Is Chain**: False
- **Message**: Remote Command Execution: Unix Command Injection with pipe
- **Severity**: CRITICAL
- **Tags**: application-multi, language-shell, platform-unix, attack-rce, paranoia-level/2, OWASP_CRS, OWASP_CRS/ATTACK-RCE, capec/1000/152/248/88
- **Actions**: id:932220, phase:2, block, capture, t:none, msg:Remote Command Execution: Unix Command Injection with pipe, logdata:Matched Data: %{TX.0} found within %{MATCHED_VAR_NAME}: %{MATCHED_VAR}, tag:application-multi, tag:language-shell, tag:platform-unix, tag:attack-rce, tag:paranoia-level/2, tag:OWASP_CRS, tag:OWASP_CRS/ATTACK-RCE, tag:capec/1000/152/248/88, ver:OWASP_CRS/4.22.0-dev, severity:CRITICAL, setvar:tx.rce_score=+%{tx.critical_anomaly_score}, setvar:tx.inbound_anomaly_score_pl2=+%{tx.critical_anomaly_score}

#### Rule 43: 932240
- **Phase**: 2
- **Variables**: REQUEST_COOKIES, REQUEST_COOKIES_NAMES, ARGS, XML:/*
- **Operator**: @rx
- **Pattern**: (?i)[\-0-9_a-z]+(?:[\s\x0b]*[\"'][^\s\x0b\"',:]+[\"']|(?:[\"'][\"']+|[\[-\]]+|\$+[!#\*\-0-9\?@\x5c_a-\{]+|``|[\$<>]\(\))[\s\x0b]*)[\-0-9_a-z]+
- **Is Chain**: True
- **Message**: Remote Command Execution: Unix Command Injection evasion attempt detected
- **Severity**: CRITICAL
- **Tags**: application-multi, language-shell, platform-unix, attack-rce, paranoia-level/2, OWASP_CRS, OWASP_CRS/ATTACK-RCE, capec/1000/152/248/88
- **Actions**: id:932240, phase:2, block, capture, t:none, msg:Remote Command Execution: Unix Command Injection evasion attempt detected, logdata:Matched Data: %{TX.0} found within %{TX.932240_MATCHED_VAR_NAME}: %{MATCHED_VAR}, tag:application-multi, tag:language-shell, tag:platform-unix, tag:attack-rce, tag:paranoia-level/2, tag:OWASP_CRS, tag:OWASP_CRS/ATTACK-RCE, tag:capec/1000/152/248/88, ver:OWASP_CRS/4.22.0-dev, severity:CRITICAL, setvar:tx.932240_matched_var_name=%{matched_var_name}, chain

#### Rule 44: Unknown
- **Phase**: Unknown
- **Variables**: MATCHED_VARS
- **Operator**: !@rx
- **Pattern**: [0-9]\s*\'\s*[0-9]
- **Is Chain**: False
- **Message**: 
- **Severity**: 
- **Actions**: t:none, setvar:tx.rce_score=+%{tx.critical_anomaly_score}, setvar:tx.inbound_anomaly_score_pl2=+%{tx.critical_anomaly_score}

#### Rule 45: 932281
- **Phase**: 2
- **Variables**: REQUEST_COOKIES, REQUEST_COOKIES_NAMES, ARGS_NAMES, ARGS, XML:/*
- **Operator**: @rx
- **Pattern**: \{[^\s\x0b,:\}]*,[^\s\x0b]*\}
- **Is Chain**: False
- **Message**: Remote Command Execution: Brace Expansion Found
- **Severity**: CRITICAL
- **Tags**: application-multi, language-shell, platform-unix, attack-rce, paranoia-level/2, OWASP_CRS, OWASP_CRS/ATTACK-RCE, capec/1000/152/248/88
- **Actions**: id:932281, phase:2, block, capture, t:none, msg:Remote Command Execution: Brace Expansion Found, logdata:Matched Data: %{TX.0} found within %{MATCHED_VAR_NAME}: %{MATCHED_VAR}, tag:application-multi, tag:language-shell, tag:platform-unix, tag:attack-rce, tag:paranoia-level/2, tag:OWASP_CRS, tag:OWASP_CRS/ATTACK-RCE, tag:capec/1000/152/248/88, ver:OWASP_CRS/4.22.0-dev, severity:CRITICAL, setvar:tx.rce_score=+%{tx.critical_anomaly_score}, setvar:tx.inbound_anomaly_score_pl2=+%{tx.critical_anomaly_score}

#### Rule 46: 932210
- **Phase**: 2
- **Variables**: REQUEST_COOKIES, REQUEST_COOKIES_NAMES, ARGS_NAMES, ARGS, XML:/*
- **Operator**: @rx
- **Pattern**: ;[\s\x0b]*\.[\s\x0b]*[\"']?(?:a(?:rchive|uth)|b(?:a(?:ckup|il)|inary)|c(?:d|h(?:anges|eck)|lone|onnection)|d(?:atabases|b(?:config|info)|ump)|e(?:cho|qp|x(?:cel|it|p(?:ert|lain)))|f(?:ilectrl|ullschema)|he(?:aders|lp)|i(?:mpo(?:rt|ster)|ndexes|otrace)|l(?:i(?:mi|n)t|o(?:ad|g))|(?:mod|n(?:onc|ullvalu)|unmodul)e|o(?:nce|pen|utput)|p(?:arameter|r(?:int|o(?:gress|mpt)))|quit|re(?:ad|cover|store)|s(?:ave|c(?:anstats|hema)|e(?:lftest|parator|ssion)|h(?:a3sum|ell|ow)?|tats|ystem)|t(?:ables|estc(?:ase|trl)|ime(?:out|r)|race)|vfs(?:info|list|name)|width)
- **Is Chain**: False
- **Message**: Remote Command Execution: SQLite System Command Execution
- **Severity**: CRITICAL
- **Tags**: application-multi, language-shell, platform-unix, attack-rce, paranoia-level/2, OWASP_CRS, OWASP_CRS/ATTACK-RCE, capec/1000/152/248/88
- **Actions**: id:932210, phase:2, block, capture, t:none, t:escapeSeqDecode, t:compressWhitespace, msg:Remote Command Execution: SQLite System Command Execution, logdata:Matched Data: %{TX.0} found within %{MATCHED_VAR_NAME}: %{MATCHED_VAR}, tag:application-multi, tag:language-shell, tag:platform-unix, tag:attack-rce, tag:paranoia-level/2, tag:OWASP_CRS, tag:OWASP_CRS/ATTACK-RCE, tag:capec/1000/152/248/88, ver:OWASP_CRS/4.22.0-dev, severity:CRITICAL, setvar:tx.rce_score=+%{tx.critical_anomaly_score}, setvar:tx.inbound_anomaly_score_pl2=+%{tx.critical_anomaly_score}

#### Rule 47: 932271
- **Phase**: 2
- **Variables**: REQUEST_COOKIES, REQUEST_COOKIES_NAMES, ARGS_NAMES, ARGS, XML:/*
- **Operator**: @rx
- **Pattern**: ~[0-9]+
- **Is Chain**: False
- **Message**: Remote Command Execution: Unix Shell Expression Found
- **Severity**: CRITICAL
- **Tags**: application-multi, language-shell, platform-unix, attack-rce, paranoia-level/2, OWASP_CRS, OWASP_CRS/ATTACK-RCE, capec/1000/152/248/88
- **Actions**: id:932271, phase:2, block, capture, t:none, t:cmdLine, msg:Remote Command Execution: Unix Shell Expression Found, logdata:Matched Data: %{TX.0} found within %{MATCHED_VAR_NAME}: %{MATCHED_VAR}, tag:application-multi, tag:language-shell, tag:platform-unix, tag:attack-rce, tag:paranoia-level/2, tag:OWASP_CRS, tag:OWASP_CRS/ATTACK-RCE, tag:capec/1000/152/248/88, ver:OWASP_CRS/4.22.0-dev, severity:CRITICAL, setvar:tx.rce_score=+%{tx.critical_anomaly_score}, setvar:tx.inbound_anomaly_score_pl2=+%{tx.critical_anomaly_score}

#### Rule 48: 932300
- **Phase**: 2
- **Variables**: REQUEST_COOKIES, REQUEST_COOKIES_NAMES, ARGS_NAMES, ARGS, XML:/*
- **Operator**: @rx
- **Pattern**: (?i)\r\n.*?\b(?:E(?:HLO[\s\x0b][\-\.a-z]{1,255}|XPN[\s\x0b].{1,64})|HELO[\s\x0b][\-\.a-z]{1,255}|MAIL[\s\x0b]FROM:<.{1,64}@.{1,255}>|R(?:CPT[\s\x0b]TO:(?:<.{1,64}@.{1,255}>| )?<.{1,64}>|SET\b)|VRFY[\s\x0b].{1,64}(?:[\s\x0b]<.{1,64}@.{1,255}>|@.{1,255})|AUTH[\s\x0b][\-0-9_a-z]{1,20}[\s\x0b](?:(?:[\+/-9A-Z_a-z]{4})*(?:[\+/-9A-Z_a-z]{2}=|[\+/-9A-Z_a-z]{3}))?=|STARTTLS\b|NOOP\b(?:[\s\x0b].{1,255})?)
- **Is Chain**: False
- **Message**: Remote Command Execution: SMTP Command Execution
- **Severity**: CRITICAL
- **Tags**: application-multi, platform-multi, attack-rce, paranoia-level/2, OWASP_CRS, OWASP_CRS/ATTACK-RCE, capec/137/134
- **Actions**: id:932300, phase:2, block, capture, t:none, t:escapeSeqDecode, msg:Remote Command Execution: SMTP Command Execution, logdata:Matched Data: %{TX.0} found within %{MATCHED_VAR_NAME}: %{MATCHED_VAR}, tag:application-multi, tag:platform-multi, tag:attack-rce, tag:paranoia-level/2, tag:OWASP_CRS, tag:OWASP_CRS/ATTACK-RCE, tag:capec/137/134, ver:OWASP_CRS/4.22.0-dev, severity:CRITICAL, setvar:tx.rce_score=+%{tx.critical_anomaly_score}, setvar:tx.inbound_anomaly_score_pl2=+%{tx.critical_anomaly_score}

#### Rule 49: 932310
- **Phase**: 2
- **Variables**: REQUEST_COOKIES, REQUEST_COOKIES_NAMES, ARGS_NAMES, ARGS, XML:/*
- **Operator**: @rx
- **Pattern**: (?is)\r\n[0-9A-Z_a-z]{1,50}\b (?:A(?:PPEND (?:[\"#%&\*\--9A-Z\x5c_a-z]+)?(?: \([ \x5ca-z]+\))?(?: \"?[0-9]{1,2}-[0-9A-Z_a-z]{3}-[0-9]{4} [0-9]{2}:[0-9]{2}:[0-9]{2} [\+\-][0-9]{4}\"?)? \{[0-9]{1,20}\+?\}|UTHENTICATE [\-0-9_a-z]{1,20}\r\n)|L(?:SUB (?:[\"#\*\.-9A-Z_a-z~]+)? (?:[\"%&\*\.-9A-Z\x5c_a-z]+)?|ISTRIGHTS (?:[\"%&\*\--9A-Z\x5c_a-z]+)?)|S(?:TATUS (?:[\"%&\*\--9A-Z\x5c_a-z]+)? \((?:U(?:NSEEN|IDNEXT)|MESSAGES|UIDVALIDITY|RECENT| )+\)|ETACL (?:[\"%&\*\--9A-Z\x5c_a-z]+)? [\+\-][ac-eiklpr-twx]+?)|UID (?:COPY|FETCH|STORE) (?:[\*,0-:]+)?|(?:(?:DELETE|GET)ACL|MYRIGHTS) (?:[\"%&\*\--9A-Z\x5c_a-z]+)?)
- **Is Chain**: False
- **Message**: Remote Command Execution: IMAP Command Execution
- **Severity**: CRITICAL
- **Tags**: application-multi, platform-multi, attack-rce, paranoia-level/2, OWASP_CRS, OWASP_CRS/ATTACK-RCE, capec/137/134
- **Actions**: id:932310, phase:2, block, capture, t:none, t:escapeSeqDecode, msg:Remote Command Execution: IMAP Command Execution, logdata:Matched Data: %{TX.0} found within %{MATCHED_VAR_NAME}: %{MATCHED_VAR}, tag:application-multi, tag:platform-multi, tag:attack-rce, tag:paranoia-level/2, tag:OWASP_CRS, tag:OWASP_CRS/ATTACK-RCE, tag:capec/137/134, ver:OWASP_CRS/4.22.0-dev, severity:CRITICAL, setvar:tx.rce_score=+%{tx.critical_anomaly_score}, setvar:tx.inbound_anomaly_score_pl2=+%{tx.critical_anomaly_score}

#### Rule 50: 932320
- **Phase**: 2
- **Variables**: REQUEST_COOKIES, REQUEST_COOKIES_NAMES, ARGS_NAMES, ARGS, XML:/*
- **Operator**: @rx
- **Pattern**: (?is)\r\n.*?\b(?:(?:LIST|TOP [0-9]+)(?: [0-9]+)?|U(?:SER .+?|IDL(?: [0-9]+)?)|PASS .+?|(?:RETR|DELE) [0-9]+?|A(?:POP [0-9A-Z_a-z]+ [0-9a-f]{32}|UTH [\-0-9_a-z]{1,20} (?:(?:[\+/-9A-Z_a-z]{4})*(?:[\+/-9A-Z_a-z]{2}=|[\+/-9A-Z_a-z]{3}))?=))
- **Is Chain**: False
- **Message**: Remote Command Execution: POP3 Command Execution
- **Severity**: CRITICAL
- **Tags**: application-multi, platform-multi, attack-rce, paranoia-level/2, OWASP_CRS, OWASP_CRS/ATTACK-RCE, capec/137/134
- **Actions**: id:932320, phase:2, block, capture, t:none, t:escapeSeqDecode, msg:Remote Command Execution: POP3 Command Execution, logdata:Matched Data: %{TX.0} found within %{MATCHED_VAR_NAME}: %{MATCHED_VAR}, tag:application-multi, tag:platform-multi, tag:attack-rce, tag:paranoia-level/2, tag:OWASP_CRS, tag:OWASP_CRS/ATTACK-RCE, tag:capec/137/134, ver:OWASP_CRS/4.22.0-dev, severity:CRITICAL, setvar:tx.rce_score=+%{tx.critical_anomaly_score}, setvar:tx.inbound_anomaly_score_pl2=+%{tx.critical_anomaly_score}

#### Rule 51: 932236
- **Phase**: 2
- **Variables**: REQUEST_COOKIES, REQUEST_COOKIES_NAMES, ARGS_NAMES, ARGS, XML:/*
- **Operator**: @rx
- **Pattern**: (?i)(?:^|b[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?u[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?s[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?y[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?b[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?o[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?x|(?:c[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?o[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?m[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?m[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?a[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?n[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?d|e[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?(?:n[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?v|v[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?a[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?l)|w[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?a[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?t[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?c[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?h)[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?(?:[\s\x0b&\),<>\|]|$).*|[ls][\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?t[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?r[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?a[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?c[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?e|n[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?o[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?h[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?u[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?p|t[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?i[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?m[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?e[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?(?:(?:[\s\x0b&\),<>\|]|$).*|o[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?u[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?t)|[\n\r;=`\{]|\|\|?|&&?|\$(?:\(\(?|[\[\{])|<(?:\(|<<)|>\(|\([\s\x0b]*\))[\s\x0b]*(?:[\$\{]|(?:[\s\x0b]*\(|!)[\s\x0b]*|[0-9A-Z_a-z]+=(?:[^\s\x0b]*|\$(?:.*|.*)|[<>].*|'[^']*'|\"[^\"]*\")[\s\x0b]+)*[\s\x0b]*[\"']*(?:[\"'-\+\--9\?A-\]_a-z\|]+/)?[\"'\x5c]*(?:7z(?:[\s\x0b&\),<>\|]|$|[arx](?:[\s\x0b&\),<>\|]|$))|a(?:a-[^\s\x0b]{1,10}\b|(?:b|w[ks]|l(?:ias|pine)|tobm|xel)(?:[\s\x0b&\),<>\|]|$)|p(?:t(?:[\s\x0b&\),<>\|]|$|-get)|parmor_[^\s\x0b]{1,10}\b)|r(?:[\s\x0b&\),<>\|]|$|j(?:[\s\x0b&\),<>\|]|$|-register|disp)|(?:p|ch)(?:[\s\x0b&\),<>\|]|$)|ia2c)|s(?:h(?:[\s\x0b&\),<>\|]|$)|cii(?:-xfr|85)|pell)|dd(?:group|user)|getty|nsible|u(?:ditctl|repot|search))|b(?:z(?:(?:z|c(?:at|mp))(?:[\s\x0b&\),<>\|]|$)|diff|e(?:grep|xe(?:[\s\x0b&\),<>\|]|$))|f?grep|ip2(?:[\s\x0b&\),<>\|]|$|recover)|less|more)|a(?:s(?:e(?:32|64|n(?:ame(?:[\s\x0b&\),<>\|]|$)|c))|h(?:[\s\x0b&\),<>\|]|$))|tch(?:[\s\x0b&\),<>\|]|$))|lkid(?:[\s\x0b&\),<>\|]|$)|pftrace|r(?:eaksw|(?:idge|wap)(?:[\s\x0b&\),<>\|]|$))|sd(?:cat|iff|tar)|u(?:iltin|n(?:dler(?:[\s\x0b&\),<>\|]|$)|zip2)|s(?:ctl|ybox))|y(?:ebug|obu(?:[\s\x0b&\),<>\|]|$)))|c(?:[89]9(?:[\s\x0b&\),<>\|]|$|-gcc)|(?:a(?:t|ncel|psh)|c|mp)(?:[\s\x0b&\),<>\|]|$)|p(?:[\s\x0b&\),<>\|]|$|(?:an|io)(?:[\s\x0b&\),<>\|]|$)|ulimit)|s(?:(?:h|cli)(?:[\s\x0b&\),<>\|]|$)|plit|vtool)|u(?:(?:t|rl)(?:[\s\x0b&\),<>\|]|$)|psfilter)|ertbot|h(?:(?:(?:att|di)r|mod|o(?:om|wn)|root|sh)(?:[\s\x0b&\),<>\|]|$)|e(?:ck_(?:by_ssh|cups|log|memory|raid|s(?:sl_cert|tatusfile))|f(?:[\s\x0b&\),\-<>\|]|$))|(?:flag|pas)s|g(?:passwd|rp(?:[\s\x0b&\),<>\|]|$)))|lang(?:\+\+|[\s\x0b&\),<>\|]|$)|o(?:bc(?:[\s\x0b&\),<>\|]|$|run)|lumn(?:[\s\x0b&\),<>\|]|$)|m(?:m(?:[\s\x0b&\),<>\|]|$|and(?:[\s\x0b&\),<>\|]|$))|p(?:oser|ress)(?:[\s\x0b&\),<>\|]|$))|proc|w(?:say|think))|r(?:ash(?:[\s\x0b&\),<>\|]|$)|ontab))|d(?:(?:[dfu]|i(?:(?:alo)?g|ff)|ash|vips)(?:[\s\x0b&\),<>\|]|$)|hclient|m(?:esg(?:[\s\x0b&\),<>\|]|$)|idecode|setup)|o(?:(?:as|ne)(?:[\s\x0b&\),<>\|]|$)|cker(?:[\s\x0b&\),\-<>\|]|$)|sbox)|pkg(?:[\s\x0b&\),\-<>\|]|$))|e(?:(?:b|qn|cho|fax|grep|macs|val)(?:[\s\x0b&\),<>\|]|$)|n(?:v(?:[\s\x0b&\),<>\|]|$|-update)|d(?:if|sw)(?:[\s\x0b&\),<>\|]|$))|s(?:[\s\x0b&\),<>\|]|$|(?:h|ac)(?:[\s\x0b&\),<>\|]|$))|x(?:[\s\x0b&\),<>\|]|$|(?:ec|p(?:and|(?:ec|or)t|r))(?:[\s\x0b&\),<>\|]|$)|iftool)|2fsck|asy_install)|f(?:(?:c|mt|etch|lock|unction)(?:[\s\x0b&\),<>\|]|$)|d(?:[\s\x0b&\),<>\|]|$|(?:find|isk)(?:[\s\x0b&\),<>\|]|$)|u?mount)|g(?:[\s\x0b&\),<>\|]|$|rep(?:[\s\x0b&\),<>\|]|$))|i(?:[\s\x0b&\),<>\|]|$|letest|(?:n(?:d|ger)|sh)(?:[\s\x0b&\),<>\|]|$))|tp(?:[\s\x0b&\),<>\|]|$|stats|who)|acter|o(?:ld(?:[\s\x0b&\),<>\|]|$)|reach)|ping(?:[\s\x0b&\),6<>\|]|$))|g(?:c(?:c[^\s\x0b]{1,10}\b|ore(?:[\s\x0b&\),<>\|]|$))|(?:db|i(?:t|mp|nsh)|o|pg|awk|z(?:cat|exe|ip))(?:[\s\x0b&\),<>\|]|$)|e(?:m(?:[\s\x0b&\),<>\|]|$)|ni(?:e(?:[\s\x0b&\),<>\|]|$)|soimage)|t(?:cap|facl(?:[\s\x0b&\),<>\|]|$)))|hc(?:[\s\x0b&\),<>\|]|$|-(?:[\s\x0b&\),<>\|]|$)|i(?:[\s\x0b&\),\-<>\|]|$))|r(?:c(?:[\s\x0b&\),<>\|]|$|at(?:[\s\x0b&\),<>\|]|$))|ep(?:[\s\x0b&\),<>\|]|$)|oup(?:[\s\x0b&\),<>\|]|$|mod))|tester|unzip)|h(?:(?:d|up|i(?:ghlight|story))(?:[\s\x0b&\),<>\|]|$)|e(?:ad(?:[\s\x0b&\),<>\|]|$)|xdump)|ost(?:id|name)|ping3|t(?:digest|op(?:[\s\x0b&\),<>\|]|$)|passwd))|i(?:p(?:[\s\x0b&\),<>\|]|$|6?tables|config|p(?:eveprinter|find|tool))|(?:rb|conv)(?:[\s\x0b&\),<>\|]|$)|f(?:config|top(?:[\s\x0b&\),<>\|]|$))|onice|spell)|j(?:(?:js|q|exec)(?:[\s\x0b&\),<>\|]|$)|o(?:(?:bs|in)(?:[\s\x0b&\),<>\|]|$)|urnalctl)|runscript)|k(?:s(?:h(?:[\s\x0b&\),<>\|]|$)|shell)|ill(?:[\s\x0b&\),<>\|]|$|all)|nife(?:[\s\x0b&\),<>\|]|$))|l(?:d(?:[\s\x0b&\),<>\|]|$|d(?:[\s\x0b&\),<>\|]|$)|config)|(?:[np]|inks|ynx)(?:[\s\x0b&\),<>\|]|$)|s(?:[\s\x0b&\),<>\|]|$|(?:-F|cpu|hw|mod|of|pci|usb)(?:[\s\x0b&\),<>\|]|$)|b_release)|ua(?:[\s\x0b&\),<>\|]|$|(?:la)?tex)|z(?:4(?:[\s\x0b&\),<>\|]|$|c(?:[\s\x0b&\),<>\|]|$|at))|(?:c(?:at|mp))?(?:[\s\x0b&\),<>\|]|$)|diff|[ef]?grep|less|m(?:a(?:[\s\x0b&\),<>\|]|$|dec|info)|ore))|a(?:st(?:[\s\x0b&\),<>\|]|$|comm(?:[\s\x0b&\),<>\|]|$)|log(?:in)?)|tex(?:[\s\x0b&\),<>\|]|$))|ess(?:[\s\x0b&\),<>\|]|$|echo|(?:fil|pip)e)|ftp(?:[\s\x0b&\),<>\|]|$|get)|o(?:(?:ca(?:l|te)|ok)(?:[\s\x0b&\),<>\|]|$)|g(?:inctl|(?:nam|sav)e)|setup)|trace|wp-(?:d(?:ownload|ump)|mirror|request))|m(?:a(?:(?:n|il[qx]|ke|wk)(?:[\s\x0b&\),<>\|]|$)|ster\.passwd)|(?:tr|v|utt)(?:[\s\x0b&\),<>\|]|$)|k(?:(?:dir|nod)(?:[\s\x0b&\),<>\|]|$)|fifo|temp)|locate|o(?:squitto|unt(?:[\s\x0b&\),<>\|]|$))|sg(?:attrib|c(?:at|onv)|filter|merge|uniq)|ysql(?:[\s\x0b&\),<>\|]|$|admin|dump(?:slow)?|hotcopy|show))|n(?:c(?:[\s\x0b&\),<>\|]|$|\.(?:openbsd|traditional)|at(?:[\s\x0b&\),<>\|]|$))|e(?:t(?:[\s\x0b&\),<>\|]|$|(?:c|st)at|kit-ftp|plan)|ofetch)|(?:l|p(?:m|ing)|a(?:no|sm|wk)|ice|o(?:de|hup)|roff)(?:[\s\x0b&\),<>\|]|$)|m(?:[\s\x0b&\),<>\|]|$|ap(?:[\s\x0b&\),<>\|]|$))|s(?:enter|lookup|tat(?:[\s\x0b&\),<>\|]|$)))|o(?:(?:d|ctave)(?:[\s\x0b&\),<>\|]|$)|nintr|p(?:en(?:ssl|v(?:pn|t))|kg(?:[\s\x0b&\),<>\|]|$)))|p(?:a(?:(?:x|rted|tch)(?:[\s\x0b&\),<>\|]|$)|s(?:swd|te(?:[\s\x0b&\),<>\|]|$)))|d(?:b(?:[\s\x0b&\),<>\|]|$|2mb|3(?:[\s\x0b&\),\.<>\|]|$))|f(?:la)?tex|ksh(?:[\s\x0b&\),<>\|]|$))|f(?:[\s\x0b&\),<>\|]|$|tp(?:[\s\x0b&\),<>\|]|$))|i(?:c(?:[\s\x0b&\),<>\|]|$|o(?:[\s\x0b&\),<>\|]|$))|p(?:[^\s\x0b]{1,10}\b|[\s\x0b&\),<>\|]|$)|dstat|(?:gz|ng6?)(?:[\s\x0b&\),<>\|]|$))|k(?:g(?:[\s\x0b&\),<>\|]|$|_?info)|exec|ill(?:[\s\x0b&\),<>\|]|$))|r(?:[\s\x0b&\),<>\|]|$|y(?:[\s\x0b&\),<>\|]|$)|int(?:env|f(?:[\s\x0b&\),<>\|]|$)))|t(?:x(?:[\s\x0b&\),<>\|]|$)|ar(?:[\s\x0b&\),<>\|]|$|diff|grep))|wd(?:[\s\x0b&\),<>\|]|$|\.db)|(?:xz|grep|opd|u(?:ppet|shd))(?:[\s\x0b&\),<>\|]|$)|er(?:(?:f|ms)(?:[\s\x0b&\),<>\|]|$)|l(?:5?(?:[\s\x0b&\),<>\|]|$)|sh))|hp(?:-cgi|[57](?:[\s\x0b&\),<>\|]|$))|s(?:(?:ed|ql)(?:[\s\x0b&\),<>\|]|$)|ftp)|y(?:3?versions|thon(?:[23]|[^\s\x0b]{1,10}\b)))|r(?:(?:a(?:r|k[eu])|bash|nano|oute|vi(?:ew|m))(?:[\s\x0b&\),<>\|]|$)|c(?:[\s\x0b&\),<>\|]|$|p(?:[\s\x0b&\),<>\|]|$))|e(?:d(?:[\s\x0b&\),<>\|]|$|carpet(?:[\s\x0b&\),<>\|]|$))|(?:v|boot|place)(?:[\s\x0b&\),<>\|]|$)|a(?:delf|lpath)|stic)|m(?:[\s\x0b&\),<>\|]|$|t(?:[\s\x0b&\),<>\|]|$|-(?:dump|tar))|dir(?:[\s\x0b&\),<>\|]|$)|user)|pm(?:[\s\x0b&\),<>\|]|$|db(?:[\s\x0b&\),<>\|]|$)|(?:quer|verif)y)|l(?:ogin|wrap)|sync(?:-ssl|[\s\x0b&\),<>\|]|$)|u(?:by[^\s\x0b]{1,10}\b|n(?:-(?:mailcap|parts)|c(?:[\s\x0b&\),<>\|]|$))))|s(?:(?:c(?:p|hed|ript)|g|ash|diff|(?:ft|na)p|l(?:eep|sh))(?:[\s\x0b&\),<>\|]|$)|e(?:(?:d|ndmail|rvice)(?:[\s\x0b&\),<>\|]|$)|t(?:[\s\x0b&\),<>\|]|$|arch|cap|env|facl(?:[\s\x0b&\),<>\|]|$)|sid))|h(?:[\s\x0b&\),<>\|]|$|\.distrib|(?:adow|ells|u(?:f|tdown))(?:[\s\x0b&\),<>\|]|$))|sh(?:[\s\x0b&\),<>\|]|$|-(?:a(?:dd|gent)|copy-id|key(?:ge|sca)n)|pass)|u(?:[\s\x0b&\),<>\|]|$|do(?:-rs|[\s\x0b&\),<>_\|]|$|edit|replay))|vn(?:[\s\x0b&\),<>\|]|$|a(?:dmin|uthz)|bench|dumpfilter|fsfs|look|mucc|rdump|s(?:erve|ync)|version)|mbclient|o(?:cat(?:[\s\x0b&\),<>\|]|$)|elim)|p(?:lit(?:[\s\x0b&\),<>\|]|$)|wd\.db)|qlite3|t(?:art-stop-daemon|d(?:buf|err|in(?:[\s\x0b&\),<>\|]|$)|out)|r(?:ace|ings(?:[\s\x0b&\),<>\|]|$)))|ys(?:ctl|tem(?:ctl|d-resolve)))|t(?:a(?:[cr](?:[\s\x0b&\),<>\|]|$)|il(?:[\s\x0b&\),<>\|]|$|f(?:[\s\x0b&\),<>\|]|$))|skset)|(?:bl|o(?:p|uch)|ftp|mux)(?:[\s\x0b&\),<>\|]|$)|c(?:p(?:[\s\x0b&\),<>\|]|$|dump|ing|traceroute)|l?sh(?:[\s\x0b&\),<>\|]|$))|e(?:[ex](?:[\s\x0b&\),<>\|]|$)|lnet)|i(?:c(?:[\s\x0b&\),<>\|]|$)|medatectl)|r(?:aceroute6?|off(?:[\s\x0b&\),<>\|]|$))|shark)|u(?:dp(?:[\s\x0b&\),<>\|]|$)|l(?:[\s\x0b&\),<>\|]|$|imit(?:[\s\x0b&\),<>\|]|$))|n(?:(?:compress|iq|rar|s(?:et|hare)|xz)(?:[\s\x0b&\),<>\|]|$)|expand|l(?:ink(?:[\s\x0b&\),<>\|]|$)|z(?:4(?:[\s\x0b&\),<>\|]|$)|ma))|pigz|z(?:ip(?:[\s\x0b&\),<>\|]|$)|std))|pdate-alternatives|ser(?:(?:ad|mo)d|del)|u(?:de|en)code)|v(?:i(?:m(?:[\s\x0b&\),<>\|]|$|diff)|(?:gr|pw|rsh)(?:[\s\x0b&\),<>\|]|$)|sudo(?:-rs)?)|algrind|olatility(?:[\s\x0b&\),<>\|]|$))|w(?:(?:3m|c|atch|get)(?:[\s\x0b&\),<>\|]|$)|h(?:iptail(?:[\s\x0b&\),<>\|]|$)|oami)|i(?:reshark|sh(?:[\s\x0b&\),<>\|]|$)))|x(?:(?:(?:x|pa)d|args|term)(?:[\s\x0b&\),<>\|]|$)|z(?:[\s\x0b&\),<>\|]|$|c(?:at|mp)(?:[\s\x0b&\),<>\|]|$)|d(?:ec(?:[\s\x0b&\),<>\|]|$)|iff)|[ef]?grep|less|more)|e(?:latex|tex(?:[\s\x0b&\),<>\|]|$))|mo(?:dmap|re(?:[\s\x0b&\),<>\|]|$)))|y(?:um|arn|elp)(?:[\s\x0b&\),<>\|]|$)|z(?:ip(?:[\s\x0b&\),<>\|]|$|c(?:loak|mp)|details|grep|info|(?:merg|not)e|split|tool)|s(?:h(?:[\s\x0b&\),<>\|]|$)|oelim|td(?:[\s\x0b&\),<>\|]|$|(?:ca|m)t|grep|less))|athura|(?:c(?:at|mp)|diff|grep|less|run)(?:[\s\x0b&\),<>\|]|$)|e(?:grep|ro(?:[\s\x0b&\),<>\|]|$))|fgrep|mo(?:dload|re(?:[\s\x0b&\),<>\|]|$))|ypper))
- **Is Chain**: False
- **Message**: Remote Command Execution: Unix Command Injection (command without evasion)
- **Severity**: CRITICAL
- **Tags**: application-multi, language-shell, platform-unix, attack-rce, paranoia-level/2, OWASP_CRS, OWASP_CRS/ATTACK-RCE, capec/1000/152/248/88
- **Actions**: id:932236, phase:2, block, capture, t:none, msg:Remote Command Execution: Unix Command Injection (command without evasion), logdata:Matched Data: %{TX.0} found within %{MATCHED_VAR_NAME}: %{MATCHED_VAR}, tag:application-multi, tag:language-shell, tag:platform-unix, tag:attack-rce, tag:paranoia-level/2, tag:OWASP_CRS, tag:OWASP_CRS/ATTACK-RCE, tag:capec/1000/152/248/88, ver:OWASP_CRS/4.22.0-dev, severity:CRITICAL, setvar:tx.rce_score=+%{tx.critical_anomaly_score}, setvar:tx.inbound_anomaly_score_pl2=+%{tx.critical_anomaly_score}

#### Rule 52: 932239
- **Phase**: 1
- **Variables**: REQUEST_HEADERS:User-Agent, REQUEST_HEADERS:Referer
- **Operator**: @rx
- **Pattern**: (?i)(?:^|b[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?u[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?s[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?y[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?b[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?o[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?x|(?:c[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?o[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?m[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?m[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?a[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?n[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?d|e[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?(?:n[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?v|v[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?a[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?l)|w[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?a[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?t[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?c[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?h)[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?(?:[\s\x0b&\),<>\|]|$).*|[ls][\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?t[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?r[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?a[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?c[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?e|n[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?o[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?h[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?u[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?p|t[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?i[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?m[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?e[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?(?:(?:[\s\x0b&\),<>\|]|$).*|o[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?u[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?t)|[\n\r;=`\{]|\|\|?|&&?|\$(?:\(\(?|[\[\{])|<(?:\(|<<)|>\(|\([\s\x0b]*\))[\s\x0b]*(?:[\$\{]|(?:[\s\x0b]*\(|!)[\s\x0b]*|[0-9A-Z_a-z]+=(?:[^\s\x0b]*|\$(?:.*|.*)|[<>].*|'[^']*'|\"[^\"]*\")[\s\x0b]+)*[\s\x0b]*[\"']*(?:[\"'-\+\--9\?A-\]_a-z\|]+/)?[\"'\x5c]*(?:7z(?:[\s\x0b&\),<>\|]|$|[arx](?:[\s\x0b&\),<>\|]|$))|a(?:a-[^\s\x0b]{1,10}\b|(?:b|w[ks]|l(?:ias|pine)|tobm|xel)(?:[\s\x0b&\),<>\|]|$)|p(?:t(?:[\s\x0b&\),<>\|]|$|-get)|parmor_[^\s\x0b]{1,10}\b)|r(?:[\s\x0b&\),<>\|]|$|j(?:[\s\x0b&\),<>\|]|$|-register|disp)|(?:p|ch)(?:[\s\x0b&\),<>\|]|$)|ia2c)|s(?:h(?:[\s\x0b&\),<>\|]|$)|cii(?:-xfr|85)|pell)|dd(?:group|user)|getty|nsible|u(?:ditctl|repot|search))|b(?:z(?:(?:z|c(?:at|mp))(?:[\s\x0b&\),<>\|]|$)|diff|e(?:grep|xe(?:[\s\x0b&\),<>\|]|$))|f?grep|ip2(?:[\s\x0b&\),<>\|]|$|recover)|less|more)|a(?:s(?:e(?:32|64|n(?:ame(?:[\s\x0b&\),<>\|]|$)|c))|h(?:[\s\x0b&\),<>\|]|$))|tch(?:[\s\x0b&\),<>\|]|$))|lkid(?:[\s\x0b&\),<>\|]|$)|pftrace|r(?:eaksw|(?:idge|wap)(?:[\s\x0b&\),<>\|]|$))|sd(?:cat|iff|tar)|u(?:iltin|n(?:dler(?:[\s\x0b&\),<>\|]|$)|zip2)|s(?:ctl|ybox))|y(?:ebug|obu(?:[\s\x0b&\),<>\|]|$)))|c(?:[89]9(?:[\s\x0b&\),<>\|]|$|-gcc)|(?:a(?:t|ncel|psh)|c|mp)(?:[\s\x0b&\),<>\|]|$)|p(?:[\s\x0b&\),<>\|]|$|io(?:[\s\x0b&\),<>\|]|$)|ulimit)|s(?:(?:h|cli)(?:[\s\x0b&\),<>\|]|$)|plit|vtool)|u(?:t(?:[\s\x0b&\),<>\|]|$)|psfilter)|ertbot|h(?:(?:(?:att|di)r|mod|o(?:om|wn)|root|sh)(?:[\s\x0b&\),<>\|]|$)|e(?:ck_(?:by_ssh|cups|log|memory|raid|s(?:sl_cert|tatusfile))|f(?:[\s\x0b&\),\-<>\|]|$))|(?:flag|pas)s|g(?:passwd|rp(?:[\s\x0b&\),<>\|]|$)))|lang(?:\+\+|[\s\x0b&\),<>\|]|$)|o(?:bc(?:[\s\x0b&\),<>\|]|$|run)|lumn(?:[\s\x0b&\),<>\|]|$)|m(?:m(?:[\s\x0b&\),<>\|]|$|and(?:[\s\x0b&\),<>\|]|$))|p(?:oser|ress)(?:[\s\x0b&\),<>\|]|$))|proc|w(?:say|think))|r(?:ash(?:[\s\x0b&\),<>\|]|$)|ontab))|d(?:(?:[dfu]|i(?:(?:alo)?g|ff)|ash|vips)(?:[\s\x0b&\),<>\|]|$)|hclient|m(?:esg(?:[\s\x0b&\),<>\|]|$)|idecode|setup)|o(?:(?:as|ne)(?:[\s\x0b&\),<>\|]|$)|cker(?:[\s\x0b&\),\-<>\|]|$)|sbox)|pkg(?:[\s\x0b&\),\-<>\|]|$))|e(?:(?:b|qn|cho|fax|grep|macs|val)(?:[\s\x0b&\),<>\|]|$)|n(?:v(?:[\s\x0b&\),<>\|]|$|-update)|d(?:if|sw)(?:[\s\x0b&\),<>\|]|$))|s(?:[\s\x0b&\),<>\|]|$|(?:h|ac)(?:[\s\x0b&\),<>\|]|$))|x(?:[\s\x0b&\),<>\|]|$|(?:ec|p(?:and|(?:ec|or)t|r))(?:[\s\x0b&\),<>\|]|$)|iftool)|2fsck|asy_install)|f(?:(?:c|mt|etch|lock|unction)(?:[\s\x0b&\),<>\|]|$)|d(?:[\s\x0b&\),<>\|]|$|(?:find|isk)(?:[\s\x0b&\),<>\|]|$)|u?mount)|g(?:[\s\x0b&\),<>\|]|$|rep(?:[\s\x0b&\),<>\|]|$))|i(?:[\s\x0b&\),<>\|]|$|letest|(?:n(?:d|ger)|sh)(?:[\s\x0b&\),<>\|]|$))|tp(?:[\s\x0b&\),<>\|]|$|stats|who)|acter|o(?:ld(?:[\s\x0b&\),<>\|]|$)|reach)|ping(?:[\s\x0b&\),6<>\|]|$))|g(?:c(?:c[^\s\x0b]{1,10}\b|ore(?:[\s\x0b&\),<>\|]|$))|(?:db|i(?:t|mp|nsh)|o|pg|awk|z(?:cat|exe|ip))(?:[\s\x0b&\),<>\|]|$)|e(?:m(?:[\s\x0b&\),<>\|]|$)|ni(?:e(?:[\s\x0b&\),<>\|]|$)|soimage)|t(?:cap|facl(?:[\s\x0b&\),<>\|]|$)))|hc(?:[\s\x0b&\),<>\|]|$|-(?:[\s\x0b&\),<>\|]|$)|i(?:[\s\x0b&\),\-<>\|]|$))|r(?:c(?:[\s\x0b&\),<>\|]|$|at(?:[\s\x0b&\),<>\|]|$))|ep(?:[\s\x0b&\),<>\|]|$)|oup(?:[\s\x0b&\),<>\|]|$|mod))|tester|unzip)|h(?:(?:d|up|i(?:ghlight|story))(?:[\s\x0b&\),<>\|]|$)|e(?:ad(?:[\s\x0b&\),<>\|]|$)|xdump)|ost(?:id|name)|ping3|t(?:digest|op(?:[\s\x0b&\),<>\|]|$)|passwd))|i(?:p(?:[\s\x0b&\),<>\|]|$|6?tables|config|p(?:eveprinter|find|tool))|(?:rb|conv)(?:[\s\x0b&\),<>\|]|$)|f(?:config|top(?:[\s\x0b&\),<>\|]|$))|onice|spell)|j(?:(?:js|q|exec)(?:[\s\x0b&\),<>\|]|$)|o(?:(?:bs|in)(?:[\s\x0b&\),<>\|]|$)|urnalctl)|runscript)|k(?:s(?:h(?:[\s\x0b&\),<>\|]|$)|shell)|ill(?:[\s\x0b&\),<>\|]|$|all)|nife(?:[\s\x0b&\),<>\|]|$))|l(?:d(?:[\s\x0b&\),<>\|]|$|d(?:[\s\x0b&\),<>\|]|$)|config)|(?:[np]|ynx)(?:[\s\x0b&\),<>\|]|$)|s(?:[\s\x0b&\),<>\|]|$|(?:-F|cpu|hw|mod|of|pci|usb)(?:[\s\x0b&\),<>\|]|$)|b_release)|ua(?:[\s\x0b&\),<>\|]|$|(?:la)?tex)|z(?:4(?:[\s\x0b&\),<>\|]|$|c(?:[\s\x0b&\),<>\|]|$|at))|(?:c(?:at|mp))?(?:[\s\x0b&\),<>\|]|$)|diff|[ef]?grep|less|m(?:a(?:[\s\x0b&\),<>\|]|$|dec|info)|ore))|a(?:st(?:[\s\x0b&\),<>\|]|$|comm(?:[\s\x0b&\),<>\|]|$)|log(?:in)?)|tex(?:[\s\x0b&\),<>\|]|$))|ess(?:[\s\x0b&\),<>\|]|$|echo|(?:fil|pip)e)|ftp(?:[\s\x0b&\),<>\|]|$|get)|o(?:(?:ca(?:l|te)|ok)(?:[\s\x0b&\),<>\|]|$)|g(?:inctl|(?:nam|sav)e)|setup)|trace|wp-(?:d(?:ownload|ump)|mirror|request))|m(?:a(?:(?:n|il[qx]|ke|wk)(?:[\s\x0b&\),<>\|]|$)|ster\.passwd)|(?:tr|v|utt)(?:[\s\x0b&\),<>\|]|$)|k(?:(?:dir|nod)(?:[\s\x0b&\),<>\|]|$)|fifo|temp)|locate|o(?:squitto|unt(?:[\s\x0b&\),<>\|]|$))|sg(?:attrib|c(?:at|onv)|filter|merge|uniq)|ysql(?:[\s\x0b&\),<>\|]|$|admin|dump(?:slow)?|hotcopy|show))|n(?:c(?:[\s\x0b&\),<>\|]|$|\.(?:openbsd|traditional)|at(?:[\s\x0b&\),<>\|]|$))|e(?:t(?:[\s\x0b&\),<>\|]|$|(?:c|st)at|kit-ftp|plan)|ofetch)|(?:l|p(?:m|ing)|a(?:no|sm|wk)|ice|o(?:de|hup)|roff)(?:[\s\x0b&\),<>\|]|$)|m(?:[\s\x0b&\),<>\|]|$|ap(?:[\s\x0b&\),<>\|]|$))|s(?:enter|lookup|tat(?:[\s\x0b&\),<>\|]|$)))|o(?:(?:d|ctave)(?:[\s\x0b&\),<>\|]|$)|nintr|p(?:en(?:ssl|v(?:pn|t))|kg(?:[\s\x0b&\),<>\|]|$)))|p(?:a(?:(?:x|rted|tch)(?:[\s\x0b&\),<>\|]|$)|s(?:swd|te(?:[\s\x0b&\),<>\|]|$)))|d(?:b(?:[\s\x0b&\),<>\|]|$|2mb|3(?:[\s\x0b&\),\.<>\|]|$))|f(?:la)?tex|ksh(?:[\s\x0b&\),<>\|]|$))|f(?:[\s\x0b&\),<>\|]|$|tp(?:[\s\x0b&\),<>\|]|$))|i(?:c(?:[\s\x0b&\),<>\|]|$|o(?:[\s\x0b&\),<>\|]|$))|p(?:[^\s\x0b]{1,10}\b|[\s\x0b&\),<>\|]|$)|dstat|(?:gz|ng6?)(?:[\s\x0b&\),<>\|]|$))|k(?:g(?:[\s\x0b&\),<>\|]|$|_?info)|exec|ill(?:[\s\x0b&\),<>\|]|$))|r(?:[\s\x0b&\),<>\|]|$|y(?:[\s\x0b&\),<>\|]|$)|int(?:env|f(?:[\s\x0b&\),<>\|]|$)))|t(?:x(?:[\s\x0b&\),<>\|]|$)|ar(?:[\s\x0b&\),<>\|]|$|diff|grep))|wd(?:[\s\x0b&\),<>\|]|$|\.db)|(?:xz|grep|opd|u(?:ppet|shd))(?:[\s\x0b&\),<>\|]|$)|er(?:(?:f|ms)(?:[\s\x0b&\),<>\|]|$)|l(?:5?(?:[\s\x0b&\),<>\|]|$)|sh))|hp(?:-cgi|[57](?:[\s\x0b&\),<>\|]|$))|s(?:(?:ed|ql)(?:[\s\x0b&\),<>\|]|$)|ftp)|y(?:3?versions|thon[23]))|r(?:(?:a(?:r|k[eu])|bash|nano|oute|vi(?:ew|m))(?:[\s\x0b&\),<>\|]|$)|c(?:[\s\x0b&\),<>\|]|$|p(?:[\s\x0b&\),<>\|]|$))|e(?:d(?:[\s\x0b&\),<>\|]|$|carpet(?:[\s\x0b&\),<>\|]|$))|(?:v|boot|place)(?:[\s\x0b&\),<>\|]|$)|a(?:delf|lpath)|stic)|m(?:[\s\x0b&\),<>\|]|$|t(?:[\s\x0b&\),<>\|]|$|-(?:dump|tar))|dir(?:[\s\x0b&\),<>\|]|$)|user)|pm(?:[\s\x0b&\),<>\|]|$|db(?:[\s\x0b&\),<>\|]|$)|(?:quer|verif)y)|l(?:ogin|wrap)|sync(?:-ssl|[\s\x0b&\),<>\|]|$)|u(?:by[^\s\x0b]{1,10}\b|n(?:-(?:mailcap|parts)|c(?:[\s\x0b&\),<>\|]|$))))|s(?:(?:c(?:p|hed|ript)|g|ash|diff|ftp|l(?:eep|sh))(?:[\s\x0b&\),<>\|]|$)|e(?:(?:d|ndmail|rvice)(?:[\s\x0b&\),<>\|]|$)|t(?:[\s\x0b&\),<>\|]|$|arch|cap|env|facl(?:[\s\x0b&\),<>\|]|$)|sid))|h(?:[\s\x0b&\),<>\|]|$|\.distrib|(?:adow|ells|u(?:f|tdown))(?:[\s\x0b&\),<>\|]|$))|sh(?:[\s\x0b&\),<>\|]|$|-(?:a(?:dd|gent)|copy-id|key(?:ge|sca)n)|pass)|u(?:[\s\x0b&\),<>\|]|$|do(?:-rs|[\s\x0b&\),<>_\|]|$|edit|replay))|vn(?:[\s\x0b&\),<>\|]|$|a(?:dmin|uthz)|bench|dumpfilter|fsfs|look|mucc|rdump|s(?:erve|ync)|version)|mbclient|o(?:cat(?:[\s\x0b&\),<>\|]|$)|elim)|p(?:lit(?:[\s\x0b&\),<>\|]|$)|wd\.db)|qlite3|t(?:art-stop-daemon|d(?:buf|err|in(?:[\s\x0b&\),<>\|]|$)|out)|r(?:ace|ings(?:[\s\x0b&\),<>\|]|$)))|ys(?:ctl|tem(?:ctl|d-resolve)))|t(?:a(?:[cr](?:[\s\x0b&\),<>\|]|$)|il(?:[\s\x0b&\),<>\|]|$|f(?:[\s\x0b&\),<>\|]|$))|skset)|(?:bl|o(?:p|uch)|ftp|mux)(?:[\s\x0b&\),<>\|]|$)|c(?:p(?:[\s\x0b&\),<>\|]|$|dump|ing|traceroute)|l?sh(?:[\s\x0b&\),<>\|]|$))|e(?:[ex](?:[\s\x0b&\),<>\|]|$)|lnet)|i(?:c(?:[\s\x0b&\),<>\|]|$)|medatectl)|r(?:aceroute6?|off(?:[\s\x0b&\),<>\|]|$))|shark)|u(?:dp(?:[\s\x0b&\),<>\|]|$)|l(?:[\s\x0b&\),<>\|]|$|imit(?:[\s\x0b&\),<>\|]|$))|n(?:(?:compress|iq|rar|s(?:et|hare)|xz)(?:[\s\x0b&\),<>\|]|$)|expand|l(?:ink(?:[\s\x0b&\),<>\|]|$)|z(?:4(?:[\s\x0b&\),<>\|]|$)|ma))|pigz|z(?:ip(?:[\s\x0b&\),<>\|]|$)|std))|pdate-alternatives|ser(?:(?:ad|mo)d|del)|u(?:de|en)code)|v(?:i(?:m(?:[\s\x0b&\),<>\|]|$|diff)|(?:gr|pw|rsh)(?:[\s\x0b&\),<>\|]|$)|sudo(?:-rs)?)|algrind|olatility(?:[\s\x0b&\),<>\|]|$))|w(?:(?:c|atch)(?:[\s\x0b&\),<>\|]|$)|h(?:iptail(?:[\s\x0b&\),<>\|]|$)|oami)|i(?:reshark|sh(?:[\s\x0b&\),<>\|]|$)))|x(?:(?:(?:x|pa)d|args|term)(?:[\s\x0b&\),<>\|]|$)|z(?:[\s\x0b&\),<>\|]|$|c(?:at|mp)(?:[\s\x0b&\),<>\|]|$)|d(?:ec(?:[\s\x0b&\),<>\|]|$)|iff)|[ef]?grep|less|more)|e(?:latex|tex(?:[\s\x0b&\),<>\|]|$))|mo(?:dmap|re(?:[\s\x0b&\),<>\|]|$)))|y(?:um|arn|elp)(?:[\s\x0b&\),<>\|]|$)|z(?:ip(?:[\s\x0b&\),<>\|]|$|c(?:loak|mp)|details|grep|info|(?:merg|not)e|split|tool)|s(?:h(?:[\s\x0b&\),<>\|]|$)|oelim|td(?:[\s\x0b&\),<>\|]|$|(?:ca|m)t|grep|less))|athura|(?:c(?:at|mp)|diff|grep|less|run)(?:[\s\x0b&\),<>\|]|$)|e(?:grep|ro(?:[\s\x0b&\),<>\|]|$))|fgrep|mo(?:dload|re(?:[\s\x0b&\),<>\|]|$))|ypper))
- **Is Chain**: False
- **Message**: Remote Command Execution: Unix Command Injection found in user-agent or referer header
- **Severity**: CRITICAL
- **Tags**: application-multi, language-shell, platform-unix, attack-rce, paranoia-level/2, OWASP_CRS, OWASP_CRS/ATTACK-RCE, capec/1000/152/248/88
- **Actions**: id:932239, phase:1, block, capture, t:none, msg:Remote Command Execution: Unix Command Injection found in user-agent or referer header, logdata:Matched Data: %{TX.0} found within %{MATCHED_VAR_NAME}: %{MATCHED_VAR}, tag:application-multi, tag:language-shell, tag:platform-unix, tag:attack-rce, tag:paranoia-level/2, tag:OWASP_CRS, tag:OWASP_CRS/ATTACK-RCE, tag:capec/1000/152/248/88, ver:OWASP_CRS/4.22.0-dev, severity:CRITICAL, setvar:tx.rce_score=+%{tx.critical_anomaly_score}, setvar:tx.inbound_anomaly_score_pl2=+%{tx.critical_anomaly_score}

#### Rule 53: 932161
- **Phase**: 1
- **Variables**: REQUEST_HEADERS:User-Agent, REQUEST_HEADERS:Referer
- **Operator**: @pmFromFile
- **Pattern**: unix-shell.data
- **Is Chain**: False
- **Message**: Remote Command Execution: Unix Shell Code Found in REQUEST_HEADERS
- **Severity**: CRITICAL
- **Tags**: application-multi, language-shell, platform-unix, attack-rce, paranoia-level/2, OWASP_CRS, OWASP_CRS/ATTACK-RCE, capec/1000/152/248/88
- **Actions**: id:932161, phase:1, block, capture, t:none, t:cmdLine, t:normalizePath, msg:Remote Command Execution: Unix Shell Code Found in REQUEST_HEADERS, logdata:Matched Data: %{TX.0} found within %{MATCHED_VAR_NAME}: %{MATCHED_VAR}, tag:application-multi, tag:language-shell, tag:platform-unix, tag:attack-rce, tag:paranoia-level/2, tag:OWASP_CRS, tag:OWASP_CRS/ATTACK-RCE, tag:capec/1000/152/248/88, ver:OWASP_CRS/4.22.0-dev, severity:CRITICAL, setvar:tx.rce_score=+%{tx.critical_anomaly_score}, setvar:tx.inbound_anomaly_score_pl2=+%{tx.critical_anomaly_score}

#### Rule 54: 932015
- **Phase**: 1
- **Variables**: TX:DETECTION_PARANOIA_LEVEL
- **Operator**: @lt
- **Pattern**: 3
- **Is Chain**: False
- **Message**: 
- **Severity**: 
- **Tags**: OWASP_CRS
- **Actions**: id:932015, phase:1, pass, nolog, tag:OWASP_CRS, ver:OWASP_CRS/4.22.0-dev, skipAfter:END-REQUEST-932-APPLICATION-ATTACK-RCE

#### Rule 55: 932016
- **Phase**: 2
- **Variables**: TX:DETECTION_PARANOIA_LEVEL
- **Operator**: @lt
- **Pattern**: 3
- **Is Chain**: False
- **Message**: 
- **Severity**: 
- **Tags**: OWASP_CRS
- **Actions**: id:932016, phase:2, pass, nolog, tag:OWASP_CRS, ver:OWASP_CRS/4.22.0-dev, skipAfter:END-REQUEST-932-APPLICATION-ATTACK-RCE

#### Rule 56: 932232
- **Phase**: 2
- **Variables**: REQUEST_COOKIES, REQUEST_COOKIES_NAMES, ARGS_NAMES, ARGS, XML:/*
- **Operator**: @rx
- **Pattern**: (?:b[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?u[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?s[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?y[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?b[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?o[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?x|(?:c[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?o[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?m[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?m[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?a[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?n[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?d|e[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?(?:n[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?v|v[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?a[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?l)|w[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?a[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?t[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?c[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?h)[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?(?:[\s\x0b&\),<>\|]|$).*|[ls][\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?t[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?r[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?a[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?c[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?e|n[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?o[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?h[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?u[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?p|t[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?i[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?m[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?e[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?(?:(?:[\s\x0b&\),<>\|]|$).*|o[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?u[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?t)|[\n\r;=`\{]|\|\|?|&&?|\$(?:\(\(?|[\[\{])|<(?:\(|<<)|>\(|\([\s\x0b]*\))[\s\x0b]*(?:[\$\{]|(?:[\s\x0b]*\(|!)[\s\x0b]*|[0-9A-Z_a-z]+=(?:[^\s\x0b]*|\$(?:.*|.*)|[<>].*|'[^']*'|\"[^\"]*\")[\s\x0b]+)*[\s\x0b]*[\"']*(?:[\"'-\+\--9\?A-\]_a-z\|]+/)?[\"'\x5c]*(?:(?:(?:a[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?p[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?t[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?i[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?t[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?u[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?d|u[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?p[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?2[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?d[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?a[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?t)[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?e|p[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?(?:a[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?c[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?m[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?a[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?n|s)|v[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?i)[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?(?:[\s\x0b&\),<>\|]|$).*|d[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?n[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?f|w[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?(?:h[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?o|(?:[\s\x0b&\),<>\|]|$).*))\b
- **Is Chain**: False
- **Message**: Remote Command Execution: Unix Command Injection
- **Severity**: CRITICAL
- **Tags**: application-multi, language-shell, platform-unix, attack-rce, paranoia-level/3, OWASP_CRS, OWASP_CRS/ATTACK-RCE, capec/1000/152/248/88
- **Actions**: id:932232, phase:2, block, capture, t:none, msg:Remote Command Execution: Unix Command Injection, logdata:Matched Data: %{TX.0} found within %{MATCHED_VAR_NAME}: %{MATCHED_VAR}, tag:application-multi, tag:language-shell, tag:platform-unix, tag:attack-rce, tag:paranoia-level/3, tag:OWASP_CRS, tag:OWASP_CRS/ATTACK-RCE, tag:capec/1000/152/248/88, ver:OWASP_CRS/4.22.0-dev, severity:CRITICAL, setvar:tx.rce_score=+%{tx.critical_anomaly_score}, setvar:tx.inbound_anomaly_score_pl3=+%{tx.critical_anomaly_score}

#### Rule 57: 932237
- **Phase**: 1
- **Variables**: REQUEST_HEADERS:User-Agent, REQUEST_HEADERS:Referer
- **Operator**: @rx
- **Pattern**: (?i)\b(?:7z(?:[\s\x0b&\),<>\|]|$|[arx](?:[\s\x0b&\),<>\|]|$))|(?:(?:GE|POS)T|y(?:e(?:s|lp)|um|arn)|HEAD)(?:[\s\x0b&\),<>\|]|$)|a(?:a-[^\s\x0b]{1,10}\b|(?:b|w[ks]|l(?:ias|pine)|xel)(?:[\s\x0b&\),<>\|]|$)|p(?:t(?:[\s\x0b&\),<>\|]|$|-get|itude(?:[\s\x0b&\),<>\|]|$))|parmor_[^\s\x0b]{1,10}\b)|r(?:[\s\x0b&\),<>\|]|$|j(?:[\s\x0b&\),<>\|]|$|-register|disp)|(?:p|ch)(?:[\s\x0b&\),<>\|]|$)|ia2c)|s(?:[\s\x0b&\),<>\|]|$|h(?:[\s\x0b&\),<>\|]|$)|cii(?:-xfr|85)|pell)|t(?:[\s\x0b&\),<>\|]|$|obm(?:[\s\x0b&\),<>\|]|$))|dd(?:group|user)|getty|nsible|u(?:ditctl|repot|search))|b(?:z(?:(?:z|c(?:at|mp))(?:[\s\x0b&\),<>\|]|$)|diff|e(?:grep|xe(?:[\s\x0b&\),<>\|]|$))|f?grep|ip2(?:[\s\x0b&\),<>\|]|$|recover)|less|more)|a(?:s(?:e(?:32|64|n(?:ame(?:[\s\x0b&\),<>\|]|$)|c))|h(?:[\s\x0b&\),<>\|]|$))|tch(?:[\s\x0b&\),<>\|]|$))|lkid(?:[\s\x0b&\),<>\|]|$)|pftrace|r(?:eaksw|(?:idge|wap)(?:[\s\x0b&\),<>\|]|$))|sd(?:cat|iff|tar)|u(?:iltin|n(?:dler(?:[\s\x0b&\),<>\|]|$)|zip2)|s(?:ctl|ybox))|y(?:ebug|obu(?:[\s\x0b&\),<>\|]|$)))|c(?:[89]9(?:[\s\x0b&\),<>\|]|$|-gcc)|(?:a(?:t|ncel|psh)|c|mp)(?:[\s\x0b&\),<>\|]|$)|p(?:[\s\x0b&\),<>\|]|$|io(?:[\s\x0b&\),<>\|]|$)|ulimit)|s(?:(?:h|cli)(?:[\s\x0b&\),<>\|]|$)|plit|vtool)|u(?:t(?:[\s\x0b&\),<>\|]|$)|psfilter)|ertbot|h(?:(?:(?:att|di)r|mod|o(?:om|wn)|root|sh)(?:[\s\x0b&\),<>\|]|$)|e(?:ck_(?:by_ssh|cups|log|memory|raid|s(?:sl_cert|tatusfile))|f(?:[\s\x0b&\),\-<>\|]|$))|(?:flag|pas)s|g(?:passwd|rp(?:[\s\x0b&\),<>\|]|$)))|lang(?:\+\+|[\s\x0b&\),<>\|]|$)|o(?:bc(?:[\s\x0b&\),<>\|]|$|run)|lumn(?:[\s\x0b&\),<>\|]|$)|m(?:m(?:[\s\x0b&\),<>\|]|$|and(?:[\s\x0b&\),<>\|]|$))|p(?:oser|ress)(?:[\s\x0b&\),<>\|]|$))|proc|w(?:say|think))|r(?:ash(?:[\s\x0b&\),<>\|]|$)|on(?:[\s\x0b&\),<>\|]|$|tab)))|d(?:(?:[dfu]|i(?:(?:alo)?g|r|ff)|a(?:sh|te)|vips)(?:[\s\x0b&\),<>\|]|$)|nf(?:[\s\x0b&\),<>\|]|$)?|hclient|m(?:esg(?:[\s\x0b&\),<>\|]|$)|idecode|setup)|o(?:(?:as|ne)(?:[\s\x0b&\),<>\|]|$)|cker(?:[\s\x0b&\),\-<>\|]|$)|sbox)|pkg(?:[\s\x0b&\),\-<>\|]|$))|e(?:(?:[bd]|qn|cho|fax|grep|macs|val)(?:[\s\x0b&\),<>\|]|$)|n(?:v(?:[\s\x0b&\),<>\|]|$|-update)|d(?:if|sw)(?:[\s\x0b&\),<>\|]|$))|s(?:[\s\x0b&\),<>\|]|$|(?:h|ac)(?:[\s\x0b&\),<>\|]|$))|x(?:[\s\x0b&\),<>\|]|$|(?:ec|p(?:and|(?:ec|or)t|r))(?:[\s\x0b&\),<>\|]|$)|iftool)|2fsck|asy_install)|f(?:(?:c|mt|etch|lock|unction)(?:[\s\x0b&\),<>\|]|$)|d(?:[\s\x0b&\),<>\|]|$|(?:find|isk)(?:[\s\x0b&\),<>\|]|$)|u?mount)|g(?:[\s\x0b&\),<>\|]|$|rep(?:[\s\x0b&\),<>\|]|$))|i(?:[\s\x0b&\),<>\|]|$|le(?:[\s\x0b&\),<>\|]|$|test)|(?:n(?:d|ger)|sh)(?:[\s\x0b&\),<>\|]|$))|tp(?:[\s\x0b&\),<>\|]|$|stats|who)|acter|o(?:ld(?:[\s\x0b&\),<>\|]|$)|reach)|ping(?:[\s\x0b&\),6<>\|]|$))|g(?:c(?:c[^\s\x0b]{1,10}\b|ore(?:[\s\x0b&\),<>\|]|$))|(?:db|i(?:t|mp|nsh)|o|pg|awk|z(?:cat|exe|ip))(?:[\s\x0b&\),<>\|]|$)|e(?:m(?:[\s\x0b&\),<>\|]|$)|ni(?:e(?:[\s\x0b&\),<>\|]|$)|soimage)|t(?:cap|facl(?:[\s\x0b&\),<>\|]|$)))|hc(?:[\s\x0b&\),<>\|]|$|-(?:[\s\x0b&\),<>\|]|$)|i(?:[\s\x0b&\),\-<>\|]|$))|r(?:c(?:[\s\x0b&\),<>\|]|$|at(?:[\s\x0b&\),<>\|]|$))|ep(?:[\s\x0b&\),<>\|]|$)|oup(?:[\s\x0b&\),<>\|]|$|mod))|tester|unzip)|h(?:(?:d|up|ash|i(?:ghlight|story))(?:[\s\x0b&\),<>\|]|$)|e(?:ad(?:[\s\x0b&\),<>\|]|$)|xdump)|ost(?:id|name)|ping3|t(?:digest|op(?:[\s\x0b&\),<>\|]|$)|passwd))|i(?:(?:d|rb|conv|nstall)(?:[\s\x0b&\),<>\|]|$)|p(?:[\s\x0b&\),<>\|]|$|6?tables|config|p(?:eveprinter|find|tool))|f(?:config|top(?:[\s\x0b&\),<>\|]|$))|onice|spell)|j(?:(?:js|q|ava|exec)(?:[\s\x0b&\),<>\|]|$)|o(?:(?:bs|in)(?:[\s\x0b&\),<>\|]|$)|urnalctl)|runscript)|k(?:s(?:h(?:[\s\x0b&\),<>\|]|$)|shell)|ill(?:[\s\x0b&\),<>\|]|$|all)|nife(?:[\s\x0b&\),<>\|]|$))|l(?:d(?:[\s\x0b&\),<>\|]|$|d(?:[\s\x0b&\),<>\|]|$)|config)|(?:[np]|ynx)(?:[\s\x0b&\),<>\|]|$)|s(?:[\s\x0b&\),<>\|]|$|(?:-F|cpu|hw|mod|of|pci|usb)(?:[\s\x0b&\),<>\|]|$)|b_release)|ua(?:[\s\x0b&\),<>\|]|$|(?:la)?tex)|z(?:4(?:[\s\x0b&\),<>\|]|$|c(?:[\s\x0b&\),<>\|]|$|at))|(?:c(?:at|mp))?(?:[\s\x0b&\),<>\|]|$)|diff|[ef]?grep|less|m(?:a(?:[\s\x0b&\),<>\|]|$|dec|info)|ore))|a(?:st(?:[\s\x0b&\),<>\|]|$|comm(?:[\s\x0b&\),<>\|]|$)|log(?:in)?)|tex(?:[\s\x0b&\),<>\|]|$))|ess(?:[\s\x0b&\),<>\|]|$|echo|(?:fil|pip)e)|ftp(?:[\s\x0b&\),<>\|]|$|get)|o(?:(?:ca(?:l|te)|ok)(?:[\s\x0b&\),<>\|]|$)|g(?:inctl|(?:nam|sav)e)|setup)|trace|wp-(?:d(?:ownload|ump)|mirror|request))|m(?:a(?:(?:n|ke|wk)(?:[\s\x0b&\),<>\|]|$)|il(?:[\s\x0b&\),<>\|]|$|[qx](?:[\s\x0b&\),<>\|]|$))|ster\.passwd)|(?:tr|v|utt)(?:[\s\x0b&\),<>\|]|$)|k(?:(?:dir|nod)(?:[\s\x0b&\),<>\|]|$)|fifo|temp)|locate|o(?:(?:re|unt)(?:[\s\x0b&\),<>\|]|$)|squitto)|sg(?:attrib|c(?:at|onv)|filter|merge|uniq)|ysql(?:[\s\x0b&\),<>\|]|$|admin|dump(?:slow)?|hotcopy|show))|n(?:c(?:[\s\x0b&\),<>\|]|$|\.(?:openbsd|traditional)|at(?:[\s\x0b&\),<>\|]|$))|e(?:t(?:[\s\x0b&\),<>\|]|$|(?:c|st)at|kit-ftp|plan)|ofetch)|(?:(?:ul)?l|p(?:m|ing)|a(?:no|sm|wk)|ice|o(?:de|hup)|roff)(?:[\s\x0b&\),<>\|]|$)|m(?:[\s\x0b&\),<>\|]|$|ap(?:[\s\x0b&\),<>\|]|$))|s(?:enter|lookup|tat(?:[\s\x0b&\),<>\|]|$)))|o(?:(?:d|ctave)(?:[\s\x0b&\),<>\|]|$)|nintr|p(?:en(?:ssl|v(?:pn|t))|kg(?:[\s\x0b&\),<>\|]|$)))|p(?:a(?:(?:x|cman|rted|tch)(?:[\s\x0b&\),<>\|]|$)|s(?:swd|te(?:[\s\x0b&\),<>\|]|$)))|d(?:b(?:[\s\x0b&\),<>\|]|$|2mb|3(?:[\s\x0b&\),\.<>\|]|$))|f(?:la)?tex|ksh(?:[\s\x0b&\),<>\|]|$))|f(?:[\s\x0b&\),<>\|]|$|tp(?:[\s\x0b&\),<>\|]|$))|g(?:[\s\x0b&\),<>\|]|$|rep(?:[\s\x0b&\),<>\|]|$))|hp(?:[\s\x0b&\),<>\|]|$|-cgi|[57](?:[\s\x0b&\),<>\|]|$))|i(?:c(?:[\s\x0b&\),<>\|]|$|o(?:[\s\x0b&\),<>\|]|$))|p(?:[^\s\x0b]{1,10}\b|[\s\x0b&\),<>\|]|$)|dstat|(?:gz|ng6?)(?:[\s\x0b&\),<>\|]|$))|k(?:g(?:[\s\x0b&\),<>\|]|$|_?info)|exec|ill(?:[\s\x0b&\),<>\|]|$))|r(?:[\s\x0b&\),<>\|]|$|y(?:[\s\x0b&\),<>\|]|$)|int(?:env|f(?:[\s\x0b&\),<>\|]|$)))|s(?:[\s\x0b&\),<>\|]|$|(?:ed|ql)(?:[\s\x0b&\),<>\|]|$)|ftp)|t(?:x(?:[\s\x0b&\),<>\|]|$)|ar(?:[\s\x0b&\),<>\|]|$|diff|grep))|wd(?:[\s\x0b&\),<>\|]|$|\.db)|(?:xz|opd|u(?:ppet|shd))(?:[\s\x0b&\),<>\|]|$)|er(?:(?:f|ms)(?:[\s\x0b&\),<>\|]|$)|l(?:5?(?:[\s\x0b&\),<>\|]|$)|sh))|y(?:3?versions|thon[23]))|r(?:(?:a(?:r|k[eu])|bash|nano|oute|vi(?:ew|m))(?:[\s\x0b&\),<>\|]|$)|c(?:[\s\x0b&\),<>\|]|$|p(?:[\s\x0b&\),<>\|]|$))|e(?:d(?:[\s\x0b&\),<>\|]|$|carpet(?:[\s\x0b&\),<>\|]|$))|(?:v|boot|name|p(?:eat|lace))(?:[\s\x0b&\),<>\|]|$)|a(?:delf|lpath)|stic)|m(?:[\s\x0b&\),<>\|]|$|t(?:[\s\x0b&\),<>\|]|$|-(?:dump|tar))|dir(?:[\s\x0b&\),<>\|]|$)|user)|pm(?:[\s\x0b&\),<>\|]|$|db(?:[\s\x0b&\),<>\|]|$)|(?:quer|verif)y)|l(?:ogin|wrap)|sync(?:-ssl|[\s\x0b&\),<>\|]|$)|u(?:by[^\s\x0b]{1,10}\b|n(?:-(?:mailcap|parts)|c(?:[\s\x0b&\),<>\|]|$))))|s(?:(?:c(?:p|hed|r(?:een|ipt))|g|ash|diff|ftp|l(?:eep|sh))(?:[\s\x0b&\),<>\|]|$)|e(?:(?:d|ndmail|rvice)(?:[\s\x0b&\),<>\|]|$)|t(?:[\s\x0b&\),<>\|]|$|arch|cap|env|facl(?:[\s\x0b&\),<>\|]|$)|sid))|h(?:[\s\x0b&\),<>\|]|$|\.distrib|(?:adow|ells|u(?:f|tdown))(?:[\s\x0b&\),<>\|]|$))|s(?:[\s\x0b&\),<>\|]|$|h(?:[\s\x0b&\),<>\|]|$|-(?:a(?:dd|gent)|copy-id|key(?:ge|sca)n)|pass))|u(?:[\s\x0b&\),<>\|]|$|do(?:-rs|[\s\x0b&\),<>_\|]|$|edit|replay))|vn(?:[\s\x0b&\),<>\|]|$|a(?:dmin|uthz)|bench|dumpfilter|fsfs|look|mucc|rdump|s(?:erve|ync)|version)|mbclient|o(?:(?:(?:ca|r)t|urce)(?:[\s\x0b&\),<>\|]|$)|elim)|p(?:lit(?:[\s\x0b&\),<>\|]|$)|wd\.db)|qlite3|t(?:art-stop-daemon|d(?:buf|err|in(?:[\s\x0b&\),<>\|]|$)|out)|r(?:ace|ings(?:[\s\x0b&\),<>\|]|$)))|ys(?:ctl|tem(?:ctl|d-resolve)))|t(?:a(?:[cr](?:[\s\x0b&\),<>\|]|$)|il(?:[\s\x0b&\),<>\|]|$|f(?:[\s\x0b&\),<>\|]|$))|sk(?:[\s\x0b&\),<>\|]|$|set))|(?:bl|o(?:p|uch)|ftp|mux)(?:[\s\x0b&\),<>\|]|$)|c(?:p(?:[\s\x0b&\),<>\|]|$|dump|ing|traceroute)|l?sh(?:[\s\x0b&\),<>\|]|$))|e(?:[ex](?:[\s\x0b&\),<>\|]|$)|lnet)|i(?:c(?:[\s\x0b&\),<>\|]|$)|me(?:[\s\x0b&\),<>\|]|$|datectl|out(?:[\s\x0b&\),<>\|]|$)))|r(?:aceroute6?|off(?:[\s\x0b&\),<>\|]|$))|shark)|u(?:dp(?:[\s\x0b&\),<>\|]|$)|l(?:[\s\x0b&\),<>\|]|$|imit(?:[\s\x0b&\),<>\|]|$))|n(?:(?:ame|compress|iq|rar|s(?:et|hare)|xz)(?:[\s\x0b&\),<>\|]|$)|expand|l(?:ink(?:[\s\x0b&\),<>\|]|$)|z(?:4(?:[\s\x0b&\),<>\|]|$)|ma))|pigz|z(?:ip(?:[\s\x0b&\),<>\|]|$)|std))|p(?:2date(?:[\s\x0b&\),<>\|]|$)|date-alternatives)|ser(?:(?:ad|mo)d|del)|u(?:de|en)code)|v(?:i(?:[\s\x0b&\),<>\|]|$|m(?:[\s\x0b&\),<>\|]|$|diff)|(?:[ep]w|gr|rsh)(?:[\s\x0b&\),<>\|]|$)|sudo(?:-rs)?)|algrind|olatility(?:[\s\x0b&\),<>\|]|$))|w(?:[\s\x0b&\),<>\|]|$|(?:c|a(?:ll|tch))(?:[\s\x0b&\),<>\|]|$)|h(?:o(?:[\s\x0b&\),<>\|]|$|ami|is(?:[\s\x0b&\),<>\|]|$))?|iptail(?:[\s\x0b&\),<>\|]|$))|i(?:reshark|sh(?:[\s\x0b&\),<>\|]|$)))|x(?:(?:(?:x|pa)d|args|term)(?:[\s\x0b&\),<>\|]|$)|z(?:[\s\x0b&\),<>\|]|$|c(?:at|mp)(?:[\s\x0b&\),<>\|]|$)|d(?:ec(?:[\s\x0b&\),<>\|]|$)|iff)|[ef]?grep|less|more)|e(?:latex|tex(?:[\s\x0b&\),<>\|]|$))|mo(?:dmap|re(?:[\s\x0b&\),<>\|]|$)))|z(?:ip(?:[\s\x0b&\),<>\|]|$|c(?:loak|mp)|details|grep|info|(?:merg|not)e|split|tool)|s(?:h(?:[\s\x0b&\),<>\|]|$)|oelim|td(?:[\s\x0b&\),<>\|]|$|(?:ca|m)t|grep|less))|athura|(?:c(?:at|mp)|diff|grep|less|run)(?:[\s\x0b&\),<>\|]|$)|e(?:grep|ro(?:[\s\x0b&\),<>\|]|$))|fgrep|mo(?:dload|re(?:[\s\x0b&\),<>\|]|$))|ypper))(?:\b|[^0-9A-Z_a-z])
- **Is Chain**: False
- **Message**: Remote Command Execution: Unix Shell Code Found in REQUEST_HEADERS
- **Severity**: CRITICAL
- **Tags**: application-multi, language-shell, platform-unix, attack-rce, paranoia-level/3, OWASP_CRS, OWASP_CRS/ATTACK-RCE, capec/1000/152/248/88
- **Actions**: id:932237, phase:1, block, capture, t:none, t:cmdLine, t:normalizePath, msg:Remote Command Execution: Unix Shell Code Found in REQUEST_HEADERS, logdata:Matched Data: %{TX.0} found within %{MATCHED_VAR_NAME}: %{MATCHED_VAR}, tag:application-multi, tag:language-shell, tag:platform-unix, tag:attack-rce, tag:paranoia-level/3, tag:OWASP_CRS, tag:OWASP_CRS/ATTACK-RCE, tag:capec/1000/152/248/88, ver:OWASP_CRS/4.22.0-dev, severity:CRITICAL, setvar:tx.rce_score=+%{tx.critical_anomaly_score}, setvar:tx.inbound_anomaly_score_pl3=+%{tx.critical_anomaly_score}

#### Rule 58: 932238
- **Phase**: 2
- **Variables**: REQUEST_COOKIES, REQUEST_COOKIES_NAMES, ARGS_NAMES, ARGS, XML:/*, REQUEST_HEADERS:Referer, REQUEST_HEADERS:User-Agent
- **Operator**: @rx
- **Pattern**: (?i)(?:^|b[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?u[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?s[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?y[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?b[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?o[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?x|(?:c[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?o[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?m[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?m[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?a[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?n[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?d|e[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?(?:n[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?v|v[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?a[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?l)|w[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?a[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?t[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?c[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?h)[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?(?:[\s\x0b&\),<>\|]|$).*|[ls][\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?t[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?r[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?a[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?c[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?e|n[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?o[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?h[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?u[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?p|t[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?i[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?m[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?e[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?(?:(?:[\s\x0b&\),<>\|]|$).*|o[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?u[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?t)|[\n\r;=`\{]|\|\|?|&&?|\$(?:\(\(?|[\[\{])|<(?:\(|<<)|>\(|\([\s\x0b]*\))[\s\x0b]*(?:[\$\{]|(?:[\s\x0b]*\(|!)[\s\x0b]*|[0-9A-Z_a-z]+=(?:[^\s\x0b]*|\$(?:.*|.*)|[<>].*|'[^']*'|\"[^\"]*\")[\s\x0b]+)*[\s\x0b]*[\"']*(?:[\"'-\+\--9\?A-\]_a-z\|]+/)?[\"'\x5c]*(?:(?:(?:a[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?p[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?t[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?i[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?t[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?u[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?d|u[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?p[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?2[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?d[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?a[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?t)[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?e|p[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?(?:a[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?c[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?m[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?a[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?n|s)|v[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?i)[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?(?:[\s\x0b&\),<>\|]|$).*|d[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?n[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?f|w[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?(?:h[\"'\)\[\x5c]*(?:(?:(?:\|\||&&)[\s\x0b]*)?\$[!#\(\*\-0-9\?@_a-\{]*)?\x5c?o|(?:[\s\x0b&\),<>\|]|$).*))
- **Is Chain**: False
- **Message**: Remote Command Execution: Unix Shell Code Found in REQUEST_HEADERS
- **Severity**: CRITICAL
- **Tags**: application-multi, language-shell, platform-unix, attack-rce, paranoia-level/3, OWASP_CRS, OWASP_CRS/ATTACK-RCE, capec/1000/152/248/88
- **Actions**: id:932238, phase:2, block, capture, t:none, t:cmdLine, t:normalizePath, msg:Remote Command Execution: Unix Shell Code Found in REQUEST_HEADERS, logdata:Matched Data: %{TX.0} found within %{MATCHED_VAR_NAME}: %{MATCHED_VAR}, tag:application-multi, tag:language-shell, tag:platform-unix, tag:attack-rce, tag:paranoia-level/3, tag:OWASP_CRS, tag:OWASP_CRS/ATTACK-RCE, tag:capec/1000/152/248/88, ver:OWASP_CRS/4.22.0-dev, severity:CRITICAL, setvar:tx.rce_score=+%{tx.critical_anomaly_score}, setvar:tx.inbound_anomaly_score_pl3=+%{tx.critical_anomaly_score}

#### Rule 59: 932190
- **Phase**: 2
- **Variables**: ARGS
- **Operator**: @rx
- **Pattern**: /(?:[?*]+[a-z/]+|[a-z/]+[?*]+)
- **Is Chain**: False
- **Message**: Remote Command Execution: Wildcard bypass technique attempt
- **Severity**: CRITICAL
- **Tags**: application-multi, language-shell, platform-unix, attack-rce, paranoia-level/3, OWASP_CRS, OWASP_CRS/ATTACK-RCE, capec/1000/152/248/88
- **Actions**: id:932190, phase:2, block, capture, t:none, t:normalizePath, t:cmdLine, msg:Remote Command Execution: Wildcard bypass technique attempt, logdata:Matched Data: %{TX.0} found within %{MATCHED_VAR_NAME}: %{MATCHED_VAR}, tag:application-multi, tag:language-shell, tag:platform-unix, tag:attack-rce, tag:paranoia-level/3, tag:OWASP_CRS, tag:OWASP_CRS/ATTACK-RCE, tag:capec/1000/152/248/88, ver:OWASP_CRS/4.22.0-dev, severity:CRITICAL, setvar:tx.rce_score=+%{tx.critical_anomaly_score}, setvar:tx.inbound_anomaly_score_pl3=+%{tx.critical_anomaly_score}

#### Rule 60: 932301
- **Phase**: 2
- **Variables**: REQUEST_COOKIES, REQUEST_COOKIES_NAMES, ARGS_NAMES, ARGS, XML:/*
- **Operator**: @rx
- **Pattern**: \r\n.*?\b(?:DATA|QUIT|HELP(?: .{1,255})?)
- **Is Chain**: False
- **Message**: Remote Command Execution: SMTP Command Execution
- **Severity**: CRITICAL
- **Tags**: application-multi, platform-multi, attack-rce, paranoia-level/3, OWASP_CRS, OWASP_CRS/ATTACK-RCE, capec/137/134
- **Actions**: id:932301, phase:2, block, capture, t:none, t:escapeSeqDecode, msg:Remote Command Execution: SMTP Command Execution, logdata:Matched Data: %{TX.0} found within %{MATCHED_VAR_NAME}: %{MATCHED_VAR}, tag:application-multi, tag:platform-multi, tag:attack-rce, tag:paranoia-level/3, tag:OWASP_CRS, tag:OWASP_CRS/ATTACK-RCE, tag:capec/137/134, ver:OWASP_CRS/4.22.0-dev, severity:CRITICAL, setvar:tx.rce_score=+%{tx.critical_anomaly_score}, setvar:tx.inbound_anomaly_score_pl3=+%{tx.critical_anomaly_score}

#### Rule 61: 932311
- **Phase**: 2
- **Variables**: REQUEST_COOKIES, REQUEST_COOKIES_NAMES, ARGS_NAMES, ARGS, XML:/*
- **Operator**: @rx
- **Pattern**: (?is)\r\n[0-9A-Z_a-z]{1,50}\b (?:C(?:(?:REATE|OPY [\*,0-:]+) [\"#%&\*\--9A-Z\x5c_a-z]+|APABILITY|HECK|LOSE)|DELETE [\"#%&\*\-\.0-9A-Z\x5c_a-z]+|EX(?:AMINE [\"#%&\*\-\.0-9A-Z\x5c_a-z]+|PUNGE)|FETCH [\*,0-:]+|L(?:IST [\"#\*\--9A-Z\x5c_a-z~]+? [\"#%&\*\--9A-Z\x5c_a-z]+|OG(?:IN [\-\.0-9@_a-z]{1,40} .*?|OUT))|RENAME [\"#%&\*\--9A-Z\x5c_a-z]+? [\"#%&\*\--9A-Z\x5c_a-z]+|S(?:E(?:LECT [\"#%&\*\--9A-Z\x5c_a-z]+|ARCH(?: CHARSET [\-\.0-9A-Z_a-z]{1,40})? (?:(KEYWORD \x5c)?(?:A(?:LL|NSWERED)|BCC|D(?:ELETED|RAFT)|(?:FLAGGE|OL)D|RECENT|SEEN|UN(?:(?:ANSWER|FLAGG)ED|D(?:ELETED|RAFT)|SEEN)|NEW)|(?:BODY|CC|FROM|HEADER .{1,100}|NOT|OR .{1,255}|T(?:EXT|O)) .{1,255}|LARGER [0-9]{1,20}|[\*,0-:]+|(?:BEFORE|ON|S(?:ENT(?:(?:BEFOR|SINC)E|ON)|INCE)) \"?[0-9]{1,2}-[0-9A-Z_a-z]{3}-[0-9]{4}\"?|S(?:MALLER [0-9]{1,20}|UBJECT .{1,255})|U(?:ID [\*,0-:]+?|NKEYWORD \x5c(Seen|(?:Answer|Flagg)ed|D(?:eleted|raft)|Recent))))|T(?:ORE [\*,0-:]+? [\+\-]?FLAGS(?:\.SILENT)? (?:\(\x5c[a-z]{1,20}\))?|ARTTLS)|UBSCRIBE [\"#%&\*\--9A-Z\x5c_a-z]+)|UN(?:SUBSCRIBE [\"#%&\*\--9A-Z\x5c_a-z]+|AUTHENTICATE)|NOOP)
- **Is Chain**: False
- **Message**: Remote Command Execution: IMAP Command Execution
- **Severity**: CRITICAL
- **Tags**: application-multi, platform-multi, attack-rce, paranoia-level/3, OWASP_CRS, OWASP_CRS/ATTACK-RCE, capec/137/134
- **Actions**: id:932311, phase:2, block, capture, t:none, t:escapeSeqDecode, msg:Remote Command Execution: IMAP Command Execution, logdata:Matched Data: %{TX.0} found within %{MATCHED_VAR_NAME}: %{MATCHED_VAR}, tag:application-multi, tag:platform-multi, tag:attack-rce, tag:paranoia-level/3, tag:OWASP_CRS, tag:OWASP_CRS/ATTACK-RCE, tag:capec/137/134, ver:OWASP_CRS/4.22.0-dev, severity:CRITICAL, setvar:tx.rce_score=+%{tx.critical_anomaly_score}, setvar:tx.inbound_anomaly_score_pl3=+%{tx.critical_anomaly_score}

#### Rule 62: 932321
- **Phase**: 2
- **Variables**: REQUEST_COOKIES, REQUEST_COOKIES_NAMES, ARGS_NAMES, ARGS, XML:/*
- **Operator**: @rx
- **Pattern**: \r\n.*?\b(?:(?:QUI|STA|RSE)T|NOOP|CAPA)
- **Is Chain**: False
- **Message**: Remote Command Execution: POP3 Command Execution
- **Severity**: CRITICAL
- **Tags**: application-multi, platform-multi, attack-rce, paranoia-level/3, OWASP_CRS, OWASP_CRS/ATTACK-RCE, capec/137/134
- **Actions**: id:932321, phase:2, block, capture, t:none, t:escapeSeqDecode, msg:Remote Command Execution: POP3 Command Execution, logdata:Matched Data: %{TX.0} found within %{MATCHED_VAR_NAME}: %{MATCHED_VAR}, tag:application-multi, tag:platform-multi, tag:attack-rce, tag:paranoia-level/3, tag:OWASP_CRS, tag:OWASP_CRS/ATTACK-RCE, tag:capec/137/134, ver:OWASP_CRS/4.22.0-dev, severity:CRITICAL, setvar:tx.rce_score=+%{tx.critical_anomaly_score}, setvar:tx.inbound_anomaly_score_pl3=+%{tx.critical_anomaly_score}

#### Rule 63: 932331
- **Phase**: 2
- **Variables**: REQUEST_COOKIES, REQUEST_COOKIES_NAMES, ARGS_NAMES, ARGS, XML:/*
- **Operator**: @rx
- **Pattern**: !(?:\d|!)
- **Is Chain**: False
- **Message**: Remote Command Execution: Unix shell history invocation
- **Severity**: CRITICAL
- **Tags**: application-multi, language-shell, platform-unix, attack-rce, paranoia-level/3, OWASP_CRS, OWASP_CRS/ATTACK-RCE, capec/1000/152/248/88
- **Actions**: id:932331, phase:2, block, capture, t:none, msg:Remote Command Execution: Unix shell history invocation, logdata:Matched Data: %{TX.0} found within %{MATCHED_VAR_NAME}: %{MATCHED_VAR}, tag:application-multi, tag:language-shell, tag:platform-unix, tag:attack-rce, tag:paranoia-level/3, tag:OWASP_CRS, tag:OWASP_CRS/ATTACK-RCE, tag:capec/1000/152/248/88, ver:OWASP_CRS/4.22.0-dev, severity:CRITICAL, setvar:tx.rce_score=+%{tx.critical_anomaly_score}, setvar:tx.inbound_anomaly_score_pl3=+%{tx.critical_anomaly_score}

#### Rule 64: 932017
- **Phase**: 1
- **Variables**: TX:DETECTION_PARANOIA_LEVEL
- **Operator**: @lt
- **Pattern**: 4
- **Is Chain**: False
- **Message**: 
- **Severity**: 
- **Tags**: OWASP_CRS
- **Actions**: id:932017, phase:1, pass, nolog, tag:OWASP_CRS, ver:OWASP_CRS/4.22.0-dev, skipAfter:END-REQUEST-932-APPLICATION-ATTACK-RCE

#### Rule 65: 932018
- **Phase**: 2
- **Variables**: TX:DETECTION_PARANOIA_LEVEL
- **Operator**: @lt
- **Pattern**: 4
- **Is Chain**: False
- **Message**: 
- **Severity**: 
- **Tags**: OWASP_CRS
- **Actions**: id:932018, phase:2, pass, nolog, tag:OWASP_CRS, ver:OWASP_CRS/4.22.0-dev, skipAfter:END-REQUEST-932-APPLICATION-ATTACK-RCE


====================================================================================================

## File: REQUEST-933-APPLICATION-ATTACK-PHP.conf

### File Summary
- Total rules: 28
- Chained rules: 0
- Non-chained rules: 28

### Detailed Rules

#### Rule 1: 933011
- **Phase**: 1
- **Variables**: TX:DETECTION_PARANOIA_LEVEL
- **Operator**: @lt
- **Pattern**: 1
- **Is Chain**: False
- **Message**: 
- **Severity**: 
- **Tags**: OWASP_CRS
- **Actions**: id:933011, phase:1, pass, nolog, tag:OWASP_CRS, ver:OWASP_CRS/4.22.0-dev, skipAfter:END-REQUEST-933-APPLICATION-ATTACK-PHP

#### Rule 2: 933012
- **Phase**: 2
- **Variables**: TX:DETECTION_PARANOIA_LEVEL
- **Operator**: @lt
- **Pattern**: 1
- **Is Chain**: False
- **Message**: 
- **Severity**: 
- **Tags**: OWASP_CRS
- **Actions**: id:933012, phase:2, pass, nolog, tag:OWASP_CRS, ver:OWASP_CRS/4.22.0-dev, skipAfter:END-REQUEST-933-APPLICATION-ATTACK-PHP

#### Rule 3: 933100
- **Phase**: 2
- **Variables**: REQUEST_COOKIES, REQUEST_COOKIES_NAMES, ARGS_NAMES, ARGS, XML:/*
- **Operator**: @rx
- **Pattern**: (?i)<\?(?:[^x]|x(?:[^m]|m(?:[^l]|l(?:[^\s\x0b]|[\s\x0b]+[^a-z]|$)))|$|php)|\[[/\x5c]?php\]
- **Is Chain**: False
- **Message**: PHP Injection Attack: PHP Open Tag Found
- **Severity**: CRITICAL
- **Tags**: application-multi, language-php, platform-multi, attack-injection-php, paranoia-level/1, OWASP_CRS, OWASP_CRS/ATTACK-PHP, capec/1000/152/242
- **Actions**: id:933100, phase:2, block, capture, t:none, msg:PHP Injection Attack: PHP Open Tag Found, logdata:Matched Data: %{TX.0} found within %{MATCHED_VAR_NAME}: %{MATCHED_VAR}, tag:application-multi, tag:language-php, tag:platform-multi, tag:attack-injection-php, tag:paranoia-level/1, tag:OWASP_CRS, tag:OWASP_CRS/ATTACK-PHP, tag:capec/1000/152/242, ver:OWASP_CRS/4.22.0-dev, severity:CRITICAL, setvar:tx.php_injection_score=+%{tx.critical_anomaly_score}, setvar:tx.inbound_anomaly_score_pl1=+%{tx.critical_anomaly_score}

#### Rule 4: 933110
- **Phase**: 2
- **Variables**: FILES, REQUEST_HEADERS:X-Filename, REQUEST_HEADERS:X_Filename, REQUEST_HEADERS:X.Filename, REQUEST_HEADERS:X-File-Name
- **Operator**: @rx
- **Pattern**: .*\.ph(?:p\d*|tml|ar|ps|t|pt)\.*$
- **Is Chain**: False
- **Message**: PHP Injection Attack: PHP Script File Upload Found
- **Severity**: CRITICAL
- **Tags**: application-multi, language-php, platform-multi, attack-injection-php, paranoia-level/1, OWASP_CRS, OWASP_CRS/ATTACK-PHP, capec/1000/152/242
- **Actions**: id:933110, phase:2, block, capture, t:none, t:lowercase, msg:PHP Injection Attack: PHP Script File Upload Found, logdata:Matched Data: %{TX.0} found within %{MATCHED_VAR_NAME}: %{MATCHED_VAR}, tag:application-multi, tag:language-php, tag:platform-multi, tag:attack-injection-php, tag:paranoia-level/1, tag:OWASP_CRS, tag:OWASP_CRS/ATTACK-PHP, tag:capec/1000/152/242, ver:OWASP_CRS/4.22.0-dev, severity:CRITICAL, setvar:tx.php_injection_score=+%{tx.critical_anomaly_score}, setvar:tx.inbound_anomaly_score_pl1=+%{tx.critical_anomaly_score}

#### Rule 5: 933120
- **Phase**: 2
- **Variables**: REQUEST_COOKIES, REQUEST_COOKIES_NAMES, ARGS_NAMES, ARGS, XML:/*
- **Operator**: @rx
- **Pattern**: (?i)\b(?:a(?:llow_url_(?:fopen|include)|pc.(?:coredump_unmap|en(?:able(?:_cli|d)|tries_hint)|(?:gc_)?ttl|mmap_file_mask|preload_path|s(?:erializer|hm_s(?:egments|ize)|lam_defense)|use_request_time)|rg_separator.(?:in|out)put|ssert.(?:active|(?:bai|quiet_eva)l|callback|exception|warning)|uto_(?:(?:ap|pre)pend_file|detect_line_endings|globals_jit))|b(?:cmath.scale|rowscap)|c(?:gi.(?:check_shebang_line|(?:discard_pat|np)h|f(?:ix_pathinfo|orce_redirect)|r(?:edirect_status_env|fc2616_headers))|hild_terminate|li(?:_server.color|.p(?:ager|rompt))|om.(?:a(?:llow_dcom|utoregister_(?:(?:casesensitiv|verbos)e|typelib))|(?:code_pag|typelib_fil)e|dotnet_version)|url.cainfo)|d(?:ate.(?:(?:default_l(?:at|ong)itud|timezon)e|sun(?:rise|set)_zenith)|ba.default_handler|efault_(?:(?:charse|socket_timeou)t|mimetype)|is(?:able_(?:classe|function)|play_(?:startup_)?error)s|oc(?:_roo|ref_(?:ex|roo))t)|e(?:n(?:able_(?:dl|post_data_reading)|gine)|rror_(?:(?:(?:ap|pre)pend_str|report)in|lo)g|x(?:i(?:f.(?:decode_(?:jis|unicode)_(?:intel|motorola)|encode_(?:jis|unicode))|t_on_timeout)|tension(?:_dir)?|p(?:ect.(?:log(?:file|user)|match_max|timeout)|ose_php)))|f(?:astcgi.(?:impersonate|logging)|fi.(?:enable|preload)|il(?:e_uploads|ter.default(?:_flags)?))|g(?:d.jpeg_ignore_warning|eoip.custom_directory)|h(?:ard_timeout|ighlight.(?:(?:commen|defaul)t|html|keyword|string)|tml_errors)|i(?:b(?:ase.(?:(?:allow_persisten|time(?:stamp)?forma)t|d(?:ateformat|efault_(?:charset|db|password|user))|max_(?:links|persistent))|m_db2.(?:binmode|i(?:5_(?:all(?:_pconnec|ow_commi)t|dbcs_alloc|ignore_userid)|nstance_name)))|conv.(?:in(?:put|ternal)|output)_encoding|g(?:binary.compact_strings|nore_(?:repeated_(?:errors|source)|user_abort))|m(?:a(?:gick.(?:locale_fix|progress_monitor|skip_version_check)|p.enable_insecure_rsh)|plicit_flush)|n(?:clude_path|put_encoding|t(?:ernal_encoding|l.(?:default_locale|error_level|use_exceptions))))|l(?:dap.max_links|og_errors(?:_max_len)?)|m(?:a(?:gic_quotes_(?:gpc|runtime)|il(?:.(?:add_x_header|force_extra_parameters|log)|parse.def_charset)|x_(?:execution_time|file_uploads|input_(?:nesting_level|time|vars)))|bstring.(?:detect_order|encoding_translation|func_overload|http_(?:input|output(?:_conv_mimetypes)?)|internal_encoding|language|regex_(?:retry|stack)_limit|s(?:trict_detection|ubstitute_character))|crypt.(?:algorithm|mode)s_dir|em(?:cache(?:.(?:allow_failover|c(?:hunk_size|ompress_threshold)|(?:default_por|lock_timeou)t|hash_(?:function|strategy)|max_failover_attempts|protocol|(?:session_)?redundancy)|d.(?:compression_(?:factor|t(?:hreshold|ype))|default_(?:binary_protocol|con(?:nect_timeout|sistent_hash))|s(?:e(?:rializer|ss_(?:binary(?:_protocol)?|con(?:nect_timeout|sistent_hash(?:_type)?)|lock(?:_(?:expire|retries|wait(?:_m(?:ax|in))?)|ing)|number_of_replicas|p(?:ersistent|refix)|r(?:andomize_replica_read|emove_failed(?:_servers)?)|s(?:asl_(?:password|username)|erver_failure_limit)))|tore_retry_count)|use_sasl))|ory_limit)|ysql(?:.(?:allow_(?:local_infile|persistent)|connect_timeout|default_(?:(?:hos|socke)t|p(?:assword|ort)|user)|max_(?:links|persistent)|trace_mode)|i.(?:allow_(?:local_infile|persistent)|default_(?:(?:hos|socke)t|p(?:ort|w)|user)|local_infile_directory|max_(?:links|persistent)|r(?:econnect|ollback_on_cached_plink))|nd.(?:collect_(?:memory_)?statistics|debug|(?:fetch_data_cop|sha256_server_public_ke)y|log_mask|mempool_default_size|net_(?:cmd_buffer_size|read_(?:buffer_size|timeout))|trace_alloc)))|o(?:ci8.(?:(?:connection_clas|event|old_oci_close_semantic)s|default_prefetch|max_persistent|p(?:ersistent_timeout|ing_interval|r(?:efetch_lob_size|ivileged_connect))|statement_cache_size)|dbc.(?:(?:allow|check)_persistent|default(?:_(?:cursortype|db|pw|user)|binmode|lrl)|max_(?:links|persistent))|p(?:cache.(?:blacklist_filename|c(?:ache_id|onsistency_checks)|dups_fix|e(?:nable(?:_(?:cli|file_override))?|rror_log)|f(?:ast_shutdown|ile_(?:cache(?:_(?:consistency_checks|fallback|only))?|update_protection)|orce_restart_timeout)|(?:huge_code_page|save_comment)s|in(?:herited_hack|terned_strings_buffer)|jit(?:_(?:b(?:isect_limit|(?:lacklist_(?:root|side)_trac|uffer_siz)e)|debug|hot_(?:func|loop|return|side_exit)|max_(?:exit_counter|(?:loop_unro|polymorphic_ca)ll|r(?:ecursive_(?:call|return)|oot_trace)|side_trace)s|prof_threshold))?|lo(?:ckfile_path|g_verbosity_level)|m(?:ax_(?:accelerated_files|(?:file_siz|wasted_percentag)e)|emory_consumption|map_base)|opt(?:_debug|imization)_level|pr(?:e(?:ferred_memory_model|load(?:_user)?)|otect_memory)|re(?:cord_warnings|strict_api|validate_(?:freq|path))|use_cwd|validate_(?:permission|root|timestamps))|en(?:_basedir|ssl.ca(?:file|path)))|utput_(?:(?:buffer|encod)ing|handler))|p(?:cre.(?:(?:backtrack|recursion)_lim|j)it|do(?:_odbc.(?:connection_pooling|db2_instance_name)|.dsn)|gsql.(?:a(?:llow|uto_reset)_persistent|(?:ignore|log)_notice|max_(?:links|persistent))|h(?:ar.(?:cache_list|re(?:adonly|quire_hash))|pdbg.(?:eol|path))|recision|ost_max_size)|r(?:e(?:alpath_cache_(?:size|ttl)|gister_argc_argv|port_(?:memleaks|zend_debug)|quest_order)|unkit.(?:internal_override|superglobal))|s(?:e(?:aslog.(?:appender(?:_retry)?|buffer_(?:disabled_in_cli|size)|d(?:efault_(?:basepath|datetime_format|logger|template)|isting_(?:(?:by_hou|folde)r|type))|ignore_warning|level|re(?:call_depth|mote_(?:hos|por|timeou)t)|t(?:hrow_exception|r(?:ace_(?:e(?:rror|xception)|notice|warning)|im_wrap))|use_buffer)|ndmail_(?:from|path)|rialize_precision|ssion.(?:auto_start|c(?:ache_(?:expire|limiter)|ookie_(?:domain|httponly|(?:lifetim|s(?:amesit|ecur))e|path))|entropy_(?:file|length)|gc_(?:divisor|maxlifetime|probability)|hash_(?:bits_per_character|function)|(?:lazy_writ|nam)e|referer_check|s(?:ave_(?:handler|path)|erialize_handler|id_(?:bits_per_character|length))|trans_sid_(?:host|tag)s|u(?:pload_progress.(?:cleanup|enabled|(?:min_)?freq|name|prefix)|se_(?:(?:only_)?cookies|strict_mode|trans_sid))))|hort_open_tag|mtp(?:_port)?|oap.wsdl_cache(?:_(?:dir|enabled|limit|ttl))?|ql(?:.safe_mode|ite3.(?:defensive|extension_dir))|tomp.default_(?:broker|(?:connection|read)_timeout_u?sec)|woole.(?:aio_thread_num|display_errors|enable_(?:coroutine|library|preemptive_scheduler)|(?:fast_serializ|u(?:nixsock_buffer_siz|se_(?:namespac|shortnam)))e)|ys(?:_temp_dir|log.(?:f(?:acility|ilter)|ident)|vshm.init_mem))|t(?:aint.e(?:nable|rror_level)|idy.(?:clean_output|default_config)|ra(?:ck_errors|der.real_(?:precision|round_mode)))|u(?:nserialize_(?:callback_func|max_depth)|opz.(?:disable|exit|overloads)|pload(?:_(?:max_filesize|tmp_dir)|progress.file.filename_template)|rl_rewriter.(?:host|tag)s|ser_(?:agent|dir|ini.(?:cache_ttl|filename)))|v(?:8js.(?:flag|max_disposed_context)s|ariables_order|ld.(?:(?:activ|execut)e|skip_(?:ap|pre)pend))|w(?:in(?:cache.(?:chkinterval|enablecli|f(?:c(?:achesize|enabled(?:filter)?|ndetect)|ile(?:count|mapdir))|(?:ignorelis|namesal)t|maxfilesize|oc(?:achesize|enabled(?:filter)?)|reroute(?:_enabled|ini)|s(?:cachesize|rwlocks)|ttlmax|uc(?:achesize|enabled))|dows.show_crt_warning)|khtmltox.graphics)|x(?:bithack|hprof.output_dir|mlrpc_error(?:_number|s))|ya(?:c(?:.(?:compress_threshold|debug|enable(?:_cli)?|(?:key|value)s_memory_size|serializer)|onf.(?:check_dela|director)y)|f.(?:action_prefer|cache_config|environ|forward_limit|l(?:ibrary|owcase_path)|name_s(?:eparator|uffix)|use_(?:namespace|spl_autoload))|ml.(?:decode_(?:binary|(?:ph|timestam)p)|output_(?:canonical|indent|width))|r.(?:(?:connect_)?timeout|debug|expose_info|packager)|z.(?:keepalive|log_mask))|z(?:end(?:_extension|.(?:assertions|(?:detect_unicod|multibyt)e|e(?:nable_gc|xception_(?:ignore_args|string_param_max_len))|s(?:cript_encoding|ignal_check)))|lib.output_(?:compression(?:_level)?|handler)|ookeeper.(?:recv_timeout|sess(?:_lock_wait|ion_lock))))[\s\x0b]*=[^=]
- **Is Chain**: False
- **Message**: PHP Injection Attack: Configuration Directive Found
- **Severity**: CRITICAL
- **Tags**: application-multi, language-php, platform-multi, attack-injection-php, paranoia-level/1, OWASP_CRS, OWASP_CRS/ATTACK-PHP, capec/1000/152/242
- **Actions**: id:933120, phase:2, block, capture, t:none, t:normalisePath, msg:PHP Injection Attack: Configuration Directive Found, logdata:Matched Data: %{TX.0} found within %{TX.933120_MATCHED_VAR_NAME}: %{TX.933120_MATCHED_VAR}, tag:application-multi, tag:language-php, tag:platform-multi, tag:attack-injection-php, tag:paranoia-level/1, tag:OWASP_CRS, tag:OWASP_CRS/ATTACK-PHP, tag:capec/1000/152/242, ver:OWASP_CRS/4.22.0-dev, severity:CRITICAL, setvar:tx.933120_matched_var=%{MATCHED_VAR}, setvar:tx.933120_matched_var_name=%{MATCHED_VAR_NAME}, setvar:tx.php_injection_score=+%{tx.critical_anomaly_score}, setvar:tx.inbound_anomaly_score_pl1=+%{tx.critical_anomaly_score}

#### Rule 6: 933130
- **Phase**: 2
- **Variables**: REQUEST_COOKIES, REQUEST_COOKIES_NAMES, ARGS_NAMES, ARGS, XML:/*
- **Operator**: @pmFromFile
- **Pattern**: php-variables.data
- **Is Chain**: False
- **Message**: PHP Injection Attack: Variables Found
- **Severity**: CRITICAL
- **Tags**: application-multi, language-php, platform-multi, attack-injection-php, paranoia-level/1, OWASP_CRS, OWASP_CRS/ATTACK-PHP, capec/1000/152/242
- **Actions**: id:933130, phase:2, block, capture, t:none, t:normalisePath, t:urlDecodeUni, msg:PHP Injection Attack: Variables Found, logdata:Matched Data: %{TX.0} found within %{MATCHED_VAR_NAME}: %{MATCHED_VAR}, tag:application-multi, tag:language-php, tag:platform-multi, tag:attack-injection-php, tag:paranoia-level/1, tag:OWASP_CRS, tag:OWASP_CRS/ATTACK-PHP, tag:capec/1000/152/242, ver:OWASP_CRS/4.22.0-dev, severity:CRITICAL, setvar:tx.php_injection_score=+%{tx.critical_anomaly_score}, setvar:tx.inbound_anomaly_score_pl1=+%{tx.critical_anomaly_score}

#### Rule 7: 933135
- **Phase**: 2
- **Variables**: REQUEST_COOKIES, REQUEST_COOKIES_NAMES, REQUEST_FILENAME, ARGS_NAMES, ARGS, XML:/*
- **Operator**: @rx
- **Pattern**: \$\s*\{\s*\S[^\{\}]*\}
- **Is Chain**: False
- **Message**: PHP Injection Attack: Variable Access Found
- **Severity**: CRITICAL
- **Tags**: application-multi, language-php, platform-multi, attack-injection-php, paranoia-level/1, OWASP_CRS, OWASP_CRS/ATTACK-PHP, capec/1000/152/242
- **Actions**: id:933135, phase:2, block, capture, t:none, msg:PHP Injection Attack: Variable Access Found, logdata:Matched Data: %{TX.0} found within %{MATCHED_VAR_NAME}: %{MATCHED_VAR}, tag:application-multi, tag:language-php, tag:platform-multi, tag:attack-injection-php, tag:paranoia-level/1, tag:OWASP_CRS, tag:OWASP_CRS/ATTACK-PHP, tag:capec/1000/152/242, ver:OWASP_CRS/4.22.0-dev, severity:CRITICAL, setvar:tx.php_injection_score=+%{tx.critical_anomaly_score}, setvar:tx.inbound_anomaly_score_pl1=+%{tx.critical_anomaly_score}

#### Rule 8: 933140
- **Phase**: 2
- **Variables**: REQUEST_COOKIES, REQUEST_COOKIES_NAMES, ARGS_NAMES, ARGS, XML:/*
- **Operator**: @rx
- **Pattern**: (?i)php://(?:std(?:in|out|err)|(?:in|out)put|fd|memory|temp|filter)
- **Is Chain**: False
- **Message**: PHP Injection Attack: I/O Stream Found
- **Severity**: CRITICAL
- **Tags**: application-multi, language-php, platform-multi, attack-injection-php, paranoia-level/1, OWASP_CRS, OWASP_CRS/ATTACK-PHP, capec/1000/152/242
- **Actions**: id:933140, phase:2, block, capture, t:none, msg:PHP Injection Attack: I/O Stream Found, logdata:Matched Data: %{TX.0} found within %{MATCHED_VAR_NAME}: %{MATCHED_VAR}, tag:application-multi, tag:language-php, tag:platform-multi, tag:attack-injection-php, tag:paranoia-level/1, tag:OWASP_CRS, tag:OWASP_CRS/ATTACK-PHP, tag:capec/1000/152/242, ver:OWASP_CRS/4.22.0-dev, severity:CRITICAL, setvar:tx.php_injection_score=+%{tx.critical_anomaly_score}, setvar:tx.inbound_anomaly_score_pl1=+%{tx.critical_anomaly_score}

#### Rule 9: 933200
- **Phase**: 2
- **Variables**: REQUEST_COOKIES, REQUEST_COOKIES_NAMES, ARGS_NAMES, ARGS, XML:/*
- **Operator**: @rx
- **Pattern**: (?:bzip2|expect|glob|ogg|(?:ph|r)ar|ssh2(?:.(?:s(?:hell|(?:ft|c)p)|exec|tunnel))?|z(?:ip|lib))://
- **Is Chain**: False
- **Message**: PHP Injection Attack: Wrapper scheme detected
- **Severity**: CRITICAL
- **Tags**: application-multi, language-php, platform-multi, attack-injection-php, paranoia-level/1, OWASP_CRS, OWASP_CRS/ATTACK-PHP, capec/1000/152/242
- **Actions**: id:933200, phase:2, block, t:none, t:utf8toUnicode, t:urlDecodeUni, t:removeNulls, t:cmdLine, msg:PHP Injection Attack: Wrapper scheme detected, logdata:Matched Data: %{MATCHED_VAR} found within %{MATCHED_VAR_NAME}, tag:application-multi, tag:language-php, tag:platform-multi, tag:attack-injection-php, tag:paranoia-level/1, tag:OWASP_CRS, tag:OWASP_CRS/ATTACK-PHP, tag:capec/1000/152/242, ver:OWASP_CRS/4.22.0-dev, severity:CRITICAL, setvar:tx.php_injection_score=+%{tx.critical_anomaly_score}, setvar:tx.inbound_anomaly_score_pl1=+%{tx.critical_anomaly_score}

#### Rule 10: 933150
- **Phase**: 2
- **Variables**: REQUEST_COOKIES, REQUEST_COOKIES_NAMES, REQUEST_FILENAME, ARGS_NAMES, ARGS, XML:/*
- **Operator**: @pmFromFile
- **Pattern**: php-function-names-933150.data
- **Is Chain**: False
- **Message**: PHP Injection Attack: High-Risk PHP Function Name Found
- **Severity**: CRITICAL
- **Tags**: application-multi, language-php, platform-multi, attack-injection-php, paranoia-level/1, OWASP_CRS, OWASP_CRS/ATTACK-PHP, capec/1000/152/242
- **Actions**: id:933150, phase:2, block, capture, t:none, msg:PHP Injection Attack: High-Risk PHP Function Name Found, logdata:Matched Data: %{TX.0} found within %{MATCHED_VAR_NAME}: %{MATCHED_VAR}, tag:application-multi, tag:language-php, tag:platform-multi, tag:attack-injection-php, tag:paranoia-level/1, tag:OWASP_CRS, tag:OWASP_CRS/ATTACK-PHP, tag:capec/1000/152/242, ver:OWASP_CRS/4.22.0-dev, severity:CRITICAL, setvar:tx.php_injection_score=+%{tx.critical_anomaly_score}, setvar:tx.inbound_anomaly_score_pl1=+%{tx.critical_anomaly_score}

#### Rule 11: 933160
- **Phase**: 2
- **Variables**: REQUEST_COOKIES, REQUEST_COOKIES_NAMES, REQUEST_FILENAME, ARGS_NAMES, ARGS, XML:/*
- **Operator**: @rx
- **Pattern**: (?i)\b\(?[\"']*(?:assert(?:_options)?|c(?:hr|reate_function)|e(?:val|x(?:ec|p))|f(?:ile(?:group)?|open|puts)|glob|i(?:mage(?:gif|(?:jpe|pn)g|wbmp|xbm)|s_a)|m(?:d5|kdir)|o(?:pendir|rd)|p(?:assthru|open|r(?:intf|ev))|r(?:eadfile|trim)|s(?:t(?:rip_tags|at)|ubstr|ystem)|tmpfile|u(?:n(?:pac|lin)k|sort))(?:/(?:\*.*?\*/|/[^\n\r]*)|#[^\n\r]*|[\s\x0b\"])*[\"']*\)?[\s\x0b]*\([^\)]*\)
- **Is Chain**: False
- **Message**: PHP Injection Attack: High-Risk PHP Function Call Found
- **Severity**: CRITICAL
- **Tags**: application-multi, language-php, platform-multi, attack-injection-php, paranoia-level/1, OWASP_CRS, OWASP_CRS/ATTACK-PHP, capec/1000/152/242
- **Actions**: id:933160, phase:2, block, capture, t:none, msg:PHP Injection Attack: High-Risk PHP Function Call Found, logdata:Matched Data: %{TX.0} found within %{MATCHED_VAR_NAME}: %{MATCHED_VAR}, tag:application-multi, tag:language-php, tag:platform-multi, tag:attack-injection-php, tag:paranoia-level/1, tag:OWASP_CRS, tag:OWASP_CRS/ATTACK-PHP, tag:capec/1000/152/242, ver:OWASP_CRS/4.22.0-dev, severity:CRITICAL, setvar:tx.php_injection_score=+%{tx.critical_anomaly_score}, setvar:tx.inbound_anomaly_score_pl1=+%{tx.critical_anomaly_score}

#### Rule 12: 933170
- **Phase**: 2
- **Variables**: REQUEST_COOKIES, REQUEST_COOKIES_NAMES, REQUEST_HEADERS, ARGS_NAMES, ARGS, XML:/*
- **Operator**: @rx
- **Pattern**: [oOcC]:\d+:\".+?\":\d+:{.*}
- **Is Chain**: False
- **Message**: PHP Injection Attack: Serialized Object Injection
- **Severity**: CRITICAL
- **Tags**: application-multi, language-php, platform-multi, attack-injection-php, paranoia-level/1, OWASP_CRS, OWASP_CRS/ATTACK-PHP, capec/1000/152/242
- **Actions**: id:933170, phase:2, block, capture, t:none, msg:PHP Injection Attack: Serialized Object Injection, logdata:Matched Data: %{TX.0} found within %{MATCHED_VAR_NAME}: %{MATCHED_VAR}, tag:application-multi, tag:language-php, tag:platform-multi, tag:attack-injection-php, tag:paranoia-level/1, tag:OWASP_CRS, tag:OWASP_CRS/ATTACK-PHP, tag:capec/1000/152/242, ver:OWASP_CRS/4.22.0-dev, severity:CRITICAL, setvar:tx.php_injection_score=+%{tx.critical_anomaly_score}, setvar:tx.inbound_anomaly_score_pl1=+%{tx.critical_anomaly_score}

#### Rule 13: 933180
- **Phase**: 2
- **Variables**: REQUEST_COOKIES, REQUEST_COOKIES_NAMES, REQUEST_FILENAME, ARGS_NAMES, ARGS, XML:/*
- **Operator**: @rx
- **Pattern**: \$+(?:[a-zA-Z_\x7f-\xff][a-zA-Z0-9_\x7f-\xff]*|\s*{.+})(?:\s|\[.+\]|{.+}|/\*.*\*/|//.*|#.*)*\(.*\)
- **Is Chain**: False
- **Message**: PHP Injection Attack: Variable Function Call Found
- **Severity**: CRITICAL
- **Tags**: application-multi, language-php, platform-multi, attack-injection-php, paranoia-level/1, OWASP_CRS, OWASP_CRS/ATTACK-PHP, capec/1000/152/242
- **Actions**: id:933180, phase:2, block, capture, t:none, msg:PHP Injection Attack: Variable Function Call Found, logdata:Matched Data: %{TX.0} found within %{MATCHED_VAR_NAME}: %{MATCHED_VAR}, tag:application-multi, tag:language-php, tag:platform-multi, tag:attack-injection-php, tag:paranoia-level/1, tag:OWASP_CRS, tag:OWASP_CRS/ATTACK-PHP, tag:capec/1000/152/242, ver:OWASP_CRS/4.22.0-dev, severity:CRITICAL, setvar:tx.php_injection_score=+%{tx.critical_anomaly_score}, setvar:tx.inbound_anomaly_score_pl1=+%{tx.critical_anomaly_score}

#### Rule 14: 933210
- **Phase**: 2
- **Variables**: REQUEST_COOKIES, REQUEST_COOKIES_NAMES, REQUEST_FILENAME, ARGS_NAMES, ARGS, XML:/*
- **Operator**: @rx
- **Pattern**: (?:\((?:.+\)(?:[\"'][\-0-9A-Z_a-z]+[\"'])?\(.+|[^\)]*string[^\)]*\)[\s\x0b\"'\-\.0-9A-\[\]_a-\{\}]+\([^\)]*)|(?:\[[0-9]+\]|\{[0-9]+\}|\$[^\(\),\./;\x5c]+|[\"'][\-0-9A-Z\x5c_a-z]+[\"'])\(.+)\);
- **Is Chain**: False
- **Message**: PHP Injection Attack: Variable Function Call Found
- **Severity**: CRITICAL
- **Tags**: application-multi, language-php, platform-multi, attack-injection-php, paranoia-level/1, OWASP_CRS, OWASP_CRS/ATTACK-PHP, capec/1000/152/242
- **Actions**: id:933210, phase:2, block, capture, t:none, t:urlDecodeUni, t:replaceComments, t:removeWhitespace, msg:PHP Injection Attack: Variable Function Call Found, logdata:Matched Data: %{TX.0} found within %{MATCHED_VAR_NAME}: %{MATCHED_VAR}, tag:application-multi, tag:language-php, tag:platform-multi, tag:attack-injection-php, tag:paranoia-level/1, tag:OWASP_CRS, tag:OWASP_CRS/ATTACK-PHP, tag:capec/1000/152/242, ver:OWASP_CRS/4.22.0-dev, severity:CRITICAL, setvar:tx.php_injection_score=+%{tx.critical_anomaly_score}, setvar:tx.inbound_anomaly_score_pl1=+%{tx.critical_anomaly_score}

#### Rule 15: 933013
- **Phase**: 1
- **Variables**: TX:DETECTION_PARANOIA_LEVEL
- **Operator**: @lt
- **Pattern**: 2
- **Is Chain**: False
- **Message**: 
- **Severity**: 
- **Tags**: OWASP_CRS
- **Actions**: id:933013, phase:1, pass, nolog, tag:OWASP_CRS, ver:OWASP_CRS/4.22.0-dev, skipAfter:END-REQUEST-933-APPLICATION-ATTACK-PHP

#### Rule 16: 933014
- **Phase**: 2
- **Variables**: TX:DETECTION_PARANOIA_LEVEL
- **Operator**: @lt
- **Pattern**: 2
- **Is Chain**: False
- **Message**: 
- **Severity**: 
- **Tags**: OWASP_CRS
- **Actions**: id:933014, phase:2, pass, nolog, tag:OWASP_CRS, ver:OWASP_CRS/4.22.0-dev, skipAfter:END-REQUEST-933-APPLICATION-ATTACK-PHP

#### Rule 17: 933151
- **Phase**: 2
- **Variables**: REQUEST_COOKIES, REQUEST_COOKIES_NAMES, REQUEST_FILENAME, ARGS_NAMES, ARGS, XML:/*
- **Operator**: @rx
- **Pattern**: (?i)\b(?:a(?:c(?:cel_chdir|osh?)|ddc?slashes|pache_(?:child_terminate|get(?:_(?:modules|version)|env)|lookup_uri|note |re(?:quest|sponse)_headers|setenv)|r(?:ray_(?:c(?:h(?:ange_key_case|unk)|o(?:lumn|mbine|unt_values))|diff(?:_(?:assoc|key|u(?:assoc|key)))?|f(?:ill(?:_keys)?|lip)|i(?:ntersect(?:_(?:assoc|key|u(?:assoc|key)))?|s_list)|key(?:_(?:fir|la)st|s)|m(?:ap|erge(?:_recursive)?|ultisort)|p(?:ad|op|roduct)|r(?:and|e(?:(?:duc|vers)e|place(?:_recursive)?))|s(?:earch|p?lice|um)|u(?:(?:diff|intersect)(?:_u?assoc)?|n(?:ique|shift))|walk(?:_recursive)?)|sort)|s(?:inh|ort|sert_options)|tan[2h]?)|b(?:ase(?:64_(?:de|en)code|_convert)|c(?:add|comp|div|m(?:od|ul)|pow(?:mod)?|s(?:cale|qrt|ub))|in(?:2hex|d(?:_textdomain_codeset|ec|textdomain))|oolval|z(?:(?:de)?compress|err(?:no|(?:o|st)r)|open|read))|c(?:al(?:_(?:days_in_month|(?:from|to)_jd|info)|l_user_func_array)|eil|h(?:(?:di)?r|grp|mod|own|unk_split)|l(?:ass_(?:alia|(?:implem|par)ent|use)s|earstatcache|ose(?:dir|log))|o(?:llator_(?:asort|c(?:ompar|reat)e|get_(?:(?:attribut|error_(?:cod|messag)|local)e|s(?:ort_key|trength))|s(?:et_(?:attribute|strength)|ort(?:_with_sort_keys)?))|m_(?:create_guid|event_sink|get_active_object|load_typelib|message_pump|print_typeinfo)|n(?:fig_get_hash|nection_(?:aborted|status)|vert_uu(?:de|en)code)|unt_chars)|rc32|type_(?:al(?:num|pha)|cntrl|(?:x?digi|p(?:rin|unc))t|graph|(?:low|upp)er|space)|url_(?:(?:c(?:los|opy_handl)|file_creat|paus)e|e(?:rr(?:no|or)|scape|xec)|getinfo|(?:ini|rese)t|multi_(?:(?:(?:add|remove)_handl|clos)e|e(?:rrno|xec)|getcontent|in(?:fo_read|it)|s(?:e(?:lec|top)t|trerror))|s(?:etopt(?:_array)?|hare_(?:close|errno|init|s(?:etopt|trerror))|trerror)|u(?:nescape|pkeep)|version))|d(?:ate(?:_(?:add|create(?:_(?:from_format|immutable(?:_from_format)?))?|d(?:(?:ate_s|efault_timezone_[gs])et|iff)|(?:forma|(?:offset_g|time(?:_s|(?:stamp|zone)_[gs]))e)t|get_last_errors|i(?:nterval_(?:create_from_date_string|format)|sodate_set)|modify|parse(?:_from_format)?|su(?:b|n(?:_info|rise|set)))|fmt_(?:(?:creat|localtim|pars)e|format(?:_object)?|get_(?:calendar(?:_object)?|(?:datetyp|error_(?:cod|messag)|local)e|pattern|time(?:type|zone(?:_id)?))|is_lenient|set_(?:calendar|lenient|pattern|timezone)))|ba_(?:(?:clos|delet|replac)e|(?:exist|handler)s|f(?:etch|irstkey)|(?:inser|key_spli|lis)t|nextkey|op(?:en|timize)|popen|sync)|(?:cn?)?gettext|e(?:bug_(?:(?:print_)?backtrace|zval_dump)|c(?:bin|hex)|flate_(?:add|init)|g2rad)|isk_(?:free|total)_space|l_test_test[12]|n(?:gettext|s_(?:check_record|get_(?:mx|record)))|om_import_simplexml)|e(?:aster_da(?:te|ys)|n(?:chant_(?:broker_(?:d(?:escribe|ict_exists)|free(?:_dict)?|get_(?:dict_path|error)|(?:ini|request_(?:pwl_)?dic)t|list_dicts|set_(?:dict_path|ordering))|dict_(?:add(?:_to_session)?|(?:quick_)?check|describe|get_error|is_added|s(?:tore_replacemen|ugges)t))|um_exists)|rror_(?:(?:clear|get)_last|(?:lo|reportin)g)|scapeshell(?:arg|cmd)|x(?:if_(?:imagetype|read_data|t(?:agname|humbnail))|pm1|tension_loaded))|f(?:astcgi_finish_request|d(?:atasync|iv)|eof|f(?:i_trampoline|lush)|get(?:c(?:sv)?|s)|i(?:l(?:e_put_contents|ter_(?:has_var|i(?:d|nput(?:_array)?)|list|var(?:_array)?))|nfo_(?:buffer|(?:clos|fil)e|open|set_flags))|loatval|(?:mo|re(?:a|nchtoj))d|nmatch|orward_static_call(?:_array)?|p(?:assthru|m_get_status|rintf|utcsv)|s(?:canf|eek|ockopen|tat|ync)|t(?:ell|ok|p_(?:a(?:lloc|ppend)|c(?:dup|h(?:dir|mod)|lose|onnect)|delete|exec|f(?:ge|pu)t|get(?:_option)?|login|m(?:dtm|kdir|lsd)|n(?:b_(?:continue|(?:f(?:ge|pu)|ge|pu)t)|list)|p(?:asv|ut|wd)|r(?:aw(?:list)?|ename|mdir)|s(?:et_option|(?:i[tz]|ystyp)e|sl_connect))|runcate)|unc_(?:get_args?|num_args)|write)|g(?:c_(?:(?:(?:collect_cycl|mem_cach)e|statu)s|disable|enabled?)|d_info|et(?:_(?:browser|c(?:(?:alled_clas|lass_(?:method|var))s|(?:fg_va|urrent_use)r)|de(?:bug_type|(?:clared_(?:(?:class|interfac)e|trait)|fined_(?:constant|function|var))s)|(?:extension_func|loaded_extension|m(?:angled_object_var|eta_tag)|parent_clas)s|h(?:eaders|tml_translation_table)|include(?:_path|d_files)|o(?:bject_vars|pen_basedir)|resource(?:_(?:id|type)|s))|(?:cw|lastmo)d|(?:dat|rusag)e|env|host(?:by(?:addr|namel?)|name)|imagesize(?:fromstring)?|my(?:[gpu]id|inode)|opt|protobyn(?:ame|umber)|servby(?:name|port)|t(?:ext|imeofday|ype))|m(?:(?:dat|(?:mk|strf)tim)e|p_(?:a(?:bs|[dn]d)|binomial|c(?:lrbit|mp|om)|div(?:_(?:qr?|r)|exact)|(?:expor|fac|hamdis|testbi)t|gcd(?:ext)?|i(?:mport|n(?:(?:i|ver)t|tval))|jacobi|(?:kronecke|x?o)r|l(?:cm|egendre)|m(?:od|ul)|ne(?:g|xtprime)|p(?:erfect_(?:power|square)|o(?:pcount|wm?)|rob_prime)|r(?:andom_(?:bits|range|seed)|oot(?:rem)?)|s(?:can[01]|etbit|ign|qrt(?:rem)?|trval|ub)))|r(?:apheme_(?:extract|s(?:tr(?:i(?:pos|str)|len|(?:ri?)?pos|str)|ubstr))|egoriantojd)|z(?:(?:un)?compress|(?:de(?:cod|flat)|encod|fil|inflat)e|open))|h(?:ash_(?:(?:algo|equal)s|copy|fi(?:le|nal)|h(?:kdf|mac(?:_(?:algos|file))?)|init|pbkdf2|update(?:_(?:file|stream))?)|e(?:ader(?:_re(?:gister_callback|move)|s_(?:lis|sen)t)|brev|x(?:2bin|dec))|ighlight_(?:file|string)|rtime|t(?:ml(?:(?:_entity|specialchars)_decode|entities)|tp_(?:build_query|response_code))|ypot)|i(?:conv(?:_(?:get_encoding|mime_(?:decode(?:_headers)?|encode)|s(?:et_encoding|tr(?:len|r?pos)|ubstr)))?|dn_to_(?:ascii|utf8)|gnore_user_abort|ma(?:ge(?:_type_to_(?:extension|mime_type)|a(?:ffine(?:matrix(?:conca|ge)t)?|lphablending|ntialias|rc|vif)|(?:bm|w(?:bm|eb))p|c(?:har(?:up)?|o(?:lor(?:a(?:llocate(?:alpha)?|t)|closest(?:alpha|hwb)?|deallocate|(?:exact|resolve)(?:alpha)?|match|s(?:et|forindex|total)|transparent)|nvolution|py(?:merge(?:gray)?|res(?:ampl|iz)ed)?)|r(?:eate(?:from(?:avif|(?:bm|w(?:bm|eb))p|g(?:d(?:2(?:part)?)?|if)|(?:jpe|(?:p|stri)n)g|tga|x[bp]m)|truecolor)?|op(?:auto)?))|d(?:ashedline|estroy)|ellipse|f(?:il(?:l(?:ed(?:arc|(?:ellips|rectangl)e|polygon)|toborder)?|ter)|lip|ont(?:height|width)|t(?:bbox|text))|g(?:ammacorrect|d2?|et(?:clip|interpolation)|if|rab(?:screen|window))|i(?:nterlace|struecolor)|jpeg|l(?:(?:ayereffec|oadfon)t|ine)|openpolygon|p(?:alette(?:copy|totruecolor)|ng|olygon)|r(?:e(?:ctangle|solution)|otate)|s(?:avealpha|cale|et(?:brush|clip|interpolation|pixel|style|t(?:hickness|ile))|tring(?:up)?|[xy])|t(?:ruecolortopalette|ypes)|xbm)|p_(?:(?:8bi|qprin)t|a(?:lerts|ppend)|b(?:ase64|inary|ody(?:struct)?)|c(?:heck|l(?:earflag_full|ose)|reatemailbox)|delete(?:mailbox)?|e(?:rrors|xpunge)|fetch(?:_overview|body|header|(?:mim|structur)e)|g(?:c|et(?:_quota(?:root)?|acl|mailboxes|subscribed))|header(?:info|s)|(?:is_)?open|l(?:ast_error|ist(?:scan)?|sub)|m(?:ail(?:_(?:co(?:mpose|py)|move)|boxmsginfo)?|ime_header_decode|sgno|utf7_to_utf8)|num_(?:msg|recent)|ping|r(?:e(?:namemailbox|open)|fc822_(?:parse_(?:adrlist|headers)|write_address))|s(?:avebody|e(?:arch|t(?:_quota|(?:ac|flag_ful)l))|ort|tatus|ubscribe)|t(?:hread|imeout)|u(?:id|n(?:delet|subscrib)e|tf(?:7_(?:de|en)code|8(?:_to_mutf7)?))))|n(?:_array|et_(?:ntop|pton)|flate_(?:add|get_(?:read_len|status)|init)|i_(?:get(?:_all)?|parse_quantity|restore|set)|t(?:div|erface_exists|l(?:_(?:error_nam|get_error_(?:cod|messag)|is_failur)e|cal_(?:a(?:dd|fter)|(?:befor|f(?:ield_differenc|rom_date_tim)|to_date_tim)e|c(?:lear|reate_instance)|equals|get(?:_(?:a(?:ctual_m(?:ax|in)imum|vailable_locales)|(?:day_of_week_typ|error_(?:cod|messag)|keyword_values_for_local)e|first_day_of_week|greatest_minimum|l(?:east_maximum|ocale)|m(?:aximum|inim(?:al_days_in_first_week|um))|now|(?:(?:repeat|skipp)ed_wall_time_op|weekend_transi)tion|t(?:ime(?:_zone)?|ype)))?|i(?:n_daylight_time|s_(?:equivalent_to|(?:lenien|se)t|weekend))|roll|set(?:_(?:(?:first_day_of|minimal_days_in_first)_week|lenient|(?:repeat|skipp)ed_wall_time_option|time(?:_zone)?))?)|gregcal_(?:(?:create_instanc|[gs]et_gregorian_chang)e|is_leap_year)|tz_(?:c(?:ount_equivalent_ids|reate_(?:default|enumeration|time_zone(?:_id_enumeration)?))|(?:(?:from|to)_date_time_zon|use_daylight_tim)e|get_(?:(?:canonical|windows)_id|d(?:isplay_name|st_savings)|e(?:quivalent_id|rror_(?:cod|messag)e)|(?:gm|offse)t|id(?:_for_windows_id)?|r(?:aw_offset|egion)|(?:tz_data_versio|unknow)n)|has_same_rules))))|p(?:2long|tc(?:embed|parse))|s_(?:bool|(?:(?:(?:c(?:all|ount)|(?:execu|wri)t)ab|uploaded_fi)l|i(?:nfinit|terabl)|re(?:adabl|sourc))e|f(?:i(?:l|nit)e|loat)|link|nan|s(?:calar|oap_fault|tring|ubclass_of))|terator_(?:(?:appl|to_arra)y|count))|j(?:d(?:dayofweek|monthname|to(?:french|gregorian|j(?:ewish|ulian)|unix))|(?:ewish|ulian)tojd|son_(?:last_error(?:_msg)?|validate)))[\s\x0b]*\(
- **Is Chain**: False
- **Message**: PHP Injection Attack: Medium-Risk PHP Function Name Found
- **Severity**: CRITICAL
- **Tags**: application-multi, language-php, platform-multi, attack-injection-php, paranoia-level/2, OWASP_CRS, OWASP_CRS/ATTACK-PHP, capec/1000/152/242
- **Actions**: id:933151, phase:2, block, capture, t:none, msg:PHP Injection Attack: Medium-Risk PHP Function Name Found, logdata:Matched Data: %{TX.0} found within %{TX.933151_MATCHED_VAR_NAME}: %{TX.933151_MATCHED_VAR}, tag:application-multi, tag:language-php, tag:platform-multi, tag:attack-injection-php, tag:paranoia-level/2, tag:OWASP_CRS, tag:OWASP_CRS/ATTACK-PHP, tag:capec/1000/152/242, ver:OWASP_CRS/4.22.0-dev, severity:CRITICAL, setvar:tx.933151_matched_var=%{MATCHED_VAR}, setvar:tx.933151_matched_var_name=%{MATCHED_VAR_NAME}, setvar:tx.php_injection_score=+%{tx.critical_anomaly_score}, setvar:tx.inbound_anomaly_score_pl2=+%{tx.critical_anomaly_score}

#### Rule 18: 933152
- **Phase**: 2
- **Variables**: REQUEST_COOKIES, REQUEST_COOKIES_NAMES, REQUEST_FILENAME, ARGS_NAMES, ARGS, XML:/*
- **Operator**: @rx
- **Pattern**: (?i)\b(?:kr?sort|l(?:c(?:first|g_value|h(?:grp|own))|dap_(?:8859_to_t61|(?:ad|bin)d(?:_ext)?|co(?:mpare|nnect(?:_wallet)?|unt_(?:entri|referenc)es)|d(?:elete(?:_ext)?|n2ufn)|e(?:rr(?:(?:2st|o)r|no)|scape|x(?:op(?:_(?:passwd|refresh|sync|whoami))?|plode_dn))|f(?:irst_(?:(?:attribut|referenc)e|entry)|ree_result)|get_(?:(?:attribut|entri)es|(?:d|optio|values_le)n)|list|mod(?:_(?:add|del|replace)(?:_ext)?|ify_batch)|next_(?:(?:attribut|referenc)e|entry)|parse_(?:exop|re(?:ference|sult))|re(?:ad|name(?:_ext)?)|s(?:asl_bind|e(?:arch|t_(?:option|rebind_proc))|tart_tls)|t61_to_8859|unbind)|evenshtein|i(?:bxml_(?:(?:clear|use_internal)_errors|disable_entity_loader|get_(?:e(?:rrors|xternal_entity_loader)|last_error)|set_(?:external_entity_loader|streams_context))|nkinfo|tespeed_(?:finish_request|re(?:quest|sponse)_headers))|o(?:cal(?:e(?:_(?:(?:accept_from_htt|looku)p|(?:c(?:anonicaliz|ompos)|pars)e|filter_matches|get_(?:(?:all_variant|keyword)s|d(?:efault|isplay_(?:(?:languag|nam)e|region|(?:scrip|varian)t))|primary_language|region|script)|set_default)|conv)|time)|g1[0p]|ng2ip)|stat|trim)|m(?:b_(?:c(?:h(?:eck_encoding|r)|onvert_(?:case|encoding|kana|variables))|de(?:code_(?:mimeheader|numericentity)|tect_(?:encoding|order))|e(?:ncod(?:e_(?:mimeheader|numericentity)|ing_aliases)|reg(?:_(?:match|replace(?:_callback)?|search(?:_(?:(?:get(?:po|reg)|(?:set)?po|reg)s|init))?)|i(?:_replace)?)?)|get_info|http_(?:in|out)put|internal_encoding|l(?:anguage|ist_encodings)|o(?:rd|utput_handler)|p(?:arse_str|referred_mime_name)|regex_(?:encoding|set_options)|s(?:crub|end_mail|plit|tr(?:_(?:pad|split)|cut|i(?:mwidth|pos|str)|len|pos|r(?:chr|i(?:chr|pos)|pos)|(?:st|to(?:low|upp)e)r|width)|ubst(?:itute_character|r(?:_count)?)))|(?:(?:d5|ove_uploaded)_fil|e(?:mory_(?:get_(?:peak_)?|reset_peak_)usag|taphon)|i(?:crotim|me_content_typ))e|hash(?:_(?:count|get_(?:block_siz|hash_nam)e|keygen_s2k))?|k(?:dir|time)|sg(?:_(?:(?:get_queu|re(?:ceiv|move_queu))e|queue_exists|s(?:e(?:nd|t_queue)|tat_queue))|fmt_(?:create|(?:format|parse)(?:_message)?|get_(?:(?:error_(?:cod|messag)|local)e|pattern)|set_pattern))|t_(?:getrandmax|s?rand)|ysqli_(?:a(?:ffected_rows|utocommit)|begin_transaction|c(?:ha(?:nge_user|racter_set_name)|lose|o(?:mmit|nnect(?:_err(?:no|or))?))|d(?:ata_seek|ebug|ump_debug_info)|e(?:rr(?:no|or(?:_list)?)|xecute_query)|f(?:etch_(?:a(?:ll|rray|ssoc)|column|field(?:_direct|s)?|lengths|object|row)|ield_(?:count|seek|tell)|ree_result)|get_(?:c(?:harset|lient_(?:info|stats|version)|onnection_stats)|(?:host|proto)_info|(?:links_stat|warning)s|server_(?:info|version))|in(?:fo|it|sert_id)|kill|m(?:ore_results|ulti_query)|n(?:ext_result|um_(?:field|row)s)|options|p(?:ing|oll|repare)|query|r(?:e(?:a(?:l_(?:connect|escape_string|query)|p_async_query)|fresh|(?:lease_savepoin|por)t)|ollback)|s(?:(?:avepoin|sl_se)t|e(?:lect_db|t_charset)|qlstate|t(?:(?:a|ore_resul)t|mt_(?:a(?:ffected_rows|ttr_[gs]et)|bind_(?:param|result)|close|data_seek|e(?:rr(?:no|or(?:_list)?)|xecute)|f(?:etch|(?:ield_coun|ree_resul)t)|get_(?:result|warnings)|in(?:it|sert_id)|more_results|n(?:ext_result|um_rows)|p(?:aram_count|repare)|res(?:et|ult_metadata)|s(?:end_long_data|qlstate|tore_result))))|thread_(?:id|safe)|(?:use_resul|warning_coun)t))|n(?:(?:at(?:case)?sor|gettex)t|et_get_interfaces|l(?:2br|_langinfo)|ormalizer_(?:get_raw_decomposition|is_normalized|normalize)|umfmt_(?:create|(?:format|parse)(?:_currency)?|get_(?:(?:(?:text_)?attribut|error_(?:cod|messag)|local)e|pattern|symbol)|set_(?:(?:text_)?attribute|pattern|symbol)))|o(?:b_(?:clean|end_(?:clean|flush)|(?:implicit_)?flush|g(?:et_(?:c(?:lean|ontents)|flush|le(?:ngth|vel)|status)|zhandler)|list_handlers)|c(?:i(?:_(?:(?:bind_(?:array_)?|define_)by_name|c(?:ancel|l(?:ient_version|ose)|o(?:llection_(?:a(?:ppend|ssign)|element_(?:assign|get)|max|size|trim)|(?:mmi|nnec)t))|e(?:rror|xecute)|f(?:etch(?:_(?:a(?:ll|rray|ssoc)|object|row))?|ield_(?:is_null|(?:nam|s(?:cal|iz))e|precision|type(?:_raw)?)|ree_(?:collection|descriptor|statement))|get_implicit_resultset|lob_(?:(?:appen|loa|re(?:a|win))d|copy|e(?:of|rase|xport)|flush|i(?:mport|s_equal)|s(?:(?:av|iz)e|eek)|t(?:ell|runcate)|write)|n(?:ew_(?:c(?:o(?:llection|nnect)|ursor)|descriptor)|um_(?:field|row)s)|p(?:a(?:rs|ssword_chang)e|connect)|r(?:e(?:gister_taf_callback|sult)|ollback)|s(?:e(?:rver_version|t_(?:(?:ac|db_opera|edi)tion|c(?:all_timeout|lient_i(?:dentifier|nfo))|module_name|prefetch(?:_lob)?))|tatement_type)|unregister_taf_callback)|fetchinto|[gs]etbufferinglob)|tdec)|dbc_(?:autocommit|(?:binmod|data_sourc)e|c(?:lose(?:_all)?|o(?:lumn(?:privilege)?s|mmit|nnect(?:ion_string_(?:is_quoted|(?:should_)?quote))?)|ursor)|e(?:rror(?:msg)?|xec(?:ute)?)|f(?:etch_(?:array|into|object|row)|ield_(?:len|n(?:ame|um)|(?:scal|typ)e)|oreignkeys|ree_result)|gettypeinfo|longreadlen|n(?:ext_result|um_(?:field|row)s)|p(?:connect|r(?:epare|(?:imarykey|ocedure(?:column)?)s))|r(?:esult(?:_all)?|ollback)|s(?:etoption|(?:pecialcolumn|tatistic)s)|table(?:privilege)?s)|p(?:cache_(?:compile_file|get_(?:configuration|status)|i(?:nvalidate|s_script_cached)|reset)|en(?:dir|log|ssl_(?:c(?:ipher_(?:iv|key)_length|ms_(?:(?:de|en)crypt|read|sign|verify)|sr_(?:export(?:_to_file)?|get_(?:public_key|subject)|new|sign))|d(?:(?:ecryp|iges)t|h_compute_key)|e(?:ncrypt|rror_string)|(?:get_(?:c(?:ert_location|ipher_method|urve_name)|md_method)|random_pseudo_byte)s|open|p(?:bkdf2|k(?:cs(?:12_(?:export(?:_to_file)?|read)|7_(?:(?:de|en)crypt|read|sign|verify))|ey_(?:(?:deriv|fre)e|export(?:_to_file)?|get_(?:details|p(?:rivate|ublic))|new))|(?:rivate|ublic)_(?:de|en)crypt)|s(?:eal|ign|pki_(?:export(?:_challenge)?|new|verify))|verify|x509_(?:check(?:_private_key|purpose)|export(?:_to_file)?|f(?:ingerprint|ree)|parse|read|verify))))|utput_(?:add_rewrite_var|reset_rewrite_vars))|p(?:a(?:rse_(?:ini_(?:file|string)|str)|ss(?:thru|word_(?:algos|get_info|(?:needs_re)?hash|verify))|thinfo)|c(?:lose|ntl_(?:a(?:larm|sync_signals)|exec|forkx?|get(?:_last_error|priority)|rfork|s(?:etpriority|ig(?:nal(?:_(?:dispatch|get_handler))?|procmask|timedwait|waitinfo)|trerror)|unshare|w(?:ait(?:pid)?|exitstatus|if(?:continu|exit|s(?:ignal|topp))ed|(?:stop|term)sig)))|do_drivers|fsockopen|g_(?:(?:affected_row|num_(?:field|row)|option)s|c(?:ancel_query|l(?:ient_encoding|ose)|o(?:n(?:nect(?:_poll|ion_(?:busy|reset|status))?|(?:sume_inpu|ver)t)|py_(?:from|to)))|d(?:bnam|elet)e|e(?:n(?:d_copy|ter_pipeline_mode)|scape_(?:bytea|identifier|literal|string)|x(?:ecut|it_pipeline_mod)e)|f(?:etch_(?:a(?:ll(?:_columns)?|rray|ssoc)|object|r(?:esult|ow))|ield(?:_(?:is_null|n(?:ame|um)|prtlen|size|t(?:able|ype(?:_oid)?))|isnull|prtlen)|lush|ree_result)|get_(?:notify|pid|result)|(?:hos|inser)t|l(?:ast_(?:error|notice|oid)|o_(?:(?:c(?:los|reat)|writ)e|(?:ex|im)port|open|read(?:_all)?|(?:see|unlin)k|t(?:ell|runcate)))|meta_data|p(?:arameter_status|(?:connec|or)t|i(?:ng|peline_s(?:tatus|ync))|(?:repar|ut_lin)e)|query(?:_params)?|result_(?:error(?:_field)?|s(?:eek|tatus))|s(?:e(?:lect|nd_(?:(?:execut|prepar)e|query(?:_params)?)|t_(?:client_encoding|error_(?:context_visibil|verbos)ity))|ocket)|t(?:ra(?:ce|nsaction_status)|ty)|u(?:n(?:escape_bytea|trace)|pdate)|version)|hp(?:_(?:ini_(?:loaded_file|scanned_files)|(?:s(?:api_nam|trip_whitespac)|unam)e)|credits|dbg_(?:break_(?:f(?:ile|unction)|method|next)|c(?:lea|olo)r|e(?:nd_oplog|xec)|get_executable|prompt|start_oplog)|info|version)|osix_(?:e?access|ctermid|f?pathconf|get(?:_last_error|(?:cw|(?:e[gu]|[su])i)d|g(?:id|r(?:gid|nam|oups))|login|p(?:g(?:id|rp)|p?id|w(?:nam|uid))|rlimit)|i(?:nitgroups|satty)|kill|mk(?:fifo|nod)|s(?:et(?:(?:e[gu]|p?g|[su])id|rlimit)|trerror|ysconf)|t(?:imes|tyname)|uname)|r(?:eg_(?:filter|grep|last_error(?:_msg)?|match_all|quote|replace_callback(?:_array)?|split)|o(?:c_(?:(?:clos|nic|terminat)e|get_status|open)|perty_exists))|spell_(?:add_to_(?:personal|session)|c(?:heck|lear_session|onfig_(?:(?:creat|ignor|mod)e|d(?:ata|ict)_dir|(?:persona|save_rep)l|r(?:epl|untogether)))|new(?:_(?:config|personal))?|s(?:(?:ave_wordli|ugge)s|tore_replacemen)t)|utenv)|quote(?:d_printable_(?:de|en)code|meta))[\s\x0b]*\(
- **Is Chain**: False
- **Message**: PHP Injection Attack: Medium-Risk PHP Function Name Found
- **Severity**: CRITICAL
- **Tags**: application-multi, language-php, platform-multi, attack-injection-php, paranoia-level/2, OWASP_CRS, OWASP_CRS/ATTACK-PHP, capec/1000/152/242
- **Actions**: id:933152, phase:2, block, capture, t:none, msg:PHP Injection Attack: Medium-Risk PHP Function Name Found, logdata:Matched Data: %{TX.0} found within %{TX.933152_MATCHED_VAR_NAME}: %{TX.933152_MATCHED_VAR}, tag:application-multi, tag:language-php, tag:platform-multi, tag:attack-injection-php, tag:paranoia-level/2, tag:OWASP_CRS, tag:OWASP_CRS/ATTACK-PHP, tag:capec/1000/152/242, ver:OWASP_CRS/4.22.0-dev, severity:CRITICAL, setvar:tx.933152_matched_var=%{MATCHED_VAR}, setvar:tx.933152_matched_var_name=%{MATCHED_VAR_NAME}, setvar:tx.php_injection_score=+%{tx.critical_anomaly_score}, setvar:tx.inbound_anomaly_score_pl2=+%{tx.critical_anomaly_score}

#### Rule 19: 933153
- **Phase**: 2
- **Variables**: REQUEST_COOKIES, REQUEST_COOKIES_NAMES, REQUEST_FILENAME, ARGS_NAMES, ARGS, XML:/*
- **Operator**: @rx
- **Pattern**: (?i)\b(?:r(?:a(?:d2deg|ndom_(?:bytes|int)|wurl(?:de|en)code)|e(?:a(?:d(?:dir|(?:gz)?file|lin(?:e(?:_(?:(?:(?:add|list|write)_histor|re(?:ad_histor|displa))y|c(?:allback_(?:handler_(?:install|remove)|read_char)|lear_history|ompletion_function)|info|on_new_line))?|k))|lpath(?:_cache_(?:get|size))?)|gister_(?:shutdown|tick)_function|s(?:ourcebundle_(?:c(?:ount|reate)|get(?:_error_(?:cod|messag)e)?|locales)|tore_e(?:rror|xception)_handler)|wind(?:dir)?)|mdir|sort)|s(?:api_windows_(?:cp_(?:conv|[gs]et|is_utf8)|(?:generate_ctrl_even|vt100_suppor)t|set_ctrl_handler)|candir|e(?:m_(?:(?:acquir|re(?:leas|mov))e|get)|ssion_(?:(?:abor|unse)t|c(?:ache_(?:expire|limiter)|reate_id)|de(?:code|stroy)|(?:encod|(?:module_)?nam|write_clos)e|g(?:c|et_cookie_params)|id|re(?:g(?:enerate_id|ister_shutdown)|set)|s(?:ave_path|et_(?:cookie_params|save_handler)|ta(?:rt|tus)))|t(?:_(?:e(?:rror|xception)_handler|include_path|time_limit)|(?:(?:raw)?cooki|local)e))|h(?:a1(?:_file)?|ell_exec|m(?:_(?:(?:at|de)tach|(?:(?:ge|pu)t|has)_var|remove(?:_var)?)|op_(?:(?:clos|(?:dele|wri)t|siz)e|open|read)))|i(?:m(?:ilar_text|plexml_(?:import_dom|load_(?:file|string)))|nh)|nmp(?:[23]_(?:get(?:next)?|(?:real_)?walk|set)|_(?:get_(?:quick_print|valueretrieval)|read_mib|set_(?:(?:(?:enum|quick)_prin|oid_output_forma)t|valueretrieval))|get(?:next)?|(?:real)?walk|set)|o(?:cket_(?:a(?:ccept|ddrinfo_(?:bind|connect|explain|lookup)|tmark)|bind|c(?:l(?:ear_error|ose)|msg_space|onnect|reate(?:_(?:listen|pair))?)|(?:ex|im)port_stream|get(?:_option|(?:peer|sock)name)|l(?:ast_error|isten)|re(?:ad|cv(?:from|msg)?)|s(?:e(?:lect|nd(?:msg|to)?|t_(?:(?:non)?block|option))|hutdown|trerror)|w(?:rite|saprotocol_info_(?:(?:ex|im)port|release)))|dium_(?:(?:ad|(?:un)?pa)d|b(?:ase642bin|in2(?:base64|hex))|c(?:ompare|rypto_(?:a(?:ead_(?:aes256gcm_(?:(?:de|en)crypt|is_available|keygen)|chacha20poly1305_(?:(?:de|en)crypt|ietf_(?:(?:de|en)crypt|keygen)|keygen)|xchacha20poly1305_ietf_(?:(?:de|en)crypt|keygen))|uth(?:_(?:keygen|verify))?)|box(?:_(?:keypair(?:_from_secretkey_and_publickey)?|open|publickey(?:_from_secretkey)?|se(?:al(?:_open)?|cretkey|ed_keypair)))?|core_ristretto255_(?:add|from_hash|is_valid_point|random|s(?:calar_(?:add|(?:complemen|inver)t|mul|negate|r(?:andom|educe)|sub)|ub))|generichash(?:_(?:final|init|keygen|update))?|k(?:df_(?:derive_from_key|keygen)|x_(?:client_session_keys|keypair|publickey|se(?:cretkey|ed_keypair|rver_session_keys)))|pwhash(?:_s(?:cryptsalsa208sha256(?:_str(?:_verify)?)?|tr(?:_(?:needs_rehash|verify))?))?|s(?:calarmult(?:_ristretto255(?:_base)?)?|ecret(?:box(?:_(?:keyg|op)en)?|stream_xchacha20poly1305_(?:(?:init_)?pu(?:ll|sh)|keygen|rekey))|horthash(?:_keygen)?|ign(?:_(?:(?:verify_)?detached|ed25519_[ps]k_to_curve25519|keypair(?:_from_secretkey_and_publickey)?|open|publickey(?:_from_secretkey)?|se(?:cretkey|ed_keypair)))?|tream(?:_(?:keygen|x(?:chacha20(?:_(?:keygen|xor(?:_ic)?))?|or)))?)))|hex2bin|increment|mem(?:cmp|zero))|undex)|p(?:l_(?:autoload(?:_(?:call|(?:extens|funct)ions|(?:un)?register))?|classes|object_(?:hash|id))|rintf)|qrt|scanf|tr(?:_(?:contains|(?:decreme|word_cou)nt|ends_with|getcsv|i(?:ncrement|replace)|pad|r(?:epeat|ot13)|s(?:huffle|plit|tarts_with))|c(?:(?:asec)?mp|oll|spn)|eam_(?:bucket_(?:(?:ap|pre)pend|make_writeable|new)|co(?:ntext_(?:create|get_(?:default|(?:option|param)s)|set_(?:default|options?|params))|py_to_stream)|filter_(?:(?:ap|pre)pend|re(?:gister|move))|get_(?:(?:(?:conten|transpor)t|(?:filt|wrapp)er)s|line|meta_data)|is(?:_local|atty)|resolve_include_path|s(?:e(?:lect|t_(?:blocking|chunk_size|(?:read|write)_buffer|timeout))|ocket_(?:(?:accep|clien)t|enable_crypto|get_name|pair|recvfrom|s(?:e(?:ndto|rver)|hutdown))|upports_lock)|wrapper_(?:re(?:gister|store)|unregister))|ftime|i(?:p(?:c?slashe|o)s|str)|n(?:at)?c(?:asec)?mp|p(?:brk|time)|r(?:chr|ev|i?pos)|s(?:pn|tr)|t(?:ok|r)|val)|ubstr_(?:co(?:mpare|unt)|replace)|ys_get(?:_temp_dir|loadavg))|t(?:anh|e(?:mpnam|st[12]|xtdomain)|i(?:dy_(?:(?:access|error|warning)_count|c(?:lean_repair|onfig_count)|diagnose|get(?:_(?:body|config|error_buffer|h(?:ead|tml(?:_ver)?)|o(?:pt_doc|utput)|r(?:elease|oot)|status)|opt)|is_x(?:ht)?ml|(?:parse|repair)_(?:file|string))|me(?:_(?:nanosleep|sleep_until)|zone_(?:(?:(?:abbreviation|identifier)s_lis|(?:(?:locat|vers)ion|transitions)_ge)t|name_(?:from_abbr|get)|o(?:ffset_get|pen))))|mpfile|oken_(?:get_all|name)|r(?:a(?:it_exists|nsliterator_(?:create(?:_(?:from_rules|inverse))?|(?:get_error_(?:cod|messag)|transliterat)e|list_ids))|igger_error))|u(?:[ak]sort|cwords|mask|n(?:i(?:qi|xtoj)d|register_tick_function)|(?:rlde|tf8_(?:de|en))code|s(?:e_soap_error_handler|leep|ort))|v(?:ar(?:_(?:dump|export)|iant_(?:a(?:bs|[dn]d)|c(?:as?t|mp)|d(?:ate_(?:from|to)_timestamp|iv)|eqv|fix|get_type|i(?:div|mp|nt)|m(?:od|ul)|n(?:eg|ot)|x?or|pow|round|s(?:et(?:_type)?|ub)))|ersion_compare|[fs]?printf)|wordwrap|xml(?:_(?:error_string|get_(?:current_(?:byte_index|(?:column|line)_number)|error_code)|parse(?:_into_struct|r_(?:create(?:_ns)?|free|[gs]et_option))?|set_(?:(?:character_data|default|e(?:lement|nd_namespace_decl|xternal_entity_ref)|(?:notation|start_namespace|unparsed_entity)_decl|processing_instruction)_handler|object))|writer_(?:end_(?:attribute|c(?:data|omment)|d(?:ocument|td(?:_(?:attlist|e(?:lement|ntity)))?)|element|pi)|f(?:lush|ull_end_element)|o(?:pen_(?:memory|uri)|utput_memory)|s(?:et_indent(?:_string)?|tart_(?:(?:attribute|element)(?:_ns)?|c(?:data|omment)|d(?:ocument|td(?:_(?:attlist|e(?:lement|ntity)))?)|pi))|text|write_(?:(?:attribute|element)(?:_ns)?|c(?:data|omment)|dtd(?:_(?:attlist|e(?:lement|ntity)))?|pi|raw)))|z(?:end_(?:c(?:all_method|reate_unterminated_string)|get_(?:current_func_name|map_ptr_last|unit_enum)|iterable(?:_legacy)?|leak_(?:bytes|variable)|(?:number_or_string|string_or_(?:object|stdclass))(?:_or_null)?|t(?:e(?:rminate_string|st_(?:(?:(?:nullable_)?array|void)_return|c(?:ompile_string|r(?:ash|eate_throwing_resource))|deprecated|f(?:ill_packed_array|unc)|is_string_marked_as_valid_utf8|(?:override_libxml_global_sta|parameter_with_attribu)te|zend_(?:call_stack_(?:get|use_all)|ini_(?:parse_u?quantity|str))))|hread_id)|version|weakmap_(?:attach|dump|remove))|ip_(?:close|entry_(?:c(?:lose|ompress(?:edsize|ionmethod))|(?:filesiz|nam)e|open|read)|open|read)|lib_(?:(?:de|en)cod|get_coding_typ)e)|ZendTestNS2_(?:ZendSubNS_)?namespaced_(?:deprecated_)?func)[\s\x0b]*\(
- **Is Chain**: False
- **Message**: PHP Injection Attack: Medium-Risk PHP Function Name Found
- **Severity**: CRITICAL
- **Tags**: application-multi, language-php, platform-multi, attack-injection-php, paranoia-level/2, OWASP_CRS, OWASP_CRS/ATTACK-PHP, capec/1000/152/242
- **Actions**: id:933153, phase:2, block, capture, t:none, msg:PHP Injection Attack: Medium-Risk PHP Function Name Found, logdata:Matched Data: %{TX.0} found within %{TX.933153_MATCHED_VAR_NAME}: %{TX.933153_MATCHED_VAR}, tag:application-multi, tag:language-php, tag:platform-multi, tag:attack-injection-php, tag:paranoia-level/2, tag:OWASP_CRS, tag:OWASP_CRS/ATTACK-PHP, tag:capec/1000/152/242, ver:OWASP_CRS/4.22.0-dev, severity:CRITICAL, setvar:tx.933153_matched_var=%{MATCHED_VAR}, setvar:tx.933153_matched_var_name=%{MATCHED_VAR_NAME}, setvar:tx.php_injection_score=+%{tx.critical_anomaly_score}, setvar:tx.inbound_anomaly_score_pl2=+%{tx.critical_anomaly_score}

#### Rule 20: 933015
- **Phase**: 1
- **Variables**: TX:DETECTION_PARANOIA_LEVEL
- **Operator**: @lt
- **Pattern**: 3
- **Is Chain**: False
- **Message**: 
- **Severity**: 
- **Tags**: OWASP_CRS
- **Actions**: id:933015, phase:1, pass, nolog, tag:OWASP_CRS, ver:OWASP_CRS/4.22.0-dev, skipAfter:END-REQUEST-933-APPLICATION-ATTACK-PHP

#### Rule 21: 933016
- **Phase**: 2
- **Variables**: TX:DETECTION_PARANOIA_LEVEL
- **Operator**: @lt
- **Pattern**: 3
- **Is Chain**: False
- **Message**: 
- **Severity**: 
- **Tags**: OWASP_CRS
- **Actions**: id:933016, phase:2, pass, nolog, tag:OWASP_CRS, ver:OWASP_CRS/4.22.0-dev, skipAfter:END-REQUEST-933-APPLICATION-ATTACK-PHP

#### Rule 22: 933131
- **Phase**: 2
- **Variables**: REQUEST_COOKIES, REQUEST_COOKIES_NAMES, ARGS_NAMES, ARGS, XML:/*
- **Operator**: @rx
- **Pattern**: AUTH_TYPE|HTTP_(?:ACCEPT(?:_(?:CHARSET|ENCODING|LANGUAGE))?|CONNECTION|(?:HOS|USER_AGEN)T|KEEP_ALIVE|(?:REFERE|X_FORWARDED_FO)R)|ORIG_PATH_INFO|PATH_(?:INFO|TRANSLATED)|QUERY_STRING|REQUEST_URI
- **Is Chain**: False
- **Message**: PHP Injection Attack: Variables Found
- **Severity**: CRITICAL
- **Tags**: application-multi, language-php, platform-multi, attack-injection-php, paranoia-level/3, OWASP_CRS, OWASP_CRS/ATTACK-PHP, capec/1000/152/242
- **Actions**: id:933131, phase:2, block, capture, t:none, t:normalisePath, t:urlDecodeUni, msg:PHP Injection Attack: Variables Found, logdata:Matched Data: %{TX.0} found within %{MATCHED_VAR_NAME}: %{MATCHED_VAR}, tag:application-multi, tag:language-php, tag:platform-multi, tag:attack-injection-php, tag:paranoia-level/3, tag:OWASP_CRS, tag:OWASP_CRS/ATTACK-PHP, tag:capec/1000/152/242, ver:OWASP_CRS/4.22.0-dev, severity:CRITICAL, setvar:tx.php_injection_score=+%{tx.critical_anomaly_score}, setvar:tx.inbound_anomaly_score_pl3=+%{tx.critical_anomaly_score}

#### Rule 23: 933161
- **Phase**: 2
- **Variables**: REQUEST_COOKIES, REQUEST_COOKIES_NAMES, REQUEST_FILENAME, ARGS_NAMES, ARGS, XML:/*
- **Operator**: @rx
- **Pattern**: (?i)\b(?:a(?:bs|s(?:in|sert(?:_options)?))|basename|c(?:h(?:eckdate|r(?:oot)?)|o(?:(?:mpac|(?:nsta|u)n)t|py|sh?)|r(?:eate_function|ypt)|urrent)|d(?:ate|e(?:coct|fined?)|ir)|e(?:nd|val|x(?:ec|p(?:lode)?|tract))|f(?:ile(?:(?:[acm]tim|inod|siz|typ)e|group|owner|perms)?|l(?:o(?:ck|or)|ush))|glob|h(?:ash|eader)|i(?:date|m(?:age(?:gif|(?:jpe|pn)g|wbmp|xbm)|plode)|s_a)|key|l(?:ink|og)|m(?:a(?:il|x)|d5|in)|n(?:ame|ext)|o(?:pendir|rd)|p(?:a(?:ck|ss(?:thru)?)|i|o(?:pen|w)|rev)|r(?:an(?:d|ge)|e(?:(?:adfil|nam)e|set)|ound)|s(?:(?:erializ|huffl)e|in|leep|(?:or|ta)t|ubstr|y(?:mlink|s(?:log|tem)))|t(?:an|(?:im|mpfil)e|ouch|rim)|u(?:cfirst|n(?:lin|pac)k)|virtual)(?:[\s\x0b]|/\*.*\*/|(?:#|//).*)*\(.*\)
- **Is Chain**: False
- **Message**: PHP Injection Attack: Low-Value PHP Function Call Found
- **Severity**: CRITICAL
- **Tags**: application-multi, language-php, platform-multi, attack-injection-php, paranoia-level/3, OWASP_CRS, OWASP_CRS/ATTACK-PHP, capec/1000/152/242
- **Actions**: id:933161, phase:2, block, capture, t:none, msg:PHP Injection Attack: Low-Value PHP Function Call Found, logdata:Matched Data: %{TX.0} found within %{MATCHED_VAR_NAME}: %{MATCHED_VAR}, tag:application-multi, tag:language-php, tag:platform-multi, tag:attack-injection-php, tag:paranoia-level/3, tag:OWASP_CRS, tag:OWASP_CRS/ATTACK-PHP, tag:capec/1000/152/242, ver:OWASP_CRS/4.22.0-dev, severity:CRITICAL, setvar:tx.php_injection_score=+%{tx.critical_anomaly_score}, setvar:tx.inbound_anomaly_score_pl3=+%{tx.critical_anomaly_score}

#### Rule 24: 933111
- **Phase**: 2
- **Variables**: FILES, REQUEST_HEADERS:X-Filename, REQUEST_HEADERS:X_Filename, REQUEST_HEADERS:X.Filename, REQUEST_HEADERS:X-File-Name
- **Operator**: @rx
- **Pattern**: .*\.(?:php\d*|phtml)\..*$
- **Is Chain**: False
- **Message**: PHP Injection Attack: PHP Script File Upload Found
- **Severity**: CRITICAL
- **Tags**: application-multi, language-php, platform-multi, attack-injection-php, paranoia-level/3, OWASP_CRS, OWASP_CRS/ATTACK-PHP, capec/1000/152/242
- **Actions**: id:933111, phase:2, block, capture, t:none, t:lowercase, msg:PHP Injection Attack: PHP Script File Upload Found, logdata:Matched Data: %{TX.0} found within %{MATCHED_VAR_NAME}: %{MATCHED_VAR}, tag:application-multi, tag:language-php, tag:platform-multi, tag:attack-injection-php, tag:paranoia-level/3, tag:OWASP_CRS, tag:OWASP_CRS/ATTACK-PHP, tag:capec/1000/152/242, ver:OWASP_CRS/4.22.0-dev, severity:CRITICAL, setvar:tx.php_injection_score=+%{tx.critical_anomaly_score}, setvar:tx.inbound_anomaly_score_pl3=+%{tx.critical_anomaly_score}

#### Rule 25: 933190
- **Phase**: 2
- **Variables**: REQUEST_COOKIES, REQUEST_COOKIES_NAMES, ARGS_NAMES, ARGS, XML:/*
- **Operator**: @pm
- **Pattern**: ?>
- **Is Chain**: False
- **Message**: PHP Injection Attack: PHP Closing Tag Found
- **Severity**: CRITICAL
- **Tags**: application-multi, language-php, platform-multi, attack-injection-php, paranoia-level/3, OWASP_CRS, OWASP_CRS/ATTACK-PHP, capec/1000/152/242
- **Actions**: id:933190, phase:2, block, capture, t:none, t:urlDecodeUni, msg:PHP Injection Attack: PHP Closing Tag Found, logdata:Matched Data: %{TX.0} found within %{MATCHED_VAR_NAME}: %{MATCHED_VAR}, tag:application-multi, tag:language-php, tag:platform-multi, tag:attack-injection-php, tag:paranoia-level/3, tag:OWASP_CRS, tag:OWASP_CRS/ATTACK-PHP, tag:capec/1000/152/242, ver:OWASP_CRS/4.22.0-dev, severity:CRITICAL, setvar:tx.php_injection_score=+%{tx.critical_anomaly_score}, setvar:tx.inbound_anomaly_score_pl3=+%{tx.critical_anomaly_score}

#### Rule 26: 933211
- **Phase**: 2
- **Variables**: REQUEST_COOKIES, REQUEST_COOKIES_NAMES, REQUEST_FILENAME, ARGS_NAMES, ARGS, XML:/*
- **Operator**: @rx
- **Pattern**: (?:\((?:.+\)(?:[\"'][\-0-9A-Z_a-z]+[\"'])?\(.+|[^\)]*string[^\)]*\)[\s\x0b\"'\-\.0-9A-\[\]_a-\{\}]+\([^\)]*)|(?:\[[0-9]+\]|\{[0-9]+\}|\$[^\(\),\./;\x5c]+|[\"'][\-0-9A-Z\x5c_a-z]+[\"'])\(.+)\)(?:;|$)?
- **Is Chain**: False
- **Message**: PHP Injection Attack: Variable Function Call Found
- **Severity**: CRITICAL
- **Tags**: application-multi, language-php, platform-multi, attack-injection-php, paranoia-level/3, OWASP_CRS, OWASP_CRS/ATTACK-PHP, capec/1000/152/242
- **Actions**: id:933211, phase:2, block, capture, t:none, t:urlDecodeUni, t:replaceComments, t:removeWhitespace, msg:PHP Injection Attack: Variable Function Call Found, logdata:Matched Data: %{TX.0} found within %{MATCHED_VAR_NAME}: %{MATCHED_VAR}, tag:application-multi, tag:language-php, tag:platform-multi, tag:attack-injection-php, tag:paranoia-level/3, tag:OWASP_CRS, tag:OWASP_CRS/ATTACK-PHP, tag:capec/1000/152/242, ver:OWASP_CRS/4.22.0-dev, severity:CRITICAL, setvar:tx.php_injection_score=+%{tx.critical_anomaly_score}, setvar:tx.inbound_anomaly_score_pl3=+%{tx.critical_anomaly_score}

#### Rule 27: 933017
- **Phase**: 1
- **Variables**: TX:DETECTION_PARANOIA_LEVEL
- **Operator**: @lt
- **Pattern**: 4
- **Is Chain**: False
- **Message**: 
- **Severity**: 
- **Tags**: OWASP_CRS
- **Actions**: id:933017, phase:1, pass, nolog, tag:OWASP_CRS, ver:OWASP_CRS/4.22.0-dev, skipAfter:END-REQUEST-933-APPLICATION-ATTACK-PHP

#### Rule 28: 933018
- **Phase**: 2
- **Variables**: TX:DETECTION_PARANOIA_LEVEL
- **Operator**: @lt
- **Pattern**: 4
- **Is Chain**: False
- **Message**: 
- **Severity**: 
- **Tags**: OWASP_CRS
- **Actions**: id:933018, phase:2, pass, nolog, tag:OWASP_CRS, ver:OWASP_CRS/4.22.0-dev, skipAfter:END-REQUEST-933-APPLICATION-ATTACK-PHP


====================================================================================================

## File: REQUEST-934-APPLICATION-ATTACK-GENERIC.conf

### File Summary
- Total rules: 18
- Chained rules: 0
- Non-chained rules: 18

### Detailed Rules

#### Rule 1: 934011
- **Phase**: 1
- **Variables**: TX:DETECTION_PARANOIA_LEVEL
- **Operator**: @lt
- **Pattern**: 1
- **Is Chain**: False
- **Message**: 
- **Severity**: 
- **Tags**: OWASP_CRS
- **Actions**: id:934011, phase:1, pass, nolog, tag:OWASP_CRS, ver:OWASP_CRS/4.22.0-dev, skipAfter:END-REQUEST-934-APPLICATION-ATTACK-GENERIC

#### Rule 2: 934012
- **Phase**: 2
- **Variables**: TX:DETECTION_PARANOIA_LEVEL
- **Operator**: @lt
- **Pattern**: 1
- **Is Chain**: False
- **Message**: 
- **Severity**: 
- **Tags**: OWASP_CRS
- **Actions**: id:934012, phase:2, pass, nolog, tag:OWASP_CRS, ver:OWASP_CRS/4.22.0-dev, skipAfter:END-REQUEST-934-APPLICATION-ATTACK-GENERIC

#### Rule 3: 934100
- **Phase**: 2
- **Variables**: REQUEST_FILENAME, REQUEST_COOKIES, REQUEST_COOKIES_NAMES, ARGS_NAMES, ARGS, XML:/*
- **Operator**: @rx
- **Pattern**: _(?:\$\$ND_FUNC\$\$_|_js_function)|(?:\beval|new[\s\x0b]+Function[\s\x0b]*)\(|(?:String\.fromCharCod|Module:prototyp)e|function\(\)\{|this\.constructor|module\.exports=|\([\s\x0b]*[^0-9A-Z_a-z]child_process[^0-9A-Z_a-z][\s\x0b]*\)|cons(?:tructor:constructor|ole(?:\.(?:(?:debu|lo)g|error|info|trace|warn)(?:\.call)?\(|\[[\"'`](?:(?:debu|lo)g|error|info|trace|warn)[\"'`]\]))|process(?:\.(?:(?:a(?:ccess|ppendfile|rgv|vailability)|c(?:aveats|h(?:mod|own)|(?:los|opyfil)e|p|reate(?:read|write)stream)|ex(?:ec(?:file)?|ists)|f(?:ch(?:mod|own)|data(?:sync)?|s(?:tat|ync)|utimes)|inodes|l(?:chmod|ink|stat|utimes)|mkd(?:ir|temp)|open(?:dir)?|r(?:e(?:ad(?:dir|file|link|v)?|name)|m)|s(?:pawn(?:file)?|tat|ymlink)|truncate|u(?:n(?:link|watchfile)|times)|w(?:atchfile|rite(?:file|v)?))(?:sync)?(?:\.call)?\(|binding|constructor|env|global|main(?:Module)?|process|require)|\[[\"'`](?:(?:a(?:ccess|ppendfile|rgv|vailability)|c(?:aveats|h(?:mod|own)|(?:los|opyfil)e|p|reate(?:read|write)stream)|ex(?:ec(?:file)?|ists)|f(?:ch(?:mod|own)|data(?:sync)?|s(?:tat|ync)|utimes)|inodes|l(?:chmod|ink|stat|utimes)|mkd(?:ir|temp)|open(?:dir)?|r(?:e(?:ad(?:dir|file|link|v)?|name)|m)|s(?:pawn(?:file)?|tat|ymlink)|truncate|u(?:n(?:link|watchfile)|times)|w(?:atchfile|rite(?:file|v)?))(?:sync)?|binding|constructor|env|global|main(?:Module)?|process|require)[\"'`]\])|(?:binding|constructor|env|global|main(?:Module)?|process|require)\[|require(?:\.(?:resolve(?:\.call)?\(|main|extensions|cache)|\[[\"'`](?:(?:resolv|cach)e|main|extensions)[\"'`]\])
- **Is Chain**: False
- **Message**: Node.js Injection Attack 1/2
- **Severity**: CRITICAL
- **Tags**: application-multi, language-javascript, platform-multi, platform-nodejs, attack-rce, attack-injection-generic, paranoia-level/1, OWASP_CRS, OWASP_CRS/ATTACK-GENERIC, capec/1000/152/242
- **Actions**: id:934100, phase:2, block, capture, t:none, t:urlDecodeUni, t:jsDecode, t:removeWhitespace, t:base64Decode, t:urlDecodeUni, t:jsDecode, t:removeWhitespace, msg:Node.js Injection Attack 1/2, logdata:Matched Data: %{TX.0} found within %{MATCHED_VAR_NAME}: %{MATCHED_VAR}, tag:application-multi, tag:language-javascript, tag:platform-multi, tag:platform-nodejs, tag:attack-rce, tag:attack-injection-generic, tag:paranoia-level/1, tag:OWASP_CRS, tag:OWASP_CRS/ATTACK-GENERIC, tag:capec/1000/152/242, ver:OWASP_CRS/4.22.0-dev, severity:CRITICAL, multiMatch, setvar:tx.rce_score=+%{tx.critical_anomaly_score}, setvar:tx.inbound_anomaly_score_pl1=+%{tx.critical_anomaly_score}

#### Rule 4: 934110
- **Phase**: 2
- **Variables**: REQUEST_COOKIES, REQUEST_COOKIES_NAMES, REQUEST_FILENAME, ARGS_NAMES, ARGS, XML:/*
- **Operator**: @pmFromFile
- **Pattern**: ssrf.data
- **Is Chain**: False
- **Message**: Possible Server Side Request Forgery (SSRF) Attack: Cloud provider metadata URL in Parameter
- **Severity**: CRITICAL
- **Tags**: application-multi, language-multi, platform-multi, attack-ssrf, paranoia-level/1, OWASP_CRS, OWASP_CRS/ATTACK-GENERIC, capec/1000/225/664
- **Actions**: id:934110, phase:2, block, capture, t:none, msg:Possible Server Side Request Forgery (SSRF) Attack: Cloud provider metadata URL in Parameter, logdata:Matched Data: %{TX.0} found within %{MATCHED_VAR_NAME}: %{MATCHED_VAR}, tag:application-multi, tag:language-multi, tag:platform-multi, tag:attack-ssrf, tag:paranoia-level/1, tag:OWASP_CRS, tag:OWASP_CRS/ATTACK-GENERIC, tag:capec/1000/225/664, ver:OWASP_CRS/4.22.0-dev, severity:CRITICAL, setvar:tx.rce_score=+%{tx.critical_anomaly_score}, setvar:tx.inbound_anomaly_score_pl1=+%{tx.critical_anomaly_score}

#### Rule 5: 934130
- **Phase**: 2
- **Variables**: REQUEST_COOKIES, REQUEST_COOKIES_NAMES, ARGS_NAMES, ARGS, XML:/*
- **Operator**: @rx
- **Pattern**: (?:__proto__|constructor\s*(?:\.|\]?\[)\s*prototype)
- **Is Chain**: False
- **Message**: JavaScript Prototype Pollution
- **Severity**: CRITICAL
- **Tags**: application-multi, language-javascript, platform-multi, attack-rce, attack-injection-generic, paranoia-level/1, OWASP_CRS, OWASP_CRS/ATTACK-GENERIC, capec/1/180/77
- **Actions**: id:934130, phase:2, block, capture, t:none, t:urlDecodeUni, t:jsDecode, msg:JavaScript Prototype Pollution, logdata:Matched Data: %{TX.0} found within %{MATCHED_VAR_NAME}: %{MATCHED_VAR}, tag:application-multi, tag:language-javascript, tag:platform-multi, tag:attack-rce, tag:attack-injection-generic, tag:paranoia-level/1, tag:OWASP_CRS, tag:OWASP_CRS/ATTACK-GENERIC, tag:capec/1/180/77, ver:OWASP_CRS/4.22.0-dev, severity:CRITICAL, multiMatch, setvar:tx.rce_score=+%{tx.critical_anomaly_score}, setvar:tx.inbound_anomaly_score_pl1=+%{tx.critical_anomaly_score}

#### Rule 6: 934150
- **Phase**: 2
- **Variables**: REQUEST_COOKIES, REQUEST_COOKIES_NAMES, ARGS_NAMES, ARGS, XML:/*
- **Operator**: @rx
- **Pattern**: Process[\s\x0b]*\.[\s\x0b]*spawn[\s\x0b]*\(
- **Is Chain**: False
- **Message**: Ruby Injection Attack
- **Severity**: CRITICAL
- **Tags**: application-multi, language-ruby, platform-multi, attack-rce, attack-injection-generic, paranoia-level/1, OWASP_CRS, OWASP_CRS/ATTACK-GENERIC, capec/1000/152/242
- **Actions**: id:934150, phase:2, block, capture, t:none, msg:Ruby Injection Attack, logdata:Matched Data: %{TX.0} found within %{MATCHED_VAR_NAME}: %{MATCHED_VAR}, tag:application-multi, tag:language-ruby, tag:platform-multi, tag:attack-rce, tag:attack-injection-generic, tag:paranoia-level/1, tag:OWASP_CRS, tag:OWASP_CRS/ATTACK-GENERIC, tag:capec/1000/152/242, ver:OWASP_CRS/4.22.0-dev, severity:CRITICAL, setvar:tx.rce_score=+%{tx.critical_anomaly_score}, setvar:tx.inbound_anomaly_score_pl1=+%{tx.critical_anomaly_score}

#### Rule 7: 934160
- **Phase**: 2
- **Variables**: REQUEST_FILENAME, REQUEST_COOKIES, REQUEST_COOKIES_NAMES, ARGS_NAMES, ARGS, XML:/*
- **Operator**: @rx
- **Pattern**: while[\s\x0b]*\([\s\x0b\(]*(?:!+(?:false|null|undefined|NaN|[\+\-]?0|\"{2}|'{2}|`{2})|(?:!!)*(?:(?:t(?:rue|his)|[\+\-]?(?:Infinity|[1-9][0-9]*)|new [A-Za-z][0-9A-Z_a-z]*|window|String|(?:Boolea|Functio)n|Object|Array)\b|\{[^\}]*\}|\[[^\]]*\]|\"[^\"]+\"|'[^']+'|`[^`]+`)).*\)
- **Is Chain**: False
- **Message**: Node.js DoS attack
- **Severity**: CRITICAL
- **Tags**: application-multi, language-javascript, platform-nodejs, attack-rce, attack-injection-generic, paranoia-level/1, OWASP_CRS, OWASP_CRS/ATTACK-GENERIC, capec/1000/152/242
- **Actions**: id:934160, phase:2, block, capture, t:none, t:urlDecodeUni, t:jsDecode, t:base64Decode, t:urlDecodeUni, t:jsDecode, t:replaceComments, msg:Node.js DoS attack, logdata:Matched Data: %{TX.0} found within %{MATCHED_VAR_NAME}: %{MATCHED_VAR}, tag:application-multi, tag:language-javascript, tag:platform-nodejs, tag:attack-rce, tag:attack-injection-generic, tag:paranoia-level/1, tag:OWASP_CRS, tag:OWASP_CRS/ATTACK-GENERIC, tag:capec/1000/152/242, ver:OWASP_CRS/4.22.0-dev, severity:CRITICAL, multiMatch, setvar:tx.rce_score=+%{tx.critical_anomaly_score}, setvar:tx.inbound_anomaly_score_pl1=+%{tx.critical_anomaly_score}

#### Rule 8: 934170
- **Phase**: 2
- **Variables**: REQUEST_FILENAME, REQUEST_COOKIES, REQUEST_COOKIES_NAMES, ARGS_NAMES, ARGS, XML:/*
- **Operator**: @rx
- **Pattern**: ^data:(?:(?:\*|[^!\"\(\),/:-\?\[-\]\{\}]+)/(?:\*|[^!\"\(\),/:-\?\[-\]\{\}]+)|\*)(?:[\s\x0b]*;[\s\x0b]*(?:charset[\s\x0b]*=[\s\x0b]*\"?(?:iso-8859-15?|utf-8|windows-1252)\b\"?|(?:[^\s\x0b-\"\(\),/:-\?\[-\]c\{\}]|c(?:[^!\"\(\),/:-\?\[-\]h\{\}]|h(?:[^!\"\(\),/:-\?\[-\]a\{\}]|a(?:[^!\"\(\),/:-\?\[-\]r\{\}]|r(?:[^!\"\(\),/:-\?\[-\]s\{\}]|s(?:[^!\"\(\),/:-\?\[-\]e\{\}]|e[^!\"\(\),/:-\?\[-\]t\{\}]))))))[^!\"\(\),/:-\?\[-\]\{\}]*[\s\x0b]*=[\s\x0b]*[^!\(\),/:-\?\[-\]\{\}]+);?)*(?:[\s\x0b]*,[\s\x0b]*(?:(?:\*|[^!\"\(\),/:-\?\[-\]\{\}]+)/(?:\*|[^!\"\(\),/:-\?\[-\]\{\}]+)|\*)(?:[\s\x0b]*;[\s\x0b]*(?:charset[\s\x0b]*=[\s\x0b]*\"?(?:iso-8859-15?|utf-8|windows-1252)\b\"?|(?:[^\s\x0b-\"\(\),/:-\?\[-\]c\{\}]|c(?:[^!\"\(\),/:-\?\[-\]h\{\}]|h(?:[^!\"\(\),/:-\?\[-\]a\{\}]|a(?:[^!\"\(\),/:-\?\[-\]r\{\}]|r(?:[^!\"\(\),/:-\?\[-\]s\{\}]|s(?:[^!\"\(\),/:-\?\[-\]e\{\}]|e[^!\"\(\),/:-\?\[-\]t\{\}]))))))[^!\"\(\),/:-\?\[-\]\{\}]*[\s\x0b]*=[\s\x0b]*[^!\(\),/:-\?\[-\]\{\}]+);?)*)*
- **Is Chain**: False
- **Message**: PHP data scheme attack
- **Severity**: CRITICAL
- **Tags**: application-multi, language-php, platform-multi, attack-ssrf, paranoia-level/1, OWASP_CRS, OWASP_CRS/ATTACK-GENERIC, capec/1000/152/242
- **Actions**: id:934170, phase:2, block, capture, t:none, t:urlDecodeUni, msg:PHP data scheme attack, logdata:Matched Data: %{TX.0} found within %{MATCHED_VAR_NAME}: %{MATCHED_VAR}, tag:application-multi, tag:language-php, tag:platform-multi, tag:attack-ssrf, tag:paranoia-level/1, tag:OWASP_CRS, tag:OWASP_CRS/ATTACK-GENERIC, tag:capec/1000/152/242, ver:OWASP_CRS/4.22.0-dev, severity:CRITICAL, setvar:tx.rce_score=+%{tx.critical_anomaly_score}, setvar:tx.inbound_anomaly_score_pl1=+%{tx.critical_anomaly_score}

#### Rule 9: 934013
- **Phase**: 1
- **Variables**: TX:DETECTION_PARANOIA_LEVEL
- **Operator**: @lt
- **Pattern**: 2
- **Is Chain**: False
- **Message**: 
- **Severity**: 
- **Tags**: OWASP_CRS
- **Actions**: id:934013, phase:1, pass, nolog, tag:OWASP_CRS, ver:OWASP_CRS/4.22.0-dev, skipAfter:END-REQUEST-934-APPLICATION-ATTACK-GENERIC

#### Rule 10: 934014
- **Phase**: 2
- **Variables**: TX:DETECTION_PARANOIA_LEVEL
- **Operator**: @lt
- **Pattern**: 2
- **Is Chain**: False
- **Message**: 
- **Severity**: 
- **Tags**: OWASP_CRS
- **Actions**: id:934014, phase:2, pass, nolog, tag:OWASP_CRS, ver:OWASP_CRS/4.22.0-dev, skipAfter:END-REQUEST-934-APPLICATION-ATTACK-GENERIC

#### Rule 11: 934101
- **Phase**: 2
- **Variables**: REQUEST_FILENAME, REQUEST_COOKIES, REQUEST_COOKIES_NAMES, ARGS_NAMES, ARGS, XML:/*
- **Operator**: @rx
- **Pattern**: (?:close|exists|fork|(?:ope|spaw)n|re(?:ad|quire)|w(?:atch|rite))[\s\x0b]*\(
- **Is Chain**: False
- **Message**: Node.js Injection Attack 2/2
- **Severity**: CRITICAL
- **Tags**: application-multi, language-javascript, platform-nodejs, attack-rce, attack-injection-generic, paranoia-level/2, OWASP_CRS, OWASP_CRS/ATTACK-GENERIC, capec/1000/152/242
- **Actions**: id:934101, phase:2, block, capture, t:none, t:urlDecodeUni, t:jsDecode, t:base64Decode, t:urlDecodeUni, t:jsDecode, msg:Node.js Injection Attack 2/2, logdata:Matched Data: %{TX.0} found within %{MATCHED_VAR_NAME}: %{MATCHED_VAR}, tag:application-multi, tag:language-javascript, tag:platform-nodejs, tag:attack-rce, tag:attack-injection-generic, tag:paranoia-level/2, tag:OWASP_CRS, tag:OWASP_CRS/ATTACK-GENERIC, tag:capec/1000/152/242, ver:OWASP_CRS/4.22.0-dev, severity:CRITICAL, multiMatch, setvar:tx.rce_score=+%{tx.critical_anomaly_score}, setvar:tx.inbound_anomaly_score_pl2=+%{tx.critical_anomaly_score}

#### Rule 12: 934120
- **Phase**: 2
- **Variables**: REQUEST_COOKIES, REQUEST_COOKIES_NAMES, REQUEST_FILENAME, ARGS_NAMES, ARGS, XML:/*
- **Operator**: @rx
- **Pattern**: (?i)(?:a(?:cap|f[ps]|ttachment)|b(?:eshare|itcoin|lob)|c(?:a(?:llto|p)|id|vs|ompress.(?:zlib|bzip2))|d(?:a(?:v|ta)|ict|n(?:s|tp))|e(?:d2k|xpect)|f(?:(?:ee)?d|i(?:le|nger|sh)|tps?)|g(?:it|o(?:pher)?|lob)|h(?:323|ttps?)|i(?:ax|cap|(?:ma|p)ps?|rc[6s]?)|ja(?:bbe)?r|l(?:dap[is]?|ocal_file)|m(?:a(?:ilto|ven)|ms|umble)|n(?:e(?:tdoc|ws)|fs|ntps?)|ogg|p(?:aparazzi|h(?:ar|p)|op(?:2|3s?)|r(?:es|oxy)|syc)|r(?:mi|sync|tm(?:f?p)?|ar)|s(?:3|ftp|ips?|m(?:[bs]|tps?)|n(?:ews|mp)|sh(?:2(?:.(?:s(?:hell|(?:ft|c)p)|exec|tunnel))?)?|vn(?:\+ssh)?)|t(?:e(?:amspeak|lnet)|ftp|urns?)|u(?:dp|nreal|t2004)|v(?:entrilo|iew-source|nc)|w(?:ebcal|ss?)|x(?:mpp|ri)|zip)://(?:[0-9]{10}|(?:0x[0-9a-f]{2}\.){3}0x[0-9a-f]{2}|0x(?:[0-9a-f]{8}|[0-9a-f]{16})|(?:0{1,4}[0-9]{1,3}\.){3}0{1,4}[0-9]{1,3}|[0-9]{1,3}\.(?:[0-9]{1,3}\.[0-9]{5}|[0-9]{8})|(?:\x5c\x5c[\-0-9a-z]\.?_?)+|\[[0-:a-f]+(?:[\.0-9]+|%[0-9A-Z_a-z]+)?\]|[a-z][\-\.0-9A-Z_a-z]{1,255}:[0-9]{1,5}(?:#?[\s\x0b]*&?@(?:(?:[0-9]{1,3}\.){3}[0-9]{1,3}|[a-z][\-\.0-9A-Z_a-z]{1,255}):[0-9]{1,5}/?)+|[\.0-9]{0,11}(?:\x{e2}(?:\x91[\xa0-\x{bf}]|\x92[\x80-\x{bf}]|\x93[\x80-\x{a9}\x{ab}-\x{bf}])|\x{e3}\x80\x82)+)
- **Is Chain**: False
- **Message**: Possible Server Side Request Forgery (SSRF) Attack: URL Parameter using IP Address
- **Severity**: CRITICAL
- **Tags**: application-multi, language-multi, platform-multi, attack-ssrf, paranoia-level/2, OWASP_CRS, OWASP_CRS/ATTACK-GENERIC, capec/1000/225/664
- **Actions**: id:934120, phase:2, block, capture, t:none, msg:Possible Server Side Request Forgery (SSRF) Attack: URL Parameter using IP Address, logdata:Matched Data: %{TX.0} found within %{MATCHED_VAR_NAME}: %{MATCHED_VAR}, tag:application-multi, tag:language-multi, tag:platform-multi, tag:attack-ssrf, tag:paranoia-level/2, tag:OWASP_CRS, tag:OWASP_CRS/ATTACK-GENERIC, tag:capec/1000/225/664, ver:OWASP_CRS/4.22.0-dev, severity:CRITICAL, setvar:tx.rce_score=+%{tx.critical_anomaly_score}, setvar:tx.inbound_anomaly_score_pl2=+%{tx.critical_anomaly_score}

#### Rule 13: 934140
- **Phase**: 2
- **Variables**: REQUEST_COOKIES, REQUEST_COOKIES_NAMES, ARGS_NAMES, ARGS, XML:/*
- **Operator**: @rx
- **Pattern**: ^(?:[^@]|@[^\{])*@+\{[^\}]*\}
- **Is Chain**: False
- **Message**: Perl Injection Attack
- **Severity**: CRITICAL
- **Tags**: application-multi, language-perl, platform-multi, attack-rce, attack-injection-generic, paranoia-level/2, OWASP_CRS, OWASP_CRS/ATTACK-GENERIC, capec/1000/152/242
- **Actions**: id:934140, phase:2, block, capture, t:none, msg:Perl Injection Attack, logdata:Matched Data: %{TX.0} found within %{MATCHED_VAR_NAME}: %{MATCHED_VAR}, tag:application-multi, tag:language-perl, tag:platform-multi, tag:attack-rce, tag:attack-injection-generic, tag:paranoia-level/2, tag:OWASP_CRS, tag:OWASP_CRS/ATTACK-GENERIC, tag:capec/1000/152/242, ver:OWASP_CRS/4.22.0-dev, severity:CRITICAL, setvar:tx.rce_score=+%{tx.critical_anomaly_score}, setvar:tx.inbound_anomaly_score_pl2=+%{tx.critical_anomaly_score}

#### Rule 14: 934180
- **Phase**: 2
- **Variables**: REQUEST_COOKIES, REQUEST_COOKIES_NAMES, ARGS_NAMES, ARGS, XML:/*
- **Operator**: @rx
- **Pattern**: (?:{%[^%}]*%}|<%=?[^%>]*%>)
- **Is Chain**: False
- **Message**: SSTI Attack
- **Severity**: CRITICAL
- **Tags**: application-multi, platform-multi, attack-ssti, attack-injection-generic, paranoia-level/2, OWASP_CRS, OWASP_CRS/ATTACK-GENERIC, capec/1000/152/242
- **Actions**: id:934180, phase:2, block, capture, t:none, msg:SSTI Attack, logdata:Matched Data: %{TX.0} found within %{MATCHED_VAR_NAME}: %{MATCHED_VAR}, tag:application-multi, tag:platform-multi, tag:attack-ssti, tag:attack-injection-generic, tag:paranoia-level/2, tag:OWASP_CRS, tag:OWASP_CRS/ATTACK-GENERIC, tag:capec/1000/152/242, ver:OWASP_CRS/4.22.0-dev, severity:CRITICAL, setvar:tx.rce_score=+%{tx.critical_anomaly_score}, setvar:tx.inbound_anomaly_score_pl2=+%{tx.critical_anomaly_score}

#### Rule 15: 934015
- **Phase**: 1
- **Variables**: TX:DETECTION_PARANOIA_LEVEL
- **Operator**: @lt
- **Pattern**: 3
- **Is Chain**: False
- **Message**: 
- **Severity**: 
- **Tags**: OWASP_CRS
- **Actions**: id:934015, phase:1, pass, nolog, tag:OWASP_CRS, ver:OWASP_CRS/4.22.0-dev, skipAfter:END-REQUEST-934-APPLICATION-ATTACK-GENERIC

#### Rule 16: 934016
- **Phase**: 2
- **Variables**: TX:DETECTION_PARANOIA_LEVEL
- **Operator**: @lt
- **Pattern**: 3
- **Is Chain**: False
- **Message**: 
- **Severity**: 
- **Tags**: OWASP_CRS
- **Actions**: id:934016, phase:2, pass, nolog, tag:OWASP_CRS, ver:OWASP_CRS/4.22.0-dev, skipAfter:END-REQUEST-934-APPLICATION-ATTACK-GENERIC

#### Rule 17: 934017
- **Phase**: 1
- **Variables**: TX:DETECTION_PARANOIA_LEVEL
- **Operator**: @lt
- **Pattern**: 4
- **Is Chain**: False
- **Message**: 
- **Severity**: 
- **Tags**: OWASP_CRS
- **Actions**: id:934017, phase:1, pass, nolog, tag:OWASP_CRS, ver:OWASP_CRS/4.22.0-dev, skipAfter:END-REQUEST-934-APPLICATION-ATTACK-GENERIC

#### Rule 18: 934018
- **Phase**: 2
- **Variables**: TX:DETECTION_PARANOIA_LEVEL
- **Operator**: @lt
- **Pattern**: 4
- **Is Chain**: False
- **Message**: 
- **Severity**: 
- **Tags**: OWASP_CRS
- **Actions**: id:934018, phase:2, pass, nolog, tag:OWASP_CRS, ver:OWASP_CRS/4.22.0-dev, skipAfter:END-REQUEST-934-APPLICATION-ATTACK-GENERIC


====================================================================================================

## File: REQUEST-941-APPLICATION-ATTACK-XSS.conf

### File Summary
- Total rules: 43
- Chained rules: 1
- Non-chained rules: 42

### Detailed Rules

#### Rule 1: 941011
- **Phase**: 1
- **Variables**: TX:DETECTION_PARANOIA_LEVEL
- **Operator**: @lt
- **Pattern**: 1
- **Is Chain**: False
- **Message**: 
- **Severity**: 
- **Tags**: OWASP_CRS
- **Actions**: id:941011, phase:1, pass, nolog, tag:OWASP_CRS, ver:OWASP_CRS/4.22.0-dev, skipAfter:END-REQUEST-941-APPLICATION-ATTACK-XSS

#### Rule 2: 941012
- **Phase**: 2
- **Variables**: TX:DETECTION_PARANOIA_LEVEL
- **Operator**: @lt
- **Pattern**: 1
- **Is Chain**: False
- **Message**: 
- **Severity**: 
- **Tags**: OWASP_CRS
- **Actions**: id:941012, phase:2, pass, nolog, tag:OWASP_CRS, ver:OWASP_CRS/4.22.0-dev, skipAfter:END-REQUEST-941-APPLICATION-ATTACK-XSS

#### Rule 3: 941010
- **Phase**: 1
- **Variables**: REQUEST_FILENAME
- **Operator**: !@validateByteRange
- **Pattern**: 20,45-47,48-57,65-90,95,97-122
- **Is Chain**: False
- **Message**: 
- **Severity**: 
- **Tags**: OWASP_CRS, OWASP_CRS/ATTACK-XSS
- **Actions**: id:941010, phase:1, pass, t:none, nolog, tag:OWASP_CRS, tag:OWASP_CRS/ATTACK-XSS, ctl:ruleRemoveTargetByTag, ver:OWASP_CRS/4.22.0-dev

#### Rule 4: 941100
- **Phase**: 2
- **Variables**: REQUEST_COOKIES, REQUEST_COOKIES_NAMES, REQUEST_HEADERS:User-Agent, ARGS_NAMES, ARGS, XML:/*
- **Operator**: @detectXSS
- **Pattern**: 
- **Is Chain**: False
- **Message**: XSS Attack Detected via libinjection
- **Severity**: CRITICAL
- **Tags**: application-multi, language-multi, platform-multi, attack-xss, xss-perf-disable, paranoia-level/1, OWASP_CRS, OWASP_CRS/ATTACK-XSS, capec/1000/152/242
- **Actions**: id:941100, phase:2, block, t:none, t:utf8toUnicode, t:urlDecodeUni, t:htmlEntityDecode, t:jsDecode, t:cssDecode, t:removeNulls, msg:XSS Attack Detected via libinjection, logdata:Matched Data: XSS data found within %{MATCHED_VAR_NAME}: %{MATCHED_VAR}, tag:application-multi, tag:language-multi, tag:platform-multi, tag:attack-xss, tag:xss-perf-disable, tag:paranoia-level/1, tag:OWASP_CRS, tag:OWASP_CRS/ATTACK-XSS, tag:capec/1000/152/242, ver:OWASP_CRS/4.22.0-dev, severity:CRITICAL, setvar:tx.xss_score=+%{tx.critical_anomaly_score}, setvar:tx.inbound_anomaly_score_pl1=+%{tx.critical_anomaly_score}

#### Rule 5: 941110
- **Phase**: 2
- **Variables**: REQUEST_COOKIES, REQUEST_COOKIES_NAMES, REQUEST_FILENAME, REQUEST_HEADERS:User-Agent, REQUEST_HEADERS:Referer, ARGS_NAMES, ARGS, XML:/*
- **Operator**: @rx
- **Pattern**: (?i)<script[^>]*>[\s\S]*?
- **Is Chain**: False
- **Message**: XSS Filter - Category 1: Script Tag Vector
- **Severity**: CRITICAL
- **Tags**: application-multi, language-multi, platform-multi, attack-xss, xss-perf-disable, paranoia-level/1, OWASP_CRS, OWASP_CRS/ATTACK-XSS, capec/1000/152/242
- **Actions**: id:941110, phase:2, block, capture, t:none, t:utf8toUnicode, t:urlDecodeUni, t:htmlEntityDecode, t:jsDecode, t:cssDecode, t:removeNulls, msg:XSS Filter - Category 1: Script Tag Vector, logdata:Matched Data: %{TX.0} found within %{MATCHED_VAR_NAME}: %{MATCHED_VAR}, tag:application-multi, tag:language-multi, tag:platform-multi, tag:attack-xss, tag:xss-perf-disable, tag:paranoia-level/1, tag:OWASP_CRS, tag:OWASP_CRS/ATTACK-XSS, tag:capec/1000/152/242, ver:OWASP_CRS/4.22.0-dev, severity:CRITICAL, setvar:tx.xss_score=+%{tx.critical_anomaly_score}, setvar:tx.inbound_anomaly_score_pl1=+%{tx.critical_anomaly_score}

#### Rule 6: 941130
- **Phase**: 2
- **Variables**: REQUEST_COOKIES, REQUEST_COOKIES_NAMES, REQUEST_HEADERS:User-Agent, ARGS_NAMES, ARGS, REQUEST_FILENAME, XML:/*
- **Operator**: @rx
- **Pattern**: (?i).(?:\b(?:(?:x(?:link:href|html|mlns)|data:text/html|formaction)\b|pattern[\s\x0b]*=)|(?:!ENTITY[\s\x0b]+(?:%[\s\x0b]+)?[^\s\x0b]+[\s\x0b]+(?:SYSTEM|PUBLIC)|@import|;base64)\b)
- **Is Chain**: False
- **Message**: XSS Filter - Category 3: Attribute Vector
- **Severity**: CRITICAL
- **Tags**: application-multi, language-multi, platform-multi, attack-xss, xss-perf-disable, paranoia-level/1, OWASP_CRS, OWASP_CRS/ATTACK-XSS, capec/1000/152/242
- **Actions**: id:941130, phase:2, block, capture, t:none, t:utf8toUnicode, t:urlDecodeUni, t:htmlEntityDecode, t:jsDecode, t:cssDecode, t:removeNulls, msg:XSS Filter - Category 3: Attribute Vector, logdata:Matched Data: %{TX.0} found within %{MATCHED_VAR_NAME}: %{MATCHED_VAR}, tag:application-multi, tag:language-multi, tag:platform-multi, tag:attack-xss, tag:xss-perf-disable, tag:paranoia-level/1, tag:OWASP_CRS, tag:OWASP_CRS/ATTACK-XSS, tag:capec/1000/152/242, ver:OWASP_CRS/4.22.0-dev, severity:CRITICAL, setvar:tx.xss_score=+%{tx.critical_anomaly_score}, setvar:tx.inbound_anomaly_score_pl1=+%{tx.critical_anomaly_score}

#### Rule 7: 941140
- **Phase**: 2
- **Variables**: REQUEST_COOKIES, REQUEST_COOKIES_NAMES, REQUEST_HEADERS:User-Agent, REQUEST_HEADERS:Referer, ARGS_NAMES, ARGS, REQUEST_FILENAME, XML:/*
- **Operator**: @rx
- **Pattern**: (?i)[a-z]+=(?:[^:=]+:.+;)*?[^:=]+:url\(javascript
- **Is Chain**: False
- **Message**: XSS Filter - Category 4: Javascript URI Vector
- **Severity**: CRITICAL
- **Tags**: application-multi, language-multi, platform-multi, attack-xss, xss-perf-disable, paranoia-level/1, OWASP_CRS, OWASP_CRS/ATTACK-XSS, capec/1000/152/242
- **Actions**: id:941140, phase:2, block, capture, t:none, t:utf8toUnicode, t:urlDecodeUni, t:htmlEntityDecode, t:jsDecode, t:cssDecode, t:removeNulls, t:removeWhitespace, msg:XSS Filter - Category 4: Javascript URI Vector, logdata:Matched Data: %{TX.0} found within %{MATCHED_VAR_NAME}: %{MATCHED_VAR}, tag:application-multi, tag:language-multi, tag:platform-multi, tag:attack-xss, tag:xss-perf-disable, tag:paranoia-level/1, tag:OWASP_CRS, tag:OWASP_CRS/ATTACK-XSS, tag:capec/1000/152/242, ver:OWASP_CRS/4.22.0-dev, severity:CRITICAL, setvar:tx.xss_score=+%{tx.critical_anomaly_score}, setvar:tx.inbound_anomaly_score_pl1=+%{tx.critical_anomaly_score}

#### Rule 8: 941160
- **Phase**: 2
- **Variables**: REQUEST_COOKIES, REQUEST_COOKIES_NAMES, REQUEST_HEADERS:User-Agent, REQUEST_HEADERS:Referer, ARGS_NAMES, ARGS, REQUEST_FILENAME, XML:/*
- **Operator**: @rx
- **Pattern**: (?i)<[^0-9<>A-Z_a-z]*(?:[^\s\x0b\"'<>]*:)?[^0-9<>A-Z_a-z]*[^0-9A-Z_a-z]*?(?:s[^0-9A-Z_a-z]*?(?:c[^0-9A-Z_a-z]*?r[^0-9A-Z_a-z]*?i[^0-9A-Z_a-z]*?p[^0-9A-Z_a-z]*?t|t[^0-9A-Z_a-z]*?y[^0-9A-Z_a-z]*?l[^0-9A-Z_a-z]*?e|v[^0-9A-Z_a-z]*?g|e[^0-9A-Z_a-z]*?t[^0-9>A-Z_a-z])|f[^0-9A-Z_a-z]*?o[^0-9A-Z_a-z]*?r[^0-9A-Z_a-z]*?m|d[^0-9A-Z_a-z]*?i[^0-9A-Z_a-z]*?a[^0-9A-Z_a-z]*?l[^0-9A-Z_a-z]*?o[^0-9A-Z_a-z]*?g|m[^0-9A-Z_a-z]*?(?:a[^0-9A-Z_a-z]*?r[^0-9A-Z_a-z]*?q[^0-9A-Z_a-z]*?u[^0-9A-Z_a-z]*?e[^0-9A-Z_a-z]*?e|e[^0-9A-Z_a-z]*?t[^0-9A-Z_a-z]*?a[^0-9>A-Z_a-z])|(?:l[^0-9A-Z_a-z]*?i[^0-9A-Z_a-z]*?n[^0-9A-Z_a-z]*?k|o[^0-9A-Z_a-z]*?b[^0-9A-Z_a-z]*?j[^0-9A-Z_a-z]*?e[^0-9A-Z_a-z]*?c[^0-9A-Z_a-z]*?t|e[^0-9A-Z_a-z]*?m[^0-9A-Z_a-z]*?b[^0-9A-Z_a-z]*?e[^0-9A-Z_a-z]*?d|a[^0-9A-Z_a-z]*?(?:p[^0-9A-Z_a-z]*?p[^0-9A-Z_a-z]*?l[^0-9A-Z_a-z]*?e[^0-9A-Z_a-z]*?t|u[^0-9A-Z_a-z]*?d[^0-9A-Z_a-z]*?i[^0-9A-Z_a-z]*?o|n[^0-9A-Z_a-z]*?i[^0-9A-Z_a-z]*?m[^0-9A-Z_a-z]*?a[^0-9A-Z_a-z]*?t[^0-9A-Z_a-z]*?e)|p[^0-9A-Z_a-z]*?a[^0-9A-Z_a-z]*?r[^0-9A-Z_a-z]*?a[^0-9A-Z_a-z]*?m|i?[^0-9A-Z_a-z]*?f[^0-9A-Z_a-z]*?r[^0-9A-Z_a-z]*?a[^0-9A-Z_a-z]*?m[^0-9A-Z_a-z]*?e|b[^0-9A-Z_a-z]*?(?:a[^0-9A-Z_a-z]*?s[^0-9A-Z_a-z]*?e|o[^0-9A-Z_a-z]*?d[^0-9A-Z_a-z]*?y|i[^0-9A-Z_a-z]*?n[^0-9A-Z_a-z]*?d[^0-9A-Z_a-z]*?i[^0-9A-Z_a-z]*?n[^0-9A-Z_a-z]*?g[^0-9A-Z_a-z]*?s)|i[^0-9A-Z_a-z]*?m[^0-9A-Z_a-z]*?a?[^0-9A-Z_a-z]*?g[^0-9A-Z_a-z]*?e?|v[^0-9A-Z_a-z]*?i[^0-9A-Z_a-z]*?d[^0-9A-Z_a-z]*?e[^0-9A-Z_a-z]*?o)[^0-9>A-Z_a-z])|(?:<[0-9A-Z_a-z][^\s\x0b/]*[\s\x0b/]|[\"'](?:[^\s\x0b/]*[\s\x0b/])?)(?:background|formaction|lowsrc|on(?:a(?:bort|ctivate|d(?:apteradded|dtrack)|fter(?:print|(?:scriptexecu|upda)te)|lerting|n(?:imation(?:cancel|end|iteration|start)|tennastatechange)|ppcommand|u(?:dio(?:end|process|start)|xclick))|b(?:e(?:fore(?:(?:(?:(?:de)?activa|scriptexecu)t|toggl)e|c(?:opy|ut)|editfocus|input|p(?:aste|rint)|u(?:nload|pdate))|gin(?:Event)?)|l(?:ocked|ur)|oun(?:ce|dary)|roadcast|usy)|c(?:a(?:(?:ch|llschang)ed|nplay(?:through)?|rdstatechange)|(?:ell|fstate)change|h(?:a(?:rging(?:time)?cha)?nge|ecking)|l(?:ick|ose)|o(?:m(?:mand(?:update)?|p(?:lete|osition(?:end|start|update)))|n(?:nect(?:ed|ing)|t(?:extmenu|rolselect))|py)|u(?:echange|t))|d(?:ata(?:(?:availabl|chang)e|error|setc(?:hanged|omplete))|blclick|e(?:activate|livery(?:error|success)|vice(?:found|light|(?:mo|orienta)tion|proximity))|i(?:aling|s(?:abled|c(?:hargingtimechange|onnect(?:ed|ing))))|o(?:m(?:a(?:ctivate|ttrmodified)|(?:characterdata|subtree)modified|focus(?:in|out)|mousescroll|node(?:inserted(?:intodocument)?|removed(?:fromdocument)?))|wnloading)|r(?:ag(?:drop|e(?:n(?:d|ter)|xit)|(?:gestur|leav)e|over|start)|op)|urationchange)|e(?:mptied|n(?:abled|d(?:ed|Event)?|ter)|rror(?:update)?|xit)|f(?:ailed|i(?:lterchange|nish)|o(?:cus(?:in|out)?|rm(?:change|input))|ullscreenchange)|g(?:amepad(?:axismove|button(?:down|up)|(?:dis)?connected)|et)|h(?:ashchange|e(?:adphoneschange|l[dp])|olding)|i(?:cc(?:cardlockerror|infochange)|n(?:coming|put|valid))|key(?:down|press|up)|l(?:evelchange|o(?:ad(?:e(?:d(?:meta)?data|nd)|start)?|secapture)|y)|m(?:ark|essage|o(?:use(?:down|enter|(?:lea|mo)ve|o(?:ut|ver)|up|wheel)|ve(?:end|start)?|z(?:a(?:fterpaint|udioavailable)|(?:beforeresiz|orientationchang|t(?:apgestur|imechang))e|(?:edgeui(?:c(?:ancel|omplet)|start)e|network(?:down|up)loa)d|fullscreen(?:change|error)|m(?:agnifygesture(?:start|update)?|ouse(?:hittest|pixelscroll))|p(?:ointerlock(?:change|error)|resstapgesture)|rotategesture(?:start|update)?|s(?:crolledareachanged|wipegesture(?:end|start|update)?))))|no(?:match|update)|o(?:(?:bsolet|(?:ff|n)lin)e|pen|verflow(?:changed)?)|p(?:a(?:ge(?:hide|show)|int|(?:st|us)e)|lay(?:ing)?|o(?:inter(?:down|enter|(?:(?:lea|mo)v|rawupdat)e|o(?:ut|ver)|up)|p(?:state|up(?:hid(?:den|ing)|show(?:ing|n))))|ro(?:gress|pertychange))|r(?:atechange|e(?:adystatechange|ceived|movetrack|peat(?:Event)?|quest|s(?:et|ize|u(?:lt|m(?:e|ing)))|trieving)|ow(?:e(?:nter|xit)|s(?:delete|inserted)))|s(?:croll(?:end)?|e(?:arch|ek(?:complete|ed|ing)|lect(?:ionchange|start)?|n(?:ding|t)|t)|how|(?:ound|peech)(?:end|start)|t(?:a(?:lled|rt|t(?:echange|uschanged))|k(?:comma|sessione)nd|op)|u(?:bmit|ccess|spend)|vg(?:abort|error|(?:un)?load|resize|scroll|zoom))|t(?:ext|ime(?:out|update)|o(?:ggle|uch(?:cancel|en(?:d|ter)|(?:lea|mo)ve|start))|ransition(?:cancel|end|run|start))|u(?:n(?:derflow|handledrejection|load)|p(?:dateready|gradeneeded)|s(?:erproximity|sdreceived))|v(?:ersion|o(?:ic|lum)e)change|w(?:a(?:it|rn)ing|ebkit(?:animation(?:end|iteration|start)|(?:playbacktargetavailabilitychange|transitionen)d)|heel)|zoom)|ping|s(?:rc|tyle))[\x08-\n\f\r ]*?=
- **Is Chain**: False
- **Message**: NoScript XSS InjectionChecker: HTML Injection
- **Severity**: CRITICAL
- **Tags**: application-multi, language-multi, platform-multi, attack-xss, xss-perf-disable, paranoia-level/1, OWASP_CRS, OWASP_CRS/ATTACK-XSS, capec/1000/152/242
- **Actions**: id:941160, phase:2, block, capture, t:none, t:utf8toUnicode, t:urlDecodeUni, t:htmlEntityDecode, t:jsDecode, t:cssDecode, t:removeNulls, msg:NoScript XSS InjectionChecker: HTML Injection, logdata:Matched Data: %{TX.0} found within %{MATCHED_VAR_NAME}: %{MATCHED_VAR}, tag:application-multi, tag:language-multi, tag:platform-multi, tag:attack-xss, tag:xss-perf-disable, tag:paranoia-level/1, tag:OWASP_CRS, tag:OWASP_CRS/ATTACK-XSS, tag:capec/1000/152/242, ver:OWASP_CRS/4.22.0-dev, severity:CRITICAL, setvar:tx.xss_score=+%{tx.critical_anomaly_score}, setvar:tx.inbound_anomaly_score_pl1=+%{tx.critical_anomaly_score}

#### Rule 9: 941170
- **Phase**: 2
- **Variables**: REQUEST_COOKIES, REQUEST_COOKIES_NAMES, REQUEST_HEADERS:User-Agent, REQUEST_HEADERS:Referer, ARGS_NAMES, ARGS, REQUEST_FILENAME, XML:/*
- **Operator**: @rx
- **Pattern**: (?i)(?:\W|^)(?:javascript:(?:[\s\S]+[=\x5c\(\[\.<]|[\s\S]*?(?:\bname\b|\x5c[ux]\d))|data:(?:(?:[a-z]\w+/\w[\w+-]+\w)?[;,]|[\s\S]*?;[\s\S]*?\b(?:base64|charset=)|[\s\S]*?,[\s\S]*?<[\s\S]*?\w[\s\S]*?>))|@\W*?i\W*?m\W*?p\W*?o\W*?r\W*?t\W*?(?:/\*[\s\S]*?)?(?:[\"']|\W*?u\W*?r\W*?l[\s\S]*?\()|[^-]*?-\W*?m\W*?o\W*?z\W*?-\W*?b\W*?i\W*?n\W*?d\W*?i\W*?n\W*?g[^:]*?:\W*?u\W*?r\W*?l[\s\S]*?\(
- **Is Chain**: False
- **Message**: NoScript XSS InjectionChecker: Attribute Injection
- **Severity**: CRITICAL
- **Tags**: application-multi, language-multi, platform-multi, attack-xss, xss-perf-disable, paranoia-level/1, OWASP_CRS, OWASP_CRS/ATTACK-XSS, capec/1000/152/242
- **Actions**: id:941170, phase:2, block, capture, t:none, t:utf8toUnicode, t:urlDecodeUni, t:htmlEntityDecode, t:jsDecode, t:cssDecode, t:removeNulls, msg:NoScript XSS InjectionChecker: Attribute Injection, logdata:Matched Data: %{TX.0} found within %{MATCHED_VAR_NAME}: %{MATCHED_VAR}, tag:application-multi, tag:language-multi, tag:platform-multi, tag:attack-xss, tag:xss-perf-disable, tag:paranoia-level/1, tag:OWASP_CRS, tag:OWASP_CRS/ATTACK-XSS, tag:capec/1000/152/242, ver:OWASP_CRS/4.22.0-dev, severity:CRITICAL, setvar:tx.xss_score=+%{tx.critical_anomaly_score}, setvar:tx.inbound_anomaly_score_pl1=+%{tx.critical_anomaly_score}

#### Rule 10: 941180
- **Phase**: 2
- **Variables**: REQUEST_COOKIES, REQUEST_COOKIES_NAMES, ARGS_NAMES, ARGS, REQUEST_FILENAME, XML:/*
- **Operator**: @pm
- **Pattern**: document.cookie document.domain document.querySelector document.body.appendChild document.write .parentnode .innerhtml window.location -moz-binding <!-- <![cdata[
- **Is Chain**: False
- **Message**: Node-Validator Deny List Keywords
- **Severity**: CRITICAL
- **Tags**: application-multi, language-multi, platform-nodejs, attack-xss, xss-perf-disable, paranoia-level/1, OWASP_CRS, OWASP_CRS/ATTACK-XSS, capec/1000/152/242
- **Actions**: id:941180, phase:2, block, capture, t:none, t:utf8toUnicode, t:urlDecodeUni, t:htmlEntityDecode, t:jsDecode, t:cssDecode, t:removeNulls, msg:Node-Validator Deny List Keywords, logdata:Matched Data: %{TX.0} found within %{MATCHED_VAR_NAME}: %{MATCHED_VAR}, tag:application-multi, tag:language-multi, tag:platform-nodejs, tag:attack-xss, tag:xss-perf-disable, tag:paranoia-level/1, tag:OWASP_CRS, tag:OWASP_CRS/ATTACK-XSS, tag:capec/1000/152/242, ver:OWASP_CRS/4.22.0-dev, severity:CRITICAL, setvar:tx.xss_score=+%{tx.critical_anomaly_score}, setvar:tx.inbound_anomaly_score_pl1=+%{tx.critical_anomaly_score}

#### Rule 11: 941190
- **Phase**: 2
- **Variables**: REQUEST_COOKIES, REQUEST_COOKIES_NAMES, ARGS_NAMES, ARGS, REQUEST_FILENAME, XML:/*
- **Operator**: @rx
- **Pattern**: (?i:<style.*?>.*?(?:@[i\x5c]|(?:[:=]|&#x?0*(?:58|3A|61|3D);?).*?(?:[(\x5c]|&#x?0*(?:40|28|92|5C);?)))
- **Is Chain**: False
- **Message**: IE XSS Filters - Attack Detected
- **Severity**: CRITICAL
- **Tags**: application-multi, language-multi, platform-internet-explorer, attack-xss, xss-perf-disable, paranoia-level/1, OWASP_CRS, OWASP_CRS/ATTACK-XSS, capec/1000/152/242
- **Actions**: id:941190, phase:2, block, capture, t:none, t:utf8toUnicode, t:urlDecodeUni, t:htmlEntityDecode, t:jsDecode, t:cssDecode, t:removeNulls, msg:IE XSS Filters - Attack Detected, logdata:Matched Data: %{TX.0} found within %{MATCHED_VAR_NAME}: %{MATCHED_VAR}, tag:application-multi, tag:language-multi, tag:platform-internet-explorer, tag:attack-xss, tag:xss-perf-disable, tag:paranoia-level/1, tag:OWASP_CRS, tag:OWASP_CRS/ATTACK-XSS, tag:capec/1000/152/242, ver:OWASP_CRS/4.22.0-dev, severity:CRITICAL, setvar:tx.xss_score=+%{tx.critical_anomaly_score}, setvar:tx.inbound_anomaly_score_pl1=+%{tx.critical_anomaly_score}

#### Rule 12: 941200
- **Phase**: 2
- **Variables**: REQUEST_COOKIES, REQUEST_COOKIES_NAMES, ARGS_NAMES, ARGS, REQUEST_FILENAME, XML:/*
- **Operator**: @rx
- **Pattern**: (?i:<.*[:]?vmlframe.*?[\s/+]*?src[\s/+]*=)
- **Is Chain**: False
- **Message**: IE XSS Filters - Attack Detected
- **Severity**: CRITICAL
- **Tags**: application-multi, language-multi, platform-internet-explorer, attack-xss, xss-perf-disable, paranoia-level/1, OWASP_CRS, OWASP_CRS/ATTACK-XSS, capec/1000/152/242
- **Actions**: id:941200, phase:2, block, capture, t:none, t:utf8toUnicode, t:urlDecodeUni, t:htmlEntityDecode, t:jsDecode, t:cssDecode, t:removeNulls, msg:IE XSS Filters - Attack Detected, logdata:Matched Data: %{TX.0} found within %{MATCHED_VAR_NAME}: %{MATCHED_VAR}, tag:application-multi, tag:language-multi, tag:platform-internet-explorer, tag:attack-xss, tag:xss-perf-disable, tag:paranoia-level/1, tag:OWASP_CRS, tag:OWASP_CRS/ATTACK-XSS, tag:capec/1000/152/242, ver:OWASP_CRS/4.22.0-dev, severity:CRITICAL, setvar:tx.xss_score=+%{tx.critical_anomaly_score}, setvar:tx.inbound_anomaly_score_pl1=+%{tx.critical_anomaly_score}

#### Rule 13: 941210
- **Phase**: 2
- **Variables**: REQUEST_COOKIES, REQUEST_COOKIES_NAMES, ARGS_NAMES, ARGS, REQUEST_FILENAME, XML:/*
- **Operator**: @rx
- **Pattern**: (?i)(?:j|&#(?:0*(?:74|106)|x0*[46]A);)(?:[\t\n\r]|&(?:#(?:0*(?:9|1[03])|x0*[AD]);?|(?:tab|newline);))*(?:a|&#(?:0*(?:65|97)|x0*[46]1);)(?:[\t\n\r]|&(?:#(?:0*(?:9|1[03])|x0*[AD]);?|(?:tab|newline);))*(?:v|&#(?:0*(?:86|118)|x0*[57]6);)(?:[\t\n\r]|&(?:#(?:0*(?:9|1[03])|x0*[AD]);?|(?:tab|newline);))*(?:a|&#(?:0*(?:65|97)|x0*[46]1);)(?:[\t\n\r]|&(?:#(?:0*(?:9|1[03])|x0*[AD]);?|(?:tab|newline);))*(?:s|&#(?:0*(?:115|83)|x0*[57]3);)(?:[\t\n\r]|&(?:#(?:0*(?:9|1[03])|x0*[AD]);?|(?:tab|newline);))*(?:c|&#(?:x0*[46]3|0*(?:99|67));)(?:[\t\n\r]|&(?:#(?:0*(?:9|1[03])|x0*[AD]);?|(?:tab|newline);))*(?:r|&#(?:x0*[57]2|0*(?:114|82));)(?:[\t\n\r]|&(?:#(?:0*(?:9|1[03])|x0*[AD]);?|(?:tab|newline);))*(?:i|&#(?:x0*[46]9|0*(?:105|73));)(?:[\t\n\r]|&(?:#(?:0*(?:9|1[03])|x0*[AD]);?|(?:tab|newline);))*(?:p|&#(?:x0*[57]0|0*(?:112|80));)(?:[\t\n\r]|&(?:#(?:0*(?:9|1[03])|x0*[AD]);?|(?:tab|newline);))*(?:t|&#(?:x0*[57]4|0*(?:116|84));)(?:[\t\n\r]|&(?:#(?:0*(?:9|1[03])|x0*[AD]);?|(?:tab|newline);))*(?::|&(?:#(?:0*58|x0*3A);?|colon;)).
- **Is Chain**: False
- **Message**: Javascript Word Detected
- **Severity**: CRITICAL
- **Tags**: application-multi, language-multi, platform-internet-explorer, attack-xss, xss-perf-disable, paranoia-level/1, OWASP_CRS, OWASP_CRS/ATTACK-XSS, capec/1000/152/242
- **Actions**: id:941210, phase:2, block, capture, t:none, t:utf8toUnicode, t:urlDecodeUni, t:htmlEntityDecode, t:jsDecode, t:cssDecode, t:removeNulls, msg:Javascript Word Detected, logdata:Matched Data: %{TX.0} found within %{MATCHED_VAR_NAME}: %{MATCHED_VAR}, tag:application-multi, tag:language-multi, tag:platform-internet-explorer, tag:attack-xss, tag:xss-perf-disable, tag:paranoia-level/1, tag:OWASP_CRS, tag:OWASP_CRS/ATTACK-XSS, tag:capec/1000/152/242, ver:OWASP_CRS/4.22.0-dev, severity:CRITICAL, setvar:tx.xss_score=+%{tx.critical_anomaly_score}, setvar:tx.inbound_anomaly_score_pl1=+%{tx.critical_anomaly_score}

#### Rule 14: 941220
- **Phase**: 2
- **Variables**: REQUEST_COOKIES, REQUEST_COOKIES_NAMES, ARGS_NAMES, ARGS, REQUEST_FILENAME, XML:/*
- **Operator**: @rx
- **Pattern**: (?i)(?:v|&#(?:0*(?:118|86)|x0*[57]6);)(?:[\t\n\r]|&(?:#(?:0*(?:9|1[03])|x0*[AD]);?|(?:tab|newline);))*(?:b|&#(?:0*(?:98|66)|x0*[46]2);)(?:[\t\n\r]|&(?:#(?:0*(?:9|1[03])|x0*[AD]);?|(?:tab|newline);))*(?:s|&#(?:0*(?:115|83)|x0*[57]3);)(?:[\t\n\r]|&(?:#(?:0*(?:9|1[03])|x0*[AD]);?|(?:tab|newline);))*(?:c|&#(?:x0*[46]3|0*(?:99|67));)(?:[\t\n\r]|&(?:#(?:0*(?:9|1[03])|x0*[AD]);?|(?:tab|newline);))*(?:r|&#(?:x0*[57]2|0*(?:114|82));)(?:[\t\n\r]|&(?:#(?:0*(?:9|1[03])|x0*[AD]);?|(?:tab|newline);))*(?:i|&#(?:x0*[46]9|0*(?:105|73));)(?:[\t\n\r]|&(?:#(?:0*(?:9|1[03])|x0*[AD]);?|(?:tab|newline);))*(?:p|&#(?:x0*[57]0|0*(?:112|80));)(?:[\t\n\r]|&(?:#(?:0*(?:9|1[03])|x0*[AD]);?|(?:tab|newline);))*(?:t|&#(?:x0*[57]4|0*(?:116|84));)(?:[\t\n\r]|&(?:#(?:0*(?:9|1[03])|x0*[AD]);?|(?:tab|newline);))*(?::|&(?:#(?:0*58|x0*3A);?|colon;)).
- **Is Chain**: False
- **Message**: IE XSS Filters - Attack Detected
- **Severity**: CRITICAL
- **Tags**: application-multi, language-multi, platform-internet-explorer, attack-xss, xss-perf-disable, paranoia-level/1, OWASP_CRS, OWASP_CRS/ATTACK-XSS, capec/1000/152/242
- **Actions**: id:941220, phase:2, block, capture, t:none, t:utf8toUnicode, t:urlDecodeUni, t:htmlEntityDecode, t:jsDecode, t:cssDecode, t:removeNulls, msg:IE XSS Filters - Attack Detected, logdata:Matched Data: %{TX.0} found within %{MATCHED_VAR_NAME}: %{MATCHED_VAR}, tag:application-multi, tag:language-multi, tag:platform-internet-explorer, tag:attack-xss, tag:xss-perf-disable, tag:paranoia-level/1, tag:OWASP_CRS, tag:OWASP_CRS/ATTACK-XSS, tag:capec/1000/152/242, ver:OWASP_CRS/4.22.0-dev, severity:CRITICAL, setvar:tx.xss_score=+%{tx.critical_anomaly_score}, setvar:tx.inbound_anomaly_score_pl1=+%{tx.critical_anomaly_score}

#### Rule 15: 941230
- **Phase**: 2
- **Variables**: REQUEST_COOKIES, REQUEST_COOKIES_NAMES, ARGS_NAMES, ARGS, REQUEST_FILENAME, XML:/*
- **Operator**: @rx
- **Pattern**: (?i)<EMBED[\s/+].*?(?:src|type).*?=
- **Is Chain**: False
- **Message**: IE XSS Filters - Attack Detected
- **Severity**: CRITICAL
- **Tags**: application-multi, language-multi, platform-internet-explorer, attack-xss, xss-perf-disable, paranoia-level/1, OWASP_CRS, OWASP_CRS/ATTACK-XSS, capec/1000/152/242
- **Actions**: id:941230, phase:2, block, capture, t:none, t:utf8toUnicode, t:urlDecodeUni, t:htmlEntityDecode, t:jsDecode, t:cssDecode, t:removeNulls, msg:IE XSS Filters - Attack Detected, logdata:Matched Data: %{TX.0} found within %{MATCHED_VAR_NAME}: %{MATCHED_VAR}, tag:application-multi, tag:language-multi, tag:platform-internet-explorer, tag:attack-xss, tag:xss-perf-disable, tag:paranoia-level/1, tag:OWASP_CRS, tag:OWASP_CRS/ATTACK-XSS, tag:capec/1000/152/242, ver:OWASP_CRS/4.22.0-dev, severity:CRITICAL, setvar:tx.xss_score=+%{tx.critical_anomaly_score}, setvar:tx.inbound_anomaly_score_pl1=+%{tx.critical_anomaly_score}

#### Rule 16: 941240
- **Phase**: 2
- **Variables**: REQUEST_COOKIES, REQUEST_COOKIES_NAMES, ARGS_NAMES, ARGS, REQUEST_FILENAME, XML:/*
- **Operator**: @rx
- **Pattern**: <[?]?import[\s/+\S]*?implementation[\s/+]*?=
- **Is Chain**: False
- **Message**: IE XSS Filters - Attack Detected
- **Severity**: CRITICAL
- **Tags**: application-multi, language-multi, platform-internet-explorer, attack-xss, xss-perf-disable, paranoia-level/1, OWASP_CRS, OWASP_CRS/ATTACK-XSS, capec/1000/152/242
- **Actions**: id:941240, phase:2, block, capture, t:none, t:utf8toUnicode, t:urlDecodeUni, t:htmlEntityDecode, t:jsDecode, t:cssDecode, t:lowercase, t:removeNulls, msg:IE XSS Filters - Attack Detected, logdata:Matched Data: %{TX.0} found within %{MATCHED_VAR_NAME}: %{MATCHED_VAR}, tag:application-multi, tag:language-multi, tag:platform-internet-explorer, tag:attack-xss, tag:xss-perf-disable, tag:paranoia-level/1, tag:OWASP_CRS, tag:OWASP_CRS/ATTACK-XSS, tag:capec/1000/152/242, ver:OWASP_CRS/4.22.0-dev, severity:CRITICAL, setvar:tx.xss_score=+%{tx.critical_anomaly_score}, setvar:tx.inbound_anomaly_score_pl1=+%{tx.critical_anomaly_score}

#### Rule 17: 941250
- **Phase**: 2
- **Variables**: REQUEST_COOKIES, REQUEST_COOKIES_NAMES, ARGS_NAMES, ARGS, REQUEST_FILENAME, XML:/*
- **Operator**: @rx
- **Pattern**: (?i:<META[\s/+].*?http-equiv[\s/+]*=[\s/+]*[\"'`]?(?:(?:c|&#x?0*(?:67|43|99|63);?)|(?:r|&#x?0*(?:82|52|114|72);?)|(?:s|&#x?0*(?:83|53|115|73);?)))
- **Is Chain**: False
- **Message**: IE XSS Filters - Attack Detected
- **Severity**: CRITICAL
- **Tags**: application-multi, language-multi, platform-internet-explorer, attack-xss, xss-perf-disable, paranoia-level/1, OWASP_CRS, OWASP_CRS/ATTACK-XSS, capec/1000/152/242
- **Actions**: id:941250, phase:2, block, capture, t:none, t:utf8toUnicode, t:urlDecodeUni, t:htmlEntityDecode, t:jsDecode, t:cssDecode, t:removeNulls, msg:IE XSS Filters - Attack Detected, logdata:Matched Data: %{TX.0} found within %{MATCHED_VAR_NAME}: %{MATCHED_VAR}, tag:application-multi, tag:language-multi, tag:platform-internet-explorer, tag:attack-xss, tag:xss-perf-disable, tag:paranoia-level/1, tag:OWASP_CRS, tag:OWASP_CRS/ATTACK-XSS, tag:capec/1000/152/242, ver:OWASP_CRS/4.22.0-dev, severity:CRITICAL, setvar:tx.xss_score=+%{tx.critical_anomaly_score}, setvar:tx.inbound_anomaly_score_pl1=+%{tx.critical_anomaly_score}

#### Rule 18: 941260
- **Phase**: 2
- **Variables**: REQUEST_COOKIES, REQUEST_COOKIES_NAMES, ARGS_NAMES, ARGS, REQUEST_FILENAME, XML:/*
- **Operator**: @rx
- **Pattern**: (?i:<META[\s/+].*?charset[\s/+]*=)
- **Is Chain**: False
- **Message**: IE XSS Filters - Attack Detected
- **Severity**: CRITICAL
- **Tags**: application-multi, language-multi, platform-internet-explorer, attack-xss, xss-perf-disable, paranoia-level/1, OWASP_CRS, OWASP_CRS/ATTACK-XSS, capec/1000/152/242
- **Actions**: id:941260, phase:2, block, capture, t:none, t:utf8toUnicode, t:urlDecodeUni, t:htmlEntityDecode, t:jsDecode, t:cssDecode, t:removeNulls, msg:IE XSS Filters - Attack Detected, logdata:Matched Data: %{TX.0} found within %{MATCHED_VAR_NAME}: %{MATCHED_VAR}, tag:application-multi, tag:language-multi, tag:platform-internet-explorer, tag:attack-xss, tag:xss-perf-disable, tag:paranoia-level/1, tag:OWASP_CRS, tag:OWASP_CRS/ATTACK-XSS, tag:capec/1000/152/242, ver:OWASP_CRS/4.22.0-dev, severity:CRITICAL, setvar:tx.xss_score=+%{tx.critical_anomaly_score}, setvar:tx.inbound_anomaly_score_pl1=+%{tx.critical_anomaly_score}

#### Rule 19: 941270
- **Phase**: 2
- **Variables**: REQUEST_COOKIES, REQUEST_COOKIES_NAMES, ARGS_NAMES, ARGS, REQUEST_FILENAME, XML:/*
- **Operator**: @rx
- **Pattern**: (?i)<LINK[\s/+].*?href[\s/+]*=
- **Is Chain**: False
- **Message**: IE XSS Filters - Attack Detected
- **Severity**: CRITICAL
- **Tags**: application-multi, language-multi, platform-internet-explorer, attack-xss, xss-perf-disable, paranoia-level/1, OWASP_CRS, OWASP_CRS/ATTACK-XSS, capec/1000/152/242
- **Actions**: id:941270, phase:2, block, capture, t:none, t:utf8toUnicode, t:urlDecodeUni, t:htmlEntityDecode, t:jsDecode, t:cssDecode, t:removeNulls, msg:IE XSS Filters - Attack Detected, logdata:Matched Data: %{TX.0} found within %{MATCHED_VAR_NAME}: %{MATCHED_VAR}, tag:application-multi, tag:language-multi, tag:platform-internet-explorer, tag:attack-xss, tag:xss-perf-disable, tag:paranoia-level/1, tag:OWASP_CRS, tag:OWASP_CRS/ATTACK-XSS, tag:capec/1000/152/242, ver:OWASP_CRS/4.22.0-dev, severity:CRITICAL, setvar:tx.xss_score=+%{tx.critical_anomaly_score}, setvar:tx.inbound_anomaly_score_pl1=+%{tx.critical_anomaly_score}

#### Rule 20: 941280
- **Phase**: 2
- **Variables**: REQUEST_COOKIES, REQUEST_COOKIES_NAMES, ARGS_NAMES, ARGS, REQUEST_FILENAME, XML:/*
- **Operator**: @rx
- **Pattern**: (?i)<BASE[\s/+].*?href[\s/+]*=
- **Is Chain**: False
- **Message**: IE XSS Filters - Attack Detected
- **Severity**: CRITICAL
- **Tags**: application-multi, language-multi, platform-internet-explorer, attack-xss, xss-perf-disable, paranoia-level/1, OWASP_CRS, OWASP_CRS/ATTACK-XSS, capec/1000/152/242
- **Actions**: id:941280, phase:2, block, capture, t:none, t:utf8toUnicode, t:urlDecodeUni, t:htmlEntityDecode, t:jsDecode, t:cssDecode, t:removeNulls, msg:IE XSS Filters - Attack Detected, logdata:Matched Data: %{TX.0} found within %{MATCHED_VAR_NAME}: %{MATCHED_VAR}, tag:application-multi, tag:language-multi, tag:platform-internet-explorer, tag:attack-xss, tag:xss-perf-disable, tag:paranoia-level/1, tag:OWASP_CRS, tag:OWASP_CRS/ATTACK-XSS, tag:capec/1000/152/242, ver:OWASP_CRS/4.22.0-dev, severity:CRITICAL, setvar:tx.xss_score=+%{tx.critical_anomaly_score}, setvar:tx.inbound_anomaly_score_pl1=+%{tx.critical_anomaly_score}

#### Rule 21: 941290
- **Phase**: 2
- **Variables**: REQUEST_COOKIES, REQUEST_COOKIES_NAMES, ARGS_NAMES, ARGS, REQUEST_FILENAME, XML:/*
- **Operator**: @rx
- **Pattern**: (?i)<APPLET[\s/+>]
- **Is Chain**: False
- **Message**: IE XSS Filters - Attack Detected
- **Severity**: CRITICAL
- **Tags**: application-multi, language-multi, platform-internet-explorer, attack-xss, xss-perf-disable, paranoia-level/1, OWASP_CRS, OWASP_CRS/ATTACK-XSS, capec/1000/152/242
- **Actions**: id:941290, phase:2, block, capture, t:none, t:utf8toUnicode, t:urlDecodeUni, t:htmlEntityDecode, t:jsDecode, t:cssDecode, t:removeNulls, msg:IE XSS Filters - Attack Detected, logdata:Matched Data: %{TX.0} found within %{MATCHED_VAR_NAME}: %{MATCHED_VAR}, tag:application-multi, tag:language-multi, tag:platform-internet-explorer, tag:attack-xss, tag:xss-perf-disable, tag:paranoia-level/1, tag:OWASP_CRS, tag:OWASP_CRS/ATTACK-XSS, tag:capec/1000/152/242, ver:OWASP_CRS/4.22.0-dev, severity:CRITICAL, setvar:tx.xss_score=+%{tx.critical_anomaly_score}, setvar:tx.inbound_anomaly_score_pl1=+%{tx.critical_anomaly_score}

#### Rule 22: 941300
- **Phase**: 2
- **Variables**: REQUEST_COOKIES, REQUEST_COOKIES_NAMES, ARGS_NAMES, ARGS, REQUEST_FILENAME, XML:/*
- **Operator**: @rx
- **Pattern**: (?i)<OBJECT[\s/+].*?(?:type|codetype|classid|code|data)[\s/+]*=
- **Is Chain**: False
- **Message**: IE XSS Filters - Attack Detected
- **Severity**: CRITICAL
- **Tags**: application-multi, language-multi, platform-internet-explorer, attack-xss, xss-perf-disable, paranoia-level/1, OWASP_CRS, OWASP_CRS/ATTACK-XSS, capec/1000/152/242
- **Actions**: id:941300, phase:2, block, capture, t:none, t:utf8toUnicode, t:urlDecodeUni, t:htmlEntityDecode, t:jsDecode, t:cssDecode, t:removeNulls, msg:IE XSS Filters - Attack Detected, logdata:Matched Data: %{TX.0} found within %{MATCHED_VAR_NAME}: %{MATCHED_VAR}, tag:application-multi, tag:language-multi, tag:platform-internet-explorer, tag:attack-xss, tag:xss-perf-disable, tag:paranoia-level/1, tag:OWASP_CRS, tag:OWASP_CRS/ATTACK-XSS, tag:capec/1000/152/242, ver:OWASP_CRS/4.22.0-dev, severity:CRITICAL, setvar:tx.xss_score=+%{tx.critical_anomaly_score}, setvar:tx.inbound_anomaly_score_pl1=+%{tx.critical_anomaly_score}

#### Rule 23: 941310
- **Phase**: 2
- **Variables**: REQUEST_COOKIES, REQUEST_COOKIES_NAMES, ARGS_NAMES, ARGS, REQUEST_FILENAME, XML:/*
- **Operator**: @rx
- **Pattern**: \xbc[^\xbe>]*[\xbe>]|<[^\xbe]*\xbe
- **Is Chain**: True
- **Message**: US-ASCII Malformed Encoding XSS Filter - Attack Detected
- **Severity**: CRITICAL
- **Tags**: application-multi, language-multi, platform-tomcat, attack-xss, xss-perf-disable, paranoia-level/1, OWASP_CRS, OWASP_CRS/ATTACK-XSS, capec/1000/152/242
- **Actions**: id:941310, phase:2, block, capture, t:none, t:lowercase, t:urlDecodeUni, t:htmlEntityDecode, t:jsDecode, msg:US-ASCII Malformed Encoding XSS Filter - Attack Detected, logdata:Matched Data: %{TX.0} found within %{MATCHED_VAR_NAME}: %{MATCHED_VAR}, tag:application-multi, tag:language-multi, tag:platform-tomcat, tag:attack-xss, tag:xss-perf-disable, tag:paranoia-level/1, tag:OWASP_CRS, tag:OWASP_CRS/ATTACK-XSS, tag:capec/1000/152/242, ver:OWASP_CRS/4.22.0-dev, severity:CRITICAL, chain

#### Rule 24: Unknown
- **Phase**: Unknown
- **Variables**: MATCHED_VARS
- **Operator**: @rx
- **Pattern**: (?:\xbc\s*/\s*[^\xbe>]*[\xbe>])|(?:<\s*/\s*[^\xbe]*\xbe)
- **Is Chain**: False
- **Message**: 
- **Severity**: 
- **Actions**: setvar:tx.xss_score=+%{tx.critical_anomaly_score}, setvar:tx.inbound_anomaly_score_pl1=+%{tx.critical_anomaly_score}

#### Rule 25: 941350
- **Phase**: 2
- **Variables**: REQUEST_COOKIES, REQUEST_COOKIES_NAMES, ARGS_NAMES, ARGS, REQUEST_FILENAME, XML:/*
- **Operator**: @rx
- **Pattern**: \+ADw-.*(?:\+AD4-|>)|<.*\+AD4-
- **Is Chain**: False
- **Message**: UTF-7 Encoding IE XSS - Attack Detected
- **Severity**: CRITICAL
- **Tags**: application-multi, language-multi, platform-internet-explorer, attack-xss, xss-perf-disable, paranoia-level/1, OWASP_CRS, OWASP_CRS/ATTACK-XSS, capec/1000/152/242
- **Actions**: id:941350, phase:2, block, capture, t:none, t:urlDecodeUni, t:htmlEntityDecode, t:jsDecode, msg:UTF-7 Encoding IE XSS - Attack Detected, logdata:Matched Data: %{TX.0} found within %{MATCHED_VAR_NAME}: %{MATCHED_VAR}, tag:application-multi, tag:language-multi, tag:platform-internet-explorer, tag:attack-xss, tag:xss-perf-disable, tag:paranoia-level/1, tag:OWASP_CRS, tag:OWASP_CRS/ATTACK-XSS, tag:capec/1000/152/242, ver:OWASP_CRS/4.22.0-dev, severity:CRITICAL, setvar:tx.xss_score=+%{tx.critical_anomaly_score}, setvar:tx.inbound_anomaly_score_pl1=+%{tx.critical_anomaly_score}

#### Rule 26: 941360
- **Phase**: 2
- **Variables**: REQUEST_COOKIES, REQUEST_COOKIES_NAMES, ARGS_NAMES, ARGS, REQUEST_FILENAME, XML:/*
- **Operator**: @rx
- **Pattern**: ![!+ ]\[\]
- **Is Chain**: False
- **Message**: JSFuck / Hieroglyphy obfuscation detected
- **Severity**: CRITICAL
- **Tags**: application-multi, language-multi, attack-xss, xss-perf-disable, paranoia-level/1, OWASP_CRS, OWASP_CRS/ATTACK-XSS, capec/1000/152/242/63
- **Actions**: id:941360, phase:2, block, capture, t:none, msg:JSFuck / Hieroglyphy obfuscation detected, logdata:Matched Data: Suspicious payload found within %{MATCHED_VAR_NAME}: %{MATCHED_VAR}, tag:application-multi, tag:language-multi, tag:attack-xss, tag:xss-perf-disable, tag:paranoia-level/1, tag:OWASP_CRS, tag:OWASP_CRS/ATTACK-XSS, tag:capec/1000/152/242/63, ver:OWASP_CRS/4.22.0-dev, severity:CRITICAL, setvar:tx.xss_score=+%{tx.critical_anomaly_score}, setvar:tx.inbound_anomaly_score_pl1=+%{tx.critical_anomaly_score}

#### Rule 27: 941370
- **Phase**: 2
- **Variables**: REQUEST_COOKIES, REQUEST_COOKIES_NAMES, ARGS, REQUEST_FILENAME, XML:/*
- **Operator**: @rx
- **Pattern**: (?:self|document|this|top|window)\s*(?:/\*|[\[)]).+?(?:\]|\*/)
- **Is Chain**: False
- **Message**: JavaScript global variable found
- **Severity**: CRITICAL
- **Tags**: application-multi, language-multi, attack-xss, xss-perf-disable, paranoia-level/1, OWASP_CRS, OWASP_CRS/ATTACK-XSS, capec/1000/152/242/63
- **Actions**: id:941370, phase:2, block, capture, t:none, t:urlDecodeUni, t:compressWhitespace, msg:JavaScript global variable found, logdata:Matched Data: Suspicious JS global variable found within %{MATCHED_VAR_NAME}: %{MATCHED_VAR}, tag:application-multi, tag:language-multi, tag:attack-xss, tag:xss-perf-disable, tag:paranoia-level/1, tag:OWASP_CRS, tag:OWASP_CRS/ATTACK-XSS, tag:capec/1000/152/242/63, ver:OWASP_CRS/4.22.0-dev, severity:CRITICAL, setvar:tx.xss_score=+%{tx.critical_anomaly_score}, setvar:tx.inbound_anomaly_score_pl1=+%{tx.critical_anomaly_score}

#### Rule 28: 941390
- **Phase**: 2
- **Variables**: REQUEST_COOKIES, REQUEST_COOKIES_NAMES, ARGS_NAMES, ARGS, REQUEST_FILENAME, XML:/*
- **Operator**: @rx
- **Pattern**: (?i)\b(?:eval|set(?:timeout|interval)|new[\s\x0b]+Function|a(?:lert|tob)|btoa|(?:promp|impor)t|con(?:firm|sole\.(?:log|dir))|fetch)[\s\x0b]*[\(\{]
- **Is Chain**: False
- **Message**: Javascript method detected
- **Severity**: CRITICAL
- **Tags**: application-multi, language-multi, platform-nodejs, attack-xss, xss-perf-disable, paranoia-level/1, OWASP_CRS, OWASP_CRS/ATTACK-XSS, capec/1000/152/242
- **Actions**: id:941390, phase:2, block, capture, t:none, t:htmlEntityDecode, t:jsDecode, msg:Javascript method detected, logdata:Matched Data: %{TX.0} found within %{MATCHED_VAR_NAME}: %{MATCHED_VAR}, tag:application-multi, tag:language-multi, tag:platform-nodejs, tag:attack-xss, tag:xss-perf-disable, tag:paranoia-level/1, tag:OWASP_CRS, tag:OWASP_CRS/ATTACK-XSS, tag:capec/1000/152/242, ver:OWASP_CRS/4.22.0-dev, severity:CRITICAL, setvar:tx.xss_score=+%{tx.critical_anomaly_score}, setvar:tx.inbound_anomaly_score_pl1=+%{tx.critical_anomaly_score}

#### Rule 29: 941400
- **Phase**: 2
- **Variables**: REQUEST_COOKIES, REQUEST_COOKIES_NAMES, ARGS_NAMES, ARGS, REQUEST_FILENAME, XML:/*
- **Operator**: @rx
- **Pattern**: ((?:\[[^\]]*\][^.]*\.)|Reflect[^.]*\.).*(?:map|sort|apply)[^.]*\..*call[^`]*`.*`
- **Is Chain**: False
- **Message**: XSS JavaScript function without parentheses
- **Severity**: CRITICAL
- **Tags**: application-multi, language-multi, attack-xss, xss-perf-disable, paranoia-level/1, OWASP_CRS, OWASP_CRS/ATTACK-XSS, capec/1000/152/242
- **Actions**: id:941400, phase:2, block, capture, t:none, t:urlDecodeUni, t:compressWhitespace, msg:XSS JavaScript function without parentheses, logdata:Matched Data: %{TX.0} found within %{MATCHED_VAR_NAME}: %{MATCHED_VAR}, tag:application-multi, tag:language-multi, tag:attack-xss, tag:xss-perf-disable, tag:paranoia-level/1, tag:OWASP_CRS, tag:OWASP_CRS/ATTACK-XSS, tag:capec/1000/152/242, ver:OWASP_CRS/4.22.0-dev, severity:CRITICAL, setvar:tx.xss_score=+%{tx.critical_anomaly_score}, setvar:tx.inbound_anomaly_score_pl1=+%{tx.critical_anomaly_score}

#### Rule 30: 941013
- **Phase**: 1
- **Variables**: TX:DETECTION_PARANOIA_LEVEL
- **Operator**: @lt
- **Pattern**: 2
- **Is Chain**: False
- **Message**: 
- **Severity**: 
- **Tags**: OWASP_CRS
- **Actions**: id:941013, phase:1, pass, nolog, tag:OWASP_CRS, ver:OWASP_CRS/4.22.0-dev, skipAfter:END-REQUEST-941-APPLICATION-ATTACK-XSS

#### Rule 31: 941014
- **Phase**: 2
- **Variables**: TX:DETECTION_PARANOIA_LEVEL
- **Operator**: @lt
- **Pattern**: 2
- **Is Chain**: False
- **Message**: 
- **Severity**: 
- **Tags**: OWASP_CRS
- **Actions**: id:941014, phase:2, pass, nolog, tag:OWASP_CRS, ver:OWASP_CRS/4.22.0-dev, skipAfter:END-REQUEST-941-APPLICATION-ATTACK-XSS

#### Rule 32: 941101
- **Phase**: 1
- **Variables**: REQUEST_FILENAME, REQUEST_HEADERS:Referer
- **Operator**: @detectXSS
- **Pattern**: 
- **Is Chain**: False
- **Message**: XSS Attack Detected via libinjection
- **Severity**: CRITICAL
- **Tags**: application-multi, language-multi, platform-multi, attack-xss, xss-perf-disable, paranoia-level/2, OWASP_CRS, OWASP_CRS/ATTACK-XSS, capec/1000/152/242
- **Actions**: id:941101, phase:1, block, capture, t:none, t:utf8toUnicode, t:urlDecodeUni, t:htmlEntityDecode, t:jsDecode, t:cssDecode, t:removeNulls, msg:XSS Attack Detected via libinjection, logdata:Matched Data: %{TX.0} found within %{MATCHED_VAR_NAME}: %{MATCHED_VAR}, tag:application-multi, tag:language-multi, tag:platform-multi, tag:attack-xss, tag:xss-perf-disable, tag:paranoia-level/2, tag:OWASP_CRS, tag:OWASP_CRS/ATTACK-XSS, tag:capec/1000/152/242, ver:OWASP_CRS/4.22.0-dev, severity:CRITICAL, setvar:tx.xss_score=+%{tx.critical_anomaly_score}, setvar:tx.inbound_anomaly_score_pl2=+%{tx.critical_anomaly_score}

#### Rule 33: 941120
- **Phase**: 2
- **Variables**: REQUEST_COOKIES, REQUEST_COOKIES_NAMES, REQUEST_HEADERS:User-Agent, REQUEST_HEADERS:Referer, ARGS_NAMES, ARGS, REQUEST_FILENAME, XML:/*
- **Operator**: @rx
- **Pattern**: (?i)[\s\"'`;/0-9=\x0B\x09\x0C\x3B\x2C\x28\x3B]on[a-zA-Z]{3,50}[\s\x0B\x09\x0C\x3B\x2C\x28\x3B]*?=[^=]
- **Is Chain**: False
- **Message**: XSS Filter - Category 2: Event Handler Vector
- **Severity**: CRITICAL
- **Tags**: application-multi, language-multi, platform-multi, attack-xss, xss-perf-disable, paranoia-level/2, OWASP_CRS, OWASP_CRS/ATTACK-XSS, capec/1000/152/242
- **Actions**: id:941120, phase:2, block, capture, t:none, t:utf8toUnicode, t:urlDecodeUni, t:htmlEntityDecode, t:jsDecode, t:cssDecode, t:removeNulls, msg:XSS Filter - Category 2: Event Handler Vector, logdata:Matched Data: %{TX.0} found within %{MATCHED_VAR_NAME}: %{MATCHED_VAR}, tag:application-multi, tag:language-multi, tag:platform-multi, tag:attack-xss, tag:xss-perf-disable, tag:paranoia-level/2, tag:OWASP_CRS, tag:OWASP_CRS/ATTACK-XSS, tag:capec/1000/152/242, ver:OWASP_CRS/4.22.0-dev, severity:CRITICAL, setvar:tx.xss_score=+%{tx.critical_anomaly_score}, setvar:tx.inbound_anomaly_score_pl2=+%{tx.critical_anomaly_score}

#### Rule 34: 941150
- **Phase**: 2
- **Variables**: REQUEST_COOKIES, REQUEST_COOKIES_NAMES, REQUEST_HEADERS:User-Agent, ARGS_NAMES, ARGS, REQUEST_FILENAME, XML:/*
- **Operator**: @rx
- **Pattern**: (?i)\b(?:s(?:tyle|rc)|href)\b[\s\S]*?=
- **Is Chain**: False
- **Message**: XSS Filter - Category 5: Disallowed HTML Attributes
- **Severity**: CRITICAL
- **Tags**: application-multi, language-multi, platform-multi, attack-xss, xss-perf-disable, paranoia-level/2, OWASP_CRS, OWASP_CRS/ATTACK-XSS, capec/1000/152/242
- **Actions**: id:941150, phase:2, block, capture, t:none, t:utf8toUnicode, t:urlDecodeUni, t:htmlEntityDecode, t:jsDecode, t:cssDecode, t:removeNulls, msg:XSS Filter - Category 5: Disallowed HTML Attributes, logdata:Matched Data: %{TX.0} found within %{MATCHED_VAR_NAME}: %{MATCHED_VAR}, tag:application-multi, tag:language-multi, tag:platform-multi, tag:attack-xss, tag:xss-perf-disable, tag:paranoia-level/2, tag:OWASP_CRS, tag:OWASP_CRS/ATTACK-XSS, tag:capec/1000/152/242, ver:OWASP_CRS/4.22.0-dev, severity:CRITICAL, setvar:tx.xss_score=+%{tx.critical_anomaly_score}, setvar:tx.inbound_anomaly_score_pl2=+%{tx.critical_anomaly_score}

#### Rule 35: 941181
- **Phase**: 2
- **Variables**: REQUEST_COOKIES, REQUEST_COOKIES_NAMES, ARGS_NAMES, ARGS, REQUEST_FILENAME, XML:/*
- **Operator**: @contains
- **Pattern**: -->
- **Is Chain**: False
- **Message**: Node-Validator Deny List Keywords
- **Severity**: CRITICAL
- **Tags**: application-multi, language-multi, platform-multi, attack-xss, xss-perf-disable, paranoia-level/2, OWASP_CRS, OWASP_CRS/ATTACK-XSS, capec/1000/152/242
- **Actions**: id:941181, phase:2, block, capture, t:none, t:utf8toUnicode, t:urlDecodeUni, t:htmlEntityDecode, t:jsDecode, t:cssDecode, t:lowercase, t:removeNulls, msg:Node-Validator Deny List Keywords, logdata:Matched Data: %{TX.0} found within %{MATCHED_VAR_NAME}: %{MATCHED_VAR}, tag:application-multi, tag:language-multi, tag:platform-multi, tag:attack-xss, tag:xss-perf-disable, tag:paranoia-level/2, tag:OWASP_CRS, tag:OWASP_CRS/ATTACK-XSS, tag:capec/1000/152/242, ver:OWASP_CRS/4.22.0-dev, severity:CRITICAL, setvar:tx.xss_score=+%{tx.critical_anomaly_score}, setvar:tx.inbound_anomaly_score_pl2=+%{tx.critical_anomaly_score}

#### Rule 36: 941320
- **Phase**: 2
- **Variables**: REQUEST_COOKIES, REQUEST_COOKIES:/_pk_ref/, REQUEST_COOKIES_NAMES, ARGS_NAMES, ARGS, REQUEST_FILENAME, XML:/*
- **Operator**: @rx
- **Pattern**: <(?:a|abbr|acronym|address|applet|area|audioscope|b|base|basefront|bdo|bgsound|big|blackface|blink|blockquote|body|bq|br|button|caption|center|cite|code|col|colgroup|comment|dd|del|dfn|dir|div|dl|dt|em|embed|fieldset|fn|font|form|frame|frameset|h1|head|hr|html|i|iframe|ilayer|img|input|ins|isindex|kdb|keygen|label|layer|legend|li|limittext|link|listing|map|marquee|menu|meta|multicol|nobr|noembed|noframes|noscript|nosmartquotes|object|ol|optgroup|option|p|param|plaintext|pre|q|rt|ruby|s|samp|script|select|server|shadow|sidebar|small|spacer|span|strike|strong|style|sub|sup|table|tbody|td|textarea|tfoot|th|thead|title|tr|tt|u|ul|var|wbr|xml|xmp)\W
- **Is Chain**: False
- **Message**: Possible XSS Attack Detected - HTML Tag Handler
- **Severity**: CRITICAL
- **Tags**: application-multi, language-multi, platform-multi, attack-xss, xss-perf-disable, paranoia-level/2, OWASP_CRS, OWASP_CRS/ATTACK-XSS, capec/1000/152/242/63
- **Actions**: id:941320, phase:2, block, capture, t:none, t:jsDecode, t:lowercase, msg:Possible XSS Attack Detected - HTML Tag Handler, logdata:Matched Data: %{TX.0} found within %{MATCHED_VAR_NAME}: %{MATCHED_VAR}, tag:application-multi, tag:language-multi, tag:platform-multi, tag:attack-xss, tag:xss-perf-disable, tag:paranoia-level/2, tag:OWASP_CRS, tag:OWASP_CRS/ATTACK-XSS, tag:capec/1000/152/242/63, ver:OWASP_CRS/4.22.0-dev, severity:CRITICAL, setvar:tx.xss_score=+%{tx.critical_anomaly_score}, setvar:tx.inbound_anomaly_score_pl2=+%{tx.critical_anomaly_score}

#### Rule 37: 941330
- **Phase**: 2
- **Variables**: REQUEST_COOKIES, REQUEST_COOKIES:/_pk_ref/, REQUEST_COOKIES_NAMES, ARGS_NAMES, ARGS, REQUEST_FILENAME, XML:/*
- **Operator**: @rx
- **Pattern**: (?i:[\"'][ ]*(?:[^a-z0-9~_:' ]|in).*?(?:(?:l|\x5cu006C)(?:o|\x5cu006F)(?:c|\x5cu0063)(?:a|\x5cu0061)(?:t|\x5cu0074)(?:i|\x5cu0069)(?:o|\x5cu006F)(?:n|\x5cu006E)|(?:n|\x5cu006E)(?:a|\x5cu0061)(?:m|\x5cu006D)(?:e|\x5cu0065)|(?:o|\x5cu006F)(?:n|\x5cu006E)(?:e|\x5cu0065)(?:r|\x5cu0072)(?:r|\x5cu0072)(?:o|\x5cu006F)(?:r|\x5cu0072)|(?:v|\x5cu0076)(?:a|\x5cu0061)(?:l|\x5cu006C)(?:u|\x5cu0075)(?:e|\x5cu0065)(?:O|\x5cu004F)(?:f|\x5cu0066)).*?=)
- **Is Chain**: False
- **Message**: IE XSS Filters - Attack Detected
- **Severity**: CRITICAL
- **Tags**: application-multi, language-multi, platform-multi, attack-xss, xss-perf-disable, paranoia-level/2, OWASP_CRS, OWASP_CRS/ATTACK-XSS, capec/1000/152/242
- **Actions**: id:941330, phase:2, block, capture, t:none, t:htmlEntityDecode, t:compressWhitespace, msg:IE XSS Filters - Attack Detected, logdata:Matched Data: %{TX.0} found within %{MATCHED_VAR_NAME}: %{MATCHED_VAR}, tag:application-multi, tag:language-multi, tag:platform-multi, tag:attack-xss, tag:xss-perf-disable, tag:paranoia-level/2, tag:OWASP_CRS, tag:OWASP_CRS/ATTACK-XSS, tag:capec/1000/152/242, ver:OWASP_CRS/4.22.0-dev, severity:CRITICAL, setvar:tx.xss_score=+%{tx.critical_anomaly_score}, setvar:tx.inbound_anomaly_score_pl2=+%{tx.critical_anomaly_score}

#### Rule 38: 941340
- **Phase**: 2
- **Variables**: REQUEST_COOKIES, REQUEST_COOKIES:/_pk_ref/, REQUEST_COOKIES_NAMES, ARGS_NAMES, ARGS, REQUEST_FILENAME, XML:/*
- **Operator**: @rx
- **Pattern**: (?i)[\"\'][ ]*(?:[^a-z0-9~_:\' ]|in).+?[.].+?=
- **Is Chain**: False
- **Message**: IE XSS Filters - Attack Detected
- **Severity**: CRITICAL
- **Tags**: application-multi, language-multi, platform-multi, attack-xss, xss-perf-disable, paranoia-level/2, OWASP_CRS, OWASP_CRS/ATTACK-XSS, capec/1000/152/242
- **Actions**: id:941340, phase:2, block, capture, t:none, t:htmlEntityDecode, t:compressWhitespace, msg:IE XSS Filters - Attack Detected, logdata:Matched Data: %{TX.0} found within %{MATCHED_VAR_NAME}: %{MATCHED_VAR}, tag:application-multi, tag:language-multi, tag:platform-multi, tag:attack-xss, tag:xss-perf-disable, tag:paranoia-level/2, tag:OWASP_CRS, tag:OWASP_CRS/ATTACK-XSS, tag:capec/1000/152/242, ver:OWASP_CRS/4.22.0-dev, severity:CRITICAL, setvar:tx.xss_score=+%{tx.critical_anomaly_score}, setvar:tx.inbound_anomaly_score_pl2=+%{tx.critical_anomaly_score}

#### Rule 39: 941380
- **Phase**: 2
- **Variables**: REQUEST_COOKIES, REQUEST_COOKIES_NAMES, ARGS_NAMES, ARGS, REQUEST_FILENAME, XML:/*
- **Operator**: @rx
- **Pattern**: {{.*?}}
- **Is Chain**: False
- **Message**: AngularJS client side template injection detected
- **Severity**: CRITICAL
- **Tags**: application-multi, language-multi, attack-xss, xss-perf-disable, paranoia-level/2, OWASP_CRS, OWASP_CRS/ATTACK-XSS, capec/1000/152/242/63
- **Actions**: id:941380, phase:2, block, capture, t:none, msg:AngularJS client side template injection detected, logdata:Matched Data: Suspicious payload found within %{MATCHED_VAR_NAME}: %{MATCHED_VAR}, tag:application-multi, tag:language-multi, tag:attack-xss, tag:xss-perf-disable, tag:paranoia-level/2, tag:OWASP_CRS, tag:OWASP_CRS/ATTACK-XSS, tag:capec/1000/152/242/63, ver:OWASP_CRS/4.22.0-dev, severity:CRITICAL, setvar:tx.xss_score=+%{tx.critical_anomaly_score}, setvar:tx.inbound_anomaly_score_pl2=+%{tx.critical_anomaly_score}

#### Rule 40: 941015
- **Phase**: 1
- **Variables**: TX:DETECTION_PARANOIA_LEVEL
- **Operator**: @lt
- **Pattern**: 3
- **Is Chain**: False
- **Message**: 
- **Severity**: 
- **Tags**: OWASP_CRS
- **Actions**: id:941015, phase:1, pass, nolog, tag:OWASP_CRS, ver:OWASP_CRS/4.22.0-dev, skipAfter:END-REQUEST-941-APPLICATION-ATTACK-XSS

#### Rule 41: 941016
- **Phase**: 2
- **Variables**: TX:DETECTION_PARANOIA_LEVEL
- **Operator**: @lt
- **Pattern**: 3
- **Is Chain**: False
- **Message**: 
- **Severity**: 
- **Tags**: OWASP_CRS
- **Actions**: id:941016, phase:2, pass, nolog, tag:OWASP_CRS, ver:OWASP_CRS/4.22.0-dev, skipAfter:END-REQUEST-941-APPLICATION-ATTACK-XSS

#### Rule 42: 941017
- **Phase**: 1
- **Variables**: TX:DETECTION_PARANOIA_LEVEL
- **Operator**: @lt
- **Pattern**: 4
- **Is Chain**: False
- **Message**: 
- **Severity**: 
- **Tags**: OWASP_CRS
- **Actions**: id:941017, phase:1, pass, nolog, tag:OWASP_CRS, ver:OWASP_CRS/4.22.0-dev, skipAfter:END-REQUEST-941-APPLICATION-ATTACK-XSS

#### Rule 43: 941018
- **Phase**: 2
- **Variables**: TX:DETECTION_PARANOIA_LEVEL
- **Operator**: @lt
- **Pattern**: 4
- **Is Chain**: False
- **Message**: 
- **Severity**: 
- **Tags**: OWASP_CRS
- **Actions**: id:941018, phase:2, pass, nolog, tag:OWASP_CRS, ver:OWASP_CRS/4.22.0-dev, skipAfter:END-REQUEST-941-APPLICATION-ATTACK-XSS


====================================================================================================

## File: REQUEST-942-APPLICATION-ATTACK-SQLI.conf

### File Summary
- Total rules: 72
- Chained rules: 4
- Non-chained rules: 68

### Detailed Rules

#### Rule 1: 942011
- **Phase**: 1
- **Variables**: TX:DETECTION_PARANOIA_LEVEL
- **Operator**: @lt
- **Pattern**: 1
- **Is Chain**: False
- **Message**: 
- **Severity**: 
- **Tags**: OWASP_CRS
- **Actions**: id:942011, phase:1, pass, nolog, tag:OWASP_CRS, ver:OWASP_CRS/4.22.0-dev, skipAfter:END-REQUEST-942-APPLICATION-ATTACK-SQLI

#### Rule 2: 942012
- **Phase**: 2
- **Variables**: TX:DETECTION_PARANOIA_LEVEL
- **Operator**: @lt
- **Pattern**: 1
- **Is Chain**: False
- **Message**: 
- **Severity**: 
- **Tags**: OWASP_CRS
- **Actions**: id:942012, phase:2, pass, nolog, tag:OWASP_CRS, ver:OWASP_CRS/4.22.0-dev, skipAfter:END-REQUEST-942-APPLICATION-ATTACK-SQLI

#### Rule 3: 942100
- **Phase**: 2
- **Variables**: REQUEST_COOKIES, REQUEST_COOKIES_NAMES, REQUEST_HEADERS:User-Agent, REQUEST_HEADERS:Referer, ARGS_NAMES, ARGS, XML:/*
- **Operator**: @detectSQLi
- **Pattern**: 
- **Is Chain**: False
- **Message**: SQL Injection Attack Detected via libinjection
- **Severity**: CRITICAL
- **Tags**: application-multi, language-multi, platform-multi, attack-sqli, paranoia-level/1, OWASP_CRS, OWASP_CRS/ATTACK-SQLI, capec/1000/152/248/66
- **Actions**: id:942100, phase:2, block, capture, t:none, t:utf8toUnicode, t:urlDecodeUni, t:removeNulls, msg:SQL Injection Attack Detected via libinjection, logdata:Matched Data: %{TX.0} found within %{MATCHED_VAR_NAME}: %{MATCHED_VAR}, tag:application-multi, tag:language-multi, tag:platform-multi, tag:attack-sqli, tag:paranoia-level/1, tag:OWASP_CRS, tag:OWASP_CRS/ATTACK-SQLI, tag:capec/1000/152/248/66, ver:OWASP_CRS/4.22.0-dev, severity:CRITICAL, multiMatch, setvar:tx.inbound_anomaly_score_pl1=+%{tx.critical_anomaly_score}, setvar:tx.sql_injection_score=+%{tx.critical_anomaly_score}

#### Rule 4: 942140
- **Phase**: 2
- **Variables**: REQUEST_COOKIES, REQUEST_COOKIES_NAMES, ARGS_NAMES, ARGS, XML:/*
- **Operator**: @rx
- **Pattern**: (?i)\b(?:d(?:atabas|b_nam)e[^0-9A-Z_a-z]*\(|(?:information_schema|m(?:aster\.\.sysdatabases|s(?:db|ys(?:ac(?:cess(?:objects|storage|xml)|es)|modules2?|(?:object|querie|relationship)s))|ysql\.db)|northwind|pg_(?:catalog|toast)|tempdb)\b|s(?:chema(?:_name\b|[^0-9A-Z_a-z]*\()|(?:qlite_(?:temp_)?master|ys(?:aux|\.database_name))\b))
- **Is Chain**: False
- **Message**: SQL Injection Attack: Common DB Names Detected
- **Severity**: CRITICAL
- **Tags**: application-multi, language-multi, platform-multi, attack-sqli, paranoia-level/1, OWASP_CRS, OWASP_CRS/ATTACK-SQLI, capec/1000/152/248/66
- **Actions**: id:942140, phase:2, block, capture, t:none, t:urlDecodeUni, msg:SQL Injection Attack: Common DB Names Detected, logdata:Matched Data: %{TX.0} found within %{MATCHED_VAR_NAME}: %{MATCHED_VAR}, tag:application-multi, tag:language-multi, tag:platform-multi, tag:attack-sqli, tag:paranoia-level/1, tag:OWASP_CRS, tag:OWASP_CRS/ATTACK-SQLI, tag:capec/1000/152/248/66, ver:OWASP_CRS/4.22.0-dev, severity:CRITICAL, setvar:tx.sql_injection_score=+%{tx.critical_anomaly_score}, setvar:tx.inbound_anomaly_score_pl1=+%{tx.critical_anomaly_score}

#### Rule 5: 942151
- **Phase**: 2
- **Variables**: REQUEST_COOKIES, REQUEST_COOKIES_NAMES, ARGS_NAMES, ARGS, XML:/*
- **Operator**: @rx
- **Pattern**: (?i)\b(?:a(?:dd(?:dat|tim)e|es_(?:de|en)crypt|s(?:cii(?:str)?|in)|tan2?)|b(?:enchmark|i(?:n_to_num|t_(?:and|count|length|x?or)))|c(?:har(?:acter)?_length|eil(?:ing)?|o(?:alesce|ercibility|llation|(?:mpres)?s|n(?:cat(?:_ws)?|nection_id|v(?:ert_tz)?)|t)|rc32|ur(?:(?:dat|tim)e|rent_(?:date|setting|time(?:stamp)?|user)))|d(?:a(?:t(?:abase(?:_to_xml)?|e(?:_(?:add|format|sub)|diff))|y(?:name|of(?:month|week|year)))|count|e(?:code|s_(?:de|en)crypt)|ump)|e(?:n(?:c(?:ode|rypt)|ds_?with)|x(?:p(?:ort_set)?|tract(?:value)?))|f(?:i(?:el|n)d_in_set|ound_rows|rom_(?:base64|days|unixtime))|g(?:e(?:ometrycollection|t(?:_(?:format|lock)|pgusername))|(?:r(?:eates|oup_conca)|tid_subse)t)|hex(?:toraw)?|i(?:fnull|n(?:et6?_(?:aton|ntoa)|s(?:ert|tr)|terval)|s(?:_(?:(?:free|used)_lock|ipv(?:4(?:_(?:compat|mapped))?|6)|n(?:ot(?:_null)?|ull)|superuser)|null))|json(?:_(?:a(?:gg|rray(?:_(?:elements(?:_text)?|length))?)|build_(?:array|object)|e(?:ac|xtract_pat)h(?:_text)?|object(?:_(?:agg|keys))?|populate_record(?:set)?|strip_nulls|t(?:o_record(?:set)?|ypeof))|b(?:_(?:array(?:_(?:elements(?:_text)?|length))?|build_(?:array|object)|e(?:ac|xtract_pat)h(?:_text)?|insert|object(?:_(?:agg|keys))?|p(?:ath_(?:(?:exists|match)(?:_tz)?|query(?:_(?:(?:array|first)(?:_tz)?|tz))?)|opulate_record(?:set)?|retty)|s(?:et(?:_lax)?|trip_nulls)|t(?:o_record(?:set)?|ypeof)))?|path)?|l(?:ast_(?:day|insert_id)|case|east|i(?:kely|nestring)|o(?:_(?:from_bytea|put)|ad_file|ca(?:ltimestamp|te)|g(?:10|2))|pad|trim)|m(?:a(?:ke(?:_set|date)|ster_pos_wait)|d5|i(?:crosecon)?d|onthname|ulti(?:linestring|po(?:int|lygon)))|n(?:ame_const|ot_in|ullif)|o(?:ct(?:et_length)?|(?:ld_passwo)?rd)|p(?:eriod_(?:add|diff)|g_(?:client_encoding|(?:databas|read_fil)e|l(?:argeobject|s_dir)|sleep|user)|o(?:lygon|w)|rocedure_analyse)|qu(?:ery_to_xml|ote)|r(?:a(?:dians|nd|wtohex)|elease_lock|ow_(?:count|to_json)|pad|trim)|s(?:chema|e(?:c_to_time|ssion_user)|ha[12]?|in|oundex|q(?:lite_(?:compileoption_(?:get|used)|source_id)|rt)|t(?:arts_?with|d(?:dev_(?:po|sam)p)?|r(?:_to_date|cmp))|ub(?:(?:dat|tim)e|str(?:ing(?:_index)?)?)|ys(?:date|tem_user))|t(?:ime(?:_(?:format|to_sec)|diff|stamp(?:add|diff)?)|o(?:_(?:base64|jsonb?)|n?char|(?:day|second)s)|r(?:im|uncate))|u(?:case|n(?:compress(?:ed_length)?|hex|i(?:str|x_timestamp))|(?:pdatexm|se_json_nul)l|tc_(?:date|time(?:stamp)?)|uid(?:_short)?)|var(?:_(?:po|sam)p|iance)|we(?:ek(?:day|ofyear)|ight_string)|xmltype|yearweek)[^0-9A-Z_a-z]*\(
- **Is Chain**: False
- **Message**: SQL Injection Attack: SQL function name detected
- **Severity**: CRITICAL
- **Tags**: application-multi, language-multi, platform-multi, attack-sqli, paranoia-level/1, OWASP_CRS, OWASP_CRS/ATTACK-SQLI, capec/1000/152/248/66
- **Actions**: id:942151, phase:2, block, capture, t:none, t:urlDecodeUni, msg:SQL Injection Attack: SQL function name detected, logdata:Matched Data: %{TX.0} found within %{MATCHED_VAR_NAME}: %{MATCHED_VAR}, tag:application-multi, tag:language-multi, tag:platform-multi, tag:attack-sqli, tag:paranoia-level/1, tag:OWASP_CRS, tag:OWASP_CRS/ATTACK-SQLI, tag:capec/1000/152/248/66, ver:OWASP_CRS/4.22.0-dev, severity:CRITICAL, setvar:tx.sql_injection_score=+%{tx.critical_anomaly_score}, setvar:tx.inbound_anomaly_score_pl1=+%{tx.critical_anomaly_score}

#### Rule 6: 942160
- **Phase**: 2
- **Variables**: REQUEST_FILENAME, REQUEST_COOKIES, REQUEST_COOKIES_NAMES, ARGS_NAMES, ARGS, XML:/*
- **Operator**: @rx
- **Pattern**: (?i:sleep\s*?\(.*?\)|benchmark\s*?\(.*?\,.*?\))
- **Is Chain**: False
- **Message**: Detects blind sqli tests using sleep() or benchmark()
- **Severity**: CRITICAL
- **Tags**: application-multi, language-multi, platform-multi, attack-sqli, paranoia-level/1, OWASP_CRS, OWASP_CRS/ATTACK-SQLI, capec/1000/152/248/66
- **Actions**: id:942160, phase:2, block, capture, t:none, t:urlDecodeUni, t:replaceComments, msg:Detects blind sqli tests using sleep() or benchmark(), logdata:Matched Data: %{TX.0} found within %{MATCHED_VAR_NAME}: %{MATCHED_VAR}, tag:application-multi, tag:language-multi, tag:platform-multi, tag:attack-sqli, tag:paranoia-level/1, tag:OWASP_CRS, tag:OWASP_CRS/ATTACK-SQLI, tag:capec/1000/152/248/66, ver:OWASP_CRS/4.22.0-dev, severity:CRITICAL, setvar:tx.sql_injection_score=+%{tx.critical_anomaly_score}, setvar:tx.inbound_anomaly_score_pl1=+%{tx.critical_anomaly_score}

#### Rule 7: 942170
- **Phase**: 2
- **Variables**: REQUEST_COOKIES, REQUEST_COOKIES_NAMES, ARGS_NAMES, ARGS, XML:/*
- **Operator**: @rx
- **Pattern**: (?i)(?:select|;)[\s\x0b]+(?:benchmark|if|sleep)[\s\x0b]*?\([\s\x0b]*?\(?[\s\x0b]*?[0-9A-Z_a-z]+
- **Is Chain**: False
- **Message**: Detects SQL benchmark and sleep injection attempts including conditional queries
- **Severity**: CRITICAL
- **Tags**: application-multi, language-multi, platform-multi, attack-sqli, paranoia-level/1, OWASP_CRS, OWASP_CRS/ATTACK-SQLI, capec/1000/152/248/66
- **Actions**: id:942170, phase:2, block, capture, t:none, t:urlDecodeUni, msg:Detects SQL benchmark and sleep injection attempts including conditional queries, logdata:Matched Data: %{TX.0} found within %{MATCHED_VAR_NAME}: %{MATCHED_VAR}, tag:application-multi, tag:language-multi, tag:platform-multi, tag:attack-sqli, tag:paranoia-level/1, tag:OWASP_CRS, tag:OWASP_CRS/ATTACK-SQLI, tag:capec/1000/152/248/66, ver:OWASP_CRS/4.22.0-dev, severity:CRITICAL, setvar:tx.sql_injection_score=+%{tx.critical_anomaly_score}, setvar:tx.inbound_anomaly_score_pl1=+%{tx.critical_anomaly_score}

#### Rule 8: 942190
- **Phase**: 2
- **Variables**: REQUEST_COOKIES, REQUEST_COOKIES_NAMES, ARGS_NAMES, ARGS, XML:/*
- **Operator**: @rx
- **Pattern**: (?i)[\"'`](?:[\s\x0b]*![\s\x0b]*[\"'0-9A-Z_-z]|;?[\s\x0b]*(?:having|select|union\b[\s\x0b]*(?:all|(?:distin|sele)ct))\b[\s\x0b]*[^\s\x0b])|\b(?:(?:(?:c(?:onnection_id|urrent_user)|database|schema|user)[\s\x0b]*?|select.*?[0-9A-Z_a-z]?user)\(|exec(?:ute)?[\s\x0b]+master\.|from[^0-9A-Z_a-z]+information_schema[^0-9A-Z_a-z]|into[\s\x0b\+]+(?:dump|out)file[\s\x0b]*?[\"'`]|union(?:[\s\x0b]select[\s\x0b]@|[\s\x0b\(0-9A-Z_a-z]*?select))|[\s\x0b]*?exec(?:ute)?.*?[^0-9A-Z_a-z]xp_cmdshell|[^0-9A-Z_a-z]iif[\s\x0b]*?\(
- **Is Chain**: False
- **Message**: Detects MSSQL code execution and information gathering attempts
- **Severity**: CRITICAL
- **Tags**: application-multi, language-multi, platform-multi, attack-sqli, paranoia-level/1, OWASP_CRS, OWASP_CRS/ATTACK-SQLI, capec/1000/152/248/66
- **Actions**: id:942190, phase:2, block, capture, t:none, t:urlDecodeUni, t:removeCommentsChar, msg:Detects MSSQL code execution and information gathering attempts, logdata:Matched Data: %{TX.0} found within %{MATCHED_VAR_NAME}: %{MATCHED_VAR}, tag:application-multi, tag:language-multi, tag:platform-multi, tag:attack-sqli, tag:paranoia-level/1, tag:OWASP_CRS, tag:OWASP_CRS/ATTACK-SQLI, tag:capec/1000/152/248/66, ver:OWASP_CRS/4.22.0-dev, severity:CRITICAL, setvar:tx.sql_injection_score=+%{tx.critical_anomaly_score}, setvar:tx.inbound_anomaly_score_pl1=+%{tx.critical_anomaly_score}

#### Rule 9: 942220
- **Phase**: 2
- **Variables**: REQUEST_COOKIES, REQUEST_COOKIES_NAMES, ARGS_NAMES, ARGS, XML:/*
- **Operator**: @rx
- **Pattern**: ^(?i:-0000023456|4294967295|4294967296|2147483648|2147483647|0000012345|-2147483648|-2147483649|0000023456|2.2250738585072007e-308|2.2250738585072011e-308|1e309)$
- **Is Chain**: False
- **Message**: Looking for integer overflow attacks, these are taken from skipfish, except 2.2.2250738585072011e-308 is the \"magic number\" crash
- **Severity**: CRITICAL
- **Tags**: application-multi, language-multi, platform-multi, attack-sqli, paranoia-level/1, OWASP_CRS, OWASP_CRS/ATTACK-SQLI, capec/1000/152/248/66
- **Actions**: id:942220, phase:2, block, capture, t:none, t:urlDecodeUni, msg:Looking for integer overflow attacks, these are taken from skipfish, except 2.2.2250738585072011e-308 is the \"magic number\" crash, logdata:Matched Data: %{TX.0} found within %{MATCHED_VAR_NAME}: %{MATCHED_VAR}, tag:application-multi, tag:language-multi, tag:platform-multi, tag:attack-sqli, tag:paranoia-level/1, tag:OWASP_CRS, tag:OWASP_CRS/ATTACK-SQLI, tag:capec/1000/152/248/66, ver:OWASP_CRS/4.22.0-dev, severity:CRITICAL, setvar:tx.sql_injection_score=+%{tx.critical_anomaly_score}, setvar:tx.inbound_anomaly_score_pl1=+%{tx.critical_anomaly_score}

#### Rule 10: 942230
- **Phase**: 2
- **Variables**: REQUEST_COOKIES, REQUEST_COOKIES_NAMES, ARGS_NAMES, ARGS, XML:/*
- **Operator**: @rx
- **Pattern**: (?i)[\s\x0b\(\)]case[\s\x0b]+when.*?then|\)[\s\x0b]*?like[\s\x0b]*?\(|select.*?having[\s\x0b]*?[^\s\x0b]+[\s\x0b]*?[^\s\x0b0-9A-Z_a-z]|if[\s\x0b]?\([0-9A-Z_a-z]+[\s\x0b]*?[<->~]
- **Is Chain**: False
- **Message**: Detects conditional SQL injection attempts
- **Severity**: CRITICAL
- **Tags**: application-multi, language-multi, platform-multi, attack-sqli, paranoia-level/1, OWASP_CRS, OWASP_CRS/ATTACK-SQLI, capec/1000/152/248/66
- **Actions**: id:942230, phase:2, block, capture, t:none, t:urlDecodeUni, msg:Detects conditional SQL injection attempts, logdata:Matched Data: %{TX.0} found within %{MATCHED_VAR_NAME}: %{MATCHED_VAR}, tag:application-multi, tag:language-multi, tag:platform-multi, tag:attack-sqli, tag:paranoia-level/1, tag:OWASP_CRS, tag:OWASP_CRS/ATTACK-SQLI, tag:capec/1000/152/248/66, ver:OWASP_CRS/4.22.0-dev, severity:CRITICAL, setvar:tx.sql_injection_score=+%{tx.critical_anomaly_score}, setvar:tx.inbound_anomaly_score_pl1=+%{tx.critical_anomaly_score}

#### Rule 11: 942240
- **Phase**: 2
- **Variables**: REQUEST_COOKIES, REQUEST_COOKIES_NAMES, ARGS_NAMES, ARGS, XML:/*
- **Operator**: @rx
- **Pattern**: (?i)alter[\s\x0b]*?[0-9A-Z_a-z]+.*?char(?:acter)?[\s\x0b]+set[\s\x0b]+[0-9A-Z_a-z]+|[\"'`](?:;*?[\s\x0b]*?waitfor[\s\x0b]+(?:time|delay)[\s\x0b]+[\"'`]|;.*?:[\s\x0b]*?goto)
- **Is Chain**: False
- **Message**: Detects MySQL charset switch and MSSQL DoS attempts
- **Severity**: CRITICAL
- **Tags**: application-multi, language-multi, platform-multi, attack-sqli, paranoia-level/1, OWASP_CRS, OWASP_CRS/ATTACK-SQLI, capec/1000/152/248/66
- **Actions**: id:942240, phase:2, block, capture, t:none, t:urlDecodeUni, msg:Detects MySQL charset switch and MSSQL DoS attempts, logdata:Matched Data: %{TX.0} found within %{MATCHED_VAR_NAME}: %{MATCHED_VAR}, tag:application-multi, tag:language-multi, tag:platform-multi, tag:attack-sqli, tag:paranoia-level/1, tag:OWASP_CRS, tag:OWASP_CRS/ATTACK-SQLI, tag:capec/1000/152/248/66, ver:OWASP_CRS/4.22.0-dev, severity:CRITICAL, setvar:tx.sql_injection_score=+%{tx.critical_anomaly_score}, setvar:tx.inbound_anomaly_score_pl1=+%{tx.critical_anomaly_score}

#### Rule 12: 942250
- **Phase**: 2
- **Variables**: REQUEST_COOKIES, REQUEST_COOKIES_NAMES, ARGS_NAMES, ARGS, XML:/*
- **Operator**: @rx
- **Pattern**: (?i:merge.*?using\s*?\(|execute\s*?immediate\s*?[\"'`]|match\s*?[\w(),+-]+\s*?against\s*?\()
- **Is Chain**: False
- **Message**: Detects MATCH AGAINST, MERGE and EXECUTE IMMEDIATE injections
- **Severity**: CRITICAL
- **Tags**: application-multi, language-multi, platform-multi, attack-sqli, paranoia-level/1, OWASP_CRS, OWASP_CRS/ATTACK-SQLI, capec/1000/152/248/66
- **Actions**: id:942250, phase:2, block, capture, t:none, t:urlDecodeUni, msg:Detects MATCH AGAINST, MERGE and EXECUTE IMMEDIATE injections, logdata:Matched Data: %{TX.0} found within %{MATCHED_VAR_NAME}: %{MATCHED_VAR}, tag:application-multi, tag:language-multi, tag:platform-multi, tag:attack-sqli, tag:paranoia-level/1, tag:OWASP_CRS, tag:OWASP_CRS/ATTACK-SQLI, tag:capec/1000/152/248/66, ver:OWASP_CRS/4.22.0-dev, severity:CRITICAL, setvar:tx.sql_injection_score=+%{tx.critical_anomaly_score}, setvar:tx.inbound_anomaly_score_pl1=+%{tx.critical_anomaly_score}

#### Rule 13: 942270
- **Phase**: 2
- **Variables**: REQUEST_COOKIES, REQUEST_COOKIES_NAMES, ARGS_NAMES, ARGS, XML:/*
- **Operator**: @rx
- **Pattern**: (?i)union.*?select.*?from
- **Is Chain**: False
- **Message**: Looking for basic sql injection. Common attack string for mysql, oracle and others
- **Severity**: CRITICAL
- **Tags**: application-multi, language-multi, platform-multi, attack-sqli, paranoia-level/1, OWASP_CRS, OWASP_CRS/ATTACK-SQLI, capec/1000/152/248/66
- **Actions**: id:942270, phase:2, block, capture, t:none, t:urlDecodeUni, msg:Looking for basic sql injection. Common attack string for mysql, oracle and others, logdata:Matched Data: %{TX.0} found within %{MATCHED_VAR_NAME}: %{MATCHED_VAR}, tag:application-multi, tag:language-multi, tag:platform-multi, tag:attack-sqli, tag:paranoia-level/1, tag:OWASP_CRS, tag:OWASP_CRS/ATTACK-SQLI, tag:capec/1000/152/248/66, ver:OWASP_CRS/4.22.0-dev, severity:CRITICAL, setvar:tx.sql_injection_score=+%{tx.critical_anomaly_score}, setvar:tx.inbound_anomaly_score_pl1=+%{tx.critical_anomaly_score}

#### Rule 14: 942280
- **Phase**: 2
- **Variables**: REQUEST_COOKIES, REQUEST_COOKIES_NAMES, REQUEST_HEADERS:User-Agent, REQUEST_HEADERS:Referer, ARGS_NAMES, ARGS, XML:/*
- **Operator**: @rx
- **Pattern**: (?i)select[\s\x0b]*?pg_sleep|waitfor[\s\x0b]*?delay[\s\x0b]?[\"'`]+[\s\x0b]?[0-9]|;[\s\x0b]*?shutdown[\s\x0b]*?(?:[#;\{]|/\*|--)
- **Is Chain**: False
- **Message**: Detects Postgres pg_sleep injection, waitfor delay attacks and database shutdown attempts
- **Severity**: CRITICAL
- **Tags**: application-multi, language-multi, platform-multi, attack-sqli, paranoia-level/1, OWASP_CRS, OWASP_CRS/ATTACK-SQLI, capec/1000/152/248/66
- **Actions**: id:942280, phase:2, block, capture, t:none, t:urlDecodeUni, msg:Detects Postgres pg_sleep injection, waitfor delay attacks and database shutdown attempts, logdata:Matched Data: %{TX.0} found within %{MATCHED_VAR_NAME}: %{MATCHED_VAR}, tag:application-multi, tag:language-multi, tag:platform-multi, tag:attack-sqli, tag:paranoia-level/1, tag:OWASP_CRS, tag:OWASP_CRS/ATTACK-SQLI, tag:capec/1000/152/248/66, ver:OWASP_CRS/4.22.0-dev, severity:CRITICAL, setvar:tx.sql_injection_score=+%{tx.critical_anomaly_score}, setvar:tx.inbound_anomaly_score_pl1=+%{tx.critical_anomaly_score}

#### Rule 15: 942290
- **Phase**: 2
- **Variables**: REQUEST_COOKIES, REQUEST_COOKIES_NAMES, ARGS_NAMES, ARGS, XML:/*
- **Operator**: @rx
- **Pattern**: (?i)\[?\$(?:a(?:bs|c(?:cumulator|osh?)|dd(?:ToSet)?|ll(?:ElementsTrue)?|n(?:d|yElementTrue)|rray(?:ElemA|ToObjec)t|sinh?|tan[2h]?|vg)|b(?:etween|i(?:narySize|t(?:And|Not|(?:O|Xo)r)?)|ottomN?|sonSize|ucket(?:Auto)?)|c(?:eil|mp|o(?:n(?:cat(?:Arrays)?|d|vert)|sh?|unt|variance(?:Po|Sam)p)|urrentDate)|d(?:a(?:te(?:Add|Diff|From(?:Parts|String)|Subtract|T(?:o(?:Parts|String)|runc))|yOf(?:Month|Week|Year))|e(?:greesToRadians|nseRank|rivative)|iv(?:ide)?|ocumentNumber)|e(?:(?:a|lemMat)ch|q|x(?:ists|p(?:MovingAvg|r)?))|f(?:i(?:lter|rstN?)|loor|unction)|g(?:etField|roup|te?)|(?:hou|xo|yea)r|i(?:fNull|n(?:c|dexOf(?:Array|Bytes|CP)|tegral)?|s(?:Array|Number|o(?:DayOfWeek|Week(?:Year)?)))|jsonSchema|l(?:astN?|et|i(?:ke|(?:nearFil|tera)l)|n|o(?:cf|g(?:10)?)|t(?:e|rim)?)|m(?:a(?:p|xN?)|e(?:dian|rgeObjects|ta)|i(?:llisecond|n(?:N|ute)?)|o(?:d|nth)|ul(?:tiply)?)|n(?:atural|e|in|o[rt])|o(?:bjectToArray|r)|p(?:ercentile|o(?:[pw]|sition)|roject|u(?:ll(?:All)?|sh))|r(?:a(?:diansToDegrees|n(?:[dk]|ge))|e(?:(?:duc|nam)e|gex(?:Find(?:All)?|Match)?|place(?:All|One)|verseArray)|ound|trim)|s(?:(?:ampleRat|lic)e|e(?:cond|t(?:Difference|(?:Equal|WindowField)s|Field|I(?:ntersection|sSubset)|OnInsert|Union)?)|(?:hif|pli|qr)t|i(?:nh?|ze)|ort(?:Array)?|t(?:dDev(?:Po|Sam)p|r(?:Len(?:Bytes|CP)|casecmp))|u(?:b(?:str(?:Bytes|CP)?|tract)|m)|witch)|t(?:anh?|ext|o(?:Bool|D(?:(?:at|oubl)e|ecimal)|HashedIndexKey|Int|Lo(?:ng|wer)|ObjectId|String|U(?:UID|pper)|pN?)|r(?:im|unc)|s(?:Increment|Second)|ype)|unset|w(?:eek|here)|zip)\]?
- **Is Chain**: False
- **Message**: Finds basic MongoDB SQL injection attempts
- **Severity**: CRITICAL
- **Tags**: application-multi, language-multi, platform-multi, attack-sqli, paranoia-level/1, OWASP_CRS, OWASP_CRS/ATTACK-SQLI, capec/1000/152/248/66
- **Actions**: id:942290, phase:2, block, capture, t:none, t:urlDecodeUni, msg:Finds basic MongoDB SQL injection attempts, logdata:Matched Data: %{TX.0} found within %{MATCHED_VAR_NAME}: %{MATCHED_VAR}, tag:application-multi, tag:language-multi, tag:platform-multi, tag:attack-sqli, tag:paranoia-level/1, tag:OWASP_CRS, tag:OWASP_CRS/ATTACK-SQLI, tag:capec/1000/152/248/66, ver:OWASP_CRS/4.22.0-dev, severity:CRITICAL, setvar:tx.sql_injection_score=+%{tx.critical_anomaly_score}, setvar:tx.inbound_anomaly_score_pl1=+%{tx.critical_anomaly_score}

#### Rule 16: 942320
- **Phase**: 2
- **Variables**: REQUEST_COOKIES, REQUEST_COOKIES_NAMES, ARGS_NAMES, ARGS, XML:/*
- **Operator**: @rx
- **Pattern**: (?i)create[\s\x0b]+(?:function|procedure)[\s\x0b]*?[0-9A-Z_a-z]+[\s\x0b]*?\([\s\x0b]*?\)[\s\x0b]*?-|d(?:eclare[^0-9A-Z_a-z]+[#@][\s\x0b]*?[0-9A-Z_a-z]+|iv[\s\x0b]*?\([\+\-]*[\s\x0b\.0-9]+,[\+\-]*[\s\x0b\.0-9]+\))|exec[\s\x0b]*?\([\s\x0b]*?@|(?:lo_(?:impor|ge)t|procedure[\s\x0b]+analyse)[\s\x0b]*?\(|;[\s\x0b]*?(?:declare|open)[\s\x0b]+[\-0-9A-Z_a-z]+|::(?:b(?:igint|ool)|double[\s\x0b]+precision|int(?:eger)?|numeric|oid|real|(?:tex|smallin)t)
- **Is Chain**: False
- **Message**: Detects MySQL and PostgreSQL stored procedure/function injections
- **Severity**: CRITICAL
- **Tags**: application-multi, language-multi, platform-multi, attack-sqli, paranoia-level/1, OWASP_CRS, OWASP_CRS/ATTACK-SQLI, capec/1000/152/248/66
- **Actions**: id:942320, phase:2, block, capture, t:none, t:urlDecodeUni, msg:Detects MySQL and PostgreSQL stored procedure/function injections, logdata:Matched Data: %{TX.0} found within %{MATCHED_VAR_NAME}: %{MATCHED_VAR}, tag:application-multi, tag:language-multi, tag:platform-multi, tag:attack-sqli, tag:paranoia-level/1, tag:OWASP_CRS, tag:OWASP_CRS/ATTACK-SQLI, tag:capec/1000/152/248/66, ver:OWASP_CRS/4.22.0-dev, severity:CRITICAL, setvar:tx.sql_injection_score=+%{tx.critical_anomaly_score}, setvar:tx.inbound_anomaly_score_pl1=+%{tx.critical_anomaly_score}

#### Rule 17: 942350
- **Phase**: 2
- **Variables**: REQUEST_COOKIES, REQUEST_COOKIES_NAMES, ARGS_NAMES, ARGS, XML:/*
- **Operator**: @rx
- **Pattern**: (?i)create[\s\x0b]+function[\s\x0b].+[\s\x0b]returns|;[\s\x0b]*?(?:alter|(?:(?:cre|trunc|upd)at|renam)e|d(?:e(?:lete|sc)|rop)|(?:inser|selec)t|load)\b[\s\x0b]*?[\(\[]?[0-9A-Z_a-z]{2,}
- **Is Chain**: False
- **Message**: Detects MySQL UDF injection and other data/structure manipulation attempts
- **Severity**: CRITICAL
- **Tags**: application-multi, language-multi, platform-multi, attack-sqli, paranoia-level/1, OWASP_CRS, OWASP_CRS/ATTACK-SQLI, capec/1000/152/248/66
- **Actions**: id:942350, phase:2, block, capture, t:none, t:urlDecodeUni, msg:Detects MySQL UDF injection and other data/structure manipulation attempts, logdata:Matched Data: %{TX.0} found within %{MATCHED_VAR_NAME}: %{MATCHED_VAR}, tag:application-multi, tag:language-multi, tag:platform-multi, tag:attack-sqli, tag:paranoia-level/1, tag:OWASP_CRS, tag:OWASP_CRS/ATTACK-SQLI, tag:capec/1000/152/248/66, ver:OWASP_CRS/4.22.0-dev, severity:CRITICAL, setvar:tx.sql_injection_score=+%{tx.critical_anomaly_score}, setvar:tx.inbound_anomaly_score_pl1=+%{tx.critical_anomaly_score}

#### Rule 18: 942360
- **Phase**: 2
- **Variables**: REQUEST_COOKIES, REQUEST_COOKIES_NAMES, ARGS_NAMES, ARGS, XML:/*
- **Operator**: @rx
- **Pattern**: (?i)\b(?:(?:alter|(?:(?:cre|trunc|upd)at|renam)e|de(?:lete|sc)|(?:inser|selec)t|load)[\s\x0b]+(?:char|group_concat|load_file)\b[\s\x0b]*\(?|end[\s\x0b]*?\);)|[\s\x0b\(]load_file[\s\x0b]*?\(|[\"'`][\s\x0b]+regexp[^0-9A-Z_a-z]|[\"'0-9A-Z_-z][\s\x0b]+as\b[\s\x0b]*[\"'0-9A-Z_-z]+[\s\x0b]*\bfrom|^[^A-Z_a-z]+[\s\x0b]*?(?:(?:(?:(?:cre|trunc)at|renam)e|d(?:e(?:lete|sc)|rop)|(?:inser|selec)t|load)[\s\x0b]+[0-9A-Z_a-z]+|u(?:pdate[\s\x0b]+[0-9A-Z_a-z]+|nion[\s\x0b]*(?:all|(?:sele|distin)ct)\b)|alter[\s\x0b]*(?:a(?:(?:ggregat|pplication[\s\x0b]*rol)e|s(?:sembl|ymmetric[\s\x0b]*ke)y|u(?:dit|thorization)|vailability[\s\x0b]*group)|b(?:roker[\s\x0b]*priority|ufferpool)|c(?:ertificate|luster|o(?:l(?:latio|um)|nversio)n|r(?:edential|yptographic[\s\x0b]*provider))|d(?:atabase|efault|i(?:mension|skgroup)|omain)|e(?:(?:ndpoi|ve)nt|xte(?:nsion|rnal))|f(?:lashback|oreign|u(?:lltext|nction))|hi(?:erarchy|stogram)|group|in(?:dex(?:type)?|memory|stance)|java|l(?:a(?:ngua|r)ge|ibrary|o(?:ckdown|g(?:file[\s\x0b]*group|in)))|m(?:a(?:s(?:k|ter[\s\x0b]*key)|terialized)|e(?:ssage[\s\x0b]*type|thod)|odule)|(?:nicknam|queu)e|o(?:perator|utline)|p(?:a(?:ckage|rtition)|ermission|ro(?:cedur|fil)e)|r(?:e(?:mot|sourc)e|o(?:l(?:e|lback)|ute))|s(?:chema|e(?:arch|curity|rv(?:er|ice)|quence|ssion)|y(?:mmetric[\s\x0b]*key|nonym)|togroup)|t(?:able(?:space)?|ext|hreshold|r(?:igger|usted)|ype)|us(?:age|er)|view|w(?:ork(?:load)?|rapper)|x(?:ml[\s\x0b]*schema|srobject))\b)
- **Is Chain**: False
- **Message**: Detects concatenated basic SQL injection and SQLLFI attempts
- **Severity**: CRITICAL
- **Tags**: application-multi, language-multi, platform-multi, attack-sqli, paranoia-level/1, OWASP_CRS, OWASP_CRS/ATTACK-SQLI, capec/1000/152/248/66
- **Actions**: id:942360, phase:2, block, capture, t:none, t:urlDecodeUni, msg:Detects concatenated basic SQL injection and SQLLFI attempts, logdata:Matched Data: %{TX.0} found within %{MATCHED_VAR_NAME}: %{MATCHED_VAR}, tag:application-multi, tag:language-multi, tag:platform-multi, tag:attack-sqli, tag:paranoia-level/1, tag:OWASP_CRS, tag:OWASP_CRS/ATTACK-SQLI, tag:capec/1000/152/248/66, ver:OWASP_CRS/4.22.0-dev, severity:CRITICAL, setvar:tx.sql_injection_score=+%{tx.critical_anomaly_score}, setvar:tx.inbound_anomaly_score_pl1=+%{tx.critical_anomaly_score}

#### Rule 19: 942500
- **Phase**: 2
- **Variables**: REQUEST_COOKIES, REQUEST_COOKIES_NAMES, ARGS_NAMES, ARGS, XML:/*
- **Operator**: @rx
- **Pattern**: (?i)/\*[\s\x0b]*?[!\+](?:[\s\x0b\(\)\-0-9=A-Z_a-z]+)?\*/
- **Is Chain**: False
- **Message**: MySQL in-line comment detected
- **Severity**: CRITICAL
- **Tags**: application-multi, language-multi, platform-multi, attack-sqli, paranoia-level/1, OWASP_CRS, OWASP_CRS/ATTACK-SQLI, capec/1000/152/248/66
- **Actions**: id:942500, phase:2, block, capture, t:none, t:urlDecodeUni, msg:MySQL in-line comment detected, logdata:Matched Data: %{TX.0} found within %{MATCHED_VAR_NAME}: %{MATCHED_VAR}, tag:application-multi, tag:language-multi, tag:platform-multi, tag:attack-sqli, tag:paranoia-level/1, tag:OWASP_CRS, tag:OWASP_CRS/ATTACK-SQLI, tag:capec/1000/152/248/66, ver:OWASP_CRS/4.22.0-dev, severity:CRITICAL, multiMatch, setvar:tx.sql_injection_score=+%{tx.critical_anomaly_score}, setvar:tx.inbound_anomaly_score_pl1=+%{tx.critical_anomaly_score}

#### Rule 20: 942540
- **Phase**: 2
- **Variables**: REQUEST_COOKIES, REQUEST_COOKIES_NAMES, ARGS_NAMES, ARGS, XML:/*
- **Operator**: @rx
- **Pattern**: ^(?:[^']*'|[^\"]*\"|[^`]*`)[\s\x0b]*;
- **Is Chain**: False
- **Message**: SQL Authentication bypass (split query)
- **Severity**: CRITICAL
- **Tags**: application-multi, language-multi, platform-multi, attack-sqli, OWASP_CRS, OWASP_CRS/ATTACK-SQLI, paranoia-level/1, capec/1000/152/248/66
- **Actions**: id:942540, phase:2, block, capture, t:none, t:urlDecodeUni, t:replaceComments, msg:SQL Authentication bypass (split query), logdata:Matched Data: %{TX.0} found within %{MATCHED_VAR_NAME}: %{MATCHED_VAR}, tag:application-multi, tag:language-multi, tag:platform-multi, tag:attack-sqli, tag:OWASP_CRS, tag:OWASP_CRS/ATTACK-SQLI, tag:paranoia-level/1, tag:capec/1000/152/248/66, ver:OWASP_CRS/4.22.0-dev, severity:CRITICAL, setvar:tx.sql_injection_score=+%{tx.critical_anomaly_score}, setvar:tx.inbound_anomaly_score_pl1=+%{tx.critical_anomaly_score}

#### Rule 21: 942560
- **Phase**: 2
- **Variables**: REQUEST_COOKIES, REQUEST_COOKIES_NAMES, ARGS_NAMES, ARGS, XML:/*
- **Operator**: @rx
- **Pattern**: (?i)1\.e(?:[\(\),]|\.[\$0-9A-Z_a-z])
- **Is Chain**: False
- **Message**: MySQL Scientific Notation payload detected
- **Severity**: CRITICAL
- **Tags**: application-multi, language-multi, platform-multi, attack-sqli, paranoia-level/1, OWASP_CRS, OWASP_CRS/ATTACK-SQLI, capec/1000/152/248/66
- **Actions**: id:942560, phase:2, block, capture, t:none, t:urlDecodeUni, t:replaceComments, msg:MySQL Scientific Notation payload detected, logdata:Matched Data: %{TX.0} found within %{MATCHED_VAR_NAME}: %{MATCHED_VAR}, tag:application-multi, tag:language-multi, tag:platform-multi, tag:attack-sqli, tag:paranoia-level/1, tag:OWASP_CRS, tag:OWASP_CRS/ATTACK-SQLI, tag:capec/1000/152/248/66, ver:OWASP_CRS/4.22.0-dev, severity:CRITICAL, setvar:tx.sql_injection_score=+%{tx.critical_anomaly_score}, setvar:tx.inbound_anomaly_score_pl1=+%{tx.critical_anomaly_score}

#### Rule 22: 942550
- **Phase**: 2
- **Variables**: REQUEST_FILENAME, REQUEST_COOKIES, REQUEST_COOKIES_NAMES, ARGS_NAMES, ARGS, XML:/*
- **Operator**: @rx
- **Pattern**: (?i)[\"'`][\[\{][^#\]\}]*[\]\}]+[\"'`]|(?:[\-@]>?|<@|@[\?@]|\?(?:(?:)|&|\|#>)|#(?:>>|-)|->>|[<>])[\"'`](?:[\[\{][^#\]\}]*[\]\}]+[\"'`]|\$[\.\[])|\bjson_extract\b[^\(]*\([^\)]*\)
- **Is Chain**: False
- **Message**: JSON-Based SQL Injection
- **Severity**: CRITICAL
- **Tags**: application-multi, language-multi, platform-multi, attack-sqli, paranoia-level/1, OWASP_CRS, OWASP_CRS/ATTACK-SQLI, capec/1000/152/248/66
- **Actions**: id:942550, phase:2, block, capture, t:none, t:urlDecodeUni, t:removeWhitespace, msg:JSON-Based SQL Injection, logdata:Matched Data: %{TX.0} found within %{MATCHED_VAR_NAME}: %{MATCHED_VAR}, tag:application-multi, tag:language-multi, tag:platform-multi, tag:attack-sqli, tag:paranoia-level/1, tag:OWASP_CRS, tag:OWASP_CRS/ATTACK-SQLI, tag:capec/1000/152/248/66, ver:OWASP_CRS/4.22.0-dev, severity:CRITICAL, setvar:tx.sql_injection_score=+%{tx.critical_anomaly_score}, setvar:tx.inbound_anomaly_score_pl1=+%{tx.critical_anomaly_score}

#### Rule 23: 942013
- **Phase**: 1
- **Variables**: TX:DETECTION_PARANOIA_LEVEL
- **Operator**: @lt
- **Pattern**: 2
- **Is Chain**: False
- **Message**: 
- **Severity**: 
- **Tags**: OWASP_CRS
- **Actions**: id:942013, phase:1, pass, nolog, tag:OWASP_CRS, ver:OWASP_CRS/4.22.0-dev, skipAfter:END-REQUEST-942-APPLICATION-ATTACK-SQLI

#### Rule 24: 942014
- **Phase**: 2
- **Variables**: TX:DETECTION_PARANOIA_LEVEL
- **Operator**: @lt
- **Pattern**: 2
- **Is Chain**: False
- **Message**: 
- **Severity**: 
- **Tags**: OWASP_CRS
- **Actions**: id:942014, phase:2, pass, nolog, tag:OWASP_CRS, ver:OWASP_CRS/4.22.0-dev, skipAfter:END-REQUEST-942-APPLICATION-ATTACK-SQLI

#### Rule 25: 942120
- **Phase**: 2
- **Variables**: ARGS_NAMES, ARGS, REQUEST_FILENAME, XML:/*
- **Operator**: @rx
- **Pattern**: (?i)[!=]=|&&|\|\||->|>[=>]|<(?:[<=]|>(?:[\s\x0b]+binary)?)|\b(?:(?:xor|r(?:egexp|like)|i(?:snull|like)|notnull)\b|collate(?:[^0-9A-Z_a-z]*?(?:U&)?[\"'`]|[^0-9A-Z_a-z]+(?:(?:binary|nocase|rtrim)\b|[0-9A-Z_a-z]*?_))|(?:likel(?:ihood|y)|unlikely)[\s\x0b]*\()|r(?:egexp|like)[\s\x0b]+binary|not[\s\x0b]+between[\s\x0b]+(?:0[\s\x0b]+and|(?:'[^']*'|\"[^\"]*\")[\s\x0b]+and[\s\x0b]+(?:'[^']*'|\"[^\"]*\"))|is[\s\x0b]+null|like[\s\x0b]+(?:null|[0-9A-Z_a-z]+[\s\x0b]+escape\b)|(?:^|[^0-9A-Z_a-z])in[\s\x0b\+]*\([\s\x0b\"0-9]+[^\(\)]*\)|[!<->][\s\x0b]*all\b
- **Is Chain**: False
- **Message**: SQL Injection Attack: SQL Operator Detected
- **Severity**: CRITICAL
- **Tags**: application-multi, language-multi, platform-multi, attack-sqli, paranoia-level/2, OWASP_CRS, OWASP_CRS/ATTACK-SQLI, capec/1000/152/248/66
- **Actions**: id:942120, phase:2, block, capture, t:none, t:utf8toUnicode, t:urlDecodeUni, msg:SQL Injection Attack: SQL Operator Detected, logdata:Matched Data: %{TX.0} found within %{MATCHED_VAR_NAME}: %{MATCHED_VAR}, tag:application-multi, tag:language-multi, tag:platform-multi, tag:attack-sqli, tag:paranoia-level/2, tag:OWASP_CRS, tag:OWASP_CRS/ATTACK-SQLI, tag:capec/1000/152/248/66, ver:OWASP_CRS/4.22.0-dev, severity:CRITICAL, setvar:tx.sql_injection_score=+%{tx.critical_anomaly_score}, setvar:tx.inbound_anomaly_score_pl2=+%{tx.critical_anomaly_score}

#### Rule 26: 942130
- **Phase**: 2
- **Variables**: ARGS_NAMES, ARGS, XML:/*
- **Operator**: @rx
- **Pattern**: (?i)[\s\x0b\"'-\)`]*?\b([0-9A-Z_a-z]+)\b[\s\x0b\"'-\)`]*?(?:=|<=>|(?:sounds[\s\x0b]+)?like|glob|r(?:like|egexp))[\s\x0b\"'-\)`]*?\b([0-9A-Z_a-z]+)\b
- **Is Chain**: True
- **Message**: SQL Injection Attack: SQL Boolean-based attack detected
- **Severity**: CRITICAL
- **Tags**: application-multi, language-multi, platform-multi, attack-sqli, paranoia-level/2, OWASP_CRS, OWASP_CRS/ATTACK-SQLI, capec/1000/152/248/66
- **Actions**: id:942130, phase:2, block, capture, t:none, t:urlDecodeUni, t:replaceComments, msg:SQL Injection Attack: SQL Boolean-based attack detected, logdata:Matched Data: %{TX.0} found within %{TX.942130_MATCHED_VAR_NAME}: %{MATCHED_VAR}, tag:application-multi, tag:language-multi, tag:platform-multi, tag:attack-sqli, tag:paranoia-level/2, tag:OWASP_CRS, tag:OWASP_CRS/ATTACK-SQLI, tag:capec/1000/152/248/66, ver:OWASP_CRS/4.22.0-dev, severity:CRITICAL, setvar:tx.942130_matched_var_name=%{matched_var_name}, chain

#### Rule 27: Unknown
- **Phase**: Unknown
- **Variables**: TX:1
- **Operator**: @streq
- **Pattern**: %{TX.2}
- **Is Chain**: False
- **Message**: 
- **Severity**: 
- **Actions**: t:none, setvar:tx.sql_injection_score=+%{tx.critical_anomaly_score}, setvar:tx.inbound_anomaly_score_pl2=+%{tx.critical_anomaly_score}

#### Rule 28: 942131
- **Phase**: 2
- **Variables**: ARGS_NAMES, ARGS, XML:/*
- **Operator**: @rx
- **Pattern**: (?i)[\s\x0b\"'-\)`]*?\b([0-9A-Z_a-z]+)\b[\s\x0b\"'-\)`]*?(?:![<->]|<[=>]?|>=?|\^|is[\s\x0b]+not|not[\s\x0b]+(?:like|r(?:like|egexp)))[\s\x0b\"'-\)`]*?\b([0-9A-Z_a-z]+)\b
- **Is Chain**: True
- **Message**: SQL Injection Attack: SQL Boolean-based attack detected
- **Severity**: CRITICAL
- **Tags**: application-multi, language-multi, platform-multi, attack-sqli, paranoia-level/2, OWASP_CRS, OWASP_CRS/ATTACK-SQLI, capec/1000/152/248/66
- **Actions**: id:942131, phase:2, block, capture, t:none, t:urlDecodeUni, t:replaceComments, msg:SQL Injection Attack: SQL Boolean-based attack detected, logdata:Matched Data: %{TX.0} found within %{TX.942131_MATCHED_VAR_NAME}: %{MATCHED_VAR}, tag:application-multi, tag:language-multi, tag:platform-multi, tag:attack-sqli, tag:paranoia-level/2, tag:OWASP_CRS, tag:OWASP_CRS/ATTACK-SQLI, tag:capec/1000/152/248/66, ver:OWASP_CRS/4.22.0-dev, severity:CRITICAL, multiMatch, setvar:tx.942131_matched_var_name=%{matched_var_name}, chain

#### Rule 29: Unknown
- **Phase**: Unknown
- **Variables**: TX:1
- **Operator**: !@streq
- **Pattern**: %{TX.2}
- **Is Chain**: False
- **Message**: 
- **Severity**: 
- **Actions**: t:none, setvar:tx.sql_injection_score=+%{tx.critical_anomaly_score}, setvar:tx.inbound_anomaly_score_pl2=+%{tx.critical_anomaly_score}

#### Rule 30: 942150
- **Phase**: 2
- **Variables**: REQUEST_COOKIES, REQUEST_COOKIES_NAMES, ARGS_NAMES, ARGS, XML:/*
- **Operator**: @rx
- **Pattern**: (?i)\b(?:json(?:_[0-9A-Z_a-z]+)?|a(?:bs|(?:cos|sin)h?|tan[2h]?|vg)|c(?:eil(?:ing)?|h(?:a(?:nges|r(?:set)?)|r)|o(?:alesce|sh?|unt)|ast)|d(?:e(?:grees|fault)|a(?:te|y))|exp|f(?:loor(?:avg)?|ormat|ield)|g(?:lob|roup_concat)|h(?:ex|our)|i(?:f(?:null)?|if|n(?:str)?)|l(?:ast(?:_insert_rowid)?|ength|ike(?:l(?:ihood|y))?|n|o(?:ad_extension|g(?:10|2)?|wer(?:pi)?|cal)|trim)|m(?:ax|in(?:ute)?|o(?:d|nth))|n(?:ullif|ow)|p(?:i|ow(?:er)?|rintf|assword)|quote|r(?:a(?:dians|ndom(?:blob)?)|e(?:p(?:lace|eat)|verse)|ound|trim|ight)|s(?:i(?:gn|nh?)|oundex|q(?:lite_(?:compileoption_(?:get|used)|offset|source_id|version)|rt)|u(?:bstr(?:ing)?|m)|econd|leep)|t(?:anh?|otal(?:_changes)?|r(?:im|unc)|ypeof|ime)|u(?:n(?:icode|likely)|(?:pp|s)er)|zeroblob|bin|v(?:alues|ersion)|week|year)[^0-9A-Z_a-z]*\(
- **Is Chain**: False
- **Message**: SQL Injection Attack: SQL function name detected
- **Severity**: CRITICAL
- **Tags**: application-multi, language-multi, platform-multi, attack-sqli, paranoia-level/2, OWASP_CRS, OWASP_CRS/ATTACK-SQLI, capec/1000/152/248/66
- **Actions**: id:942150, phase:2, block, capture, t:none, t:urlDecodeUni, msg:SQL Injection Attack: SQL function name detected, logdata:Matched Data: %{TX.0} found within %{MATCHED_VAR_NAME}: %{MATCHED_VAR}, tag:application-multi, tag:language-multi, tag:platform-multi, tag:attack-sqli, tag:paranoia-level/2, tag:OWASP_CRS, tag:OWASP_CRS/ATTACK-SQLI, tag:capec/1000/152/248/66, ver:OWASP_CRS/4.22.0-dev, severity:CRITICAL, setvar:tx.sql_injection_score=+%{tx.critical_anomaly_score}, setvar:tx.inbound_anomaly_score_pl2=+%{tx.critical_anomaly_score}

#### Rule 31: 942180
- **Phase**: 2
- **Variables**: REQUEST_COOKIES, REQUEST_COOKIES_NAMES, ARGS_NAMES, ARGS, XML:/*
- **Operator**: @rx
- **Pattern**: (?i)(?:/\*)+[\"'`]+[\s\x0b]?(?:--|[#\{]|/\*)?|[\"'`](?:[\s\x0b]*(?:(?:x?or|and|div|like|between)[\s\x0b\-0-9A-Z_a-z]+[\(\)\+-\-<->][\s\x0b]*[\"'0-9`]|[!=\|](?:[\s\x0b!\+\-0-9=]+[^\[]*[\"'\(`].*|[\s\x0b!0-9=]+[^0-9]*[0-9]+)$|(?:like|print)[^0-9A-Z_a-z]+[\"'\(0-9A-Z_-z]|;)|(?:[<>~]+|[\s\x0b]*[^\s\x0b0-9A-Z_a-z]?=[\s\x0b]*|[^0-9A-Z_a-z]*?[\+=]+[^0-9A-Z_a-z]*?)[\"'`])|[0-9][\"'`][\s\x0b]+[\"'`][\s\x0b]+[0-9]|^admin[\s\x0b]*?[\"'`]|[\s\x0b\"'\(`][\s\x0b]*?glob[^0-9A-Z_a-z]+[\"'\(0-9A-Z_-z]|[\s\x0b]is[\s\x0b]*?0[^0-9A-Z_a-z]|where[\s\x0b][\s\x0b,-\.0-9A-Z_a-z]+[\s\x0b]=
- **Is Chain**: False
- **Message**: Detects basic SQL authentication bypass attempts 1/3
- **Severity**: CRITICAL
- **Tags**: application-multi, language-multi, platform-multi, attack-sqli, paranoia-level/2, OWASP_CRS, OWASP_CRS/ATTACK-SQLI, capec/1000/152/248/66
- **Actions**: id:942180, phase:2, block, capture, t:none, t:urlDecodeUni, msg:Detects basic SQL authentication bypass attempts 1/3, logdata:Matched Data: %{TX.0} found within %{MATCHED_VAR_NAME}: %{MATCHED_VAR}, tag:application-multi, tag:language-multi, tag:platform-multi, tag:attack-sqli, tag:paranoia-level/2, tag:OWASP_CRS, tag:OWASP_CRS/ATTACK-SQLI, tag:capec/1000/152/248/66, ver:OWASP_CRS/4.22.0-dev, severity:CRITICAL, setvar:tx.sql_injection_score=+%{tx.critical_anomaly_score}, setvar:tx.inbound_anomaly_score_pl2=+%{tx.critical_anomaly_score}

#### Rule 32: 942200
- **Phase**: 2
- **Variables**: REQUEST_COOKIES, REQUEST_COOKIES_NAMES, REQUEST_HEADERS:User-Agent, REQUEST_HEADERS:Referer, ARGS_NAMES, ARGS, XML:/*
- **Operator**: @rx
- **Pattern**: (?i),.*?[\"'\)0-9`-f][\"'`](?:[\"'`].*?[\"'`]|(?:\r?\n)?\z|[^\"'`]+)|[^0-9A-Z_a-z]select.+[^0-9A-Z_a-z]*?from|(?:alter|(?:(?:cre|trunc|upd)at|renam)e|d(?:e(?:lete|sc)|rop)|(?:inser|selec)t|load)[\s\x0b]*?\([\s\x0b]*?space[\s\x0b]*?\(
- **Is Chain**: False
- **Message**: Detects MySQL comment-/space-obfuscated injections and backtick termination
- **Severity**: CRITICAL
- **Tags**: application-multi, language-multi, platform-multi, attack-sqli, paranoia-level/2, OWASP_CRS, OWASP_CRS/ATTACK-SQLI, capec/1000/152/248/66
- **Actions**: id:942200, phase:2, block, capture, t:none, t:urlDecodeUni, msg:Detects MySQL comment-/space-obfuscated injections and backtick termination, logdata:Matched Data: %{TX.0} found within %{MATCHED_VAR_NAME}: %{MATCHED_VAR}, tag:application-multi, tag:language-multi, tag:platform-multi, tag:attack-sqli, tag:paranoia-level/2, tag:OWASP_CRS, tag:OWASP_CRS/ATTACK-SQLI, tag:capec/1000/152/248/66, ver:OWASP_CRS/4.22.0-dev, severity:CRITICAL, setvar:tx.sql_injection_score=+%{tx.critical_anomaly_score}, setvar:tx.inbound_anomaly_score_pl2=+%{tx.critical_anomaly_score}

#### Rule 33: 942210
- **Phase**: 2
- **Variables**: REQUEST_COOKIES, REQUEST_COOKIES_NAMES, ARGS_NAMES, ARGS, XML:/*
- **Operator**: @rx
- **Pattern**: (?i)(?:&&|\|\||and|between|div|like|n(?:and|ot)|(?:xx?)?or)[\s\x0b\(]+[0-9A-Z_a-z]+[\s\x0b\)]*?[!\+=]+[\s\x0b0-9]*?[\"'-\)=`]|[0-9](?:[\s\x0b]*?(?:and|between|div|like|x?or)[\s\x0b]*?[0-9]+[\s\x0b]*?[\+\-]|[\s\x0b]+group[\s\x0b]+by.+\()|/[0-9A-Z_a-z]+;?[\s\x0b]+(?:and|between|div|having|like|x?or|select)[^0-9A-Z_a-z]|(?:[#;]|--)[\s\x0b]*?(?:alter|drop|(?:insert|update)[\s\x0b]*?[0-9A-Z_a-z]{2,})|@.+=[\s\x0b]*?\([\s\x0b]*?select|[^0-9A-Z_a-z]SET[\s\x0b]*?@[0-9A-Z_a-z]+
- **Is Chain**: False
- **Message**: Detects chained SQL injection attempts 1/2
- **Severity**: CRITICAL
- **Tags**: application-multi, language-multi, platform-multi, attack-sqli, paranoia-level/2, OWASP_CRS, OWASP_CRS/ATTACK-SQLI, capec/1000/152/248/66
- **Actions**: id:942210, phase:2, block, capture, t:none, t:urlDecodeUni, msg:Detects chained SQL injection attempts 1/2, logdata:Matched Data: %{TX.0} found within %{MATCHED_VAR_NAME}: %{MATCHED_VAR}, tag:application-multi, tag:language-multi, tag:platform-multi, tag:attack-sqli, tag:paranoia-level/2, tag:OWASP_CRS, tag:OWASP_CRS/ATTACK-SQLI, tag:capec/1000/152/248/66, ver:OWASP_CRS/4.22.0-dev, severity:CRITICAL, setvar:tx.sql_injection_score=+%{tx.critical_anomaly_score}, setvar:tx.inbound_anomaly_score_pl2=+%{tx.critical_anomaly_score}

#### Rule 34: 942260
- **Phase**: 2
- **Variables**: REQUEST_COOKIES, REQUEST_COOKIES_NAMES, ARGS_NAMES, ARGS, XML:/*
- **Operator**: @rx
- **Pattern**: (?i)[\"'`][\s\x0b]*?(?:(?:and|n(?:and|ot)|(?:xx?)?or|div|like|between|\|\||&&)[\s\x0b]+[\s\x0b0-9A-Z_a-z]+=[\s\x0b]*?[0-9A-Z_a-z]+[\s\x0b]*?having[\s\x0b]+|like[^0-9A-Z_a-z]*?[\"'0-9`])|[0-9A-Z_a-z][\s\x0b]+like[\s\x0b]+[\"'`]|like[\s\x0b]*?[\"'`]%|select[\s\x0b]+?[\s\x0b\"'-\),-\.0-9A-\[\]_-z]+from[\s\x0b]+
- **Is Chain**: False
- **Message**: Detects basic SQL authentication bypass attempts 2/3
- **Severity**: CRITICAL
- **Tags**: application-multi, language-multi, platform-multi, attack-sqli, paranoia-level/2, OWASP_CRS, OWASP_CRS/ATTACK-SQLI, capec/1000/152/248/66
- **Actions**: id:942260, phase:2, block, capture, t:none, t:urlDecodeUni, msg:Detects basic SQL authentication bypass attempts 2/3, logdata:Matched Data: %{TX.0} found within %{MATCHED_VAR_NAME}: %{MATCHED_VAR}, tag:application-multi, tag:language-multi, tag:platform-multi, tag:attack-sqli, tag:paranoia-level/2, tag:OWASP_CRS, tag:OWASP_CRS/ATTACK-SQLI, tag:capec/1000/152/248/66, ver:OWASP_CRS/4.22.0-dev, severity:CRITICAL, setvar:tx.sql_injection_score=+%{tx.critical_anomaly_score}, setvar:tx.inbound_anomaly_score_pl2=+%{tx.critical_anomaly_score}

#### Rule 35: 942300
- **Phase**: 2
- **Variables**: REQUEST_COOKIES, REQUEST_COOKIES_NAMES, ARGS_NAMES, ARGS, XML:/*
- **Operator**: @rx
- **Pattern**: (?i)\)[\s\x0b]*?when[\s\x0b]*?[0-9]+[\s\x0b]*?then|[\"'`][\s\x0b]*?(?:[#\{]|--)|/\*![\s\x0b]?[0-9]+|\b(?:(?:binary|cha?r)[\s\x0b]*?\([\s\x0b]*?[0-9]|(?:and|n(?:and|ot)|(?:xx?)?or|div|like|between|r(?:egexp|like))[\s\x0b]+[0-9A-Z_a-z]+\()|(?:\|\||&&)[\s\x0b]*?[0-9A-Z_a-z]+\(
- **Is Chain**: False
- **Message**: Detects MySQL comments, conditions and ch(a)r injections
- **Severity**: CRITICAL
- **Tags**: application-multi, language-multi, platform-multi, attack-sqli, paranoia-level/2, OWASP_CRS, OWASP_CRS/ATTACK-SQLI, capec/1000/152/248/66
- **Actions**: id:942300, phase:2, block, capture, t:none, t:urlDecodeUni, msg:Detects MySQL comments, conditions and ch(a)r injections, logdata:Matched Data: %{TX.0} found within %{MATCHED_VAR_NAME}: %{MATCHED_VAR}, tag:application-multi, tag:language-multi, tag:platform-multi, tag:attack-sqli, tag:paranoia-level/2, tag:OWASP_CRS, tag:OWASP_CRS/ATTACK-SQLI, tag:capec/1000/152/248/66, ver:OWASP_CRS/4.22.0-dev, severity:CRITICAL, setvar:tx.sql_injection_score=+%{tx.critical_anomaly_score}, setvar:tx.inbound_anomaly_score_pl2=+%{tx.critical_anomaly_score}

#### Rule 36: 942310
- **Phase**: 2
- **Variables**: REQUEST_COOKIES, REQUEST_COOKIES_NAMES, ARGS_NAMES, ARGS, XML:/*
- **Operator**: @rx
- **Pattern**: (?i)(?:\([\s\x0b]*?select[\s\x0b]*?[0-9A-Z_a-z]+|coalesce|order[\s\x0b]+by[\s\x0b]+if[0-9A-Z_a-z]*?)[\s\x0b]*?\(|\*/from|\+[\s\x0b]*?[0-9]+[\s\x0b]*?\+[\s\x0b]*?@|[0-9A-Z_a-z][\"'`][\s\x0b]*?(?:(?:[\+\-=@\|]+[\s\x0b]+?)+|[\+\-=@\|]+)[\(0-9]|@@[0-9A-Z_a-z]+[\s\x0b]*?[^\s\x0b0-9A-Z_a-z]|[^0-9A-Z_a-z]!+[\"'`][0-9A-Z_a-z]|[\"'`](?:;[\s\x0b]*?(?:if|while|begin)|[\s\x0b0-9]+=[\s\x0b]*?[0-9])|[\s\x0b\(]+case[0-9]*?[^0-9A-Z_a-z].+[tw]hen[\s\x0b\(]
- **Is Chain**: False
- **Message**: Detects chained SQL injection attempts 2/2
- **Severity**: CRITICAL
- **Tags**: application-multi, language-multi, platform-multi, attack-sqli, paranoia-level/2, OWASP_CRS, OWASP_CRS/ATTACK-SQLI, capec/1000/152/248/66
- **Actions**: id:942310, phase:2, block, capture, t:none, t:urlDecodeUni, msg:Detects chained SQL injection attempts 2/2, logdata:Matched Data: %{TX.0} found within %{MATCHED_VAR_NAME}: %{MATCHED_VAR}, tag:application-multi, tag:language-multi, tag:platform-multi, tag:attack-sqli, tag:paranoia-level/2, tag:OWASP_CRS, tag:OWASP_CRS/ATTACK-SQLI, tag:capec/1000/152/248/66, ver:OWASP_CRS/4.22.0-dev, severity:CRITICAL, setvar:tx.sql_injection_score=+%{tx.critical_anomaly_score}, setvar:tx.inbound_anomaly_score_pl2=+%{tx.critical_anomaly_score}

#### Rule 37: 942330
- **Phase**: 2
- **Variables**: REQUEST_COOKIES, REQUEST_COOKIES_NAMES, ARGS_NAMES, ARGS, XML:/*
- **Operator**: @rx
- **Pattern**: (?i)[\"'`][\s\x0b]*?\b(?:x?or|div|like|between|and)\b[\s\x0b]*?[\"'`]?[0-9]|\x5cx(?:2[37]|3d)|^(?:.?[\"'`]$|[\"'\x5c`]*?(?:[\"'0-9`]+|[^\"'`]+[\"'`])[\s\x0b]*?\b(?:and|n(?:and|ot)|(?:xx?)?or|div|like|between|\|\||&&)\b[\s\x0b]*?[\"'0-9A-Z_-z][!&\(\)\+-\.@])|[^\s\x0b0-9A-Z_a-z][0-9A-Z_a-z]+[\s\x0b]*?[\-\|][\s\x0b]*?[\"'`][\s\x0b]*?[0-9A-Z_a-z]|@(?:[0-9A-Z_a-z]+[\s\x0b]+(?:and|x?or|div|like|between)\b[\s\x0b]*?[\"'0-9`]+|[\-0-9A-Z_a-z]+[\s\x0b](?:and|x?or|div|like|between)\b[\s\x0b]*?[^\s\x0b0-9A-Z_a-z])|[^\s\x0b0-:A-Z_a-z][\s\x0b]*?[0-9][^0-9A-Z_a-z]+[^\s\x0b0-9A-Z_a-z][\s\x0b]*?[\"'`].|[^0-9A-Z_a-z]information_schema|table_name[^0-9A-Z_a-z]
- **Is Chain**: False
- **Message**: Detects classic SQL injection probings 1/3
- **Severity**: CRITICAL
- **Tags**: application-multi, language-multi, platform-multi, attack-sqli, paranoia-level/2, OWASP_CRS, OWASP_CRS/ATTACK-SQLI, capec/1000/152/248/66
- **Actions**: id:942330, phase:2, block, capture, t:none, t:urlDecodeUni, msg:Detects classic SQL injection probings 1/3, logdata:Matched Data: %{TX.0} found within %{MATCHED_VAR_NAME}: %{MATCHED_VAR}, tag:application-multi, tag:language-multi, tag:platform-multi, tag:attack-sqli, tag:paranoia-level/2, tag:OWASP_CRS, tag:OWASP_CRS/ATTACK-SQLI, tag:capec/1000/152/248/66, ver:OWASP_CRS/4.22.0-dev, severity:CRITICAL, setvar:tx.sql_injection_score=+%{tx.critical_anomaly_score}, setvar:tx.inbound_anomaly_score_pl2=+%{tx.critical_anomaly_score}

#### Rule 38: 942340
- **Phase**: 2
- **Variables**: REQUEST_COOKIES, REQUEST_COOKIES_NAMES, ARGS_NAMES, ARGS, XML:/*
- **Operator**: @rx
- **Pattern**: (?i)in[\s\x0b]*?\(+[\s\x0b]*?select|(?:(?:and|n(?:and|ot)|(?:xx?)?or|div|like|between)[\s\x0b]+|(?:\|\||&&)[\s\x0b]*?)[\s\x0b\+0-9A-Z_a-z]+(?:regexp[\s\x0b]*?\(|sounds[\s\x0b]+like[\s\x0b]*?[\"'`]|[0-9=]+x)|[\"'`](?:[\s\x0b]*?(?:(?:[0-9]+[\s\x0b]*?(?:--|#)|is[\s\x0b]*?(?:[0-9][^\"'`]+[\"'`]?[0-9A-Z_a-z]|[\.0-9]+[\s\x0b]*?[^0-9A-Z_a-z][^\"'`]*[\"'`])|(?:and|n(?:and|ot)|(?:xx?)?or|div|like|between)[\s\x0b]+|(?:\|\||&&)[\s\x0b]*?)(?:array[\s\x0b]*?\[|(?:tru|fals)e\b|[0-9A-Z_a-z]+(?:[\s\x0b]*?!?~|[\s\x0b]+(?:not[\s\x0b]+)?similar[\s\x0b]+to[\s\x0b]+))|[%&<->\^]+[0-9]+[\s\x0b]*?(?:and|n(?:and|ot)|(?:xx?)?or|div|like|between)=)|(?:[^0-9A-Z_a-z]+[\+\-0-9A-Z_a-z]+[\s\x0b]*?=[\s\x0b]*?[0-9][^0-9A-Z_a-z]+|\|?[\-0-9A-Z_a-z]{3,}[^\s\x0b,\.0-9A-Z_a-z]+)[\"'`])|\bexcept[\s\x0b]+(?:select\b|values[\s\x0b]*?\()
- **Is Chain**: False
- **Message**: Detects basic SQL authentication bypass attempts 3/3
- **Severity**: CRITICAL
- **Tags**: application-multi, language-multi, platform-multi, attack-sqli, paranoia-level/2, OWASP_CRS, OWASP_CRS/ATTACK-SQLI, capec/1000/152/248/66
- **Actions**: id:942340, phase:2, block, capture, t:none, t:urlDecodeUni, msg:Detects basic SQL authentication bypass attempts 3/3, logdata:Matched Data: %{TX.0} found within %{MATCHED_VAR_NAME}: %{MATCHED_VAR}, tag:application-multi, tag:language-multi, tag:platform-multi, tag:attack-sqli, tag:paranoia-level/2, tag:OWASP_CRS, tag:OWASP_CRS/ATTACK-SQLI, tag:capec/1000/152/248/66, ver:OWASP_CRS/4.22.0-dev, severity:CRITICAL, setvar:tx.sql_injection_score=+%{tx.critical_anomaly_score}, setvar:tx.inbound_anomaly_score_pl2=+%{tx.critical_anomaly_score}

#### Rule 39: 942361
- **Phase**: 2
- **Variables**: REQUEST_COOKIES, REQUEST_COOKIES_NAMES, ARGS_NAMES, ARGS, XML:/*
- **Operator**: @rx
- **Pattern**: (?i:^[\W\d]+\s*?(?:alter|union)\b)
- **Is Chain**: False
- **Message**: Detects basic SQL injection based on keyword alter or union
- **Severity**: CRITICAL
- **Tags**: application-multi, language-multi, platform-multi, attack-sqli, paranoia-level/2, OWASP_CRS, OWASP_CRS/ATTACK-SQLI, capec/1000/152/248/66
- **Actions**: id:942361, phase:2, block, capture, t:none, t:urlDecodeUni, msg:Detects basic SQL injection based on keyword alter or union, logdata:Matched Data: %{TX.0} found within %{MATCHED_VAR_NAME}: %{MATCHED_VAR}, tag:application-multi, tag:language-multi, tag:platform-multi, tag:attack-sqli, tag:paranoia-level/2, tag:OWASP_CRS, tag:OWASP_CRS/ATTACK-SQLI, tag:capec/1000/152/248/66, ver:OWASP_CRS/4.22.0-dev, severity:CRITICAL, setvar:tx.sql_injection_score=+%{tx.critical_anomaly_score}, setvar:tx.inbound_anomaly_score_pl2=+%{tx.critical_anomaly_score}

#### Rule 40: 942362
- **Phase**: 2
- **Variables**: REQUEST_COOKIES, REQUEST_COOKIES_NAMES, ARGS_NAMES, ARGS, XML:/*
- **Operator**: @rx
- **Pattern**: (?i)(?:alter|(?:(?:cre|trunc|upd)at|renam)e|de(?:lete|sc)|(?:inser|selec)t|load)[\s\x0b]+(?:char|group_concat|load_file)[\s\x0b]?\(?|end[\s\x0b]*?\);|[\s\x0b\(]load_file[\s\x0b]*?\(|[\"'`][\s\x0b]+regexp[^0-9A-Z_a-z]|[^A-Z_a-z][\s\x0b]+as\b[\s\x0b]*[\"'0-9A-Z_-z]+[\s\x0b]*\bfrom|^[^A-Z_a-z]+[\s\x0b]*?(?:create[\s\x0b]+[0-9A-Z_a-z]+|(?:d(?:e(?:lete|sc)|rop)|(?:inser|selec)t|load|(?:renam|truncat)e|u(?:pdate|nion[\s\x0b]*(?:all|(?:sele|distin)ct))|alter[\s\x0b]*(?:a(?:(?:ggregat|pplication[\s\x0b]*rol)e|s(?:sembl|ymmetric[\s\x0b]*ke)y|u(?:dit|thorization)|vailability[\s\x0b]*group)|b(?:roker[\s\x0b]*priority|ufferpool)|c(?:ertificate|luster|o(?:l(?:latio|um)|nversio)n|r(?:edential|yptographic[\s\x0b]*provider))|d(?:atabase|efault|i(?:mension|skgroup)|omain)|e(?:(?:ndpoi|ve)nt|xte(?:nsion|rnal))|f(?:lashback|oreign|u(?:lltext|nction))|hi(?:erarchy|stogram)|group|in(?:dex(?:type)?|memory|stance)|java|l(?:a(?:ngua|r)ge|ibrary|o(?:ckdown|g(?:file[\s\x0b]*group|in)))|m(?:a(?:s(?:k|ter[\s\x0b]*key)|terialized)|e(?:ssage[\s\x0b]*type|thod)|odule)|(?:nicknam|queu)e|o(?:perator|utline)|p(?:a(?:ckage|rtition)|ermission|ro(?:cedur|fil)e)|r(?:e(?:mot|sourc)e|o(?:l(?:e|lback)|ute))|s(?:chema|e(?:arch|curity|rv(?:er|ice)|quence|ssion)|y(?:mmetric[\s\x0b]*key|nonym)|togroup)|t(?:able(?:space)?|ext|hreshold|r(?:igger|usted)|ype)|us(?:age|er)|view|w(?:ork(?:load)?|rapper)|x(?:ml[\s\x0b]*schema|srobject)))\b)
- **Is Chain**: False
- **Message**: Detects concatenated basic SQL injection and SQLLFI attempts
- **Severity**: CRITICAL
- **Tags**: application-multi, language-multi, platform-multi, attack-sqli, paranoia-level/2, OWASP_CRS, OWASP_CRS/ATTACK-SQLI, capec/1000/152/248/66
- **Actions**: id:942362, phase:2, block, capture, t:none, t:urlDecodeUni, msg:Detects concatenated basic SQL injection and SQLLFI attempts, logdata:Matched Data: %{TX.0} found within %{MATCHED_VAR_NAME}: %{MATCHED_VAR}, tag:application-multi, tag:language-multi, tag:platform-multi, tag:attack-sqli, tag:paranoia-level/2, tag:OWASP_CRS, tag:OWASP_CRS/ATTACK-SQLI, tag:capec/1000/152/248/66, ver:OWASP_CRS/4.22.0-dev, severity:CRITICAL, setvar:tx.sql_injection_score=+%{tx.critical_anomaly_score}, setvar:tx.inbound_anomaly_score_pl2=+%{tx.critical_anomaly_score}

#### Rule 41: 942370
- **Phase**: 2
- **Variables**: REQUEST_COOKIES, REQUEST_COOKIES_NAMES, REQUEST_HEADERS:Referer, REQUEST_HEADERS:User-Agent, ARGS_NAMES, ARGS, XML:/*
- **Operator**: @rx
- **Pattern**: (?i)[\"'`](?:[\s\x0b]*?(?:(?:\*.+(?:x?or|div|like|between|(?:an|i)d)[^0-9A-Z_a-z]*?[\"'`]|(?:x?or|div|like|between|and)[\s\x0b][^0-9]+[\-0-9A-Z_a-z]+[^0-9]*)[0-9]|[^\s\x0b0-9\?A-Z_a-z]+[\s\x0b]*?[^\s\x0b0-9A-Z_a-z]+[\s\x0b]*?[\"'`]|[^\s\x0b0-9A-Z_a-z]+[\s\x0b]*?[^A-Z_a-z](?:[^#]*#|.*?--))|[^\*]*\*[\s\x0b]*?[0-9])|\^[\"'`]|[%\(-\+\-<>][\-0-9A-Z_a-z]+[^\s\x0b0-9A-Z_a-z]+[\"'`][^,]
- **Is Chain**: False
- **Message**: Detects classic SQL injection probings 2/3
- **Severity**: CRITICAL
- **Tags**: application-multi, language-multi, platform-multi, attack-sqli, paranoia-level/2, OWASP_CRS, OWASP_CRS/ATTACK-SQLI, capec/1000/152/248/66
- **Actions**: id:942370, phase:2, block, capture, t:none, t:urlDecodeUni, msg:Detects classic SQL injection probings 2/3, logdata:Matched Data: %{TX.0} found within %{MATCHED_VAR_NAME}: %{MATCHED_VAR}, tag:application-multi, tag:language-multi, tag:platform-multi, tag:attack-sqli, tag:paranoia-level/2, tag:OWASP_CRS, tag:OWASP_CRS/ATTACK-SQLI, tag:capec/1000/152/248/66, ver:OWASP_CRS/4.22.0-dev, severity:CRITICAL, setvar:tx.sql_injection_score=+%{tx.critical_anomaly_score}, setvar:tx.inbound_anomaly_score_pl2=+%{tx.critical_anomaly_score}

#### Rule 42: 942380
- **Phase**: 2
- **Variables**: REQUEST_COOKIES, REQUEST_COOKIES:/_pk_ref/, REQUEST_COOKIES_NAMES, ARGS_NAMES, ARGS, XML:/*
- **Operator**: @rx
- **Pattern**: (?i)\b(?:having\b(?:[\s\x0b]+(?:[0-9]{1,10}|'[^=]{1,10}')[\s\x0b]*?[<->]| ?(?:[0-9]{1,10} ?[<->]+|[\"'][^=]{1,10}[ \"'<-\?\[]+))|ex(?:ecute(?:\(|[\s\x0b]{1,5}[\$\.0-9A-Z_a-z]{1,5}[\s\x0b]{0,3})|ists[\s\x0b]*?\([\s\x0b]*?select\b)|(?:create[\s\x0b]+?table.{0,20}?|like[^0-9A-Z_a-z]*?char[^0-9A-Z_a-z]*?)\()|select.*?case|from.*?limit|order[\s\x0b]by|exists[\s\x0b](?:[\s\x0b]select|s(?:elect[^\s\x0b](?:if(?:null)?[\s\x0b]\(|top|concat)|ystem[\s\x0b]\()|\bhaving\b[\s\x0b]+[0-9]{1,10}|'[^=]{1,10}')
- **Is Chain**: False
- **Message**: SQL Injection Attack
- **Severity**: CRITICAL
- **Tags**: application-multi, language-multi, platform-multi, attack-sqli, paranoia-level/2, OWASP_CRS, OWASP_CRS/ATTACK-SQLI, capec/1000/152/248/66
- **Actions**: id:942380, phase:2, block, capture, t:none, t:urlDecodeUni, msg:SQL Injection Attack, logdata:Matched Data: %{TX.0} found within %{MATCHED_VAR_NAME}: %{MATCHED_VAR}, tag:application-multi, tag:language-multi, tag:platform-multi, tag:attack-sqli, tag:paranoia-level/2, tag:OWASP_CRS, tag:OWASP_CRS/ATTACK-SQLI, tag:capec/1000/152/248/66, ver:OWASP_CRS/4.22.0-dev, severity:CRITICAL, setvar:tx.sql_injection_score=+%{tx.critical_anomaly_score}, setvar:tx.inbound_anomaly_score_pl2=+%{tx.critical_anomaly_score}

#### Rule 43: 942390
- **Phase**: 2
- **Variables**: REQUEST_COOKIES, REQUEST_COOKIES:/_pk_ref/, REQUEST_COOKIES_NAMES, ARGS_NAMES, ARGS, XML:/*
- **Operator**: @rx
- **Pattern**: (?i)\b(?:or\b(?:[\s\x0b]?(?:[0-9]{1,10}|[\"'][^=]{1,10}[\"'])[\s\x0b]?[<->]+|[\s\x0b]+(?:[0-9]{1,10}|'[^=]{1,10}')(?:[\s\x0b]*?[<->])?)|xor\b[\s\x0b]+(?:[0-9]{1,10}|'[^=]{1,10}')(?:[\s\x0b]*?[<->])?)|'[\s\x0b]+x?or[\s\x0b]+.{1,20}[!\+\-<->]
- **Is Chain**: False
- **Message**: SQL Injection Attack
- **Severity**: CRITICAL
- **Tags**: application-multi, language-multi, platform-multi, attack-sqli, paranoia-level/2, OWASP_CRS, OWASP_CRS/ATTACK-SQLI, capec/1000/152/248/66
- **Actions**: id:942390, phase:2, block, capture, t:none, t:urlDecodeUni, msg:SQL Injection Attack, logdata:Matched Data: %{TX.0} found within %{MATCHED_VAR_NAME}: %{MATCHED_VAR}, tag:application-multi, tag:language-multi, tag:platform-multi, tag:attack-sqli, tag:paranoia-level/2, tag:OWASP_CRS, tag:OWASP_CRS/ATTACK-SQLI, tag:capec/1000/152/248/66, ver:OWASP_CRS/4.22.0-dev, severity:CRITICAL, setvar:tx.sql_injection_score=+%{tx.critical_anomaly_score}, setvar:tx.inbound_anomaly_score_pl2=+%{tx.critical_anomaly_score}

#### Rule 44: 942400
- **Phase**: 2
- **Variables**: REQUEST_COOKIES, REQUEST_COOKIES:/_pk_ref/, REQUEST_COOKIES_NAMES, ARGS_NAMES, ARGS, XML:/*
- **Operator**: @rx
- **Pattern**: (?i)\band\b(?:[\s\x0b]+(?:[0-9]{1,10}[\s\x0b]*?[<->]|'[^=]{1,10}')| ?(?:[0-9]{1,10}|[\"'][^=]{1,10}[\"']) ?[<->]+)
- **Is Chain**: False
- **Message**: SQL Injection Attack
- **Severity**: CRITICAL
- **Tags**: application-multi, language-multi, platform-multi, attack-sqli, paranoia-level/2, OWASP_CRS, OWASP_CRS/ATTACK-SQLI, capec/1000/152/248/66
- **Actions**: id:942400, phase:2, block, capture, t:none, t:urlDecodeUni, msg:SQL Injection Attack, logdata:Matched Data: %{TX.0} found within %{MATCHED_VAR_NAME}: %{MATCHED_VAR}, tag:application-multi, tag:language-multi, tag:platform-multi, tag:attack-sqli, tag:paranoia-level/2, tag:OWASP_CRS, tag:OWASP_CRS/ATTACK-SQLI, tag:capec/1000/152/248/66, ver:OWASP_CRS/4.22.0-dev, severity:CRITICAL, setvar:tx.sql_injection_score=+%{tx.critical_anomaly_score}, setvar:tx.inbound_anomaly_score_pl2=+%{tx.critical_anomaly_score}

#### Rule 45: 942410
- **Phase**: 2
- **Variables**: REQUEST_COOKIES, REQUEST_COOKIES:/_pk_ref/, REQUEST_COOKIES_NAMES, ARGS_NAMES, ARGS, XML:/*
- **Operator**: @rx
- **Pattern**: (?i)\b(?:a(?:(?:b|co)s|dd(?:dat|tim)e|es_(?:de|en)crypt|s(?:in|cii(?:str)?)|tan2?|vg)|b(?:enchmark|i(?:n(?:_to_num)?|t_(?:and|count|length|x?or)))|c(?:ast|h(?:ar(?:(?:acter)?_length|set)?|r)|iel(?:ing)?|o(?:alesce|ercibility|(?:mpres)?s|n(?:cat(?:_ws)?|nection_id|v(?:ert(?:_tz)?)?)|(?:un)?t)|r32|ur(?:(?:dat|tim)e|rent_(?:date|time(?:stamp)?|user)))|d(?:a(?:t(?:abase|e(?:_(?:add|format|sub)|diff)?)|y(?:name|of(?:month|week|year))?)|count|e(?:code|(?:faul|s_(?:de|en)cryp)t|grees)|ump)|e(?:lt|nc(?:ode|rypt)|x(?:p(?:ort_set)?|tract(?:value)?))|f(?:i(?:eld(?:_in_set)?|nd_in_set)|loor|o(?:rmat|und_rows)|rom_(?:base64|days|unixtime))|g(?:et_(?:format|lock)|r(?:eates|oup_conca)t)|h(?:ex(?:toraw)?|our)|i(?:f(?:null)?|n(?:et6?_(?:aton|ntoa)|s(?:ert|tr)|terval)?|s(?:_(?:(?:free|used)_lock|ipv(?:4(?:_(?:compat|mapped))?|6)|n(?:ot(?:_null)?|ull))|null)?)|l(?:ast(?:_(?:day|insert_id))?|case|e(?:(?:as|f)t|ngth)|n|o(?:ad_file|ca(?:l(?:timestamp)?|te)|g(?:10|2)?|wer)|pad|trim)|m(?:a(?:ke(?:date|_set)|ster_pos_wait|x)|d5|i(?:(?:crosecon)?d|n(?:ute)?)|o(?:d|nth(?:name)?))|n(?:ame_const|o(?:t_in|w)|ullif)|o(?:ct(?:et_length)?|(?:ld_passwo)?rd)|p(?:assword|eriod_(?:add|diff)|g_sleep|i|o(?:sition|w(?:er)?)|rocedure_analyse)|qu(?:arter|ote)|r(?:a(?:dians|nd|wto(?:hex|nhex(?:toraw)?))|e(?:lease_lock|p(?:eat|lace)|verse)|ight|o(?:und|w_count)|pad|trim)|s(?:chema|e(?:c(?:ond|_to_time)|ssion_user)|ha[12]?|ig?n|leep|oundex|pace|qrt|t(?:d(?:dev(?:_(?:po|sam)p)?)?|r(?:cmp|_to_date))|u(?:b(?:(?:dat|tim)e|str(?:ing(?:_index)?)?)|m)|ys(?:date|tem_user))|t(?:an|ime(?:diff|_(?:format|to_sec)|stamp(?:add|diff)?)?|o_(?:base64|n?char|(?:day|second)s)|r(?:im|uncate))|u(?:case|n(?:compress(?:ed_length)?|hex|ix_timestamp)|p(?:datexml|per)|ser|tc_(?:date|time(?:stamp)?)|uid(?:_short)?)|v(?:a(?:lues|r(?:iance|_(?:po|sam)p))|ersion)|we(?:ek(?:day|ofyear)?|ight_string)|xmltype|year(?:week)?)[^0-9A-Z_a-z]*?\(
- **Is Chain**: False
- **Message**: SQL Injection Attack
- **Severity**: CRITICAL
- **Tags**: application-multi, language-multi, platform-multi, attack-sqli, paranoia-level/2, OWASP_CRS, OWASP_CRS/ATTACK-SQLI, capec/1000/152/248/66
- **Actions**: id:942410, phase:2, block, capture, t:none, t:urlDecodeUni, msg:SQL Injection Attack, logdata:Matched Data: %{TX.0} found within %{MATCHED_VAR_NAME}: %{MATCHED_VAR}, tag:application-multi, tag:language-multi, tag:platform-multi, tag:attack-sqli, tag:paranoia-level/2, tag:OWASP_CRS, tag:OWASP_CRS/ATTACK-SQLI, tag:capec/1000/152/248/66, ver:OWASP_CRS/4.22.0-dev, severity:CRITICAL, setvar:tx.sql_injection_score=+%{tx.critical_anomaly_score}, setvar:tx.inbound_anomaly_score_pl2=+%{tx.critical_anomaly_score}

#### Rule 46: 942470
- **Phase**: 2
- **Variables**: REQUEST_COOKIES, REQUEST_COOKIES:/_pk_ref/, REQUEST_COOKIES_NAMES, ARGS_NAMES, ARGS, XML:/*
- **Operator**: @rx
- **Pattern**: (?i)autonomous_transaction|(?:current_use|n?varcha|tbcreato)r|db(?:a_users|ms_java)|open(?:owa_util|query|rowset)|s(?:p_(?:(?:addextendedpro|sqlexe)c|execute(?:sql)?|help|is_srvrolemember|makewebtask|oacreate|p(?:assword|repare)|replwritetovarbin)|ql_(?:longvarchar|variant))|utl_(?:file|http)|xp_(?:availablemedia|(?:cmdshel|servicecontro)l|dirtree|e(?:numdsn|xecresultset)|filelist|loginconfig|makecab|ntsec(?:_enumdomains)?|reg(?:addmultistring|delete(?:key|value)|enum(?:key|value)s|re(?:ad|movemultistring)|write)|terminate(?:_process)?)
- **Is Chain**: False
- **Message**: SQL Injection Attack
- **Severity**: CRITICAL
- **Tags**: application-multi, language-multi, platform-multi, attack-sqli, paranoia-level/2, OWASP_CRS, OWASP_CRS/ATTACK-SQLI, capec/1000/152/248/66
- **Actions**: id:942470, phase:2, block, capture, t:none, t:urlDecodeUni, msg:SQL Injection Attack, logdata:Matched Data: %{TX.0} found within %{MATCHED_VAR_NAME}: %{MATCHED_VAR}, tag:application-multi, tag:language-multi, tag:platform-multi, tag:attack-sqli, tag:paranoia-level/2, tag:OWASP_CRS, tag:OWASP_CRS/ATTACK-SQLI, tag:capec/1000/152/248/66, ver:OWASP_CRS/4.22.0-dev, severity:CRITICAL, setvar:tx.sql_injection_score=+%{tx.critical_anomaly_score}, setvar:tx.inbound_anomaly_score_pl2=+%{tx.critical_anomaly_score}

#### Rule 47: 942480
- **Phase**: 2
- **Variables**: REQUEST_COOKIES, REQUEST_COOKIES:/_pk_ref/, REQUEST_COOKIES_NAMES, REQUEST_HEADERS, ARGS_NAMES, ARGS, XML:/*
- **Operator**: @rx
- **Pattern**: (?i)\b(?:(?:d(?:bms_[0-9A-Z_a-z]+\.|elete\b[^0-9A-Z_a-z]*?\bfrom)|(?:group\b.*?\bby\b.{1,100}?\bhav|overlay\b[^0-9A-Z_a-z]*?\(.*?\b[^0-9A-Z_a-z]*?plac)ing|in(?:ner\b[^0-9A-Z_a-z]*?\bjoin|sert\b[^0-9A-Z_a-z]*?\binto|to\b[^0-9A-Z_a-z]*?\b(?:dump|out)file)|load\b[^0-9A-Z_a-z]*?\bdata\b.*?\binfile|s(?:elect\b.{1,100}?\b(?:(?:.*?\bdump\b.*|(?:count|length)\b.{1,100}?)\bfrom|(?:data_typ|from\b.{1,100}?\bwher)e|instr|to(?:_(?:cha|numbe)r|p\b.{1,100}?\bfrom))|ys_context)|u(?:nion\b.{1,100}?\bselect|tl_inaddr))\b|print\b[^0-9A-Z_a-z]*?@@)|(?:collation[^0-9A-Z_a-z]*?\(a|@@version|;[^0-9A-Z_a-z]*?\b(?:drop|shutdown))\b|'(?:dbo|msdasql|s(?:a|qloledb))'
- **Is Chain**: False
- **Message**: SQL Injection Attack
- **Severity**: CRITICAL
- **Tags**: application-multi, language-multi, platform-multi, attack-sqli, paranoia-level/2, OWASP_CRS, OWASP_CRS/ATTACK-SQLI, capec/1000/152/248/66
- **Actions**: id:942480, phase:2, block, capture, t:none, t:urlDecodeUni, msg:SQL Injection Attack, logdata:Matched Data: %{TX.0} found within %{MATCHED_VAR_NAME}: %{MATCHED_VAR}, tag:application-multi, tag:language-multi, tag:platform-multi, tag:attack-sqli, tag:paranoia-level/2, tag:OWASP_CRS, tag:OWASP_CRS/ATTACK-SQLI, tag:capec/1000/152/248/66, ver:OWASP_CRS/4.22.0-dev, severity:CRITICAL, setvar:tx.sql_injection_score=+%{tx.critical_anomaly_score}, setvar:tx.inbound_anomaly_score_pl2=+%{tx.critical_anomaly_score}

#### Rule 48: 942430
- **Phase**: 2
- **Variables**: ARGS_NAMES, ARGS, XML:/*
- **Operator**: @rx
- **Pattern**: ((?:[~!@#\$%\^&\*\(\)\-\+=\{\}\[\]\|:;\"'´’‘`<>][^~!@#\$%\^&\*\(\)\-\+=\{\}\[\]\|:;\"'´’‘`<>]*?){12})
- **Is Chain**: False
- **Message**: Restricted SQL Character Anomaly Detection (args): # of special characters exceeded (12)
- **Severity**: WARNING
- **Tags**: application-multi, language-multi, platform-multi, attack-sqli, paranoia-level/2, OWASP_CRS, OWASP_CRS/ATTACK-SQLI, capec/1000/152/248/66
- **Actions**: id:942430, phase:2, block, capture, t:none, t:urlDecodeUni, msg:Restricted SQL Character Anomaly Detection (args): # of special characters exceeded (12), logdata:Matched Data: %{TX.1} found within %{MATCHED_VAR_NAME}: %{MATCHED_VAR}, tag:application-multi, tag:language-multi, tag:platform-multi, tag:attack-sqli, tag:paranoia-level/2, tag:OWASP_CRS, tag:OWASP_CRS/ATTACK-SQLI, tag:capec/1000/152/248/66, ver:OWASP_CRS/4.22.0-dev, severity:WARNING, setvar:tx.inbound_anomaly_score_pl2=+%{tx.warning_anomaly_score}, setvar:tx.sql_injection_score=+%{tx.warning_anomaly_score}

#### Rule 49: 942440
- **Phase**: 2
- **Variables**: REQUEST_COOKIES, REQUEST_COOKIES:/_pk_ref/, REQUEST_COOKIES_NAMES, ARGS_NAMES, ARGS, XML:/*
- **Operator**: @rx
- **Pattern**: /\*!?|\*/|[';]--|--(?:[\s\x0b]|[^\-]*?-)|[^&\-]#.*?[\s\x0b]|;?\x00
- **Is Chain**: True
- **Message**: SQL Comment Sequence Detected
- **Severity**: CRITICAL
- **Tags**: application-multi, language-multi, platform-multi, attack-sqli, paranoia-level/2, OWASP_CRS, OWASP_CRS/ATTACK-SQLI, capec/1000/152/248/66
- **Actions**: id:942440, phase:2, block, capture, t:none, t:urlDecodeUni, msg:SQL Comment Sequence Detected, logdata:Matched Data: %{TX.0} found within %{MATCHED_VAR_NAME}: %{MATCHED_VAR}, tag:application-multi, tag:language-multi, tag:platform-multi, tag:attack-sqli, tag:paranoia-level/2, tag:OWASP_CRS, tag:OWASP_CRS/ATTACK-SQLI, tag:capec/1000/152/248/66, ver:OWASP_CRS/4.22.0-dev, severity:CRITICAL, chain

#### Rule 50: Unknown
- **Phase**: Unknown
- **Variables**: MATCHED_VARS
- **Operator**: !@rx
- **Pattern**: ^(?:ey[\-0-9A-Z_a-z]+\.ey[\-0-9A-Z_a-z]+\.)?[\-0-9A-Z_a-z]+$
- **Is Chain**: False
- **Message**: 
- **Severity**: 
- **Actions**: t:none, setvar:tx.inbound_anomaly_score_pl2=+%{tx.critical_anomaly_score}, setvar:tx.sql_injection_score=+%{tx.critical_anomaly_score}

#### Rule 51: 942450
- **Phase**: 2
- **Variables**: REQUEST_COOKIES, REQUEST_COOKIES:/_pk_ref/, REQUEST_COOKIES_NAMES, ARGS_NAMES, ARGS, XML:/*
- **Operator**: @rx
- **Pattern**: (?i:\b0x[a-f\d]{3,})
- **Is Chain**: False
- **Message**: SQL Hex Encoding Identified
- **Severity**: CRITICAL
- **Tags**: application-multi, language-multi, platform-multi, attack-sqli, paranoia-level/2, OWASP_CRS, OWASP_CRS/ATTACK-SQLI, capec/1000/152/248/66
- **Actions**: id:942450, phase:2, block, capture, t:none, t:urlDecodeUni, msg:SQL Hex Encoding Identified, logdata:Matched Data: %{TX.0} found within %{MATCHED_VAR_NAME}: %{MATCHED_VAR}, tag:application-multi, tag:language-multi, tag:platform-multi, tag:attack-sqli, tag:paranoia-level/2, tag:OWASP_CRS, tag:OWASP_CRS/ATTACK-SQLI, tag:capec/1000/152/248/66, ver:OWASP_CRS/4.22.0-dev, severity:CRITICAL, setvar:tx.sql_injection_score=+%{tx.critical_anomaly_score}, setvar:tx.inbound_anomaly_score_pl2=+%{tx.critical_anomaly_score}

#### Rule 52: 942510
- **Phase**: 2
- **Variables**: REQUEST_COOKIES, REQUEST_COOKIES_NAMES, ARGS_NAMES, ARGS, XML:/*
- **Operator**: @rx
- **Pattern**: (?:`(?:(?:[\w\s=_\-+{}()<@]){2,29}|(?:[A-Za-z0-9+/]{4})+(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?)`)
- **Is Chain**: False
- **Message**: SQLi bypass attempt by ticks or backticks detected
- **Severity**: CRITICAL
- **Tags**: application-multi, language-multi, platform-multi, attack-sqli, paranoia-level/2, OWASP_CRS, OWASP_CRS/ATTACK-SQLI, capec/1000/152/248/66
- **Actions**: id:942510, phase:2, block, capture, t:none, t:urlDecodeUni, msg:SQLi bypass attempt by ticks or backticks detected, logdata:Matched Data: %{TX.0} found within %{MATCHED_VAR_NAME}: %{MATCHED_VAR}, tag:application-multi, tag:language-multi, tag:platform-multi, tag:attack-sqli, tag:paranoia-level/2, tag:OWASP_CRS, tag:OWASP_CRS/ATTACK-SQLI, tag:capec/1000/152/248/66, ver:OWASP_CRS/4.22.0-dev, severity:CRITICAL, setvar:tx.sql_injection_score=+%{tx.critical_anomaly_score}, setvar:tx.inbound_anomaly_score_pl2=+%{tx.critical_anomaly_score}

#### Rule 53: 942520
- **Phase**: 2
- **Variables**: REQUEST_COOKIES, REQUEST_COOKIES_NAMES, ARGS_NAMES, ARGS, XML:/*
- **Operator**: @rx
- **Pattern**: (?i)[\"'`][\s\x0b]*?(?:(?:is[\s\x0b]+not|not[\s\x0b]+(?:like|glob|(?:betwee|i)n|null|regexp|match)|mod|div|sounds[\s\x0b]+like)\b|[%&\*\+\-/<->\^\|]{1,3})
- **Is Chain**: False
- **Message**: Detects basic SQL authentication bypass attempts 4.0/4
- **Severity**: CRITICAL
- **Tags**: application-multi, language-multi, platform-multi, attack-sqli, paranoia-level/2, OWASP_CRS, OWASP_CRS/ATTACK-SQLI, capec/1000/152/248/66
- **Actions**: id:942520, phase:2, block, capture, t:none, t:urlDecodeUni, msg:Detects basic SQL authentication bypass attempts 4.0/4, logdata:Matched Data: %{TX.0} found within %{MATCHED_VAR_NAME}: %{MATCHED_VAR}, tag:application-multi, tag:language-multi, tag:platform-multi, tag:attack-sqli, tag:paranoia-level/2, tag:OWASP_CRS, tag:OWASP_CRS/ATTACK-SQLI, tag:capec/1000/152/248/66, ver:OWASP_CRS/4.22.0-dev, severity:CRITICAL, setvar:tx.sql_injection_score=+%{tx.critical_anomaly_score}, setvar:tx.inbound_anomaly_score_pl2=+%{tx.critical_anomaly_score}

#### Rule 54: 942521
- **Phase**: 2
- **Variables**: REQUEST_HEADERS:User-Agent, REQUEST_HEADERS:Referer, ARGS_NAMES, ARGS, XML:/*
- **Operator**: @rx
- **Pattern**: (?i)^(?:[^']*?(?:'[^']*?'[^']*?)*?'|[^\"]*?(?:\"[^\"]*?\"[^\"]*?)*?\"|[^`]*?(?:`[^`]*?`[^`]*?)*?`)[\s\x0b]*([0-9A-Z_a-z]+)\b
- **Is Chain**: True
- **Message**: Detects basic SQL authentication bypass attempts 4.1/4
- **Severity**: CRITICAL
- **Tags**: application-multi, language-multi, platform-multi, attack-sqli, paranoia-level/2, OWASP_CRS, OWASP_CRS/ATTACK-SQLI, capec/1000/152/248/66
- **Actions**: id:942521, phase:2, block, capture, t:none, t:urlDecodeUni, msg:Detects basic SQL authentication bypass attempts 4.1/4, logdata:Matched Data: %{TX.0} found within %{TX.942521_MATCHED_VAR_NAME}: %{MATCHED_VAR}, tag:application-multi, tag:language-multi, tag:platform-multi, tag:attack-sqli, tag:paranoia-level/2, tag:OWASP_CRS, tag:OWASP_CRS/ATTACK-SQLI, tag:capec/1000/152/248/66, ver:OWASP_CRS/4.22.0-dev, severity:CRITICAL, setvar:tx.942521_matched_var_name=%{matched_var_name}, chain

#### Rule 55: Unknown
- **Phase**: Unknown
- **Variables**: TX:1
- **Operator**: @rx
- **Pattern**: ^(?:and|or)$
- **Is Chain**: False
- **Message**: 
- **Severity**: 
- **Actions**: t:none, setvar:tx.sql_injection_score=+%{tx.critical_anomaly_score}, setvar:tx.inbound_anomaly_score_pl2=+%{tx.critical_anomaly_score}

#### Rule 56: 942522
- **Phase**: 2
- **Variables**: ARGS_NAMES, ARGS, XML:/*
- **Operator**: @rx
- **Pattern**: ^.*?\x5c['\"`](?:.*?['\"`])?\s*(?:and|or)\b
- **Is Chain**: False
- **Message**: Detects basic SQL authentication bypass attempts 4.1/4
- **Severity**: CRITICAL
- **Tags**: application-multi, language-multi, platform-multi, attack-sqli, paranoia-level/2, OWASP_CRS, OWASP_CRS/ATTACK-SQLI, capec/1000/152/248/66
- **Actions**: id:942522, phase:2, block, capture, t:none, t:urlDecodeUni, msg:Detects basic SQL authentication bypass attempts 4.1/4, logdata:Matched Data: %{TX.0} found within %{MATCHED_VAR_NAME}: %{MATCHED_VAR}, tag:application-multi, tag:language-multi, tag:platform-multi, tag:attack-sqli, tag:paranoia-level/2, tag:OWASP_CRS, tag:OWASP_CRS/ATTACK-SQLI, tag:capec/1000/152/248/66, ver:OWASP_CRS/4.22.0-dev, severity:CRITICAL, setvar:tx.sql_injection_score=+%{tx.critical_anomaly_score}, setvar:tx.inbound_anomaly_score_pl2=+%{tx.critical_anomaly_score}

#### Rule 57: 942101
- **Phase**: 1
- **Variables**: REQUEST_BASENAME, REQUEST_FILENAME
- **Operator**: @detectSQLi
- **Pattern**: 
- **Is Chain**: False
- **Message**: SQL Injection Attack Detected via libinjection
- **Severity**: CRITICAL
- **Tags**: application-multi, language-multi, platform-multi, attack-sqli, paranoia-level/2, OWASP_CRS, OWASP_CRS/ATTACK-SQLI, capec/1000/152/248/66
- **Actions**: id:942101, phase:1, block, capture, t:none, t:utf8toUnicode, t:urlDecodeUni, t:removeNulls, msg:SQL Injection Attack Detected via libinjection, logdata:Matched Data: %{TX.0} found within %{MATCHED_VAR_NAME}: %{MATCHED_VAR}, tag:application-multi, tag:language-multi, tag:platform-multi, tag:attack-sqli, tag:paranoia-level/2, tag:OWASP_CRS, tag:OWASP_CRS/ATTACK-SQLI, tag:capec/1000/152/248/66, ver:OWASP_CRS/4.22.0-dev, severity:CRITICAL, setvar:tx.sql_injection_score=+%{tx.critical_anomaly_score}, setvar:tx.inbound_anomaly_score_pl2=+%{tx.critical_anomaly_score}

#### Rule 58: 942152
- **Phase**: 1
- **Variables**: REQUEST_HEADERS:Referer, REQUEST_HEADERS:User-Agent
- **Operator**: @rx
- **Pattern**: (?i)\b(?:a(?:dd(?:dat|tim)e|es_(?:de|en)crypt|s(?:cii(?:str)?|in)|tan2?)|b(?:enchmark|i(?:n_to_num|t_(?:and|count|length|x?or)))|c(?:har(?:acter)?_length|eil(?:ing)?|o(?:alesce|ercibility|llation|(?:mpres)?s|n(?:cat(?:_ws)?|nection_id|v(?:ert(?:_tz)?)?)|t)|rc32|ur(?:(?:dat|tim)e|rent_(?:date|setting|time(?:stamp)?|user)))|d(?:a(?:t(?:abase(?:_to_xml)?|e(?:_(?:add|format|sub)|diff))|y(?:name|of(?:month|week|year)))|count|e(?:code|grees|s_(?:de|en)crypt)|ump)|e(?:lt|n(?:c(?:ode|rypt)|ds_?with)|x(?:p(?:ort_set)?|tract(?:value)?))|f(?:i(?:el|n)d_in_set|ound_rows|rom_(?:base64|days|unixtime))|g(?:e(?:ometrycollection|t(?:_(?:format|lock)|pgusername))|(?:r(?:eates|oup_conca)|tid_subse)t)|hex(?:toraw)?|i(?:fnull|n(?:et6?_(?:aton|ntoa)|s(?:ert|tr)|terval)|s(?:_(?:(?:free|used)_lock|ipv(?:4(?:_(?:compat|mapped))?|6)|n(?:ot(?:_null)?|ull)|superuser)|null))|json(?:_(?:a(?:gg|rray(?:_(?:elements(?:_text)?|length))?)|build_(?:array|object)|e(?:ac|xtract_pat)h(?:_text)?|object(?:_(?:agg|keys))?|populate_record(?:set)?|strip_nulls|t(?:o_record(?:set)?|ypeof))|b(?:_(?:array(?:_(?:elements(?:_text)?|length))?|build_(?:array|object)|object(?:_(?:agg|keys))?|e(?:ac|xtract_pat)h(?:_text)?|insert|p(?:ath_(?:(?:exists|match)(?:_tz)?|query(?:_(?:(?:array|first)(?:_tz)?|tz))?)|opulate_record(?:set)?|retty)|s(?:et(?:_lax)?|trip_nulls)|t(?:o_record(?:set)?|ypeof)))?|path)?|l(?:ast_(?:day|insert_id)|case|e(?:as|f)t|i(?:kel(?:ihood|y)|nestring)|o(?:_(?:from_bytea|put)|ad_file|ca(?:ltimestamp|te)|g(?:10|2)|wer)|pad|trim)|m(?:a(?:ke(?:_set|date)|ster_pos_wait)|d5|i(?:crosecon)?d|onthname|ulti(?:linestring|po(?:int|lygon)))|n(?:ame_const|ot_in|ullif)|o(?:ct(?:et_length)?|(?:ld_passwo)?rd)|p(?:eriod_(?:add|diff)|g_(?:client_encoding|(?:databas|read_fil)e|l(?:argeobject|s_dir)|sleep|user)|o(?:(?:lyg|siti)on|w)|rocedure_analyse)|qu(?:arter|ery_to_xml|ote)|r(?:a(?:dians|nd|wtohex)|elease_lock|ow_(?:count|to_json)|pad|trim)|s(?:chema|e(?:c_to_time|ssion_user)|ha[12]?|in|oundex|pace|q(?:lite_(?:compileoption_(?:get|used)|source_id)|rt)|t(?:arts_?with|d(?:dev_(?:po|sam)p)?|r(?:_to_date|cmp))|ub(?:(?:dat|tim)e|str(?:ing(?:_index)?)?)|ys(?:date|tem_user))|t(?:ime(?:_(?:format|to_sec)|diff|stamp(?:add|diff)?)|o(?:_(?:base64|jsonb?)|n?char|(?:day|second)s)|r(?:im|uncate))|u(?:case|n(?:compress(?:ed_length)?|hex|i(?:str|x_timestamp)|likely)|(?:pdatexm|se_json_nul)l|tc_(?:date|time(?:stamp)?)|uid(?:_short)?)|var(?:_(?:po|sam)p|iance)|we(?:ek(?:day|ofyear)|ight_string)|xmltype|yearweek)[^0-9A-Z_a-z]*\(
- **Is Chain**: False
- **Message**: SQL Injection Attack: SQL function name detected
- **Severity**: CRITICAL
- **Tags**: application-multi, language-multi, platform-multi, attack-sqli, paranoia-level/2, OWASP_CRS, OWASP_CRS/ATTACK-SQLI, capec/1000/152/248/66
- **Actions**: id:942152, phase:1, block, capture, t:none, t:urlDecodeUni, msg:SQL Injection Attack: SQL function name detected, logdata:Matched Data: %{TX.0} found within %{MATCHED_VAR_NAME}: %{MATCHED_VAR}, tag:application-multi, tag:language-multi, tag:platform-multi, tag:attack-sqli, tag:paranoia-level/2, tag:OWASP_CRS, tag:OWASP_CRS/ATTACK-SQLI, tag:capec/1000/152/248/66, ver:OWASP_CRS/4.22.0-dev, severity:CRITICAL, setvar:tx.sql_injection_score=+%{tx.critical_anomaly_score}, setvar:tx.inbound_anomaly_score_pl2=+%{tx.critical_anomaly_score}

#### Rule 59: 942321
- **Phase**: 1
- **Variables**: REQUEST_HEADERS:Referer, REQUEST_HEADERS:User-Agent
- **Operator**: @rx
- **Pattern**: (?i)create[\s\x0b]+(?:function|procedure)[\s\x0b]*?[0-9A-Z_a-z]+[\s\x0b]*?\([\s\x0b]*?\)[\s\x0b]*?-|d(?:eclare[^0-9A-Z_a-z]+[#@][\s\x0b]*?[0-9A-Z_a-z]+|iv[\s\x0b]*?\([\+\-]*[\s\x0b\.0-9]+,[\+\-]*[\s\x0b\.0-9]+\))|exec[\s\x0b]*?\([\s\x0b]*?@|(?:lo_(?:impor|ge)t|procedure[\s\x0b]+analyse)[\s\x0b]*?\(|;[\s\x0b]*?(?:declare|open)[\s\x0b]+[\-0-9A-Z_a-z]+|::(?:b(?:igint|ool)|double[\s\x0b]+precision|int(?:eger)?|numeric|oid|real|(?:tex|smallin)t)
- **Is Chain**: False
- **Message**: Detects MySQL and PostgreSQL stored procedure/function injections
- **Severity**: CRITICAL
- **Tags**: application-multi, language-multi, platform-multi, attack-sqli, paranoia-level/2, OWASP_CRS, OWASP_CRS/ATTACK-SQLI, capec/1000/152/248/66
- **Actions**: id:942321, phase:1, block, capture, t:none, t:urlDecodeUni, msg:Detects MySQL and PostgreSQL stored procedure/function injections, logdata:Matched Data: %{TX.0} found within %{MATCHED_VAR_NAME}: %{MATCHED_VAR}, tag:application-multi, tag:language-multi, tag:platform-multi, tag:attack-sqli, tag:paranoia-level/2, tag:OWASP_CRS, tag:OWASP_CRS/ATTACK-SQLI, tag:capec/1000/152/248/66, ver:OWASP_CRS/4.22.0-dev, severity:CRITICAL, setvar:tx.sql_injection_score=+%{tx.critical_anomaly_score}, setvar:tx.inbound_anomaly_score_pl2=+%{tx.critical_anomaly_score}

#### Rule 60: 942015
- **Phase**: 1
- **Variables**: TX:DETECTION_PARANOIA_LEVEL
- **Operator**: @lt
- **Pattern**: 3
- **Is Chain**: False
- **Message**: 
- **Severity**: 
- **Tags**: OWASP_CRS
- **Actions**: id:942015, phase:1, pass, nolog, tag:OWASP_CRS, ver:OWASP_CRS/4.22.0-dev, skipAfter:END-REQUEST-942-APPLICATION-ATTACK-SQLI

#### Rule 61: 942016
- **Phase**: 2
- **Variables**: TX:DETECTION_PARANOIA_LEVEL
- **Operator**: @lt
- **Pattern**: 3
- **Is Chain**: False
- **Message**: 
- **Severity**: 
- **Tags**: OWASP_CRS
- **Actions**: id:942016, phase:2, pass, nolog, tag:OWASP_CRS, ver:OWASP_CRS/4.22.0-dev, skipAfter:END-REQUEST-942-APPLICATION-ATTACK-SQLI

#### Rule 62: 942251
- **Phase**: 2
- **Variables**: REQUEST_COOKIES, REQUEST_COOKIES_NAMES, ARGS_NAMES, ARGS, XML:/*
- **Operator**: @rx
- **Pattern**: (?i)\W+\d*?\s*?\bhaving\b\s*?[^\s\-]
- **Is Chain**: False
- **Message**: Detects HAVING injections
- **Severity**: CRITICAL
- **Tags**: application-multi, language-multi, platform-multi, attack-sqli, paranoia-level/3, OWASP_CRS, OWASP_CRS/ATTACK-SQLI, capec/1000/152/248/66
- **Actions**: id:942251, phase:2, block, capture, t:none, t:urlDecodeUni, msg:Detects HAVING injections, logdata:Matched Data: %{TX.0} found within %{MATCHED_VAR_NAME}: %{MATCHED_VAR}, tag:application-multi, tag:language-multi, tag:platform-multi, tag:attack-sqli, tag:paranoia-level/3, tag:OWASP_CRS, tag:OWASP_CRS/ATTACK-SQLI, tag:capec/1000/152/248/66, ver:OWASP_CRS/4.22.0-dev, severity:CRITICAL, setvar:tx.sql_injection_score=+%{tx.critical_anomaly_score}, setvar:tx.inbound_anomaly_score_pl3=+%{tx.critical_anomaly_score}

#### Rule 63: 942490
- **Phase**: 2
- **Variables**: REQUEST_COOKIES, REQUEST_COOKIES_NAMES, ARGS_NAMES, ARGS, XML:/*
- **Operator**: @rx
- **Pattern**: [\"'`][\s\d]*?[^\w\s]\W*?\d\W*?.*?[\"'`\d]
- **Is Chain**: False
- **Message**: Detects classic SQL injection probings 3/3
- **Severity**: CRITICAL
- **Tags**: application-multi, language-multi, platform-multi, attack-sqli, paranoia-level/3, OWASP_CRS, OWASP_CRS/ATTACK-SQLI, capec/1000/152/248/66
- **Actions**: id:942490, phase:2, block, capture, t:none, t:urlDecodeUni, msg:Detects classic SQL injection probings 3/3, logdata:Matched Data: %{TX.0} found within %{MATCHED_VAR_NAME}: %{MATCHED_VAR}, tag:application-multi, tag:language-multi, tag:platform-multi, tag:attack-sqli, tag:paranoia-level/3, tag:OWASP_CRS, tag:OWASP_CRS/ATTACK-SQLI, tag:capec/1000/152/248/66, ver:OWASP_CRS/4.22.0-dev, severity:CRITICAL, setvar:tx.sql_injection_score=+%{tx.critical_anomaly_score}, setvar:tx.inbound_anomaly_score_pl3=+%{tx.critical_anomaly_score}

#### Rule 64: 942420
- **Phase**: 1
- **Variables**: REQUEST_COOKIES, REQUEST_COOKIES:/_pk_ref/, REQUEST_COOKIES_NAMES
- **Operator**: @rx
- **Pattern**: ((?:[~!@#\$%\^&\*\(\)\-\+=\{\}\[\]\|:;\"'´’‘`<>][^~!@#\$%\^&\*\(\)\-\+=\{\}\[\]\|:;\"'´’‘`<>]*?){8})
- **Is Chain**: False
- **Message**: Restricted SQL Character Anomaly Detection (cookies): # of special characters exceeded (8)
- **Severity**: WARNING
- **Tags**: application-multi, language-multi, platform-multi, attack-sqli, paranoia-level/3, OWASP_CRS, OWASP_CRS/ATTACK-SQLI, capec/1000/152/248/66
- **Actions**: id:942420, phase:1, block, capture, t:none, t:urlDecodeUni, msg:Restricted SQL Character Anomaly Detection (cookies): # of special characters exceeded (8), logdata:Matched Data: %{TX.1} found within %{MATCHED_VAR_NAME}: %{MATCHED_VAR}, tag:application-multi, tag:language-multi, tag:platform-multi, tag:attack-sqli, tag:paranoia-level/3, tag:OWASP_CRS, tag:OWASP_CRS/ATTACK-SQLI, tag:capec/1000/152/248/66, ver:OWASP_CRS/4.22.0-dev, severity:WARNING, setvar:tx.inbound_anomaly_score_pl3=+%{tx.warning_anomaly_score}, setvar:tx.sql_injection_score=+%{tx.warning_anomaly_score}

#### Rule 65: 942431
- **Phase**: 2
- **Variables**: ARGS_NAMES, ARGS_NAMES:/^[\w]+\[[\w\-]+\]\[[\w\-]*?\]$/, ARGS_NAMES:/^[\w]+\[[\w\-]+\]\[[\w\-]+\]\[[\w\-]*?\]$/, ARGS, XML:/*
- **Operator**: @rx
- **Pattern**: ((?:[~!@#\$%\^&\*\(\)\-\+=\{\}\[\]\|:;\"'´’‘`<>][^~!@#\$%\^&\*\(\)\-\+=\{\}\[\]\|:;\"'´’‘`<>]*?){6})
- **Is Chain**: False
- **Message**: Restricted SQL Character Anomaly Detection (args): # of special characters exceeded (6)
- **Severity**: WARNING
- **Tags**: application-multi, language-multi, platform-multi, attack-sqli, paranoia-level/3, OWASP_CRS, OWASP_CRS/ATTACK-SQLI, capec/1000/152/248/66
- **Actions**: id:942431, phase:2, block, capture, t:none, t:urlDecodeUni, msg:Restricted SQL Character Anomaly Detection (args): # of special characters exceeded (6), logdata:Matched Data: %{TX.1} found within %{MATCHED_VAR_NAME}: %{MATCHED_VAR}, tag:application-multi, tag:language-multi, tag:platform-multi, tag:attack-sqli, tag:paranoia-level/3, tag:OWASP_CRS, tag:OWASP_CRS/ATTACK-SQLI, tag:capec/1000/152/248/66, ver:OWASP_CRS/4.22.0-dev, severity:WARNING, setvar:tx.inbound_anomaly_score_pl3=+%{tx.warning_anomaly_score}, setvar:tx.sql_injection_score=+%{tx.warning_anomaly_score}

#### Rule 66: 942460
- **Phase**: 2
- **Variables**: ARGS
- **Operator**: @rx
- **Pattern**: \W{4}
- **Is Chain**: False
- **Message**: Meta-Character Anomaly Detection Alert - Repetitive Non-Word Characters
- **Severity**: WARNING
- **Tags**: application-multi, language-multi, platform-multi, attack-sqli, paranoia-level/3, OWASP_CRS, OWASP_CRS/ATTACK-SQLI, capec/1000/152/248/66
- **Actions**: id:942460, phase:2, block, capture, t:none, msg:Meta-Character Anomaly Detection Alert - Repetitive Non-Word Characters, logdata:Matched Data: %{TX.0} found within %{MATCHED_VAR_NAME}: %{MATCHED_VAR}, tag:application-multi, tag:language-multi, tag:platform-multi, tag:attack-sqli, tag:paranoia-level/3, tag:OWASP_CRS, tag:OWASP_CRS/ATTACK-SQLI, tag:capec/1000/152/248/66, ver:OWASP_CRS/4.22.0-dev, severity:WARNING, setvar:tx.sql_injection_score=+%{tx.warning_anomaly_score}, setvar:tx.inbound_anomaly_score_pl3=+%{tx.warning_anomaly_score}

#### Rule 67: 942511
- **Phase**: 2
- **Variables**: REQUEST_COOKIES, REQUEST_COOKIES_NAMES, ARGS_NAMES, ARGS, XML:/*
- **Operator**: @rx
- **Pattern**: (?:'(?:(?:[\w\s=_\-+{}()<@]){2,29}|(?:[A-Za-z0-9+/]{4})+(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?)')
- **Is Chain**: False
- **Message**: SQLi bypass attempt by ticks detected
- **Severity**: CRITICAL
- **Tags**: application-multi, language-multi, platform-multi, attack-sqli, paranoia-level/3, OWASP_CRS, OWASP_CRS/ATTACK-SQLI, capec/1000/152/248/66
- **Actions**: id:942511, phase:2, block, capture, t:none, t:urlDecodeUni, msg:SQLi bypass attempt by ticks detected, logdata:Matched Data: %{TX.0} found within %{MATCHED_VAR_NAME}: %{MATCHED_VAR}, tag:application-multi, tag:language-multi, tag:platform-multi, tag:attack-sqli, tag:paranoia-level/3, tag:OWASP_CRS, tag:OWASP_CRS/ATTACK-SQLI, tag:capec/1000/152/248/66, ver:OWASP_CRS/4.22.0-dev, severity:CRITICAL, setvar:tx.sql_injection_score=+%{tx.critical_anomaly_score}, setvar:tx.inbound_anomaly_score_pl3=+%{tx.critical_anomaly_score}

#### Rule 68: 942530
- **Phase**: 2
- **Variables**: REQUEST_COOKIES, REQUEST_COOKIES_NAMES, ARGS_NAMES, ARGS, XML:/*
- **Operator**: @rx
- **Pattern**: ';
- **Is Chain**: False
- **Message**: SQLi query termination detected
- **Severity**: CRITICAL
- **Tags**: application-multi, language-multi, platform-multi, attack-sqli, paranoia-level/3, OWASP_CRS, OWASP_CRS/ATTACK-SQLI, capec/1000/152/248/66
- **Actions**: id:942530, phase:2, block, capture, t:none, t:urlDecodeUni, msg:SQLi query termination detected, logdata:Matched Data: %{TX.0} found within %{MATCHED_VAR_NAME}: %{MATCHED_VAR}, tag:application-multi, tag:language-multi, tag:platform-multi, tag:attack-sqli, tag:paranoia-level/3, tag:OWASP_CRS, tag:OWASP_CRS/ATTACK-SQLI, tag:capec/1000/152/248/66, ver:OWASP_CRS/4.22.0-dev, severity:CRITICAL, setvar:tx.sql_injection_score=+%{tx.critical_anomaly_score}, setvar:tx.inbound_anomaly_score_pl3=+%{tx.critical_anomaly_score}

#### Rule 69: 942017
- **Phase**: 1
- **Variables**: TX:DETECTION_PARANOIA_LEVEL
- **Operator**: @lt
- **Pattern**: 4
- **Is Chain**: False
- **Message**: 
- **Severity**: 
- **Tags**: OWASP_CRS
- **Actions**: id:942017, phase:1, pass, nolog, tag:OWASP_CRS, ver:OWASP_CRS/4.22.0-dev, skipAfter:END-REQUEST-942-APPLICATION-ATTACK-SQLI

#### Rule 70: 942018
- **Phase**: 2
- **Variables**: TX:DETECTION_PARANOIA_LEVEL
- **Operator**: @lt
- **Pattern**: 4
- **Is Chain**: False
- **Message**: 
- **Severity**: 
- **Tags**: OWASP_CRS
- **Actions**: id:942018, phase:2, pass, nolog, tag:OWASP_CRS, ver:OWASP_CRS/4.22.0-dev, skipAfter:END-REQUEST-942-APPLICATION-ATTACK-SQLI

#### Rule 71: 942421
- **Phase**: 1
- **Variables**: REQUEST_COOKIES, REQUEST_COOKIES:/_pk_ref/, REQUEST_COOKIES_NAMES
- **Operator**: @rx
- **Pattern**: ((?:[~!@#\$%\^&\*\(\)\-\+=\{\}\[\]\|:;\"'´’‘`<>][^~!@#\$%\^&\*\(\)\-\+=\{\}\[\]\|:;\"'´’‘`<>]*?){3})
- **Is Chain**: False
- **Message**: Restricted SQL Character Anomaly Detection (cookies): # of special characters exceeded (3)
- **Severity**: WARNING
- **Tags**: application-multi, language-multi, platform-multi, attack-sqli, paranoia-level/4, OWASP_CRS, OWASP_CRS/ATTACK-SQLI, capec/1000/152/248/66
- **Actions**: id:942421, phase:1, block, capture, t:none, t:urlDecodeUni, msg:Restricted SQL Character Anomaly Detection (cookies): # of special characters exceeded (3), logdata:Matched Data: %{TX.1} found within %{MATCHED_VAR_NAME}: %{MATCHED_VAR}, tag:application-multi, tag:language-multi, tag:platform-multi, tag:attack-sqli, tag:paranoia-level/4, tag:OWASP_CRS, tag:OWASP_CRS/ATTACK-SQLI, tag:capec/1000/152/248/66, ver:OWASP_CRS/4.22.0-dev, severity:WARNING, setvar:tx.inbound_anomaly_score_pl4=+%{tx.warning_anomaly_score}, setvar:tx.sql_injection_score=+%{tx.warning_anomaly_score}

#### Rule 72: 942432
- **Phase**: 2
- **Variables**: ARGS_NAMES, ARGS, XML:/*
- **Operator**: @rx
- **Pattern**: ((?:[~!@#\$%\^&\*\(\)\-\+=\{\}\[\]\|:;\"'´’‘`<>][^~!@#\$%\^&\*\(\)\-\+=\{\}\[\]\|:;\"'´’‘`<>]*?){2})
- **Is Chain**: False
- **Message**: Restricted SQL Character Anomaly Detection (args): # of special characters exceeded (2)
- **Severity**: WARNING
- **Tags**: application-multi, language-multi, platform-multi, attack-sqli, paranoia-level/4, OWASP_CRS, OWASP_CRS/ATTACK-SQLI, capec/1000/152/248/66
- **Actions**: id:942432, phase:2, block, capture, t:none, t:urlDecodeUni, msg:Restricted SQL Character Anomaly Detection (args): # of special characters exceeded (2), logdata:Matched Data: %{TX.1} found within %{MATCHED_VAR_NAME}: %{MATCHED_VAR}, tag:application-multi, tag:language-multi, tag:platform-multi, tag:attack-sqli, tag:paranoia-level/4, tag:OWASP_CRS, tag:OWASP_CRS/ATTACK-SQLI, tag:capec/1000/152/248/66, ver:OWASP_CRS/4.22.0-dev, severity:WARNING, setvar:tx.inbound_anomaly_score_pl4=+%{tx.warning_anomaly_score}, setvar:tx.sql_injection_score=+%{tx.warning_anomaly_score}


====================================================================================================

## File: REQUEST-943-APPLICATION-ATTACK-SESSION-FIXATION.conf

### File Summary
- Total rules: 14
- Chained rules: 3
- Non-chained rules: 11

### Detailed Rules

#### Rule 1: 943011
- **Phase**: 1
- **Variables**: TX:DETECTION_PARANOIA_LEVEL
- **Operator**: @lt
- **Pattern**: 1
- **Is Chain**: False
- **Message**: 
- **Severity**: 
- **Tags**: OWASP_CRS
- **Actions**: id:943011, phase:1, pass, nolog, tag:OWASP_CRS, ver:OWASP_CRS/4.22.0-dev, skipAfter:END-REQUEST-943-APPLICATION-ATTACK-SESSION-FIXATION

#### Rule 2: 943012
- **Phase**: 2
- **Variables**: TX:DETECTION_PARANOIA_LEVEL
- **Operator**: @lt
- **Pattern**: 1
- **Is Chain**: False
- **Message**: 
- **Severity**: 
- **Tags**: OWASP_CRS
- **Actions**: id:943012, phase:2, pass, nolog, tag:OWASP_CRS, ver:OWASP_CRS/4.22.0-dev, skipAfter:END-REQUEST-943-APPLICATION-ATTACK-SESSION-FIXATION

#### Rule 3: 943100
- **Phase**: 2
- **Variables**: REQUEST_COOKIES, REQUEST_COOKIES_NAMES, ARGS_NAMES, ARGS, XML:/*
- **Operator**: @rx
- **Pattern**: (?i:\.cookie\b.*?;\W*?(?:expires|domain)\W*?=|\bhttp-equiv\W+set-cookie\b)
- **Is Chain**: False
- **Message**: Possible Session Fixation Attack: Setting Cookie Values in HTML
- **Severity**: CRITICAL
- **Tags**: application-multi, language-multi, platform-multi, attack-fixation, paranoia-level/1, OWASP_CRS, OWASP_CRS/ATTACK-SESSION-FIXATION, capec/1000/225/21/593/61
- **Actions**: id:943100, phase:2, block, capture, t:none, t:urlDecodeUni, msg:Possible Session Fixation Attack: Setting Cookie Values in HTML, logdata:Matched Data: %{TX.0} found within %{MATCHED_VAR_NAME}: %{MATCHED_VAR}, tag:application-multi, tag:language-multi, tag:platform-multi, tag:attack-fixation, tag:paranoia-level/1, tag:OWASP_CRS, tag:OWASP_CRS/ATTACK-SESSION-FIXATION, tag:capec/1000/225/21/593/61, ver:OWASP_CRS/4.22.0-dev, severity:CRITICAL, setvar:tx.session_fixation_score=+%{tx.critical_anomaly_score}, setvar:tx.inbound_anomaly_score_pl1=+%{tx.critical_anomaly_score}

#### Rule 4: 943110
- **Phase**: 2
- **Variables**: ARGS_NAMES
- **Operator**: @rx
- **Pattern**: ^(?:jsessionid|aspsessionid|asp\.net_sessionid|phpsession|phpsessid|weblogicsession|session_id|session-id|sessionid|cfid|cftoken|cfsid|jservsession|jwsession|_flask_session|_session_id|connect\.sid|laravel_session)$
- **Is Chain**: True
- **Message**: Possible Session Fixation Attack: SessionID Parameter Name with Off-Domain Referer
- **Severity**: CRITICAL
- **Tags**: application-multi, language-multi, platform-multi, attack-fixation, paranoia-level/1, OWASP_CRS, OWASP_CRS/ATTACK-SESSION-FIXATION, capec/1000/225/21/593/61
- **Actions**: id:943110, phase:2, block, capture, t:none, t:lowercase, msg:Possible Session Fixation Attack: SessionID Parameter Name with Off-Domain Referer, logdata:Matched Data: %{TX.0} found within %{TX.943110_MATCHED_VAR_NAME}: %{MATCHED_VAR}, tag:application-multi, tag:language-multi, tag:platform-multi, tag:attack-fixation, tag:paranoia-level/1, tag:OWASP_CRS, tag:OWASP_CRS/ATTACK-SESSION-FIXATION, tag:capec/1000/225/21/593/61, ver:OWASP_CRS/4.22.0-dev, severity:CRITICAL, setvar:tx.943110_matched_var_name=%{matched_var_name}, chain

#### Rule 5: Unknown
- **Phase**: Unknown
- **Variables**: REQUEST_HEADERS:Referer
- **Operator**: @rx
- **Pattern**: ^(?:ht|f)tps?://(.*?)/
- **Is Chain**: True
- **Message**: 
- **Severity**: 
- **Actions**: capture, chain

#### Rule 6: Unknown
- **Phase**: Unknown
- **Variables**: TX:1
- **Operator**: !@endsWith
- **Pattern**: %{request_headers.host}
- **Is Chain**: False
- **Message**: 
- **Severity**: 
- **Actions**: setvar:tx.session_fixation_score=+%{tx.critical_anomaly_score}, setvar:tx.inbound_anomaly_score_pl1=+%{tx.critical_anomaly_score}

#### Rule 7: 943120
- **Phase**: 2
- **Variables**: ARGS_NAMES
- **Operator**: @rx
- **Pattern**: ^(?:jsessionid|aspsessionid|asp\.net_sessionid|phpsession|phpsessid|weblogicsession|session_id|session-id|sessionid|cfid|cftoken|cfsid|jservsession|jwsession|_flask_session|_session_id|connect\.sid|laravel_session)$
- **Is Chain**: True
- **Message**: Possible Session Fixation Attack: SessionID Parameter Name with No Referer
- **Severity**: CRITICAL
- **Tags**: application-multi, language-multi, platform-multi, attack-fixation, paranoia-level/1, OWASP_CRS, OWASP_CRS/ATTACK-SESSION-FIXATION, capec/1000/225/21/593/61
- **Actions**: id:943120, phase:2, block, capture, t:none, t:lowercase, msg:Possible Session Fixation Attack: SessionID Parameter Name with No Referer, logdata:Matched Data: %{TX.0} found within %{TX.943120_MATCHED_VAR_NAME}: %{MATCHED_VAR}, tag:application-multi, tag:language-multi, tag:platform-multi, tag:attack-fixation, tag:paranoia-level/1, tag:OWASP_CRS, tag:OWASP_CRS/ATTACK-SESSION-FIXATION, tag:capec/1000/225/21/593/61, ver:OWASP_CRS/4.22.0-dev, severity:CRITICAL, setvar:tx.943120_matched_var_name=%{matched_var_name}, chain

#### Rule 8: Unknown
- **Phase**: Unknown
- **Variables**: REQUEST_HEADERS:Referer
- **Operator**: @eq
- **Pattern**: 0
- **Is Chain**: False
- **Message**: 
- **Severity**: 
- **Actions**: setvar:tx.session_fixation_score=+%{tx.critical_anomaly_score}, setvar:tx.inbound_anomaly_score_pl1=+%{tx.critical_anomaly_score}

#### Rule 9: 943013
- **Phase**: 1
- **Variables**: TX:DETECTION_PARANOIA_LEVEL
- **Operator**: @lt
- **Pattern**: 2
- **Is Chain**: False
- **Message**: 
- **Severity**: 
- **Tags**: OWASP_CRS
- **Actions**: id:943013, phase:1, pass, nolog, tag:OWASP_CRS, ver:OWASP_CRS/4.22.0-dev, skipAfter:END-REQUEST-943-APPLICATION-ATTACK-SESSION-FIXATION

#### Rule 10: 943014
- **Phase**: 2
- **Variables**: TX:DETECTION_PARANOIA_LEVEL
- **Operator**: @lt
- **Pattern**: 2
- **Is Chain**: False
- **Message**: 
- **Severity**: 
- **Tags**: OWASP_CRS
- **Actions**: id:943014, phase:2, pass, nolog, tag:OWASP_CRS, ver:OWASP_CRS/4.22.0-dev, skipAfter:END-REQUEST-943-APPLICATION-ATTACK-SESSION-FIXATION

#### Rule 11: 943015
- **Phase**: 1
- **Variables**: TX:DETECTION_PARANOIA_LEVEL
- **Operator**: @lt
- **Pattern**: 3
- **Is Chain**: False
- **Message**: 
- **Severity**: 
- **Tags**: OWASP_CRS
- **Actions**: id:943015, phase:1, pass, nolog, tag:OWASP_CRS, ver:OWASP_CRS/4.22.0-dev, skipAfter:END-REQUEST-943-APPLICATION-ATTACK-SESSION-FIXATION

#### Rule 12: 943016
- **Phase**: 2
- **Variables**: TX:DETECTION_PARANOIA_LEVEL
- **Operator**: @lt
- **Pattern**: 3
- **Is Chain**: False
- **Message**: 
- **Severity**: 
- **Tags**: OWASP_CRS
- **Actions**: id:943016, phase:2, pass, nolog, tag:OWASP_CRS, ver:OWASP_CRS/4.22.0-dev, skipAfter:END-REQUEST-943-APPLICATION-ATTACK-SESSION-FIXATION

#### Rule 13: 943017
- **Phase**: 1
- **Variables**: TX:DETECTION_PARANOIA_LEVEL
- **Operator**: @lt
- **Pattern**: 4
- **Is Chain**: False
- **Message**: 
- **Severity**: 
- **Tags**: OWASP_CRS
- **Actions**: id:943017, phase:1, pass, nolog, tag:OWASP_CRS, ver:OWASP_CRS/4.22.0-dev, skipAfter:END-REQUEST-943-APPLICATION-ATTACK-SESSION-FIXATION

#### Rule 14: 943018
- **Phase**: 2
- **Variables**: TX:DETECTION_PARANOIA_LEVEL
- **Operator**: @lt
- **Pattern**: 4
- **Is Chain**: False
- **Message**: 
- **Severity**: 
- **Tags**: OWASP_CRS
- **Actions**: id:943018, phase:2, pass, nolog, tag:OWASP_CRS, ver:OWASP_CRS/4.22.0-dev, skipAfter:END-REQUEST-943-APPLICATION-ATTACK-SESSION-FIXATION


====================================================================================================

## File: REQUEST-944-APPLICATION-ATTACK-JAVA.conf

### File Summary
- Total rules: 24
- Chained rules: 2
- Non-chained rules: 22

### Detailed Rules

#### Rule 1: 944011
- **Phase**: 1
- **Variables**: TX:DETECTION_PARANOIA_LEVEL
- **Operator**: @lt
- **Pattern**: 1
- **Is Chain**: False
- **Message**: 
- **Severity**: 
- **Tags**: OWASP_CRS
- **Actions**: id:944011, phase:1, pass, nolog, tag:OWASP_CRS, ver:OWASP_CRS/4.22.0-dev, skipAfter:END-REQUEST-944-APPLICATION-ATTACK-JAVA

#### Rule 2: 944012
- **Phase**: 2
- **Variables**: TX:DETECTION_PARANOIA_LEVEL
- **Operator**: @lt
- **Pattern**: 1
- **Is Chain**: False
- **Message**: 
- **Severity**: 
- **Tags**: OWASP_CRS
- **Actions**: id:944012, phase:2, pass, nolog, tag:OWASP_CRS, ver:OWASP_CRS/4.22.0-dev, skipAfter:END-REQUEST-944-APPLICATION-ATTACK-JAVA

#### Rule 3: 944100
- **Phase**: 2
- **Variables**: ARGS, ARGS_NAMES, REQUEST_COOKIES, REQUEST_COOKIES_NAMES, REQUEST_BODY, REQUEST_HEADERS, XML:/*, XML://@*
- **Operator**: @rx
- **Pattern**: java\.lang\.(?:runtime|processbuilder)
- **Is Chain**: False
- **Message**: Remote Command Execution: Suspicious Java class detected
- **Severity**: CRITICAL
- **Tags**: application-multi, language-java, platform-multi, attack-rce, paranoia-level/1, OWASP_CRS, OWASP_CRS/ATTACK-JAVA, capec/1000/152/137/6
- **Actions**: id:944100, phase:2, block, t:none, t:lowercase, msg:Remote Command Execution: Suspicious Java class detected, logdata:Matched Data: %{MATCHED_VAR} found within %{MATCHED_VAR_NAME}, tag:application-multi, tag:language-java, tag:platform-multi, tag:attack-rce, tag:paranoia-level/1, tag:OWASP_CRS, tag:OWASP_CRS/ATTACK-JAVA, tag:capec/1000/152/137/6, ver:OWASP_CRS/4.22.0-dev, severity:CRITICAL, setvar:tx.rce_score=+%{tx.critical_anomaly_score}, setvar:tx.inbound_anomaly_score_pl1=+%{tx.critical_anomaly_score}

#### Rule 4: 944110
- **Phase**: 2
- **Variables**: ARGS, ARGS_NAMES, REQUEST_COOKIES, REQUEST_COOKIES_NAMES, REQUEST_BODY, REQUEST_HEADERS, XML:/*, XML://@*
- **Operator**: @rx
- **Pattern**: (?:runtime|processbuilder)
- **Is Chain**: True
- **Message**: Remote Command Execution: Java process spawn (CVE-2017-9805)
- **Severity**: CRITICAL
- **Tags**: application-multi, language-java, platform-multi, attack-rce, paranoia-level/1, OWASP_CRS, OWASP_CRS/ATTACK-JAVA, capec/1000/152/248
- **Actions**: id:944110, phase:2, block, t:none, t:lowercase, msg:Remote Command Execution: Java process spawn (CVE-2017-9805), logdata:Matched Data: %{MATCHED_VAR} found within %{MATCHED_VAR_NAME}, tag:application-multi, tag:language-java, tag:platform-multi, tag:attack-rce, tag:paranoia-level/1, tag:OWASP_CRS, tag:OWASP_CRS/ATTACK-JAVA, tag:capec/1000/152/248, ver:OWASP_CRS/4.22.0-dev, severity:CRITICAL, chain

#### Rule 5: Unknown
- **Phase**: Unknown
- **Variables**: MATCHED_VARS, XML:/*, XML://@*
- **Operator**: @rx
- **Pattern**: (?i)(?:unmarshaller|base64data|java\.)
- **Is Chain**: False
- **Message**: 
- **Severity**: 
- **Actions**: setvar:tx.rce_score=+%{tx.critical_anomaly_score}, setvar:tx.inbound_anomaly_score_pl1=+%{tx.critical_anomaly_score}

#### Rule 6: 944120
- **Phase**: 2
- **Variables**: ARGS, ARGS_NAMES, REQUEST_COOKIES, REQUEST_COOKIES_NAMES, REQUEST_BODY, REQUEST_HEADERS, XML:/*, XML://@*
- **Operator**: @rx
- **Pattern**: (?:clonetransformer|forclosure|instantiatefactory|instantiatetransformer|invokertransformer|prototypeclonefactory|prototypeserializationfactory|whileclosure|getproperty|filewriter|xmldecoder)
- **Is Chain**: True
- **Message**: Remote Command Execution: Java serialization (CVE-2015-4852)
- **Severity**: CRITICAL
- **Tags**: application-multi, language-java, platform-multi, attack-rce, paranoia-level/1, OWASP_CRS, OWASP_CRS/ATTACK-JAVA, capec/1000/152/248
- **Actions**: id:944120, phase:2, block, t:none, t:lowercase, msg:Remote Command Execution: Java serialization (CVE-2015-4852), logdata:Matched Data: %{MATCHED_VAR} found within %{MATCHED_VAR_NAME}, tag:application-multi, tag:language-java, tag:platform-multi, tag:attack-rce, tag:paranoia-level/1, tag:OWASP_CRS, tag:OWASP_CRS/ATTACK-JAVA, tag:capec/1000/152/248, ver:OWASP_CRS/4.22.0-dev, severity:CRITICAL, chain

#### Rule 7: Unknown
- **Phase**: Unknown
- **Variables**: MATCHED_VARS
- **Operator**: @rx
- **Pattern**: (?:runtime|processbuilder)
- **Is Chain**: False
- **Message**: 
- **Severity**: 
- **Actions**: setvar:tx.rce_score=+%{tx.critical_anomaly_score}, setvar:tx.inbound_anomaly_score_pl1=+%{tx.critical_anomaly_score}

#### Rule 8: 944130
- **Phase**: 2
- **Variables**: ARGS, ARGS_NAMES, REQUEST_COOKIES, REQUEST_COOKIES_NAMES, REQUEST_BODY, REQUEST_FILENAME, REQUEST_HEADERS, XML:/*, XML://@*
- **Operator**: @pmFromFile
- **Pattern**: java-classes.data
- **Is Chain**: False
- **Message**: Suspicious Java class detected
- **Severity**: CRITICAL
- **Tags**: application-multi, language-java, platform-multi, attack-rce, paranoia-level/1, OWASP_CRS, OWASP_CRS/ATTACK-JAVA, capec/1000/152/248
- **Actions**: id:944130, phase:2, block, t:none, msg:Suspicious Java class detected, logdata:Matched Data: %{MATCHED_VAR} found within %{MATCHED_VAR_NAME}, tag:application-multi, tag:language-java, tag:platform-multi, tag:attack-rce, tag:paranoia-level/1, tag:OWASP_CRS, tag:OWASP_CRS/ATTACK-JAVA, tag:capec/1000/152/248, ver:OWASP_CRS/4.22.0-dev, severity:CRITICAL, setvar:tx.rce_score=+%{tx.critical_anomaly_score}, setvar:tx.inbound_anomaly_score_pl1=+%{tx.critical_anomaly_score}

#### Rule 9: 944140
- **Phase**: 2
- **Variables**: FILES, REQUEST_HEADERS:X-Filename, REQUEST_HEADERS:X_Filename, REQUEST_HEADERS:X.Filename, REQUEST_HEADERS:X-File-Name
- **Operator**: @rx
- **Pattern**: .*\.(?:jsp|jspx)\.*$
- **Is Chain**: False
- **Message**: Java Injection Attack: Java Script File Upload Found
- **Severity**: CRITICAL
- **Tags**: application-multi, language-java, platform-multi, attack-injection-java, paranoia-level/1, OWASP_CRS, OWASP_CRS/ATTACK-JAVA, capec/1000/152/242
- **Actions**: id:944140, phase:2, block, capture, t:none, t:lowercase, msg:Java Injection Attack: Java Script File Upload Found, logdata:Matched Data: %{TX.0} found within %{MATCHED_VAR_NAME}: %{MATCHED_VAR}, tag:application-multi, tag:language-java, tag:platform-multi, tag:attack-injection-java, tag:paranoia-level/1, tag:OWASP_CRS, tag:OWASP_CRS/ATTACK-JAVA, tag:capec/1000/152/242, ver:OWASP_CRS/4.22.0-dev, severity:CRITICAL, setvar:tx.rce_score=+%{tx.critical_anomaly_score}, setvar:tx.inbound_anomaly_score_pl1=+%{tx.critical_anomaly_score}

#### Rule 10: 944150
- **Phase**: 2
- **Variables**: REQUEST_LINE, ARGS, ARGS_NAMES, REQUEST_COOKIES, REQUEST_COOKIES_NAMES, REQUEST_HEADERS, XML:/*, XML://@*
- **Operator**: @rx
- **Pattern**: (?i)(?:\$|&dollar;?)(?:\{|&l(?:brace|cub);?)(?:[^\}]{0,15}(?:\$|&dollar;?)(?:\{|&l(?:brace|cub);?)|jndi|ctx)
- **Is Chain**: False
- **Message**: Potential Remote Command Execution: Log4j / Log4shell
- **Severity**: CRITICAL
- **Tags**: application-multi, language-java, platform-multi, attack-rce, paranoia-level/1, OWASP_CRS, OWASP_CRS/ATTACK-JAVA, capec/1000/152/137/6
- **Actions**: id:944150, phase:2, block, t:none, t:urlDecodeUni, t:jsDecode, t:htmlEntityDecode, log, msg:Potential Remote Command Execution: Log4j / Log4shell, tag:application-multi, tag:language-java, tag:platform-multi, tag:attack-rce, tag:paranoia-level/1, tag:OWASP_CRS, tag:OWASP_CRS/ATTACK-JAVA, tag:capec/1000/152/137/6, ver:OWASP_CRS/4.22.0-dev, severity:CRITICAL, setvar:tx.rce_score=+%{tx.critical_anomaly_score}, setvar:tx.inbound_anomaly_score_pl1=+%{tx.critical_anomaly_score}

#### Rule 11: 944013
- **Phase**: 1
- **Variables**: TX:DETECTION_PARANOIA_LEVEL
- **Operator**: @lt
- **Pattern**: 2
- **Is Chain**: False
- **Message**: 
- **Severity**: 
- **Tags**: OWASP_CRS
- **Actions**: id:944013, phase:1, pass, nolog, tag:OWASP_CRS, ver:OWASP_CRS/4.22.0-dev, skipAfter:END-REQUEST-944-APPLICATION-ATTACK-JAVA

#### Rule 12: 944014
- **Phase**: 2
- **Variables**: TX:DETECTION_PARANOIA_LEVEL
- **Operator**: @lt
- **Pattern**: 2
- **Is Chain**: False
- **Message**: 
- **Severity**: 
- **Tags**: OWASP_CRS
- **Actions**: id:944014, phase:2, pass, nolog, tag:OWASP_CRS, ver:OWASP_CRS/4.22.0-dev, skipAfter:END-REQUEST-944-APPLICATION-ATTACK-JAVA

#### Rule 13: 944151
- **Phase**: 2
- **Variables**: REQUEST_LINE, ARGS, ARGS_NAMES, REQUEST_COOKIES, REQUEST_COOKIES_NAMES, REQUEST_HEADERS, XML:/*, XML://@*
- **Operator**: @rx
- **Pattern**: (?i)(?:\$|&dollar;?)(?:\{|&l(?:brace|cub);?)(?:[^\}]*(?:\$|&dollar;?)(?:\{|&l(?:brace|cub);?)|jndi|ctx)
- **Is Chain**: False
- **Message**: Potential Remote Command Execution: Log4j / Log4shell
- **Severity**: CRITICAL
- **Tags**: application-multi, language-java, platform-multi, attack-rce, paranoia-level/2, OWASP_CRS, OWASP_CRS/ATTACK-JAVA, capec/1000/152/137/6
- **Actions**: id:944151, phase:2, block, t:none, t:urlDecodeUni, t:jsDecode, t:htmlEntityDecode, log, msg:Potential Remote Command Execution: Log4j / Log4shell, tag:application-multi, tag:language-java, tag:platform-multi, tag:attack-rce, tag:paranoia-level/2, tag:OWASP_CRS, tag:OWASP_CRS/ATTACK-JAVA, tag:capec/1000/152/137/6, ver:OWASP_CRS/4.22.0-dev, severity:CRITICAL, setvar:tx.rce_score=+%{tx.critical_anomaly_score}, setvar:tx.inbound_anomaly_score_pl2=+%{tx.critical_anomaly_score}

#### Rule 14: 944200
- **Phase**: 2
- **Variables**: ARGS, ARGS_NAMES, REQUEST_COOKIES, REQUEST_COOKIES_NAMES, REQUEST_BODY, REQUEST_HEADERS, XML:/*, XML://@*
- **Operator**: @rx
- **Pattern**: \xac\xed\x00\x05
- **Is Chain**: False
- **Message**: Magic bytes Detected, probable java serialization in use
- **Severity**: CRITICAL
- **Tags**: application-multi, language-java, platform-multi, attack-rce, paranoia-level/2, OWASP_CRS, OWASP_CRS/ATTACK-JAVA, capec/1000/152/248
- **Actions**: id:944200, phase:2, block, msg:Magic bytes Detected, probable java serialization in use, logdata:Matched Data: %{MATCHED_VAR} found within %{MATCHED_VAR_NAME}, tag:application-multi, tag:language-java, tag:platform-multi, tag:attack-rce, tag:paranoia-level/2, tag:OWASP_CRS, tag:OWASP_CRS/ATTACK-JAVA, tag:capec/1000/152/248, ver:OWASP_CRS/4.22.0-dev, severity:CRITICAL, setvar:tx.rce_score=+%{tx.critical_anomaly_score}, setvar:tx.inbound_anomaly_score_pl2=+%{tx.critical_anomaly_score}

#### Rule 15: 944210
- **Phase**: 2
- **Variables**: ARGS, ARGS_NAMES, REQUEST_COOKIES, REQUEST_COOKIES_NAMES, REQUEST_BODY, REQUEST_HEADERS, XML:/*, XML://@*
- **Operator**: @rx
- **Pattern**: (?:rO0ABQ|KztAAU|Cs7QAF)
- **Is Chain**: False
- **Message**: Magic bytes Detected Base64 Encoded, probable java serialization in use
- **Severity**: CRITICAL
- **Tags**: application-multi, language-java, platform-multi, attack-rce, paranoia-level/2, OWASP_CRS, OWASP_CRS/ATTACK-JAVA, capec/1000/152/248
- **Actions**: id:944210, phase:2, block, msg:Magic bytes Detected Base64 Encoded, probable java serialization in use, logdata:Matched Data: %{MATCHED_VAR} found within %{MATCHED_VAR_NAME}, tag:application-multi, tag:language-java, tag:platform-multi, tag:attack-rce, tag:paranoia-level/2, tag:OWASP_CRS, tag:OWASP_CRS/ATTACK-JAVA, tag:capec/1000/152/248, ver:OWASP_CRS/4.22.0-dev, severity:CRITICAL, setvar:tx.rce_score=+%{tx.critical_anomaly_score}, setvar:tx.inbound_anomaly_score_pl2=+%{tx.critical_anomaly_score}

#### Rule 16: 944240
- **Phase**: 2
- **Variables**: ARGS, ARGS_NAMES, REQUEST_COOKIES, REQUEST_COOKIES_NAMES, REQUEST_BODY, REQUEST_HEADERS, XML:/*, XML://@*
- **Operator**: @rx
- **Pattern**: (?:clonetransformer|forclosure|instantiatefactory|instantiatetransformer|invokertransformer|prototypeclonefactory|prototypeserializationfactory|whileclosure|getproperty|filewriter|xmldecoder)
- **Is Chain**: False
- **Message**: Remote Command Execution: Java serialization (CVE-2015-4852)
- **Severity**: CRITICAL
- **Tags**: application-multi, language-java, platform-multi, attack-rce, paranoia-level/2, OWASP_CRS, OWASP_CRS/ATTACK-JAVA, capec/1000/152/248
- **Actions**: id:944240, phase:2, block, t:none, t:lowercase, msg:Remote Command Execution: Java serialization (CVE-2015-4852), logdata:Matched Data: %{MATCHED_VAR} found within %{MATCHED_VAR_NAME}, tag:application-multi, tag:language-java, tag:platform-multi, tag:attack-rce, tag:paranoia-level/2, tag:OWASP_CRS, tag:OWASP_CRS/ATTACK-JAVA, tag:capec/1000/152/248, ver:OWASP_CRS/4.22.0-dev, severity:CRITICAL, setvar:tx.rce_score=+%{tx.critical_anomaly_score}, setvar:tx.inbound_anomaly_score_pl2=+%{tx.critical_anomaly_score}

#### Rule 17: 944250
- **Phase**: 2
- **Variables**: ARGS, ARGS_NAMES, REQUEST_COOKIES, REQUEST_COOKIES_NAMES, REQUEST_BODY, REQUEST_HEADERS, XML:/*, XML://@*
- **Operator**: @rx
- **Pattern**: java\b.+(?:runtime|processbuilder)
- **Is Chain**: False
- **Message**: Remote Command Execution: Suspicious Java method detected
- **Severity**: CRITICAL
- **Tags**: application-multi, language-java, platform-multi, attack-rce, paranoia-level/2, OWASP_CRS, OWASP_CRS/ATTACK-JAVA, capec/1000/152/248
- **Actions**: id:944250, phase:2, block, t:lowercase, msg:Remote Command Execution: Suspicious Java method detected, logdata:Matched Data: %{MATCHED_VAR} found within %{MATCHED_VAR_NAME}, tag:application-multi, tag:language-java, tag:platform-multi, tag:attack-rce, tag:paranoia-level/2, tag:OWASP_CRS, tag:OWASP_CRS/ATTACK-JAVA, tag:capec/1000/152/248, ver:OWASP_CRS/4.22.0-dev, severity:CRITICAL, setvar:tx.rce_score=+%{tx.critical_anomaly_score}, setvar:tx.inbound_anomaly_score_pl2=+%{tx.critical_anomaly_score}

#### Rule 18: 944260
- **Phase**: 2
- **Variables**: ARGS, ARGS_NAMES, REQUEST_COOKIES, REQUEST_COOKIES_NAMES, REQUEST_BODY, REQUEST_HEADERS, XML:/*, XML://@*
- **Operator**: @rx
- **Pattern**: (?:class\.module\.classLoader\.resources\.context\.parent\.pipeline|springframework\.context\.support\.FileSystemXmlApplicationContext)
- **Is Chain**: False
- **Message**: Remote Command Execution: Malicious class-loading payload
- **Severity**: CRITICAL
- **Tags**: application-multi, language-java, platform-multi, attack-rce, paranoia-level/2, OWASP_CRS, OWASP_CRS/ATTACK-JAVA, capec/1000/152/248
- **Actions**: id:944260, phase:2, block, t:urlDecodeUni, msg:Remote Command Execution: Malicious class-loading payload, logdata:Matched Data: %{MATCHED_VAR} found within %{MATCHED_VAR_NAME}, tag:application-multi, tag:language-java, tag:platform-multi, tag:attack-rce, tag:paranoia-level/2, tag:OWASP_CRS, tag:OWASP_CRS/ATTACK-JAVA, tag:capec/1000/152/248, ver:OWASP_CRS/4.22.0-dev, severity:CRITICAL, setvar:tx.rce_score=+%{tx.critical_anomaly_score}, setvar:tx.inbound_anomaly_score_pl2=+%{tx.critical_anomaly_score}

#### Rule 19: 944015
- **Phase**: 1
- **Variables**: TX:DETECTION_PARANOIA_LEVEL
- **Operator**: @lt
- **Pattern**: 3
- **Is Chain**: False
- **Message**: 
- **Severity**: 
- **Tags**: OWASP_CRS
- **Actions**: id:944015, phase:1, pass, nolog, tag:OWASP_CRS, ver:OWASP_CRS/4.22.0-dev, skipAfter:END-REQUEST-944-APPLICATION-ATTACK-JAVA

#### Rule 20: 944016
- **Phase**: 2
- **Variables**: TX:DETECTION_PARANOIA_LEVEL
- **Operator**: @lt
- **Pattern**: 3
- **Is Chain**: False
- **Message**: 
- **Severity**: 
- **Tags**: OWASP_CRS
- **Actions**: id:944016, phase:2, pass, nolog, tag:OWASP_CRS, ver:OWASP_CRS/4.22.0-dev, skipAfter:END-REQUEST-944-APPLICATION-ATTACK-JAVA

#### Rule 21: 944300
- **Phase**: 2
- **Variables**: ARGS, ARGS_NAMES, REQUEST_COOKIES, REQUEST_COOKIES_NAMES, REQUEST_BODY, REQUEST_HEADERS, XML:/*, XML://@*
- **Operator**: @rx
- **Pattern**: (?:cnVudGltZQ|HJ1bnRpbWU|BydW50aW1l|cHJvY2Vzc2J1aWxkZXI|HByb2Nlc3NidWlsZGVy|Bwcm9jZXNzYnVpbGRlcg|Y2xvbmV0cmFuc2Zvcm1lcg|GNsb25ldHJhbnNmb3JtZXI|BjbG9uZXRyYW5zZm9ybWVy|Zm9yY2xvc3VyZQ|GZvcmNsb3N1cmU|Bmb3JjbG9zdXJl|aW5zdGFudGlhdGVmYWN0b3J5|Gluc3RhbnRpYXRlZmFjdG9yeQ|BpbnN0YW50aWF0ZWZhY3Rvcnk|aW5zdGFudGlhdGV0cmFuc2Zvcm1lcg|Gluc3RhbnRpYXRldHJhbnNmb3JtZXI|BpbnN0YW50aWF0ZXRyYW5zZm9ybWVy|aW52b2tlcnRyYW5zZm9ybWVy|Gludm9rZXJ0cmFuc2Zvcm1lcg|BpbnZva2VydHJhbnNmb3JtZXI|cHJvdG90eXBlY2xvbmVmYWN0b3J5|HByb3RvdHlwZWNsb25lZmFjdG9yeQ|Bwcm90b3R5cGVjbG9uZWZhY3Rvcnk|cHJvdG90eXBlc2VyaWFsaXphdGlvbmZhY3Rvcnk|HByb3RvdHlwZXNlcmlhbGl6YXRpb25mYWN0b3J5|Bwcm90b3R5cGVzZXJpYWxpemF0aW9uZmFjdG9yeQ|d2hpbGVjbG9zdXJl|HdoaWxlY2xvc3VyZQ|B3aGlsZWNsb3N1cmU)
- **Is Chain**: False
- **Message**: Base64 encoded string matched suspicious keyword
- **Severity**: CRITICAL
- **Tags**: application-multi, language-java, platform-multi, attack-rce, paranoia-level/3, OWASP_CRS, OWASP_CRS/ATTACK-JAVA, capec/1000/152/248
- **Actions**: id:944300, phase:2, block, t:none, msg:Base64 encoded string matched suspicious keyword, logdata:Matched Data: %{MATCHED_VAR} found within %{MATCHED_VAR_NAME}, tag:application-multi, tag:language-java, tag:platform-multi, tag:attack-rce, tag:paranoia-level/3, tag:OWASP_CRS, tag:OWASP_CRS/ATTACK-JAVA, tag:capec/1000/152/248, ver:OWASP_CRS/4.22.0-dev, severity:CRITICAL, setvar:tx.rce_score=+%{tx.critical_anomaly_score}, setvar:tx.inbound_anomaly_score_pl3=+%{tx.critical_anomaly_score}

#### Rule 22: 944017
- **Phase**: 1
- **Variables**: TX:DETECTION_PARANOIA_LEVEL
- **Operator**: @lt
- **Pattern**: 4
- **Is Chain**: False
- **Message**: 
- **Severity**: 
- **Tags**: OWASP_CRS
- **Actions**: id:944017, phase:1, pass, nolog, tag:OWASP_CRS, ver:OWASP_CRS/4.22.0-dev, skipAfter:END-REQUEST-944-APPLICATION-ATTACK-JAVA

#### Rule 23: 944018
- **Phase**: 2
- **Variables**: TX:DETECTION_PARANOIA_LEVEL
- **Operator**: @lt
- **Pattern**: 4
- **Is Chain**: False
- **Message**: 
- **Severity**: 
- **Tags**: OWASP_CRS
- **Actions**: id:944018, phase:2, pass, nolog, tag:OWASP_CRS, ver:OWASP_CRS/4.22.0-dev, skipAfter:END-REQUEST-944-APPLICATION-ATTACK-JAVA

#### Rule 24: 944152
- **Phase**: 2
- **Variables**: REQUEST_LINE, ARGS, ARGS_NAMES, REQUEST_COOKIES, REQUEST_COOKIES_NAMES, REQUEST_HEADERS, XML:/*, XML://@*
- **Operator**: @rx
- **Pattern**: (?i)(?:\$|&dollar;?)(?:\{|&l(?:brace|cub);?)
- **Is Chain**: False
- **Message**: Potential Remote Command Execution: Log4j / Log4shell
- **Severity**: CRITICAL
- **Tags**: application-multi, language-java, platform-multi, attack-rce, paranoia-level/4, OWASP_CRS, OWASP_CRS/ATTACK-JAVA, capec/1000/152/137/6
- **Actions**: id:944152, phase:2, block, t:none, t:urlDecodeUni, t:jsDecode, t:htmlEntityDecode, log, msg:Potential Remote Command Execution: Log4j / Log4shell, tag:application-multi, tag:language-java, tag:platform-multi, tag:attack-rce, tag:paranoia-level/4, tag:OWASP_CRS, tag:OWASP_CRS/ATTACK-JAVA, tag:capec/1000/152/137/6, ver:OWASP_CRS/4.22.0-dev, severity:CRITICAL, setvar:tx.rce_score=+%{tx.critical_anomaly_score}, setvar:tx.inbound_anomaly_score_pl4=+%{tx.critical_anomaly_score}


====================================================================================================

## File: REQUEST-949-BLOCKING-EVALUATION.conf

### File Summary
- Total rules: 27
- Chained rules: 1
- Non-chained rules: 26

### Detailed Rules

#### Rule 1: 949052
- **Phase**: 1
- **Variables**: TX:BLOCKING_PARANOIA_LEVEL
- **Operator**: @ge
- **Pattern**: 1
- **Is Chain**: False
- **Message**: 
- **Severity**: 
- **Tags**: OWASP_CRS
- **Actions**: id:949052, phase:1, pass, t:none, nolog, tag:OWASP_CRS, ver:OWASP_CRS/4.22.0-dev, setvar:tx.blocking_inbound_anomaly_score=+%{tx.inbound_anomaly_score_pl1}

#### Rule 2: 949152
- **Phase**: 1
- **Variables**: TX:DETECTION_PARANOIA_LEVEL
- **Operator**: @ge
- **Pattern**: 1
- **Is Chain**: False
- **Message**: 
- **Severity**: 
- **Tags**: OWASP_CRS
- **Actions**: id:949152, phase:1, pass, t:none, nolog, tag:OWASP_CRS, ver:OWASP_CRS/4.22.0-dev, setvar:tx.detection_inbound_anomaly_score=+%{tx.inbound_anomaly_score_pl1}

#### Rule 3: 949053
- **Phase**: 1
- **Variables**: TX:BLOCKING_PARANOIA_LEVEL
- **Operator**: @ge
- **Pattern**: 2
- **Is Chain**: False
- **Message**: 
- **Severity**: 
- **Tags**: OWASP_CRS
- **Actions**: id:949053, phase:1, pass, t:none, nolog, tag:OWASP_CRS, ver:OWASP_CRS/4.22.0-dev, setvar:tx.blocking_inbound_anomaly_score=+%{tx.inbound_anomaly_score_pl2}

#### Rule 4: 949153
- **Phase**: 1
- **Variables**: TX:DETECTION_PARANOIA_LEVEL
- **Operator**: @ge
- **Pattern**: 2
- **Is Chain**: False
- **Message**: 
- **Severity**: 
- **Tags**: OWASP_CRS
- **Actions**: id:949153, phase:1, pass, t:none, nolog, tag:OWASP_CRS, ver:OWASP_CRS/4.22.0-dev, setvar:tx.detection_inbound_anomaly_score=+%{tx.inbound_anomaly_score_pl2}

#### Rule 5: 949054
- **Phase**: 1
- **Variables**: TX:BLOCKING_PARANOIA_LEVEL
- **Operator**: @ge
- **Pattern**: 3
- **Is Chain**: False
- **Message**: 
- **Severity**: 
- **Tags**: OWASP_CRS
- **Actions**: id:949054, phase:1, pass, t:none, nolog, tag:OWASP_CRS, ver:OWASP_CRS/4.22.0-dev, setvar:tx.blocking_inbound_anomaly_score=+%{tx.inbound_anomaly_score_pl3}

#### Rule 6: 949154
- **Phase**: 1
- **Variables**: TX:DETECTION_PARANOIA_LEVEL
- **Operator**: @ge
- **Pattern**: 3
- **Is Chain**: False
- **Message**: 
- **Severity**: 
- **Tags**: OWASP_CRS
- **Actions**: id:949154, phase:1, pass, t:none, nolog, tag:OWASP_CRS, ver:OWASP_CRS/4.22.0-dev, setvar:tx.detection_inbound_anomaly_score=+%{tx.inbound_anomaly_score_pl3}

#### Rule 7: 949055
- **Phase**: 1
- **Variables**: TX:BLOCKING_PARANOIA_LEVEL
- **Operator**: @ge
- **Pattern**: 4
- **Is Chain**: False
- **Message**: 
- **Severity**: 
- **Tags**: OWASP_CRS
- **Actions**: id:949055, phase:1, pass, t:none, nolog, tag:OWASP_CRS, ver:OWASP_CRS/4.22.0-dev, setvar:tx.blocking_inbound_anomaly_score=+%{tx.inbound_anomaly_score_pl4}

#### Rule 8: 949155
- **Phase**: 1
- **Variables**: TX:DETECTION_PARANOIA_LEVEL
- **Operator**: @ge
- **Pattern**: 4
- **Is Chain**: False
- **Message**: 
- **Severity**: 
- **Tags**: OWASP_CRS
- **Actions**: id:949155, phase:1, pass, t:none, nolog, tag:OWASP_CRS, ver:OWASP_CRS/4.22.0-dev, setvar:tx.detection_inbound_anomaly_score=+%{tx.inbound_anomaly_score_pl4}

#### Rule 9: 949060
- **Phase**: 2
- **Variables**: TX:BLOCKING_PARANOIA_LEVEL
- **Operator**: @ge
- **Pattern**: 1
- **Is Chain**: False
- **Message**: 
- **Severity**: 
- **Tags**: OWASP_CRS
- **Actions**: id:949060, phase:2, pass, t:none, nolog, tag:OWASP_CRS, ver:OWASP_CRS/4.22.0-dev, setvar:tx.blocking_inbound_anomaly_score=+%{tx.inbound_anomaly_score_pl1}

#### Rule 10: 949160
- **Phase**: 2
- **Variables**: TX:DETECTION_PARANOIA_LEVEL
- **Operator**: @ge
- **Pattern**: 1
- **Is Chain**: False
- **Message**: 
- **Severity**: 
- **Tags**: OWASP_CRS
- **Actions**: id:949160, phase:2, pass, t:none, nolog, tag:OWASP_CRS, ver:OWASP_CRS/4.22.0-dev, setvar:tx.detection_inbound_anomaly_score=+%{tx.inbound_anomaly_score_pl1}

#### Rule 11: 949061
- **Phase**: 2
- **Variables**: TX:BLOCKING_PARANOIA_LEVEL
- **Operator**: @ge
- **Pattern**: 2
- **Is Chain**: False
- **Message**: 
- **Severity**: 
- **Tags**: OWASP_CRS
- **Actions**: id:949061, phase:2, pass, t:none, nolog, tag:OWASP_CRS, ver:OWASP_CRS/4.22.0-dev, setvar:tx.blocking_inbound_anomaly_score=+%{tx.inbound_anomaly_score_pl2}

#### Rule 12: 949161
- **Phase**: 2
- **Variables**: TX:DETECTION_PARANOIA_LEVEL
- **Operator**: @ge
- **Pattern**: 2
- **Is Chain**: False
- **Message**: 
- **Severity**: 
- **Tags**: OWASP_CRS
- **Actions**: id:949161, phase:2, pass, t:none, nolog, tag:OWASP_CRS, ver:OWASP_CRS/4.22.0-dev, setvar:tx.detection_inbound_anomaly_score=+%{tx.inbound_anomaly_score_pl2}

#### Rule 13: 949062
- **Phase**: 2
- **Variables**: TX:BLOCKING_PARANOIA_LEVEL
- **Operator**: @ge
- **Pattern**: 3
- **Is Chain**: False
- **Message**: 
- **Severity**: 
- **Tags**: OWASP_CRS
- **Actions**: id:949062, phase:2, pass, t:none, nolog, tag:OWASP_CRS, ver:OWASP_CRS/4.22.0-dev, setvar:tx.blocking_inbound_anomaly_score=+%{tx.inbound_anomaly_score_pl3}

#### Rule 14: 949162
- **Phase**: 2
- **Variables**: TX:DETECTION_PARANOIA_LEVEL
- **Operator**: @ge
- **Pattern**: 3
- **Is Chain**: False
- **Message**: 
- **Severity**: 
- **Tags**: OWASP_CRS
- **Actions**: id:949162, phase:2, pass, t:none, nolog, tag:OWASP_CRS, ver:OWASP_CRS/4.22.0-dev, setvar:tx.detection_inbound_anomaly_score=+%{tx.inbound_anomaly_score_pl3}

#### Rule 15: 949063
- **Phase**: 2
- **Variables**: TX:BLOCKING_PARANOIA_LEVEL
- **Operator**: @ge
- **Pattern**: 4
- **Is Chain**: False
- **Message**: 
- **Severity**: 
- **Tags**: OWASP_CRS
- **Actions**: id:949063, phase:2, pass, t:none, nolog, tag:OWASP_CRS, ver:OWASP_CRS/4.22.0-dev, setvar:tx.blocking_inbound_anomaly_score=+%{tx.inbound_anomaly_score_pl4}

#### Rule 16: 949163
- **Phase**: 2
- **Variables**: TX:DETECTION_PARANOIA_LEVEL
- **Operator**: @ge
- **Pattern**: 4
- **Is Chain**: False
- **Message**: 
- **Severity**: 
- **Tags**: OWASP_CRS
- **Actions**: id:949163, phase:2, pass, t:none, nolog, tag:OWASP_CRS, ver:OWASP_CRS/4.22.0-dev, setvar:tx.detection_inbound_anomaly_score=+%{tx.inbound_anomaly_score_pl4}

#### Rule 17: 949111
- **Phase**: 1
- **Variables**: TX:BLOCKING_INBOUND_ANOMALY_SCORE
- **Operator**: @ge
- **Pattern**: %{tx.inbound_anomaly_score_threshold}
- **Is Chain**: True
- **Message**: Inbound Anomaly Score Exceeded in phase 1 (Total Score: %{TX.BLOCKING_INBOUND_ANOMALY_SCORE})
- **Severity**: 
- **Tags**: anomaly-evaluation, OWASP_CRS
- **Actions**: id:949111, phase:1, deny, t:none, msg:Inbound Anomaly Score Exceeded in phase 1 (Total Score: %{TX.BLOCKING_INBOUND_ANOMALY_SCORE}), tag:anomaly-evaluation, tag:OWASP_CRS, ver:OWASP_CRS/4.22.0-dev, chain

#### Rule 18: Unknown
- **Phase**: Unknown
- **Variables**: TX:EARLY_BLOCKING
- **Operator**: @eq
- **Pattern**: 1
- **Is Chain**: False
- **Message**: 
- **Severity**: 

#### Rule 19: 949110
- **Phase**: 2
- **Variables**: TX:BLOCKING_INBOUND_ANOMALY_SCORE
- **Operator**: @ge
- **Pattern**: %{tx.inbound_anomaly_score_threshold}
- **Is Chain**: False
- **Message**: Inbound Anomaly Score Exceeded (Total Score: %{TX.BLOCKING_INBOUND_ANOMALY_SCORE})
- **Severity**: 
- **Tags**: anomaly-evaluation, OWASP_CRS
- **Actions**: id:949110, phase:2, deny, t:none, msg:Inbound Anomaly Score Exceeded (Total Score: %{TX.BLOCKING_INBOUND_ANOMALY_SCORE}), tag:anomaly-evaluation, tag:OWASP_CRS, ver:OWASP_CRS/4.22.0-dev

#### Rule 20: 949011
- **Phase**: 1
- **Variables**: TX:DETECTION_PARANOIA_LEVEL
- **Operator**: @lt
- **Pattern**: 1
- **Is Chain**: False
- **Message**: 
- **Severity**: 
- **Tags**: OWASP_CRS
- **Actions**: id:949011, phase:1, pass, nolog, tag:OWASP_CRS, ver:OWASP_CRS/4.22.0-dev, skipAfter:END-REQUEST-949-BLOCKING-EVALUATION

#### Rule 21: 949012
- **Phase**: 2
- **Variables**: TX:DETECTION_PARANOIA_LEVEL
- **Operator**: @lt
- **Pattern**: 1
- **Is Chain**: False
- **Message**: 
- **Severity**: 
- **Tags**: OWASP_CRS
- **Actions**: id:949012, phase:2, pass, nolog, tag:OWASP_CRS, ver:OWASP_CRS/4.22.0-dev, skipAfter:END-REQUEST-949-BLOCKING-EVALUATION

#### Rule 22: 949013
- **Phase**: 1
- **Variables**: TX:DETECTION_PARANOIA_LEVEL
- **Operator**: @lt
- **Pattern**: 2
- **Is Chain**: False
- **Message**: 
- **Severity**: 
- **Tags**: OWASP_CRS
- **Actions**: id:949013, phase:1, pass, nolog, tag:OWASP_CRS, ver:OWASP_CRS/4.22.0-dev, skipAfter:END-REQUEST-949-BLOCKING-EVALUATION

#### Rule 23: 949014
- **Phase**: 2
- **Variables**: TX:DETECTION_PARANOIA_LEVEL
- **Operator**: @lt
- **Pattern**: 2
- **Is Chain**: False
- **Message**: 
- **Severity**: 
- **Tags**: OWASP_CRS
- **Actions**: id:949014, phase:2, pass, nolog, tag:OWASP_CRS, ver:OWASP_CRS/4.22.0-dev, skipAfter:END-REQUEST-949-BLOCKING-EVALUATION

#### Rule 24: 949015
- **Phase**: 1
- **Variables**: TX:DETECTION_PARANOIA_LEVEL
- **Operator**: @lt
- **Pattern**: 3
- **Is Chain**: False
- **Message**: 
- **Severity**: 
- **Tags**: OWASP_CRS
- **Actions**: id:949015, phase:1, pass, nolog, tag:OWASP_CRS, ver:OWASP_CRS/4.22.0-dev, skipAfter:END-REQUEST-949-BLOCKING-EVALUATION

#### Rule 25: 949016
- **Phase**: 2
- **Variables**: TX:DETECTION_PARANOIA_LEVEL
- **Operator**: @lt
- **Pattern**: 3
- **Is Chain**: False
- **Message**: 
- **Severity**: 
- **Tags**: OWASP_CRS
- **Actions**: id:949016, phase:2, pass, nolog, tag:OWASP_CRS, ver:OWASP_CRS/4.22.0-dev, skipAfter:END-REQUEST-949-BLOCKING-EVALUATION

#### Rule 26: 949017
- **Phase**: 1
- **Variables**: TX:DETECTION_PARANOIA_LEVEL
- **Operator**: @lt
- **Pattern**: 4
- **Is Chain**: False
- **Message**: 
- **Severity**: 
- **Tags**: OWASP_CRS
- **Actions**: id:949017, phase:1, pass, nolog, tag:OWASP_CRS, ver:OWASP_CRS/4.22.0-dev, skipAfter:END-REQUEST-949-BLOCKING-EVALUATION

#### Rule 27: 949018
- **Phase**: 2
- **Variables**: TX:DETECTION_PARANOIA_LEVEL
- **Operator**: @lt
- **Pattern**: 4
- **Is Chain**: False
- **Message**: 
- **Severity**: 
- **Tags**: OWASP_CRS
- **Actions**: id:949018, phase:2, pass, nolog, tag:OWASP_CRS, ver:OWASP_CRS/4.22.0-dev, skipAfter:END-REQUEST-949-BLOCKING-EVALUATION


====================================================================================================

## File: RESPONSE-950-DATA-LEAKAGES.conf

### File Summary
- Total rules: 14
- Chained rules: 0
- Non-chained rules: 14

### Detailed Rules

#### Rule 1: 950021
- **Phase**: 3
- **Variables**: TX:crs_skip_response_analysis
- **Operator**: @eq
- **Pattern**: 1
- **Is Chain**: False
- **Message**: 
- **Severity**: 
- **Tags**: OWASP_CRS, OWASP_CRS/DATA-LEAKAGES
- **Actions**: id:950021, phase:3, pass, nolog, tag:OWASP_CRS, tag:OWASP_CRS/DATA-LEAKAGES, ver:OWASP_CRS/4.22.0-dev, skipAfter:END-RESPONSE-959-BLOCKING-EVALUATION

#### Rule 2: 950010
- **Phase**: 4
- **Variables**: RESPONSE_HEADERS:Content-Encoding
- **Operator**: @pm
- **Pattern**: gzip compress deflate br zstd
- **Is Chain**: False
- **Message**: 
- **Severity**: 
- **Tags**: OWASP_CRS, OWASP_CRS/DATA-LEAKAGES
- **Actions**: id:950010, phase:4, pass, nolog, tag:OWASP_CRS, tag:OWASP_CRS/DATA-LEAKAGES, ver:OWASP_CRS/4.22.0-dev, skipAfter:END-RESPONSE-950-DATA-LEAKAGES

#### Rule 3: 950011
- **Phase**: 3
- **Variables**: TX:DETECTION_PARANOIA_LEVEL
- **Operator**: @lt
- **Pattern**: 1
- **Is Chain**: False
- **Message**: 
- **Severity**: 
- **Tags**: OWASP_CRS
- **Actions**: id:950011, phase:3, pass, nolog, tag:OWASP_CRS, ver:OWASP_CRS/4.22.0-dev, skipAfter:END-RESPONSE-950-DATA-LEAKAGES

#### Rule 4: 950012
- **Phase**: 4
- **Variables**: TX:DETECTION_PARANOIA_LEVEL
- **Operator**: @lt
- **Pattern**: 1
- **Is Chain**: False
- **Message**: 
- **Severity**: 
- **Tags**: OWASP_CRS
- **Actions**: id:950012, phase:4, pass, nolog, tag:OWASP_CRS, ver:OWASP_CRS/4.22.0-dev, skipAfter:END-RESPONSE-950-DATA-LEAKAGES

#### Rule 5: 950130
- **Phase**: 4
- **Variables**: RESPONSE_BODY
- **Operator**: @rx
- **Pattern**: (?:<(?:TITLE>Index of.*?<H|title>Index of.*?<h)1>Index of|>\[To Parent Directory\]</[Aa]><br>)
- **Is Chain**: False
- **Message**: Directory Listing
- **Severity**: ERROR
- **Tags**: application-multi, language-multi, platform-multi, attack-disclosure, paranoia-level/1, OWASP_CRS, OWASP_CRS/DATA-LEAKAGES, capec/1000/118/116/54/127
- **Actions**: id:950130, phase:4, block, capture, t:none, msg:Directory Listing, logdata:Matched Data: %{TX.0} found within %{MATCHED_VAR_NAME}, tag:application-multi, tag:language-multi, tag:platform-multi, tag:attack-disclosure, tag:paranoia-level/1, tag:OWASP_CRS, tag:OWASP_CRS/DATA-LEAKAGES, tag:capec/1000/118/116/54/127, ver:OWASP_CRS/4.22.0-dev, severity:ERROR, setvar:tx.outbound_anomaly_score_pl1=+%{tx.error_anomaly_score}

#### Rule 6: 950140
- **Phase**: 4
- **Variables**: RESPONSE_BODY
- **Operator**: @rx
- **Pattern**: ^#\!\s?/
- **Is Chain**: False
- **Message**: CGI source code leakage
- **Severity**: ERROR
- **Tags**: application-multi, language-multi, platform-multi, attack-disclosure, paranoia-level/1, OWASP_CRS, OWASP_CRS/DATA-LEAKAGES, capec/1000/118/116
- **Actions**: id:950140, phase:4, block, capture, t:none, msg:CGI source code leakage, logdata:Matched Data: %{TX.0} found within %{MATCHED_VAR_NAME}, tag:application-multi, tag:language-multi, tag:platform-multi, tag:attack-disclosure, tag:paranoia-level/1, tag:OWASP_CRS, tag:OWASP_CRS/DATA-LEAKAGES, tag:capec/1000/118/116, ver:OWASP_CRS/4.22.0-dev, severity:ERROR, setvar:tx.outbound_anomaly_score_pl1=+%{tx.error_anomaly_score}

#### Rule 7: 950150
- **Phase**: 4
- **Variables**: RESPONSE_BODY
- **Operator**: @pmFromFile
- **Pattern**: asp-dotnet-errors.data
- **Is Chain**: False
- **Message**: ASP.NET exception leakage
- **Severity**: ERROR
- **Tags**: application-multi, language-aspnet, platform-multi, attack-disclosure, paranoia-level/1, OWASP_CRS, OWASP_CRS/DATA-LEAKAGES, capec/1000/118/116/54/127
- **Actions**: id:950150, phase:4, block, capture, t:none, msg:ASP.NET exception leakage, logdata:Matched Data: %{TX.0} found within %{MATCHED_VAR_NAME}, tag:application-multi, tag:language-aspnet, tag:platform-multi, tag:attack-disclosure, tag:paranoia-level/1, tag:OWASP_CRS, tag:OWASP_CRS/DATA-LEAKAGES, tag:capec/1000/118/116/54/127, ver:OWASP_CRS/4.22.0-dev, severity:ERROR, setvar:tx.outbound_anomaly_score_pl1=+%{tx.error_anomaly_score}

#### Rule 8: 950013
- **Phase**: 3
- **Variables**: TX:DETECTION_PARANOIA_LEVEL
- **Operator**: @lt
- **Pattern**: 2
- **Is Chain**: False
- **Message**: 
- **Severity**: 
- **Tags**: OWASP_CRS
- **Actions**: id:950013, phase:3, pass, nolog, tag:OWASP_CRS, ver:OWASP_CRS/4.22.0-dev, skipAfter:END-RESPONSE-950-DATA-LEAKAGES

#### Rule 9: 950014
- **Phase**: 4
- **Variables**: TX:DETECTION_PARANOIA_LEVEL
- **Operator**: @lt
- **Pattern**: 2
- **Is Chain**: False
- **Message**: 
- **Severity**: 
- **Tags**: OWASP_CRS
- **Actions**: id:950014, phase:4, pass, nolog, tag:OWASP_CRS, ver:OWASP_CRS/4.22.0-dev, skipAfter:END-RESPONSE-950-DATA-LEAKAGES

#### Rule 10: 950100
- **Phase**: 3
- **Variables**: RESPONSE_STATUS
- **Operator**: @rx
- **Pattern**: ^5\d{2}$
- **Is Chain**: False
- **Message**: The Application Returned a 500-Level Status Code
- **Severity**: ERROR
- **Tags**: application-multi, language-multi, platform-multi, attack-disclosure, paranoia-level/2, OWASP_CRS, OWASP_CRS/DATA-LEAKAGES, capec/1000/152
- **Actions**: id:950100, phase:3, block, capture, t:none, msg:The Application Returned a 500-Level Status Code, logdata:Matched Data: %{TX.0} found within %{MATCHED_VAR_NAME}, tag:application-multi, tag:language-multi, tag:platform-multi, tag:attack-disclosure, tag:paranoia-level/2, tag:OWASP_CRS, tag:OWASP_CRS/DATA-LEAKAGES, tag:capec/1000/152, ver:OWASP_CRS/4.22.0-dev, severity:ERROR, setvar:tx.outbound_anomaly_score_pl2=+%{tx.error_anomaly_score}

#### Rule 11: 950015
- **Phase**: 3
- **Variables**: TX:DETECTION_PARANOIA_LEVEL
- **Operator**: @lt
- **Pattern**: 3
- **Is Chain**: False
- **Message**: 
- **Severity**: 
- **Tags**: OWASP_CRS
- **Actions**: id:950015, phase:3, pass, nolog, tag:OWASP_CRS, ver:OWASP_CRS/4.22.0-dev, skipAfter:END-RESPONSE-950-DATA-LEAKAGES

#### Rule 12: 950016
- **Phase**: 4
- **Variables**: TX:DETECTION_PARANOIA_LEVEL
- **Operator**: @lt
- **Pattern**: 3
- **Is Chain**: False
- **Message**: 
- **Severity**: 
- **Tags**: OWASP_CRS
- **Actions**: id:950016, phase:4, pass, nolog, tag:OWASP_CRS, ver:OWASP_CRS/4.22.0-dev, skipAfter:END-RESPONSE-950-DATA-LEAKAGES

#### Rule 13: 950017
- **Phase**: 3
- **Variables**: TX:DETECTION_PARANOIA_LEVEL
- **Operator**: @lt
- **Pattern**: 4
- **Is Chain**: False
- **Message**: 
- **Severity**: 
- **Tags**: OWASP_CRS
- **Actions**: id:950017, phase:3, pass, nolog, tag:OWASP_CRS, ver:OWASP_CRS/4.22.0-dev, skipAfter:END-RESPONSE-950-DATA-LEAKAGES

#### Rule 14: 950018
- **Phase**: 4
- **Variables**: TX:DETECTION_PARANOIA_LEVEL
- **Operator**: @lt
- **Pattern**: 4
- **Is Chain**: False
- **Message**: 
- **Severity**: 
- **Tags**: OWASP_CRS
- **Actions**: id:950018, phase:4, pass, nolog, tag:OWASP_CRS, ver:OWASP_CRS/4.22.0-dev, skipAfter:END-RESPONSE-950-DATA-LEAKAGES


====================================================================================================

## File: RESPONSE-951-DATA-LEAKAGES-SQL.conf

### File Summary
- Total rules: 26
- Chained rules: 0
- Non-chained rules: 26

### Detailed Rules

#### Rule 1: 951010
- **Phase**: 4
- **Variables**: RESPONSE_HEADERS:Content-Encoding
- **Operator**: @pm
- **Pattern**: gzip compress deflate br zstd
- **Is Chain**: False
- **Message**: 
- **Severity**: 
- **Tags**: OWASP_CRS, OWASP_CRS/DATA-LEAKAGES-SQL
- **Actions**: id:951010, phase:4, pass, nolog, tag:OWASP_CRS, tag:OWASP_CRS/DATA-LEAKAGES-SQL, ver:OWASP_CRS/4.22.0-dev, skipAfter:END-RESPONSE-951-DATA-LEAKAGES-SQL

#### Rule 2: 951011
- **Phase**: 3
- **Variables**: TX:DETECTION_PARANOIA_LEVEL
- **Operator**: @lt
- **Pattern**: 1
- **Is Chain**: False
- **Message**: 
- **Severity**: 
- **Tags**: OWASP_CRS
- **Actions**: id:951011, phase:3, pass, nolog, tag:OWASP_CRS, ver:OWASP_CRS/4.22.0-dev, skipAfter:END-RESPONSE-951-DATA-LEAKAGES-SQL

#### Rule 3: 951012
- **Phase**: 4
- **Variables**: TX:DETECTION_PARANOIA_LEVEL
- **Operator**: @lt
- **Pattern**: 1
- **Is Chain**: False
- **Message**: 
- **Severity**: 
- **Tags**: OWASP_CRS
- **Actions**: id:951012, phase:4, pass, nolog, tag:OWASP_CRS, ver:OWASP_CRS/4.22.0-dev, skipAfter:END-RESPONSE-951-DATA-LEAKAGES-SQL

#### Rule 4: 951100
- **Phase**: 4
- **Variables**: RESPONSE_BODY
- **Operator**: !@pmFromFile
- **Pattern**: sql-errors.data
- **Is Chain**: False
- **Message**: 
- **Severity**: 
- **Tags**: application-multi, language-multi, platform-multi, attack-disclosure, OWASP_CRS, OWASP_CRS/DATA-LEAKAGES-SQL, capec/1000/118/116/54
- **Actions**: id:951100, phase:4, pass, t:none, nolog, tag:application-multi, tag:language-multi, tag:platform-multi, tag:attack-disclosure, tag:OWASP_CRS, tag:OWASP_CRS/DATA-LEAKAGES-SQL, tag:capec/1000/118/116/54, ver:OWASP_CRS/4.22.0-dev, skipAfter:END-SQL-ERROR-MATCH-PL1

#### Rule 5: 951110
- **Phase**: 4
- **Variables**: RESPONSE_BODY
- **Operator**: @rx
- **Pattern**: (?i:JET Database Engine|Access Database Engine|\[Microsoft\]\[ODBC Microsoft Access Driver\])
- **Is Chain**: False
- **Message**: Microsoft Access SQL Information Leakage
- **Severity**: CRITICAL
- **Tags**: application-multi, language-multi, platform-msaccess, attack-disclosure, paranoia-level/1, OWASP_CRS, OWASP_CRS/DATA-LEAKAGES-SQL, capec/1000/118/116/54
- **Actions**: id:951110, phase:4, block, capture, t:none, msg:Microsoft Access SQL Information Leakage, logdata:Matched Data: %{TX.0} found within %{MATCHED_VAR_NAME}, tag:application-multi, tag:language-multi, tag:platform-msaccess, tag:attack-disclosure, tag:paranoia-level/1, tag:OWASP_CRS, tag:OWASP_CRS/DATA-LEAKAGES-SQL, tag:capec/1000/118/116/54, ver:OWASP_CRS/4.22.0-dev, severity:CRITICAL, setvar:tx.outbound_anomaly_score_pl1=+%{tx.critical_anomaly_score}, setvar:tx.sql_injection_score=+%{tx.critical_anomaly_score}

#### Rule 6: 951120
- **Phase**: 4
- **Variables**: RESPONSE_BODY
- **Operator**: @rx
- **Pattern**: (?i)\bORA-[0-9][0-9][0-9][0-9][0-9]:|java\.sql\.SQLException|Oracle(?: erro|[^\(\)]{0,20}Drive)r|Warning.{1,10}o(?:ci_.{1,30}|ra_.{1,20})
- **Is Chain**: False
- **Message**: Oracle SQL Information Leakage
- **Severity**: CRITICAL
- **Tags**: application-multi, language-multi, platform-oracle, attack-disclosure, paranoia-level/1, OWASP_CRS, OWASP_CRS/DATA-LEAKAGES-SQL, capec/1000/118/116/54
- **Actions**: id:951120, phase:4, block, capture, t:none, msg:Oracle SQL Information Leakage, logdata:Matched Data: %{TX.0} found within %{MATCHED_VAR_NAME}, tag:application-multi, tag:language-multi, tag:platform-oracle, tag:attack-disclosure, tag:paranoia-level/1, tag:OWASP_CRS, tag:OWASP_CRS/DATA-LEAKAGES-SQL, tag:capec/1000/118/116/54, ver:OWASP_CRS/4.22.0-dev, severity:CRITICAL, setvar:tx.outbound_anomaly_score_pl1=+%{tx.critical_anomaly_score}, setvar:tx.sql_injection_score=+%{tx.critical_anomaly_score}

#### Rule 7: 951130
- **Phase**: 4
- **Variables**: RESPONSE_BODY
- **Operator**: @rx
- **Pattern**: (?i:DB2 SQL error:|\[IBM\]\[CLI Driver\]\[DB2/6000\]|CLI Driver.*DB2|DB2 SQL error|db2_\w+\()
- **Is Chain**: False
- **Message**: DB2 SQL Information Leakage
- **Severity**: CRITICAL
- **Tags**: application-multi, language-multi, platform-db2, attack-disclosure, paranoia-level/1, OWASP_CRS, OWASP_CRS/DATA-LEAKAGES-SQL, capec/1000/118/116/54
- **Actions**: id:951130, phase:4, block, capture, t:none, msg:DB2 SQL Information Leakage, logdata:Matched Data: %{TX.0} found within %{MATCHED_VAR_NAME}, tag:application-multi, tag:language-multi, tag:platform-db2, tag:attack-disclosure, tag:paranoia-level/1, tag:OWASP_CRS, tag:OWASP_CRS/DATA-LEAKAGES-SQL, tag:capec/1000/118/116/54, ver:OWASP_CRS/4.22.0-dev, severity:CRITICAL, setvar:tx.outbound_anomaly_score_pl1=+%{tx.critical_anomaly_score}, setvar:tx.sql_injection_score=+%{tx.critical_anomaly_score}

#### Rule 8: 951140
- **Phase**: 4
- **Variables**: RESPONSE_BODY
- **Operator**: @rx
- **Pattern**: (?i:\[DM_QUERY_E_SYNTAX\]|has occurred in the vicinity of:)
- **Is Chain**: False
- **Message**: EMC SQL Information Leakage
- **Severity**: CRITICAL
- **Tags**: application-multi, language-multi, platform-emc, attack-disclosure, paranoia-level/1, OWASP_CRS, OWASP_CRS/DATA-LEAKAGES-SQL, capec/1000/118/116/54
- **Actions**: id:951140, phase:4, block, capture, t:none, msg:EMC SQL Information Leakage, logdata:Matched Data: %{TX.0} found within %{MATCHED_VAR_NAME}, tag:application-multi, tag:language-multi, tag:platform-emc, tag:attack-disclosure, tag:paranoia-level/1, tag:OWASP_CRS, tag:OWASP_CRS/DATA-LEAKAGES-SQL, tag:capec/1000/118/116/54, ver:OWASP_CRS/4.22.0-dev, severity:CRITICAL, setvar:tx.outbound_anomaly_score_pl1=+%{tx.critical_anomaly_score}, setvar:tx.sql_injection_score=+%{tx.critical_anomaly_score}

#### Rule 9: 951150
- **Phase**: 4
- **Variables**: RESPONSE_BODY
- **Operator**: @rx
- **Pattern**: (?i)Dynamic SQL Error
- **Is Chain**: False
- **Message**: firebird SQL Information Leakage
- **Severity**: CRITICAL
- **Tags**: application-multi, language-multi, platform-firebird, attack-disclosure, paranoia-level/1, OWASP_CRS, OWASP_CRS/DATA-LEAKAGES-SQL, capec/1000/118/116/54
- **Actions**: id:951150, phase:4, block, capture, t:none, msg:firebird SQL Information Leakage, logdata:Matched Data: %{TX.0} found within %{MATCHED_VAR_NAME}, tag:application-multi, tag:language-multi, tag:platform-firebird, tag:attack-disclosure, tag:paranoia-level/1, tag:OWASP_CRS, tag:OWASP_CRS/DATA-LEAKAGES-SQL, tag:capec/1000/118/116/54, ver:OWASP_CRS/4.22.0-dev, severity:CRITICAL, setvar:tx.outbound_anomaly_score_pl1=+%{tx.critical_anomaly_score}, setvar:tx.sql_injection_score=+%{tx.critical_anomaly_score}

#### Rule 10: 951160
- **Phase**: 4
- **Variables**: RESPONSE_BODY
- **Operator**: @rx
- **Pattern**: (?i)Exception (?:condition )?\d+\. Transaction rollback\.
- **Is Chain**: False
- **Message**: Frontbase SQL Information Leakage
- **Severity**: CRITICAL
- **Tags**: application-multi, language-multi, platform-frontbase, attack-disclosure, paranoia-level/1, OWASP_CRS, OWASP_CRS/DATA-LEAKAGES-SQL, capec/1000/118/116/54
- **Actions**: id:951160, phase:4, block, capture, t:none, msg:Frontbase SQL Information Leakage, logdata:Matched Data: %{TX.0} found within %{MATCHED_VAR_NAME}, tag:application-multi, tag:language-multi, tag:platform-frontbase, tag:attack-disclosure, tag:paranoia-level/1, tag:OWASP_CRS, tag:OWASP_CRS/DATA-LEAKAGES-SQL, tag:capec/1000/118/116/54, ver:OWASP_CRS/4.22.0-dev, severity:CRITICAL, setvar:tx.outbound_anomaly_score_pl1=+%{tx.critical_anomaly_score}, setvar:tx.sql_injection_score=+%{tx.critical_anomaly_score}

#### Rule 11: 951170
- **Phase**: 4
- **Variables**: RESPONSE_BODY
- **Operator**: @rx
- **Pattern**: (?i)org\.hsqldb\.jdbc
- **Is Chain**: False
- **Message**: hsqldb SQL Information Leakage
- **Severity**: CRITICAL
- **Tags**: application-multi, language-multi, platform-hsqldb, attack-disclosure, paranoia-level/1, OWASP_CRS, OWASP_CRS/DATA-LEAKAGES-SQL, capec/1000/118/116/54
- **Actions**: id:951170, phase:4, block, capture, t:none, msg:hsqldb SQL Information Leakage, logdata:Matched Data: %{TX.0} found within %{MATCHED_VAR_NAME}, tag:application-multi, tag:language-multi, tag:platform-hsqldb, tag:attack-disclosure, tag:paranoia-level/1, tag:OWASP_CRS, tag:OWASP_CRS/DATA-LEAKAGES-SQL, tag:capec/1000/118/116/54, ver:OWASP_CRS/4.22.0-dev, severity:CRITICAL, setvar:tx.outbound_anomaly_score_pl1=+%{tx.critical_anomaly_score}, setvar:tx.sql_injection_score=+%{tx.critical_anomaly_score}

#### Rule 12: 951180
- **Phase**: 4
- **Variables**: RESPONSE_BODY
- **Operator**: @rx
- **Pattern**: (?i:An illegal character has been found in the statement|com\.informix\.jdbc|Exception.*Informix)
- **Is Chain**: False
- **Message**: informix SQL Information Leakage
- **Severity**: CRITICAL
- **Tags**: application-multi, language-multi, platform-informix, attack-disclosure, paranoia-level/1, OWASP_CRS, OWASP_CRS/DATA-LEAKAGES-SQL, capec/1000/118/116/54
- **Actions**: id:951180, phase:4, block, capture, t:none, msg:informix SQL Information Leakage, logdata:Matched Data: %{TX.0} found within %{MATCHED_VAR_NAME}, tag:application-multi, tag:language-multi, tag:platform-informix, tag:attack-disclosure, tag:paranoia-level/1, tag:OWASP_CRS, tag:OWASP_CRS/DATA-LEAKAGES-SQL, tag:capec/1000/118/116/54, ver:OWASP_CRS/4.22.0-dev, severity:CRITICAL, setvar:tx.outbound_anomaly_score_pl1=+%{tx.critical_anomaly_score}, setvar:tx.sql_injection_score=+%{tx.critical_anomaly_score}

#### Rule 13: 951190
- **Phase**: 4
- **Variables**: RESPONSE_BODY
- **Operator**: @rx
- **Pattern**: (?i:Warning.*ingres_|Ingres SQLSTATE|Ingres\W.*Driver)
- **Is Chain**: False
- **Message**: ingres SQL Information Leakage
- **Severity**: CRITICAL
- **Tags**: application-multi, language-multi, platform-ingres, attack-disclosure, paranoia-level/1, OWASP_CRS, OWASP_CRS/DATA-LEAKAGES-SQL, capec/1000/118/116/54
- **Actions**: id:951190, phase:4, block, capture, t:none, msg:ingres SQL Information Leakage, logdata:Matched Data: %{TX.0} found within %{MATCHED_VAR_NAME}, tag:application-multi, tag:language-multi, tag:platform-ingres, tag:attack-disclosure, tag:paranoia-level/1, tag:OWASP_CRS, tag:OWASP_CRS/DATA-LEAKAGES-SQL, tag:capec/1000/118/116/54, ver:OWASP_CRS/4.22.0-dev, severity:CRITICAL, setvar:tx.outbound_anomaly_score_pl1=+%{tx.critical_anomaly_score}, setvar:tx.sql_injection_score=+%{tx.critical_anomaly_score}

#### Rule 14: 951200
- **Phase**: 4
- **Variables**: RESPONSE_BODY
- **Operator**: @rx
- **Pattern**: (?i:<b>Warning</b>: ibase_|Unexpected end of command in statement)
- **Is Chain**: False
- **Message**: interbase SQL Information Leakage
- **Severity**: CRITICAL
- **Tags**: application-multi, language-multi, platform-interbase, attack-disclosure, paranoia-level/1, OWASP_CRS, OWASP_CRS/DATA-LEAKAGES-SQL, capec/1000/118/116/54
- **Actions**: id:951200, phase:4, block, capture, t:none, msg:interbase SQL Information Leakage, logdata:Matched Data: %{TX.0} found within %{MATCHED_VAR_NAME}, tag:application-multi, tag:language-multi, tag:platform-interbase, tag:attack-disclosure, tag:paranoia-level/1, tag:OWASP_CRS, tag:OWASP_CRS/DATA-LEAKAGES-SQL, tag:capec/1000/118/116/54, ver:OWASP_CRS/4.22.0-dev, severity:CRITICAL, setvar:tx.outbound_anomaly_score_pl1=+%{tx.critical_anomaly_score}, setvar:tx.sql_injection_score=+%{tx.critical_anomaly_score}

#### Rule 15: 951210
- **Phase**: 4
- **Variables**: RESPONSE_BODY
- **Operator**: @rx
- **Pattern**: (?i:SQL error.*POS[0-9]+.*|Warning.*maxdb.*)
- **Is Chain**: False
- **Message**: maxDB SQL Information Leakage
- **Severity**: CRITICAL
- **Tags**: application-multi, language-multi, platform-maxdb, attack-disclosure, paranoia-level/1, OWASP_CRS, OWASP_CRS/DATA-LEAKAGES-SQL, capec/1000/118/116/54
- **Actions**: id:951210, phase:4, block, capture, t:none, msg:maxDB SQL Information Leakage, logdata:Matched Data: %{TX.0} found within %{MATCHED_VAR_NAME}, tag:application-multi, tag:language-multi, tag:platform-maxdb, tag:attack-disclosure, tag:paranoia-level/1, tag:OWASP_CRS, tag:OWASP_CRS/DATA-LEAKAGES-SQL, tag:capec/1000/118/116/54, ver:OWASP_CRS/4.22.0-dev, severity:CRITICAL, setvar:tx.outbound_anomaly_score_pl1=+%{tx.critical_anomaly_score}, setvar:tx.sql_injection_score=+%{tx.critical_anomaly_score}

#### Rule 16: 951220
- **Phase**: 4
- **Variables**: RESPONSE_BODY
- **Operator**: @rx
- **Pattern**: (?i)(?:System\.Data\.OleDb\.OleDbException|\[Microsoft\]\[ODBC SQL Server Driver\]|\[Macromedia\]\[SQLServer JDBC Driver\]|\[SqlException|System\.Data\.SqlClient\.SqlException|Unclosed quotation mark after the character string|'80040e14'|mssql_query\(\)|Microsoft OLE DB Provider for ODBC Drivers|Microsoft OLE DB Provider for SQL Server|Incorrect syntax near|Sintaxis incorrecta cerca de|Syntax error in string in query expression|Procedure or function '.{1,128}' expects parameter|Unclosed quotation mark before the character string|Syntax error .* in query expression|Data type mismatch in criteria expression\.|ADODB\.Field \(0x800A0BCD\)|the used select statements have different number of columns|OLE DB.*SQL Server|Warning.*mssql_.*|Driver.*SQL[ _-]*Server|Exception.*\WSystem\.Data\.SqlClient\.|Conversion failed when converting the varchar value .*? to data type int\.)
- **Is Chain**: False
- **Message**: mssql SQL Information Leakage
- **Severity**: CRITICAL
- **Tags**: application-multi, language-multi, platform-mssql, attack-disclosure, paranoia-level/1, OWASP_CRS, OWASP_CRS/DATA-LEAKAGES-SQL, capec/1000/118/116/54
- **Actions**: id:951220, phase:4, block, capture, t:none, msg:mssql SQL Information Leakage, logdata:Matched Data: %{TX.0} found within %{MATCHED_VAR_NAME}, tag:application-multi, tag:language-multi, tag:platform-mssql, tag:attack-disclosure, tag:paranoia-level/1, tag:OWASP_CRS, tag:OWASP_CRS/DATA-LEAKAGES-SQL, tag:capec/1000/118/116/54, ver:OWASP_CRS/4.22.0-dev, severity:CRITICAL, setvar:tx.outbound_anomaly_score_pl1=+%{tx.critical_anomaly_score}, setvar:tx.sql_injection_score=+%{tx.critical_anomaly_score}

#### Rule 17: 951230
- **Phase**: 4
- **Variables**: RESPONSE_BODY
- **Operator**: @rx
- **Pattern**: (?i)(?:supplied argument is not a valid |SQL syntax.*)MySQL|Column count doesn't match(?: value count at row)?|mysql_fetch_array\(\)|on MySQL result index|You have an error in your SQL syntax(?:;| near)|MyS(?:QL server version for the right syntax to use|qlClient\.)|\[MySQL\]\[ODBC|(?:Table '[^']+' doesn't exis|valid MySQL resul)t|Warning.{1,10}mysql_(?:[\(\)_a-z]{1,26})?|(?:ERROR [0-9]{4} \([0-9a-z]{5}\)|XPATH syntax error):
- **Is Chain**: False
- **Message**: mysql SQL Information Leakage
- **Severity**: CRITICAL
- **Tags**: application-multi, language-multi, platform-mysql, attack-disclosure, paranoia-level/1, OWASP_CRS, OWASP_CRS/DATA-LEAKAGES-SQL, capec/1000/118/116/54
- **Actions**: id:951230, phase:4, block, capture, t:none, msg:mysql SQL Information Leakage, logdata:Matched Data: %{TX.0} found within %{MATCHED_VAR_NAME}, tag:application-multi, tag:language-multi, tag:platform-mysql, tag:attack-disclosure, tag:paranoia-level/1, tag:OWASP_CRS, tag:OWASP_CRS/DATA-LEAKAGES-SQL, tag:capec/1000/118/116/54, ver:OWASP_CRS/4.22.0-dev, severity:CRITICAL, setvar:tx.outbound_anomaly_score_pl1=+%{tx.critical_anomaly_score}, setvar:tx.sql_injection_score=+%{tx.critical_anomaly_score}

#### Rule 18: 951240
- **Phase**: 4
- **Variables**: RESPONSE_BODY
- **Operator**: @rx
- **Pattern**: (?i)P(?:ostgreSQL(?: query failed:|.{1,20}ERROR)|G::[a-z]*Error)|(?:pg_(?:query|exec)\(\) \[|org\.postgresql\.util\.PSQLException):|Warning.{1,20}\bpg_.*|valid PostgreSQL result|Npgsql\.|Supplied argument is not a valid PostgreSQL .*? resource|(?:Unable to connect to PostgreSQL serv|invalid input syntax for integ)er
- **Is Chain**: False
- **Message**: postgres SQL Information Leakage
- **Severity**: CRITICAL
- **Tags**: application-multi, language-multi, platform-pgsql, attack-disclosure, paranoia-level/1, OWASP_CRS, OWASP_CRS/DATA-LEAKAGES-SQL, capec/1000/118/116/54
- **Actions**: id:951240, phase:4, block, capture, t:none, msg:postgres SQL Information Leakage, logdata:Matched Data: %{TX.0} found within %{MATCHED_VAR_NAME}, tag:application-multi, tag:language-multi, tag:platform-pgsql, tag:attack-disclosure, tag:paranoia-level/1, tag:OWASP_CRS, tag:OWASP_CRS/DATA-LEAKAGES-SQL, tag:capec/1000/118/116/54, ver:OWASP_CRS/4.22.0-dev, severity:CRITICAL, setvar:tx.outbound_anomaly_score_pl1=+%{tx.critical_anomaly_score}, setvar:tx.sql_injection_score=+%{tx.critical_anomaly_score}

#### Rule 19: 951250
- **Phase**: 4
- **Variables**: RESPONSE_BODY
- **Operator**: @rx
- **Pattern**: (?i)(?:Warning.*sqlite_|Warning.*SQLite3::|SQLite/JDBCDriver|SQLite\.Exception|System\.Data\.SQLite\.SQLiteException)
- **Is Chain**: False
- **Message**: sqlite SQL Information Leakage
- **Severity**: CRITICAL
- **Tags**: application-multi, language-multi, platform-sqlite, attack-disclosure, paranoia-level/1, OWASP_CRS, OWASP_CRS/DATA-LEAKAGES-SQL, capec/1000/118/116/54
- **Actions**: id:951250, phase:4, block, capture, t:none, msg:sqlite SQL Information Leakage, logdata:Matched Data: %{TX.0} found within %{MATCHED_VAR_NAME}, tag:application-multi, tag:language-multi, tag:platform-sqlite, tag:attack-disclosure, tag:paranoia-level/1, tag:OWASP_CRS, tag:OWASP_CRS/DATA-LEAKAGES-SQL, tag:capec/1000/118/116/54, ver:OWASP_CRS/4.22.0-dev, severity:CRITICAL, setvar:tx.outbound_anomaly_score_pl1=+%{tx.critical_anomaly_score}, setvar:tx.sql_injection_score=+%{tx.critical_anomaly_score}

#### Rule 20: 951260
- **Phase**: 4
- **Variables**: RESPONSE_BODY
- **Operator**: @rx
- **Pattern**: (?i)(?:Sybase message:|Warning.{2,20}sybase|Sybase.*Server message)
- **Is Chain**: False
- **Message**: Sybase SQL Information Leakage
- **Severity**: CRITICAL
- **Tags**: application-multi, language-multi, platform-sybase, attack-disclosure, paranoia-level/1, OWASP_CRS, OWASP_CRS/DATA-LEAKAGES-SQL, capec/1000/118/116/54
- **Actions**: id:951260, phase:4, block, capture, t:none, msg:Sybase SQL Information Leakage, logdata:Matched Data: %{TX.0} found within %{MATCHED_VAR_NAME}, tag:application-multi, tag:language-multi, tag:platform-sybase, tag:attack-disclosure, tag:paranoia-level/1, tag:OWASP_CRS, tag:OWASP_CRS/DATA-LEAKAGES-SQL, tag:capec/1000/118/116/54, ver:OWASP_CRS/4.22.0-dev, severity:CRITICAL, setvar:tx.outbound_anomaly_score_pl1=+%{tx.critical_anomaly_score}, setvar:tx.sql_injection_score=+%{tx.critical_anomaly_score}

#### Rule 21: 951013
- **Phase**: 3
- **Variables**: TX:DETECTION_PARANOIA_LEVEL
- **Operator**: @lt
- **Pattern**: 2
- **Is Chain**: False
- **Message**: 
- **Severity**: 
- **Tags**: OWASP_CRS
- **Actions**: id:951013, phase:3, pass, nolog, tag:OWASP_CRS, ver:OWASP_CRS/4.22.0-dev, skipAfter:END-RESPONSE-951-DATA-LEAKAGES-SQL

#### Rule 22: 951014
- **Phase**: 4
- **Variables**: TX:DETECTION_PARANOIA_LEVEL
- **Operator**: @lt
- **Pattern**: 2
- **Is Chain**: False
- **Message**: 
- **Severity**: 
- **Tags**: OWASP_CRS
- **Actions**: id:951014, phase:4, pass, nolog, tag:OWASP_CRS, ver:OWASP_CRS/4.22.0-dev, skipAfter:END-RESPONSE-951-DATA-LEAKAGES-SQL

#### Rule 23: 951015
- **Phase**: 3
- **Variables**: TX:DETECTION_PARANOIA_LEVEL
- **Operator**: @lt
- **Pattern**: 3
- **Is Chain**: False
- **Message**: 
- **Severity**: 
- **Tags**: OWASP_CRS
- **Actions**: id:951015, phase:3, pass, nolog, tag:OWASP_CRS, ver:OWASP_CRS/4.22.0-dev, skipAfter:END-RESPONSE-951-DATA-LEAKAGES-SQL

#### Rule 24: 951016
- **Phase**: 4
- **Variables**: TX:DETECTION_PARANOIA_LEVEL
- **Operator**: @lt
- **Pattern**: 3
- **Is Chain**: False
- **Message**: 
- **Severity**: 
- **Tags**: OWASP_CRS
- **Actions**: id:951016, phase:4, pass, nolog, tag:OWASP_CRS, ver:OWASP_CRS/4.22.0-dev, skipAfter:END-RESPONSE-951-DATA-LEAKAGES-SQL

#### Rule 25: 951017
- **Phase**: 3
- **Variables**: TX:DETECTION_PARANOIA_LEVEL
- **Operator**: @lt
- **Pattern**: 4
- **Is Chain**: False
- **Message**: 
- **Severity**: 
- **Tags**: OWASP_CRS
- **Actions**: id:951017, phase:3, pass, nolog, tag:OWASP_CRS, ver:OWASP_CRS/4.22.0-dev, skipAfter:END-RESPONSE-951-DATA-LEAKAGES-SQL

#### Rule 26: 951018
- **Phase**: 4
- **Variables**: TX:DETECTION_PARANOIA_LEVEL
- **Operator**: @lt
- **Pattern**: 4
- **Is Chain**: False
- **Message**: 
- **Severity**: 
- **Tags**: OWASP_CRS
- **Actions**: id:951018, phase:4, pass, nolog, tag:OWASP_CRS, ver:OWASP_CRS/4.22.0-dev, skipAfter:END-RESPONSE-951-DATA-LEAKAGES-SQL


====================================================================================================

## File: RESPONSE-952-DATA-LEAKAGES-JAVA.conf

### File Summary
- Total rules: 10
- Chained rules: 0
- Non-chained rules: 10

### Detailed Rules

#### Rule 1: 952010
- **Phase**: 4
- **Variables**: RESPONSE_HEADERS:Content-Encoding
- **Operator**: @pm
- **Pattern**: gzip compress deflate br zstd
- **Is Chain**: False
- **Message**: 
- **Severity**: 
- **Tags**: OWASP_CRS, OWASP_CRS/DATA-LEAKAGES-JAVA
- **Actions**: id:952010, phase:4, pass, nolog, tag:OWASP_CRS, tag:OWASP_CRS/DATA-LEAKAGES-JAVA, ver:OWASP_CRS/4.22.0-dev, skipAfter:END-RESPONSE-952-DATA-LEAKAGES-JAVA

#### Rule 2: 952011
- **Phase**: 3
- **Variables**: TX:DETECTION_PARANOIA_LEVEL
- **Operator**: @lt
- **Pattern**: 1
- **Is Chain**: False
- **Message**: 
- **Severity**: 
- **Tags**: OWASP_CRS
- **Actions**: id:952011, phase:3, pass, nolog, tag:OWASP_CRS, ver:OWASP_CRS/4.22.0-dev, skipAfter:END-RESPONSE-952-DATA-LEAKAGES-JAVA

#### Rule 3: 952012
- **Phase**: 4
- **Variables**: TX:DETECTION_PARANOIA_LEVEL
- **Operator**: @lt
- **Pattern**: 1
- **Is Chain**: False
- **Message**: 
- **Severity**: 
- **Tags**: OWASP_CRS
- **Actions**: id:952012, phase:4, pass, nolog, tag:OWASP_CRS, ver:OWASP_CRS/4.22.0-dev, skipAfter:END-RESPONSE-952-DATA-LEAKAGES-JAVA

#### Rule 4: 952110
- **Phase**: 4
- **Variables**: RESPONSE_BODY
- **Operator**: @rx
- **Pattern**: (?i)\b(?:java[\.a-z]+E(?:xception|rror)|(?:org|com)\.[\.a-z]+Exception|Exception in thread \"[^\"]*\"|at[\s\x0b]+(?:ja(?:vax?|karta)|org|com))\b
- **Is Chain**: False
- **Message**: Java Errors
- **Severity**: ERROR
- **Tags**: application-multi, language-java, platform-multi, attack-disclosure, paranoia-level/1, OWASP_CRS, OWASP_CRS/DATA-LEAKAGES-JAVA, capec/1000/118/116
- **Actions**: id:952110, phase:4, block, capture, t:none, msg:Java Errors, logdata:Matched Data: %{TX.0} found within %{MATCHED_VAR_NAME}, tag:application-multi, tag:language-java, tag:platform-multi, tag:attack-disclosure, tag:paranoia-level/1, tag:OWASP_CRS, tag:OWASP_CRS/DATA-LEAKAGES-JAVA, tag:capec/1000/118/116, ver:OWASP_CRS/4.22.0-dev, severity:ERROR, setvar:tx.outbound_anomaly_score_pl1=+%{tx.error_anomaly_score}

#### Rule 5: 952013
- **Phase**: 3
- **Variables**: TX:DETECTION_PARANOIA_LEVEL
- **Operator**: @lt
- **Pattern**: 2
- **Is Chain**: False
- **Message**: 
- **Severity**: 
- **Tags**: OWASP_CRS
- **Actions**: id:952013, phase:3, pass, nolog, tag:OWASP_CRS, ver:OWASP_CRS/4.22.0-dev, skipAfter:END-RESPONSE-952-DATA-LEAKAGES-JAVA

#### Rule 6: 952014
- **Phase**: 4
- **Variables**: TX:DETECTION_PARANOIA_LEVEL
- **Operator**: @lt
- **Pattern**: 2
- **Is Chain**: False
- **Message**: 
- **Severity**: 
- **Tags**: OWASP_CRS
- **Actions**: id:952014, phase:4, pass, nolog, tag:OWASP_CRS, ver:OWASP_CRS/4.22.0-dev, skipAfter:END-RESPONSE-952-DATA-LEAKAGES-JAVA

#### Rule 7: 952015
- **Phase**: 3
- **Variables**: TX:DETECTION_PARANOIA_LEVEL
- **Operator**: @lt
- **Pattern**: 3
- **Is Chain**: False
- **Message**: 
- **Severity**: 
- **Tags**: OWASP_CRS
- **Actions**: id:952015, phase:3, pass, nolog, tag:OWASP_CRS, ver:OWASP_CRS/4.22.0-dev, skipAfter:END-RESPONSE-952-DATA-LEAKAGES-JAVA

#### Rule 8: 952016
- **Phase**: 4
- **Variables**: TX:DETECTION_PARANOIA_LEVEL
- **Operator**: @lt
- **Pattern**: 3
- **Is Chain**: False
- **Message**: 
- **Severity**: 
- **Tags**: OWASP_CRS
- **Actions**: id:952016, phase:4, pass, nolog, tag:OWASP_CRS, ver:OWASP_CRS/4.22.0-dev, skipAfter:END-RESPONSE-952-DATA-LEAKAGES-JAVA

#### Rule 9: 952017
- **Phase**: 3
- **Variables**: TX:DETECTION_PARANOIA_LEVEL
- **Operator**: @lt
- **Pattern**: 4
- **Is Chain**: False
- **Message**: 
- **Severity**: 
- **Tags**: OWASP_CRS
- **Actions**: id:952017, phase:3, pass, nolog, tag:OWASP_CRS, ver:OWASP_CRS/4.22.0-dev, skipAfter:END-RESPONSE-952-DATA-LEAKAGES-JAVA

#### Rule 10: 952018
- **Phase**: 4
- **Variables**: TX:DETECTION_PARANOIA_LEVEL
- **Operator**: @lt
- **Pattern**: 4
- **Is Chain**: False
- **Message**: 
- **Severity**: 
- **Tags**: OWASP_CRS
- **Actions**: id:952018, phase:4, pass, nolog, tag:OWASP_CRS, ver:OWASP_CRS/4.22.0-dev, skipAfter:END-RESPONSE-952-DATA-LEAKAGES-JAVA


====================================================================================================

## File: RESPONSE-953-DATA-LEAKAGES-PHP.conf

### File Summary
- Total rules: 13
- Chained rules: 0
- Non-chained rules: 13

### Detailed Rules

#### Rule 1: 953010
- **Phase**: 4
- **Variables**: RESPONSE_HEADERS:Content-Encoding
- **Operator**: @pm
- **Pattern**: gzip compress deflate br zstd
- **Is Chain**: False
- **Message**: 
- **Severity**: 
- **Tags**: OWASP_CRS, OWASP_CRS/DATA-LEAKAGES-PHP
- **Actions**: id:953010, phase:4, pass, nolog, tag:OWASP_CRS, tag:OWASP_CRS/DATA-LEAKAGES-PHP, ver:OWASP_CRS/4.22.0-dev, skipAfter:END-RESPONSE-953-DATA-LEAKAGES-PHP

#### Rule 2: 953011
- **Phase**: 3
- **Variables**: TX:DETECTION_PARANOIA_LEVEL
- **Operator**: @lt
- **Pattern**: 1
- **Is Chain**: False
- **Message**: 
- **Severity**: 
- **Tags**: OWASP_CRS
- **Actions**: id:953011, phase:3, pass, nolog, tag:OWASP_CRS, ver:OWASP_CRS/4.22.0-dev, skipAfter:END-RESPONSE-953-DATA-LEAKAGES-PHP

#### Rule 3: 953012
- **Phase**: 4
- **Variables**: TX:DETECTION_PARANOIA_LEVEL
- **Operator**: @lt
- **Pattern**: 1
- **Is Chain**: False
- **Message**: 
- **Severity**: 
- **Tags**: OWASP_CRS
- **Actions**: id:953012, phase:4, pass, nolog, tag:OWASP_CRS, ver:OWASP_CRS/4.22.0-dev, skipAfter:END-RESPONSE-953-DATA-LEAKAGES-PHP

#### Rule 4: 953100
- **Phase**: 4
- **Variables**: RESPONSE_BODY
- **Operator**: @pmFromFile
- **Pattern**: php-errors.data
- **Is Chain**: False
- **Message**: PHP Information Leakage
- **Severity**: ERROR
- **Tags**: application-multi, language-php, platform-multi, attack-disclosure, paranoia-level/1, OWASP_CRS, OWASP_CRS/DATA-LEAKAGES-PHP, capec/1000/118/116
- **Actions**: id:953100, phase:4, block, capture, t:none, msg:PHP Information Leakage, logdata:Matched Data: %{TX.0} found within %{MATCHED_VAR_NAME}, tag:application-multi, tag:language-php, tag:platform-multi, tag:attack-disclosure, tag:paranoia-level/1, tag:OWASP_CRS, tag:OWASP_CRS/DATA-LEAKAGES-PHP, tag:capec/1000/118/116, ver:OWASP_CRS/4.22.0-dev, severity:ERROR, setvar:tx.outbound_anomaly_score_pl1=+%{tx.error_anomaly_score}

#### Rule 5: 953110
- **Phase**: 4
- **Variables**: RESPONSE_BODY
- **Operator**: @rx
- **Pattern**: (?:\b(?:f(?:tp_(?:nb_)?f?(?:ge|pu)t|get(?:s?s|c)|scanf|write|open|read)|gz(?:(?:encod|writ)e|compress|open|read)|s(?:ession_start|candir)|read(?:(?:gz)?file|dir)|move_uploaded_file|(?:proc_|bz)open|call_user_func)|\$_(?:(?:pos|ge)t|session))\b
- **Is Chain**: False
- **Message**: PHP source code leakage
- **Severity**: ERROR
- **Tags**: application-multi, language-php, platform-multi, attack-disclosure, paranoia-level/1, OWASP_CRS, OWASP_CRS/DATA-LEAKAGES-PHP, capec/1000/118/116
- **Actions**: id:953110, phase:4, block, capture, t:none, msg:PHP source code leakage, logdata:Matched Data: %{TX.0} found within %{MATCHED_VAR_NAME}, tag:application-multi, tag:language-php, tag:platform-multi, tag:attack-disclosure, tag:paranoia-level/1, tag:OWASP_CRS, tag:OWASP_CRS/DATA-LEAKAGES-PHP, tag:capec/1000/118/116, ver:OWASP_CRS/4.22.0-dev, severity:ERROR, setvar:tx.outbound_anomaly_score_pl1=+%{tx.error_anomaly_score}

#### Rule 6: 953120
- **Phase**: 4
- **Variables**: RESPONSE_BODY
- **Operator**: @rx
- **Pattern**: (?i)<\?(?:=|php)?\s+
- **Is Chain**: False
- **Message**: PHP source code leakage
- **Severity**: ERROR
- **Tags**: application-multi, language-php, platform-multi, attack-disclosure, paranoia-level/1, OWASP_CRS, OWASP_CRS/DATA-LEAKAGES-PHP, capec/1000/118/116
- **Actions**: id:953120, phase:4, block, capture, t:none, msg:PHP source code leakage, logdata:Matched Data: %{TX.0} found within %{MATCHED_VAR_NAME}, tag:application-multi, tag:language-php, tag:platform-multi, tag:attack-disclosure, tag:paranoia-level/1, tag:OWASP_CRS, tag:OWASP_CRS/DATA-LEAKAGES-PHP, tag:capec/1000/118/116, ver:OWASP_CRS/4.22.0-dev, severity:ERROR, setvar:tx.outbound_anomaly_score_pl1=+%{tx.error_anomaly_score}

#### Rule 7: 953013
- **Phase**: 3
- **Variables**: TX:DETECTION_PARANOIA_LEVEL
- **Operator**: @lt
- **Pattern**: 2
- **Is Chain**: False
- **Message**: 
- **Severity**: 
- **Tags**: OWASP_CRS
- **Actions**: id:953013, phase:3, pass, nolog, tag:OWASP_CRS, ver:OWASP_CRS/4.22.0-dev, skipAfter:END-RESPONSE-953-DATA-LEAKAGES-PHP

#### Rule 8: 953014
- **Phase**: 4
- **Variables**: TX:DETECTION_PARANOIA_LEVEL
- **Operator**: @lt
- **Pattern**: 2
- **Is Chain**: False
- **Message**: 
- **Severity**: 
- **Tags**: OWASP_CRS
- **Actions**: id:953014, phase:4, pass, nolog, tag:OWASP_CRS, ver:OWASP_CRS/4.22.0-dev, skipAfter:END-RESPONSE-953-DATA-LEAKAGES-PHP

#### Rule 9: 953101
- **Phase**: 4
- **Variables**: RESPONSE_BODY
- **Operator**: @rx
- **Pattern**: (?i)Empty string|F(?:ile size is|reeing memory)|Header (?:name )?\"|Invalid date|No active class|(?:Out of memor|cannot be empt)y|Pa(?:ir level|ssword is too long)|Re(?:ading file|starting!)|S(?:ession is not active|tatic function\b)|T(?:elling\.\.\.|he function\b)|(?:Unknown reas|invalid opti)on|e(?:mpty password|rror reading)
- **Is Chain**: False
- **Message**: PHP Information Leakage
- **Severity**: ERROR
- **Tags**: application-multi, language-php, platform-multi, attack-disclosure, paranoia-level/2, OWASP_CRS, OWASP_CRS/DATA-LEAKAGES-PHP, capec/1000/118/116
- **Actions**: id:953101, phase:4, block, capture, t:none, msg:PHP Information Leakage, logdata:Matched Data: %{TX.0} found within %{MATCHED_VAR_NAME}, tag:application-multi, tag:language-php, tag:platform-multi, tag:attack-disclosure, tag:paranoia-level/2, tag:OWASP_CRS, tag:OWASP_CRS/DATA-LEAKAGES-PHP, tag:capec/1000/118/116, ver:OWASP_CRS/4.22.0-dev, severity:ERROR, setvar:tx.outbound_anomaly_score_pl2=+%{tx.error_anomaly_score}

#### Rule 10: 953015
- **Phase**: 3
- **Variables**: TX:DETECTION_PARANOIA_LEVEL
- **Operator**: @lt
- **Pattern**: 3
- **Is Chain**: False
- **Message**: 
- **Severity**: 
- **Tags**: OWASP_CRS
- **Actions**: id:953015, phase:3, pass, nolog, tag:OWASP_CRS, ver:OWASP_CRS/4.22.0-dev, skipAfter:END-RESPONSE-953-DATA-LEAKAGES-PHP

#### Rule 11: 953016
- **Phase**: 4
- **Variables**: TX:DETECTION_PARANOIA_LEVEL
- **Operator**: @lt
- **Pattern**: 3
- **Is Chain**: False
- **Message**: 
- **Severity**: 
- **Tags**: OWASP_CRS
- **Actions**: id:953016, phase:4, pass, nolog, tag:OWASP_CRS, ver:OWASP_CRS/4.22.0-dev, skipAfter:END-RESPONSE-953-DATA-LEAKAGES-PHP

#### Rule 12: 953017
- **Phase**: 3
- **Variables**: TX:DETECTION_PARANOIA_LEVEL
- **Operator**: @lt
- **Pattern**: 4
- **Is Chain**: False
- **Message**: 
- **Severity**: 
- **Tags**: OWASP_CRS
- **Actions**: id:953017, phase:3, pass, nolog, tag:OWASP_CRS, ver:OWASP_CRS/4.22.0-dev, skipAfter:END-RESPONSE-953-DATA-LEAKAGES-PHP

#### Rule 13: 953018
- **Phase**: 4
- **Variables**: TX:DETECTION_PARANOIA_LEVEL
- **Operator**: @lt
- **Pattern**: 4
- **Is Chain**: False
- **Message**: 
- **Severity**: 
- **Tags**: OWASP_CRS
- **Actions**: id:953018, phase:4, pass, nolog, tag:OWASP_CRS, ver:OWASP_CRS/4.22.0-dev, skipAfter:END-RESPONSE-953-DATA-LEAKAGES-PHP


====================================================================================================

## File: RESPONSE-954-DATA-LEAKAGES-IIS.conf

### File Summary
- Total rules: 15
- Chained rules: 1
- Non-chained rules: 14

### Detailed Rules

#### Rule 1: 954010
- **Phase**: 4
- **Variables**: RESPONSE_HEADERS:Content-Encoding
- **Operator**: @pm
- **Pattern**: gzip compress deflate br zstd
- **Is Chain**: False
- **Message**: 
- **Severity**: 
- **Tags**: OWASP_CRS, OWASP_CRS/DATA-LEAKAGES-IIS
- **Actions**: id:954010, phase:4, pass, nolog, tag:OWASP_CRS, tag:OWASP_CRS/DATA-LEAKAGES-IIS, ver:OWASP_CRS/4.22.0-dev, skipAfter:END-RESPONSE-954-DATA-LEAKAGES-IIS

#### Rule 2: 954011
- **Phase**: 3
- **Variables**: TX:DETECTION_PARANOIA_LEVEL
- **Operator**: @lt
- **Pattern**: 1
- **Is Chain**: False
- **Message**: 
- **Severity**: 
- **Tags**: OWASP_CRS
- **Actions**: id:954011, phase:3, pass, nolog, tag:OWASP_CRS, ver:OWASP_CRS/4.22.0-dev, skipAfter:END-RESPONSE-954-DATA-LEAKAGES-IIS

#### Rule 3: 954012
- **Phase**: 4
- **Variables**: TX:DETECTION_PARANOIA_LEVEL
- **Operator**: @lt
- **Pattern**: 1
- **Is Chain**: False
- **Message**: 
- **Severity**: 
- **Tags**: OWASP_CRS
- **Actions**: id:954012, phase:4, pass, nolog, tag:OWASP_CRS, ver:OWASP_CRS/4.22.0-dev, skipAfter:END-RESPONSE-954-DATA-LEAKAGES-IIS

#### Rule 4: 954100
- **Phase**: 4
- **Variables**: RESPONSE_BODY
- **Operator**: @rx
- **Pattern**: (?i)[a-z]:[\x5c/]inetpub\b
- **Is Chain**: False
- **Message**: Disclosure of IIS install location
- **Severity**: ERROR
- **Tags**: application-multi, language-multi, platform-iis, platform-windows, attack-disclosure, paranoia-level/1, OWASP_CRS, OWASP_CRS/DATA-LEAKAGES-IIS, capec/1000/118/116
- **Actions**: id:954100, phase:4, block, capture, t:none, msg:Disclosure of IIS install location, logdata:Matched Data: %{TX.0} found within %{MATCHED_VAR_NAME}, tag:application-multi, tag:language-multi, tag:platform-iis, tag:platform-windows, tag:attack-disclosure, tag:paranoia-level/1, tag:OWASP_CRS, tag:OWASP_CRS/DATA-LEAKAGES-IIS, tag:capec/1000/118/116, ver:OWASP_CRS/4.22.0-dev, severity:ERROR, setvar:tx.outbound_anomaly_score_pl1=+%{tx.error_anomaly_score}

#### Rule 5: 954110
- **Phase**: 4
- **Variables**: RESPONSE_BODY
- **Operator**: @rx
- **Pattern**: (?:Microsoft OLE DB Provider for SQL Server(?:</font>.{1,20}?error '800(?:04005|40e31)'.{1,40}?Timeout expired| \(0x80040e31\)<br>Timeout expired<br>)|<h1>internal server error</h1>.*?<h2>part of the server has crashed or it has a configuration error\.</h2>|cannot connect to the server: timed out)
- **Is Chain**: False
- **Message**: Application Availability Error
- **Severity**: ERROR
- **Tags**: application-multi, language-multi, platform-iis, platform-windows, attack-disclosure, paranoia-level/1, OWASP_CRS, OWASP_CRS/DATA-LEAKAGES-IIS, capec/1000/118/116
- **Actions**: id:954110, phase:4, block, capture, t:none, msg:Application Availability Error, logdata:Matched Data: %{TX.0} found within %{MATCHED_VAR_NAME}, tag:application-multi, tag:language-multi, tag:platform-iis, tag:platform-windows, tag:attack-disclosure, tag:paranoia-level/1, tag:OWASP_CRS, tag:OWASP_CRS/DATA-LEAKAGES-IIS, tag:capec/1000/118/116, ver:OWASP_CRS/4.22.0-dev, severity:ERROR, setvar:tx.outbound_anomaly_score_pl1=+%{tx.error_anomaly_score}

#### Rule 6: 954120
- **Phase**: 4
- **Variables**: RESPONSE_BODY
- **Operator**: @pmFromFile
- **Pattern**: iis-errors.data
- **Is Chain**: False
- **Message**: IIS Information Leakage
- **Severity**: ERROR
- **Tags**: application-multi, language-multi, platform-iis, platform-windows, attack-disclosure, paranoia-level/1, OWASP_CRS, OWASP_CRS/DATA-LEAKAGES-IIS, capec/1000/118/116
- **Actions**: id:954120, phase:4, block, capture, t:none, msg:IIS Information Leakage, logdata:Matched Data: %{TX.0} found within %{MATCHED_VAR_NAME}, tag:application-multi, tag:language-multi, tag:platform-iis, tag:platform-windows, tag:attack-disclosure, tag:paranoia-level/1, tag:OWASP_CRS, tag:OWASP_CRS/DATA-LEAKAGES-IIS, tag:capec/1000/118/116, ver:OWASP_CRS/4.22.0-dev, severity:ERROR, setvar:tx.outbound_anomaly_score_pl1=+%{tx.error_anomaly_score}

#### Rule 7: 954130
- **Phase**: 4
- **Variables**: RESPONSE_STATUS
- **Operator**: !@rx
- **Pattern**: ^404$
- **Is Chain**: True
- **Message**: IIS Information Leakage
- **Severity**: ERROR
- **Tags**: application-multi, language-multi, platform-iis, platform-windows, attack-disclosure, paranoia-level/1, OWASP_CRS, OWASP_CRS/DATA-LEAKAGES-IIS, capec/1000/118/116
- **Actions**: id:954130, phase:4, block, capture, t:none, msg:IIS Information Leakage, logdata:Matched Data: %{TX.0} found within %{MATCHED_VAR_NAME}, tag:application-multi, tag:language-multi, tag:platform-iis, tag:platform-windows, tag:attack-disclosure, tag:paranoia-level/1, tag:OWASP_CRS, tag:OWASP_CRS/DATA-LEAKAGES-IIS, tag:capec/1000/118/116, ver:OWASP_CRS/4.22.0-dev, severity:ERROR, chain

#### Rule 8: Unknown
- **Phase**: Unknown
- **Variables**: RESPONSE_BODY
- **Operator**: @rx
- **Pattern**: \bServer Error in.{0,50}?\bApplication\b
- **Is Chain**: False
- **Message**: 
- **Severity**: 
- **Actions**: capture, t:none, setvar:tx.outbound_anomaly_score_pl1=+%{tx.error_anomaly_score}

#### Rule 9: 954013
- **Phase**: 3
- **Variables**: TX:DETECTION_PARANOIA_LEVEL
- **Operator**: @lt
- **Pattern**: 2
- **Is Chain**: False
- **Message**: 
- **Severity**: 
- **Tags**: OWASP_CRS
- **Actions**: id:954013, phase:3, pass, nolog, tag:OWASP_CRS, ver:OWASP_CRS/4.22.0-dev, skipAfter:END-RESPONSE-954-DATA-LEAKAGES-IIS

#### Rule 10: 954014
- **Phase**: 4
- **Variables**: TX:DETECTION_PARANOIA_LEVEL
- **Operator**: @lt
- **Pattern**: 2
- **Is Chain**: False
- **Message**: 
- **Severity**: 
- **Tags**: OWASP_CRS
- **Actions**: id:954014, phase:4, pass, nolog, tag:OWASP_CRS, ver:OWASP_CRS/4.22.0-dev, skipAfter:END-RESPONSE-954-DATA-LEAKAGES-IIS

#### Rule 11: 954101
- **Phase**: 4
- **Variables**: RESPONSE_BODY
- **Operator**: @rx
- **Pattern**: (?i)[\x5c/]inetpub\b
- **Is Chain**: False
- **Message**: Disclosure of IIS install location
- **Severity**: ERROR
- **Tags**: application-multi, language-multi, platform-iis, platform-windows, attack-disclosure, paranoia-level/2, OWASP_CRS, OWASP_CRS/DATA-LEAKAGES-IIS, capec/1000/118/116
- **Actions**: id:954101, phase:4, block, capture, t:none, msg:Disclosure of IIS install location, logdata:Matched Data: %{TX.0} found within %{MATCHED_VAR_NAME}, tag:application-multi, tag:language-multi, tag:platform-iis, tag:platform-windows, tag:attack-disclosure, tag:paranoia-level/2, tag:OWASP_CRS, tag:OWASP_CRS/DATA-LEAKAGES-IIS, tag:capec/1000/118/116, ver:OWASP_CRS/4.22.0-dev, severity:ERROR, setvar:tx.outbound_anomaly_score_pl2=+%{tx.error_anomaly_score}

#### Rule 12: 954015
- **Phase**: 3
- **Variables**: TX:DETECTION_PARANOIA_LEVEL
- **Operator**: @lt
- **Pattern**: 3
- **Is Chain**: False
- **Message**: 
- **Severity**: 
- **Tags**: OWASP_CRS
- **Actions**: id:954015, phase:3, pass, nolog, tag:OWASP_CRS, ver:OWASP_CRS/4.22.0-dev, skipAfter:END-RESPONSE-954-DATA-LEAKAGES-IIS

#### Rule 13: 954016
- **Phase**: 4
- **Variables**: TX:DETECTION_PARANOIA_LEVEL
- **Operator**: @lt
- **Pattern**: 3
- **Is Chain**: False
- **Message**: 
- **Severity**: 
- **Tags**: OWASP_CRS
- **Actions**: id:954016, phase:4, pass, nolog, tag:OWASP_CRS, ver:OWASP_CRS/4.22.0-dev, skipAfter:END-RESPONSE-954-DATA-LEAKAGES-IIS

#### Rule 14: 954017
- **Phase**: 3
- **Variables**: TX:DETECTION_PARANOIA_LEVEL
- **Operator**: @lt
- **Pattern**: 4
- **Is Chain**: False
- **Message**: 
- **Severity**: 
- **Tags**: OWASP_CRS
- **Actions**: id:954017, phase:3, pass, nolog, tag:OWASP_CRS, ver:OWASP_CRS/4.22.0-dev, skipAfter:END-RESPONSE-954-DATA-LEAKAGES-IIS

#### Rule 15: 954018
- **Phase**: 4
- **Variables**: TX:DETECTION_PARANOIA_LEVEL
- **Operator**: @lt
- **Pattern**: 4
- **Is Chain**: False
- **Message**: 
- **Severity**: 
- **Tags**: OWASP_CRS
- **Actions**: id:954018, phase:4, pass, nolog, tag:OWASP_CRS, ver:OWASP_CRS/4.22.0-dev, skipAfter:END-RESPONSE-954-DATA-LEAKAGES-IIS


====================================================================================================

## File: RESPONSE-955-WEB-SHELLS.conf

### File Summary
- Total rules: 36
- Chained rules: 0
- Non-chained rules: 36

### Detailed Rules

#### Rule 1: 955010
- **Phase**: 4
- **Variables**: RESPONSE_HEADERS:Content-Encoding
- **Operator**: @pm
- **Pattern**: gzip compress deflate br zstd
- **Is Chain**: False
- **Message**: 
- **Severity**: 
- **Tags**: OWASP_CRS, OWASP_CRS/WEB-SHELLS
- **Actions**: id:955010, phase:4, pass, nolog, tag:OWASP_CRS, tag:OWASP_CRS/WEB-SHELLS, ver:OWASP_CRS/4.22.0-dev, skipAfter:END-RESPONSE-955-WEB-SHELLS

#### Rule 2: 955011
- **Phase**: 3
- **Variables**: TX:DETECTION_PARANOIA_LEVEL
- **Operator**: @lt
- **Pattern**: 1
- **Is Chain**: False
- **Message**: 
- **Severity**: 
- **Tags**: OWASP_CRS
- **Actions**: id:955011, phase:3, pass, nolog, tag:OWASP_CRS, ver:OWASP_CRS/4.22.0-dev, skipAfter:END-RESPONSE-955-WEB-SHELLS

#### Rule 3: 955012
- **Phase**: 4
- **Variables**: TX:DETECTION_PARANOIA_LEVEL
- **Operator**: @lt
- **Pattern**: 1
- **Is Chain**: False
- **Message**: 
- **Severity**: 
- **Tags**: OWASP_CRS
- **Actions**: id:955012, phase:4, pass, nolog, tag:OWASP_CRS, ver:OWASP_CRS/4.22.0-dev, skipAfter:END-RESPONSE-955-WEB-SHELLS

#### Rule 4: 955100
- **Phase**: 4
- **Variables**: RESPONSE_BODY
- **Operator**: @pmFromFile
- **Pattern**: web-shells-php.data
- **Is Chain**: False
- **Message**: PHP Web shell detected
- **Severity**: CRITICAL
- **Tags**: language-php, platform-multi, attack-rce, paranoia-level/1, OWASP_CRS, OWASP_CRS/WEB-SHELLS, capec/1000/225/122/17/650
- **Actions**: id:955100, phase:4, block, capture, t:none, msg:PHP Web shell detected, logdata:Matched Data: %{TX.0} found within %{MATCHED_VAR_NAME}, tag:language-php, tag:platform-multi, tag:attack-rce, tag:paranoia-level/1, tag:OWASP_CRS, tag:OWASP_CRS/WEB-SHELLS, tag:capec/1000/225/122/17/650, ver:OWASP_CRS/4.22.0-dev, severity:CRITICAL, setvar:tx.outbound_anomaly_score_pl1=+%{tx.critical_anomaly_score}

#### Rule 5: 955110
- **Phase**: 4
- **Variables**: RESPONSE_BODY
- **Operator**: @rx
- **Pattern**: <title>r57 Shell Version [0-9.]+</title>|<title>r57 shell</title>
- **Is Chain**: False
- **Message**: r57 web shell
- **Severity**: CRITICAL
- **Tags**: language-php, platform-multi, attack-rce, paranoia-level/1, OWASP_CRS, OWASP_CRS/WEB-SHELLS, capec/1000/225/122/17/650
- **Actions**: id:955110, phase:4, block, capture, t:none, msg:r57 web shell, logdata:Matched Data: %{TX.0} found within %{MATCHED_VAR_NAME}, tag:language-php, tag:platform-multi, tag:attack-rce, tag:paranoia-level/1, tag:OWASP_CRS, tag:OWASP_CRS/WEB-SHELLS, tag:capec/1000/225/122/17/650, ver:OWASP_CRS/4.22.0-dev, severity:CRITICAL, setvar:tx.outbound_anomaly_score_pl1=+%{tx.critical_anomaly_score}

#### Rule 6: 955120
- **Phase**: 4
- **Variables**: RESPONSE_BODY
- **Operator**: @rx
- **Pattern**: ^<html><head><meta http-equiv='Content-Type' content='text/html; charset=(?:Windows-1251|UTF-8)?'><title>.*?(?: -)? W[Ss][Oo] [0-9.]+</title>
- **Is Chain**: False
- **Message**: WSO web shell
- **Severity**: CRITICAL
- **Tags**: language-php, platform-multi, attack-rce, paranoia-level/1, OWASP_CRS, OWASP_CRS/WEB-SHELLS, capec/1000/225/122/17/650
- **Actions**: id:955120, phase:4, block, capture, t:none, msg:WSO web shell, logdata:Matched Data: %{TX.0} found within %{MATCHED_VAR_NAME}, tag:language-php, tag:platform-multi, tag:attack-rce, tag:paranoia-level/1, tag:OWASP_CRS, tag:OWASP_CRS/WEB-SHELLS, tag:capec/1000/225/122/17/650, ver:OWASP_CRS/4.22.0-dev, severity:CRITICAL, setvar:tx.outbound_anomaly_score_pl1=+%{tx.critical_anomaly_score}

#### Rule 7: 955130
- **Phase**: 4
- **Variables**: RESPONSE_BODY
- **Operator**: @rx
- **Pattern**: B4TM4N SH3LL</title>[^<]*<meta name='author' content='k4mpr3t'/>
- **Is Chain**: False
- **Message**: b4tm4n web shell
- **Severity**: CRITICAL
- **Tags**: language-php, platform-multi, attack-rce, paranoia-level/1, OWASP_CRS, OWASP_CRS/WEB-SHELLS, capec/1000/225/122/17/650
- **Actions**: id:955130, phase:4, block, capture, t:none, msg:b4tm4n web shell, logdata:Matched Data: %{TX.0} found within %{MATCHED_VAR_NAME}, tag:language-php, tag:platform-multi, tag:attack-rce, tag:paranoia-level/1, tag:OWASP_CRS, tag:OWASP_CRS/WEB-SHELLS, tag:capec/1000/225/122/17/650, ver:OWASP_CRS/4.22.0-dev, severity:CRITICAL, setvar:tx.outbound_anomaly_score_pl1=+%{tx.critical_anomaly_score}

#### Rule 8: 955140
- **Phase**: 4
- **Variables**: RESPONSE_BODY
- **Operator**: @rx
- **Pattern**: <title>Mini Shell</title>[^D]*Developed By LameHacker
- **Is Chain**: False
- **Message**: Mini Shell web shell
- **Severity**: CRITICAL
- **Tags**: language-php, platform-multi, attack-rce, paranoia-level/1, OWASP_CRS, OWASP_CRS/WEB-SHELLS, capec/1000/225/122/17/650
- **Actions**: id:955140, phase:4, block, capture, t:none, msg:Mini Shell web shell, logdata:Matched Data: %{TX.0} found within %{MATCHED_VAR_NAME}, tag:language-php, tag:platform-multi, tag:attack-rce, tag:paranoia-level/1, tag:OWASP_CRS, tag:OWASP_CRS/WEB-SHELLS, tag:capec/1000/225/122/17/650, ver:OWASP_CRS/4.22.0-dev, severity:CRITICAL, setvar:tx.outbound_anomaly_score_pl1=+%{tx.critical_anomaly_score}

#### Rule 9: 955150
- **Phase**: 4
- **Variables**: RESPONSE_BODY
- **Operator**: @rx
- **Pattern**: <title>\.:: [^~]*~ Ashiyane V [0-9.]+ ::\.</title>
- **Is Chain**: False
- **Message**: Ashiyane web shell
- **Severity**: CRITICAL
- **Tags**: language-php, platform-multi, attack-rce, paranoia-level/1, OWASP_CRS, OWASP_CRS/WEB-SHELLS, capec/1000/225/122/17/650
- **Actions**: id:955150, phase:4, block, capture, t:none, msg:Ashiyane web shell, logdata:Matched Data: %{TX.0} found within %{MATCHED_VAR_NAME}, tag:language-php, tag:platform-multi, tag:attack-rce, tag:paranoia-level/1, tag:OWASP_CRS, tag:OWASP_CRS/WEB-SHELLS, tag:capec/1000/225/122/17/650, ver:OWASP_CRS/4.22.0-dev, severity:CRITICAL, setvar:tx.outbound_anomaly_score_pl1=+%{tx.critical_anomaly_score}

#### Rule 10: 955160
- **Phase**: 4
- **Variables**: RESPONSE_BODY
- **Operator**: @rx
- **Pattern**: <title>Symlink_Sa [0-9.]+</title>
- **Is Chain**: False
- **Message**: Symlink_Sa web shell
- **Severity**: CRITICAL
- **Tags**: language-php, platform-multi, attack-rce, paranoia-level/1, OWASP_CRS, OWASP_CRS/WEB-SHELLS, capec/1000/225/122/17/650
- **Actions**: id:955160, phase:4, block, capture, t:none, msg:Symlink_Sa web shell, logdata:Matched Data: %{TX.0} found within %{MATCHED_VAR_NAME}, tag:language-php, tag:platform-multi, tag:attack-rce, tag:paranoia-level/1, tag:OWASP_CRS, tag:OWASP_CRS/WEB-SHELLS, tag:capec/1000/225/122/17/650, ver:OWASP_CRS/4.22.0-dev, severity:CRITICAL, setvar:tx.outbound_anomaly_score_pl1=+%{tx.critical_anomaly_score}

#### Rule 11: 955170
- **Phase**: 4
- **Variables**: RESPONSE_BODY
- **Operator**: @rx
- **Pattern**: <title>CasuS [0-9.]+ by MafiABoY</title>
- **Is Chain**: False
- **Message**: CasuS web shell
- **Severity**: CRITICAL
- **Tags**: language-php, platform-multi, attack-rce, paranoia-level/1, OWASP_CRS, OWASP_CRS/WEB-SHELLS, capec/1000/225/122/17/650
- **Actions**: id:955170, phase:4, block, capture, t:none, msg:CasuS web shell, logdata:Matched Data: %{TX.0} found within %{MATCHED_VAR_NAME}, tag:language-php, tag:platform-multi, tag:attack-rce, tag:paranoia-level/1, tag:OWASP_CRS, tag:OWASP_CRS/WEB-SHELLS, tag:capec/1000/225/122/17/650, ver:OWASP_CRS/4.22.0-dev, severity:CRITICAL, setvar:tx.outbound_anomaly_score_pl1=+%{tx.critical_anomaly_score}

#### Rule 12: 955180
- **Phase**: 4
- **Variables**: RESPONSE_BODY
- **Operator**: @rx
- **Pattern**: ^<html>\r\n<head>\r\n<title>GRP WebShell [0-9.]+ 
- **Is Chain**: False
- **Message**: GRP WebShell
- **Severity**: CRITICAL
- **Tags**: language-php, platform-multi, attack-rce, paranoia-level/1, OWASP_CRS, OWASP_CRS/WEB-SHELLS, capec/1000/225/122/17/650
- **Actions**: id:955180, phase:4, block, capture, t:none, msg:GRP WebShell, logdata:Matched Data: %{TX.0} found within %{MATCHED_VAR_NAME}, tag:language-php, tag:platform-multi, tag:attack-rce, tag:paranoia-level/1, tag:OWASP_CRS, tag:OWASP_CRS/WEB-SHELLS, tag:capec/1000/225/122/17/650, ver:OWASP_CRS/4.22.0-dev, severity:CRITICAL, setvar:tx.outbound_anomaly_score_pl1=+%{tx.critical_anomaly_score}

#### Rule 13: 955190
- **Phase**: 4
- **Variables**: RESPONSE_BODY
- **Operator**: @rx
- **Pattern**: <small>NGHshell [0-9.]+ by Cr4sh</body></html>\n$
- **Is Chain**: False
- **Message**: NGHshell web shell
- **Severity**: CRITICAL
- **Tags**: language-php, platform-multi, attack-rce, paranoia-level/1, OWASP_CRS, OWASP_CRS/WEB-SHELLS, capec/1000/225/122/17/650
- **Actions**: id:955190, phase:4, block, capture, t:none, msg:NGHshell web shell, logdata:Matched Data: %{TX.0} found within %{MATCHED_VAR_NAME}, tag:language-php, tag:platform-multi, tag:attack-rce, tag:paranoia-level/1, tag:OWASP_CRS, tag:OWASP_CRS/WEB-SHELLS, tag:capec/1000/225/122/17/650, ver:OWASP_CRS/4.22.0-dev, severity:CRITICAL, setvar:tx.outbound_anomaly_score_pl1=+%{tx.critical_anomaly_score}

#### Rule 14: 955200
- **Phase**: 4
- **Variables**: RESPONSE_BODY
- **Operator**: @rx
- **Pattern**: <title>SimAttacker - (?:Version|Vrsion) : [0-9.]+ - 
- **Is Chain**: False
- **Message**: SimAttacker web shell
- **Severity**: CRITICAL
- **Tags**: language-php, platform-multi, attack-rce, paranoia-level/1, OWASP_CRS, OWASP_CRS/WEB-SHELLS, capec/1000/225/122/17/650
- **Actions**: id:955200, phase:4, block, capture, t:none, msg:SimAttacker web shell, logdata:Matched Data: %{TX.0} found within %{MATCHED_VAR_NAME}, tag:language-php, tag:platform-multi, tag:attack-rce, tag:paranoia-level/1, tag:OWASP_CRS, tag:OWASP_CRS/WEB-SHELLS, tag:capec/1000/225/122/17/650, ver:OWASP_CRS/4.22.0-dev, severity:CRITICAL, setvar:tx.outbound_anomaly_score_pl1=+%{tx.critical_anomaly_score}

#### Rule 15: 955210
- **Phase**: 4
- **Variables**: RESPONSE_BODY
- **Operator**: @rx
- **Pattern**: ^<!DOCTYPE html>\n<html>\n<!-- By Artyum [^<]*<title>Web Shell</title>
- **Is Chain**: False
- **Message**: Unknown web shell
- **Severity**: CRITICAL
- **Tags**: language-php, platform-multi, attack-rce, paranoia-level/1, OWASP_CRS, OWASP_CRS/WEB-SHELLS, capec/1000/225/122/17/650
- **Actions**: id:955210, phase:4, block, capture, t:none, msg:Unknown web shell, logdata:Matched Data: %{TX.0} found within %{MATCHED_VAR_NAME}, tag:language-php, tag:platform-multi, tag:attack-rce, tag:paranoia-level/1, tag:OWASP_CRS, tag:OWASP_CRS/WEB-SHELLS, tag:capec/1000/225/122/17/650, ver:OWASP_CRS/4.22.0-dev, severity:CRITICAL, setvar:tx.outbound_anomaly_score_pl1=+%{tx.critical_anomaly_score}

#### Rule 16: 955220
- **Phase**: 4
- **Variables**: RESPONSE_BODY
- **Operator**: @rx
- **Pattern**: <title>lama's'hell v. [0-9.]+</title>
- **Is Chain**: False
- **Message**: lama\'s\'hell web shell
- **Severity**: CRITICAL
- **Tags**: language-php, platform-multi, attack-rce, paranoia-level/1, OWASP_CRS, OWASP_CRS/WEB-SHELLS, capec/1000/225/122/17/650
- **Actions**: id:955220, phase:4, block, capture, t:none, msg:lama\'s\'hell web shell, logdata:Matched Data: %{TX.0} found within %{MATCHED_VAR_NAME}, tag:language-php, tag:platform-multi, tag:attack-rce, tag:paranoia-level/1, tag:OWASP_CRS, tag:OWASP_CRS/WEB-SHELLS, tag:capec/1000/225/122/17/650, ver:OWASP_CRS/4.22.0-dev, severity:CRITICAL, setvar:tx.outbound_anomaly_score_pl1=+%{tx.critical_anomaly_score}

#### Rule 17: 955230
- **Phase**: 4
- **Variables**: RESPONSE_BODY
- **Operator**: @rx
- **Pattern**: ^ *<html>\n[ ]+<head>\n[ ]+<title>lostDC - 
- **Is Chain**: False
- **Message**: lostDC web shell
- **Severity**: CRITICAL
- **Tags**: language-php, platform-multi, attack-rce, paranoia-level/1, OWASP_CRS, OWASP_CRS/WEB-SHELLS, capec/1000/225/122/17/650
- **Actions**: id:955230, phase:4, block, capture, t:none, msg:lostDC web shell, logdata:Matched Data: %{TX.0} found within %{MATCHED_VAR_NAME}, tag:language-php, tag:platform-multi, tag:attack-rce, tag:paranoia-level/1, tag:OWASP_CRS, tag:OWASP_CRS/WEB-SHELLS, tag:capec/1000/225/122/17/650, ver:OWASP_CRS/4.22.0-dev, severity:CRITICAL, setvar:tx.outbound_anomaly_score_pl1=+%{tx.critical_anomaly_score}

#### Rule 18: 955240
- **Phase**: 4
- **Variables**: RESPONSE_BODY
- **Operator**: @rx
- **Pattern**: ^<title>PHP Web Shell</title>\r\n<html>\r\n<body>\r\n    <!-- Replaces command with Base64-encoded Data -->
- **Is Chain**: False
- **Message**: Unknown web shell
- **Severity**: CRITICAL
- **Tags**: language-php, platform-multi, attack-rce, paranoia-level/1, OWASP_CRS, OWASP_CRS/WEB-SHELLS, capec/1000/225/122/17/650
- **Actions**: id:955240, phase:4, block, capture, t:none, msg:Unknown web shell, logdata:Matched Data: %{TX.0} found within %{MATCHED_VAR_NAME}, tag:language-php, tag:platform-multi, tag:attack-rce, tag:paranoia-level/1, tag:OWASP_CRS, tag:OWASP_CRS/WEB-SHELLS, tag:capec/1000/225/122/17/650, ver:OWASP_CRS/4.22.0-dev, severity:CRITICAL, setvar:tx.outbound_anomaly_score_pl1=+%{tx.critical_anomaly_score}

#### Rule 19: 955250
- **Phase**: 4
- **Variables**: RESPONSE_BODY
- **Operator**: @rx
- **Pattern**: ^<html>\n<head>\n<div align=\"left\"><font size=\"1\">Input command :</font></div>\n<form name=\"cmd\" method=\"POST\" enctype=\"multipart/form-data\">
- **Is Chain**: False
- **Message**: Unknown web shell
- **Severity**: CRITICAL
- **Tags**: language-php, platform-multi, attack-rce, paranoia-level/1, OWASP_CRS, OWASP_CRS/WEB-SHELLS, capec/1000/225/122/17/650
- **Actions**: id:955250, phase:4, block, capture, t:none, msg:Unknown web shell, logdata:Matched Data: %{TX.0} found within %{MATCHED_VAR_NAME}, tag:language-php, tag:platform-multi, tag:attack-rce, tag:paranoia-level/1, tag:OWASP_CRS, tag:OWASP_CRS/WEB-SHELLS, tag:capec/1000/225/122/17/650, ver:OWASP_CRS/4.22.0-dev, severity:CRITICAL, setvar:tx.outbound_anomaly_score_pl1=+%{tx.critical_anomaly_score}

#### Rule 20: 955260
- **Phase**: 4
- **Variables**: RESPONSE_BODY
- **Operator**: @rx
- **Pattern**: ^<html>\n<head>\n<title>Ru24PostWebShell 
- **Is Chain**: False
- **Message**: Ru24PostWebShell web shell
- **Severity**: CRITICAL
- **Tags**: language-php, platform-multi, attack-rce, paranoia-level/1, OWASP_CRS, OWASP_CRS/WEB-SHELLS, capec/1000/225/122/17/650
- **Actions**: id:955260, phase:4, block, capture, t:none, msg:Ru24PostWebShell web shell, logdata:Matched Data: %{TX.0} found within %{MATCHED_VAR_NAME}, tag:language-php, tag:platform-multi, tag:attack-rce, tag:paranoia-level/1, tag:OWASP_CRS, tag:OWASP_CRS/WEB-SHELLS, tag:capec/1000/225/122/17/650, ver:OWASP_CRS/4.22.0-dev, severity:CRITICAL, setvar:tx.outbound_anomaly_score_pl1=+%{tx.critical_anomaly_score}

#### Rule 21: 955270
- **Phase**: 4
- **Variables**: RESPONSE_BODY
- **Operator**: @rx
- **Pattern**: <title>s72 Shell v[0-9.]+ Codinf by Cr@zy_King</title>
- **Is Chain**: False
- **Message**: s72 Shell web shell
- **Severity**: CRITICAL
- **Tags**: language-php, platform-multi, attack-rce, paranoia-level/1, OWASP_CRS, OWASP_CRS/WEB-SHELLS, capec/1000/225/122/17/650
- **Actions**: id:955270, phase:4, block, capture, t:none, msg:s72 Shell web shell, logdata:Matched Data: %{TX.0} found within %{MATCHED_VAR_NAME}, tag:language-php, tag:platform-multi, tag:attack-rce, tag:paranoia-level/1, tag:OWASP_CRS, tag:OWASP_CRS/WEB-SHELLS, tag:capec/1000/225/122/17/650, ver:OWASP_CRS/4.22.0-dev, severity:CRITICAL, setvar:tx.outbound_anomaly_score_pl1=+%{tx.critical_anomaly_score}

#### Rule 22: 955280
- **Phase**: 4
- **Variables**: RESPONSE_BODY
- **Operator**: @rx
- **Pattern**: ^<html>\r\n<head>\r\n<meta http-equiv=\"Content-Type\" content=\"text/html; charset=gb2312\">\r\n<title>PhpSpy Ver [0-9]+</title>
- **Is Chain**: False
- **Message**: PhpSpy web shell
- **Severity**: CRITICAL
- **Tags**: language-php, platform-multi, attack-rce, paranoia-level/1, OWASP_CRS, OWASP_CRS/WEB-SHELLS, capec/1000/225/122/17/650
- **Actions**: id:955280, phase:4, block, capture, t:none, msg:PhpSpy web shell, logdata:Matched Data: %{TX.0} found within %{MATCHED_VAR_NAME}, tag:language-php, tag:platform-multi, tag:attack-rce, tag:paranoia-level/1, tag:OWASP_CRS, tag:OWASP_CRS/WEB-SHELLS, tag:capec/1000/225/122/17/650, ver:OWASP_CRS/4.22.0-dev, severity:CRITICAL, setvar:tx.outbound_anomaly_score_pl1=+%{tx.critical_anomaly_score}

#### Rule 23: 955290
- **Phase**: 4
- **Variables**: RESPONSE_BODY
- **Operator**: @rx
- **Pattern**: ^ <html>\n\n<head>\n\n<title>g00nshell v[0-9.]+ 
- **Is Chain**: False
- **Message**: g00nshell web shell
- **Severity**: CRITICAL
- **Tags**: language-php, platform-multi, attack-rce, paranoia-level/1, OWASP_CRS, OWASP_CRS/WEB-SHELLS, capec/1000/225/122/17/650
- **Actions**: id:955290, phase:4, block, capture, t:none, msg:g00nshell web shell, logdata:Matched Data: %{TX.0} found within %{MATCHED_VAR_NAME}, tag:language-php, tag:platform-multi, tag:attack-rce, tag:paranoia-level/1, tag:OWASP_CRS, tag:OWASP_CRS/WEB-SHELLS, tag:capec/1000/225/122/17/650, ver:OWASP_CRS/4.22.0-dev, severity:CRITICAL, setvar:tx.outbound_anomaly_score_pl1=+%{tx.critical_anomaly_score}

#### Rule 24: 955300
- **Phase**: 4
- **Variables**: RESPONSE_BODY
- **Operator**: @contains
- **Pattern**: <title>punkholicshell</title>
- **Is Chain**: False
- **Message**: PuNkHoLic shell web shell
- **Severity**: CRITICAL
- **Tags**: language-php, platform-multi, attack-rce, paranoia-level/1, OWASP_CRS, OWASP_CRS/WEB-SHELLS, capec/1000/225/122/17/650
- **Actions**: id:955300, phase:4, block, capture, t:none, t:removeWhitespace, t:lowercase, msg:PuNkHoLic shell web shell, logdata:Matched Data: %{TX.0} found within %{MATCHED_VAR_NAME}, tag:language-php, tag:platform-multi, tag:attack-rce, tag:paranoia-level/1, tag:OWASP_CRS, tag:OWASP_CRS/WEB-SHELLS, tag:capec/1000/225/122/17/650, ver:OWASP_CRS/4.22.0-dev, severity:CRITICAL, setvar:tx.outbound_anomaly_score_pl1=+%{tx.critical_anomaly_score}

#### Rule 25: 955310
- **Phase**: 4
- **Variables**: RESPONSE_BODY
- **Operator**: @rx
- **Pattern**: ^<html>\n      <head>\n             <title>azrail [0-9.]+ by C-W-M</title>
- **Is Chain**: False
- **Message**: azrail web shell
- **Severity**: CRITICAL
- **Tags**: language-php, platform-multi, attack-rce, paranoia-level/1, OWASP_CRS, OWASP_CRS/WEB-SHELLS, capec/1000/225/122/17/650
- **Actions**: id:955310, phase:4, block, capture, t:none, msg:azrail web shell, logdata:Matched Data: %{TX.0} found within %{MATCHED_VAR_NAME}, tag:language-php, tag:platform-multi, tag:attack-rce, tag:paranoia-level/1, tag:OWASP_CRS, tag:OWASP_CRS/WEB-SHELLS, tag:capec/1000/225/122/17/650, ver:OWASP_CRS/4.22.0-dev, severity:CRITICAL, setvar:tx.outbound_anomaly_score_pl1=+%{tx.critical_anomaly_score}

#### Rule 26: 955320
- **Phase**: 4
- **Variables**: RESPONSE_BODY
- **Operator**: @rx
- **Pattern**: >SmEvK_PaThAn Shell v[0-9]+ coded by <a href=
- **Is Chain**: False
- **Message**: SmEvK_PaThAn Shell web shell
- **Severity**: CRITICAL
- **Tags**: language-php, platform-multi, attack-rce, paranoia-level/1, OWASP_CRS, OWASP_CRS/WEB-SHELLS, capec/1000/225/122/17/650
- **Actions**: id:955320, phase:4, block, capture, t:none, msg:SmEvK_PaThAn Shell web shell, logdata:Matched Data: %{TX.0} found within %{MATCHED_VAR_NAME}, tag:language-php, tag:platform-multi, tag:attack-rce, tag:paranoia-level/1, tag:OWASP_CRS, tag:OWASP_CRS/WEB-SHELLS, tag:capec/1000/225/122/17/650, ver:OWASP_CRS/4.22.0-dev, severity:CRITICAL, setvar:tx.outbound_anomaly_score_pl1=+%{tx.critical_anomaly_score}

#### Rule 27: 955330
- **Phase**: 4
- **Variables**: RESPONSE_BODY
- **Operator**: @rx
- **Pattern**: ^<html>\n<title>[^~]*~ Shell I</title>\n<head>\n<style>
- **Is Chain**: False
- **Message**: Shell I web shell
- **Severity**: CRITICAL
- **Tags**: language-php, platform-multi, attack-rce, paranoia-level/1, OWASP_CRS, OWASP_CRS/WEB-SHELLS, capec/1000/225/122/17/650
- **Actions**: id:955330, phase:4, block, capture, t:none, msg:Shell I web shell, logdata:Matched Data: %{TX.0} found within %{MATCHED_VAR_NAME}, tag:language-php, tag:platform-multi, tag:attack-rce, tag:paranoia-level/1, tag:OWASP_CRS, tag:OWASP_CRS/WEB-SHELLS, tag:capec/1000/225/122/17/650, ver:OWASP_CRS/4.22.0-dev, severity:CRITICAL, setvar:tx.outbound_anomaly_score_pl1=+%{tx.critical_anomaly_score}

#### Rule 28: 955340
- **Phase**: 4
- **Variables**: RESPONSE_BODY
- **Operator**: @rx
- **Pattern**: ^ <html><head><title>:: b374k m1n1 [0-9.]+ ::</title>
- **Is Chain**: False
- **Message**: b374k m1n1 web shell
- **Severity**: CRITICAL
- **Tags**: language-php, platform-multi, attack-rce, paranoia-level/1, OWASP_CRS, OWASP_CRS/WEB-SHELLS, capec/1000/225/122/17/650
- **Actions**: id:955340, phase:4, block, capture, t:none, msg:b374k m1n1 web shell, logdata:Matched Data: %{TX.0} found within %{MATCHED_VAR_NAME}, tag:language-php, tag:platform-multi, tag:attack-rce, tag:paranoia-level/1, tag:OWASP_CRS, tag:OWASP_CRS/WEB-SHELLS, tag:capec/1000/225/122/17/650, ver:OWASP_CRS/4.22.0-dev, severity:CRITICAL, setvar:tx.outbound_anomaly_score_pl1=+%{tx.critical_anomaly_score}

#### Rule 29: 955400
- **Phase**: 4
- **Variables**: RESPONSE_BODY
- **Operator**: @pmFromFile
- **Pattern**: web-shells-asp.data
- **Is Chain**: False
- **Message**: ASP Web shell detected
- **Severity**: CRITICAL
- **Tags**: language-php, platform-multi, attack-rce, paranoia-level/1, OWASP_CRS, OWASP_CRS/WEB-SHELLS, capec/1000/225/122/17/650
- **Actions**: id:955400, phase:4, block, capture, t:none, msg:ASP Web shell detected, logdata:Matched Data: %{TX.0} found within %{MATCHED_VAR_NAME}, tag:language-php, tag:platform-multi, tag:attack-rce, tag:paranoia-level/1, tag:OWASP_CRS, tag:OWASP_CRS/WEB-SHELLS, tag:capec/1000/225/122/17/650, ver:OWASP_CRS/4.22.0-dev, severity:CRITICAL, setvar:tx.outbound_anomaly_score_pl1=+%{tx.critical_anomaly_score}

#### Rule 30: 955013
- **Phase**: 3
- **Variables**: TX:DETECTION_PARANOIA_LEVEL
- **Operator**: @lt
- **Pattern**: 2
- **Is Chain**: False
- **Message**: 
- **Severity**: 
- **Tags**: OWASP_CRS
- **Actions**: id:955013, phase:3, pass, nolog, tag:OWASP_CRS, ver:OWASP_CRS/4.22.0-dev, skipAfter:END-RESPONSE-955-WEB-SHELLS

#### Rule 31: 955014
- **Phase**: 4
- **Variables**: TX:DETECTION_PARANOIA_LEVEL
- **Operator**: @lt
- **Pattern**: 2
- **Is Chain**: False
- **Message**: 
- **Severity**: 
- **Tags**: OWASP_CRS
- **Actions**: id:955014, phase:4, pass, nolog, tag:OWASP_CRS, ver:OWASP_CRS/4.22.0-dev, skipAfter:END-RESPONSE-955-WEB-SHELLS

#### Rule 32: 955350
- **Phase**: 4
- **Variables**: RESPONSE_BODY
- **Operator**: @contains
- **Pattern**: <h1 style=\"margin-bottom: 0\">webadmin.php</h1>
- **Is Chain**: False
- **Message**: webadmin.php file manager
- **Severity**: CRITICAL
- **Tags**: language-php, platform-multi, attack-rce, paranoia-level/2, OWASP_CRS, OWASP_CRS/WEB-SHELLS, capec/1000/225/122/17/650
- **Actions**: id:955350, phase:4, block, capture, t:none, msg:webadmin.php file manager, logdata:Matched Data: %{TX.0} found within %{MATCHED_VAR_NAME}, tag:language-php, tag:platform-multi, tag:attack-rce, tag:paranoia-level/2, tag:OWASP_CRS, tag:OWASP_CRS/WEB-SHELLS, tag:capec/1000/225/122/17/650, ver:OWASP_CRS/4.22.0-dev, severity:CRITICAL, setvar:tx.outbound_anomaly_score_pl2=+%{tx.critical_anomaly_score}

#### Rule 33: 955015
- **Phase**: 3
- **Variables**: TX:DETECTION_PARANOIA_LEVEL
- **Operator**: @lt
- **Pattern**: 3
- **Is Chain**: False
- **Message**: 
- **Severity**: 
- **Tags**: OWASP_CRS
- **Actions**: id:955015, phase:3, pass, nolog, tag:OWASP_CRS, ver:OWASP_CRS/4.22.0-dev, skipAfter:END-RESPONSE-955-WEB-SHELLS

#### Rule 34: 955016
- **Phase**: 4
- **Variables**: TX:DETECTION_PARANOIA_LEVEL
- **Operator**: @lt
- **Pattern**: 3
- **Is Chain**: False
- **Message**: 
- **Severity**: 
- **Tags**: OWASP_CRS
- **Actions**: id:955016, phase:4, pass, nolog, tag:OWASP_CRS, ver:OWASP_CRS/4.22.0-dev, skipAfter:END-RESPONSE-955-WEB-SHELLS

#### Rule 35: 955017
- **Phase**: 3
- **Variables**: TX:DETECTION_PARANOIA_LEVEL
- **Operator**: @lt
- **Pattern**: 4
- **Is Chain**: False
- **Message**: 
- **Severity**: 
- **Tags**: OWASP_CRS
- **Actions**: id:955017, phase:3, pass, nolog, tag:OWASP_CRS, ver:OWASP_CRS/4.22.0-dev, skipAfter:END-RESPONSE-955-WEB-SHELLS

#### Rule 36: 955018
- **Phase**: 4
- **Variables**: TX:DETECTION_PARANOIA_LEVEL
- **Operator**: @lt
- **Pattern**: 4
- **Is Chain**: False
- **Message**: 
- **Severity**: 
- **Tags**: OWASP_CRS
- **Actions**: id:955018, phase:4, pass, nolog, tag:OWASP_CRS, ver:OWASP_CRS/4.22.0-dev, skipAfter:END-RESPONSE-955-WEB-SHELLS


====================================================================================================

## File: RESPONSE-956-DATA-LEAKAGES-RUBY.conf

### File Summary
- Total rules: 11
- Chained rules: 0
- Non-chained rules: 11

### Detailed Rules

#### Rule 1: 956010
- **Phase**: 4
- **Variables**: RESPONSE_HEADERS:Content-Encoding
- **Operator**: @pm
- **Pattern**: gzip compress deflate br zstd
- **Is Chain**: False
- **Message**: 
- **Severity**: 
- **Tags**: OWASP_CRS, OWASP_CRS/DATA-LEAKAGES-RUBY
- **Actions**: id:956010, phase:4, pass, nolog, tag:OWASP_CRS, tag:OWASP_CRS/DATA-LEAKAGES-RUBY, ver:OWASP_CRS/4.22.0-dev, skipAfter:END-RESPONSE-956-DATA-LEAKAGES-RUBY

#### Rule 2: 956011
- **Phase**: 3
- **Variables**: TX:DETECTION_PARANOIA_LEVEL
- **Operator**: @lt
- **Pattern**: 1
- **Is Chain**: False
- **Message**: 
- **Severity**: 
- **Tags**: OWASP_CRS
- **Actions**: id:956011, phase:3, pass, nolog, tag:OWASP_CRS, ver:OWASP_CRS/4.22.0-dev, skipAfter:END-RESPONSE-956-DATA-LEAKAGES-RUBY

#### Rule 3: 956012
- **Phase**: 4
- **Variables**: TX:DETECTION_PARANOIA_LEVEL
- **Operator**: @lt
- **Pattern**: 1
- **Is Chain**: False
- **Message**: 
- **Severity**: 
- **Tags**: OWASP_CRS
- **Actions**: id:956012, phase:4, pass, nolog, tag:OWASP_CRS, ver:OWASP_CRS/4.22.0-dev, skipAfter:END-RESPONSE-956-DATA-LEAKAGES-RUBY

#### Rule 4: 956100
- **Phase**: 4
- **Variables**: RESPONSE_BODY
- **Operator**: @pmFromFile
- **Pattern**: ruby-errors.data
- **Is Chain**: False
- **Message**: RUBY Information Leakage
- **Severity**: ERROR
- **Tags**: application-multi, language-ruby, platform-multi, attack-disclosure, paranoia-level/1, OWASP_CRS, OWASP_CRS/DATA-LEAKAGES-RUBY, capec/1000/118/116
- **Actions**: id:956100, phase:4, block, capture, t:none, msg:RUBY Information Leakage, logdata:Matched Data: %{TX.0} found within %{MATCHED_VAR_NAME}, tag:application-multi, tag:language-ruby, tag:platform-multi, tag:attack-disclosure, tag:paranoia-level/1, tag:OWASP_CRS, tag:OWASP_CRS/DATA-LEAKAGES-RUBY, tag:capec/1000/118/116, ver:OWASP_CRS/4.22.0-dev, severity:ERROR, setvar:tx.outbound_anomaly_score_pl1=+%{tx.error_anomaly_score}

#### Rule 5: 956013
- **Phase**: 3
- **Variables**: TX:DETECTION_PARANOIA_LEVEL
- **Operator**: @lt
- **Pattern**: 2
- **Is Chain**: False
- **Message**: 
- **Severity**: 
- **Tags**: OWASP_CRS
- **Actions**: id:956013, phase:3, pass, nolog, tag:OWASP_CRS, ver:OWASP_CRS/4.22.0-dev, skipAfter:END-RESPONSE-956-DATA-LEAKAGES-RUBY

#### Rule 6: 956014
- **Phase**: 4
- **Variables**: TX:DETECTION_PARANOIA_LEVEL
- **Operator**: @lt
- **Pattern**: 2
- **Is Chain**: False
- **Message**: 
- **Severity**: 
- **Tags**: OWASP_CRS
- **Actions**: id:956014, phase:4, pass, nolog, tag:OWASP_CRS, ver:OWASP_CRS/4.22.0-dev, skipAfter:END-RESPONSE-956-DATA-LEAKAGES-RUBY

#### Rule 7: 956110
- **Phase**: 4
- **Variables**: RESPONSE_BODY
- **Operator**: @rx
- **Pattern**: (?i)(?:<%[=#\s]|#\{[^}]+\})
- **Is Chain**: False
- **Message**: Ruby source code leakage
- **Severity**: ERROR
- **Tags**: application-multi, language-ruby, platform-multi, attack-disclosure, paranoia-level/2, OWASP_CRS, OWASP_CRS/DATA-LEAKAGES-RUBY, capec/1000/118/116
- **Actions**: id:956110, phase:4, block, capture, t:none, msg:Ruby source code leakage, logdata:Matched Data: %{TX.0} found within %{MATCHED_VAR_NAME}, tag:application-multi, tag:language-ruby, tag:platform-multi, tag:attack-disclosure, tag:paranoia-level/2, tag:OWASP_CRS, tag:OWASP_CRS/DATA-LEAKAGES-RUBY, tag:capec/1000/118/116, ver:OWASP_CRS/4.22.0-dev, severity:ERROR, setvar:tx.outbound_anomaly_score_pl2=+%{tx.error_anomaly_score}

#### Rule 8: 956015
- **Phase**: 3
- **Variables**: TX:DETECTION_PARANOIA_LEVEL
- **Operator**: @lt
- **Pattern**: 3
- **Is Chain**: False
- **Message**: 
- **Severity**: 
- **Tags**: OWASP_CRS
- **Actions**: id:956015, phase:3, pass, nolog, tag:OWASP_CRS, ver:OWASP_CRS/4.22.0-dev, skipAfter:END-RESPONSE-956-DATA-LEAKAGES-RUBY

#### Rule 9: 956016
- **Phase**: 4
- **Variables**: TX:DETECTION_PARANOIA_LEVEL
- **Operator**: @lt
- **Pattern**: 3
- **Is Chain**: False
- **Message**: 
- **Severity**: 
- **Tags**: OWASP_CRS
- **Actions**: id:956016, phase:4, pass, nolog, tag:OWASP_CRS, ver:OWASP_CRS/4.22.0-dev, skipAfter:END-RESPONSE-956-DATA-LEAKAGES-RUBY

#### Rule 10: 956017
- **Phase**: 3
- **Variables**: TX:DETECTION_PARANOIA_LEVEL
- **Operator**: @lt
- **Pattern**: 4
- **Is Chain**: False
- **Message**: 
- **Severity**: 
- **Tags**: OWASP_CRS
- **Actions**: id:956017, phase:3, pass, nolog, tag:OWASP_CRS, ver:OWASP_CRS/4.22.0-dev, skipAfter:END-RESPONSE-956-DATA-LEAKAGES-RUBY

#### Rule 11: 956018
- **Phase**: 4
- **Variables**: TX:DETECTION_PARANOIA_LEVEL
- **Operator**: @lt
- **Pattern**: 4
- **Is Chain**: False
- **Message**: 
- **Severity**: 
- **Tags**: OWASP_CRS
- **Actions**: id:956018, phase:4, pass, nolog, tag:OWASP_CRS, ver:OWASP_CRS/4.22.0-dev, skipAfter:END-RESPONSE-956-DATA-LEAKAGES-RUBY


====================================================================================================

## File: RESPONSE-959-BLOCKING-EVALUATION.conf

### File Summary
- Total rules: 27
- Chained rules: 1
- Non-chained rules: 26

### Detailed Rules

#### Rule 1: 959052
- **Phase**: 3
- **Variables**: TX:BLOCKING_PARANOIA_LEVEL
- **Operator**: @ge
- **Pattern**: 1
- **Is Chain**: False
- **Message**: 
- **Severity**: 
- **Tags**: OWASP_CRS
- **Actions**: id:959052, phase:3, pass, t:none, nolog, tag:OWASP_CRS, ver:OWASP_CRS/4.22.0-dev, setvar:tx.blocking_outbound_anomaly_score=+%{tx.outbound_anomaly_score_pl1}

#### Rule 2: 959152
- **Phase**: 3
- **Variables**: TX:DETECTION_PARANOIA_LEVEL
- **Operator**: @ge
- **Pattern**: 1
- **Is Chain**: False
- **Message**: 
- **Severity**: 
- **Tags**: OWASP_CRS
- **Actions**: id:959152, phase:3, pass, t:none, nolog, tag:OWASP_CRS, ver:OWASP_CRS/4.22.0-dev, setvar:tx.detection_outbound_anomaly_score=+%{tx.outbound_anomaly_score_pl1}

#### Rule 3: 959053
- **Phase**: 3
- **Variables**: TX:BLOCKING_PARANOIA_LEVEL
- **Operator**: @ge
- **Pattern**: 2
- **Is Chain**: False
- **Message**: 
- **Severity**: 
- **Tags**: OWASP_CRS
- **Actions**: id:959053, phase:3, pass, t:none, nolog, tag:OWASP_CRS, ver:OWASP_CRS/4.22.0-dev, setvar:tx.blocking_outbound_anomaly_score=+%{tx.outbound_anomaly_score_pl2}

#### Rule 4: 959153
- **Phase**: 3
- **Variables**: TX:DETECTION_PARANOIA_LEVEL
- **Operator**: @ge
- **Pattern**: 2
- **Is Chain**: False
- **Message**: 
- **Severity**: 
- **Tags**: OWASP_CRS
- **Actions**: id:959153, phase:3, pass, t:none, nolog, tag:OWASP_CRS, ver:OWASP_CRS/4.22.0-dev, setvar:tx.detection_outbound_anomaly_score=+%{tx.outbound_anomaly_score_pl2}

#### Rule 5: 959054
- **Phase**: 3
- **Variables**: TX:BLOCKING_PARANOIA_LEVEL
- **Operator**: @ge
- **Pattern**: 3
- **Is Chain**: False
- **Message**: 
- **Severity**: 
- **Tags**: OWASP_CRS
- **Actions**: id:959054, phase:3, pass, t:none, nolog, tag:OWASP_CRS, ver:OWASP_CRS/4.22.0-dev, setvar:tx.blocking_outbound_anomaly_score=+%{tx.outbound_anomaly_score_pl3}

#### Rule 6: 959154
- **Phase**: 3
- **Variables**: TX:DETECTION_PARANOIA_LEVEL
- **Operator**: @ge
- **Pattern**: 3
- **Is Chain**: False
- **Message**: 
- **Severity**: 
- **Tags**: OWASP_CRS
- **Actions**: id:959154, phase:3, pass, t:none, nolog, tag:OWASP_CRS, ver:OWASP_CRS/4.22.0-dev, setvar:tx.detection_outbound_anomaly_score=+%{tx.outbound_anomaly_score_pl3}

#### Rule 7: 959055
- **Phase**: 3
- **Variables**: TX:BLOCKING_PARANOIA_LEVEL
- **Operator**: @ge
- **Pattern**: 4
- **Is Chain**: False
- **Message**: 
- **Severity**: 
- **Tags**: OWASP_CRS
- **Actions**: id:959055, phase:3, pass, t:none, nolog, tag:OWASP_CRS, ver:OWASP_CRS/4.22.0-dev, setvar:tx.blocking_outbound_anomaly_score=+%{tx.outbound_anomaly_score_pl4}

#### Rule 8: 959155
- **Phase**: 3
- **Variables**: TX:DETECTION_PARANOIA_LEVEL
- **Operator**: @ge
- **Pattern**: 4
- **Is Chain**: False
- **Message**: 
- **Severity**: 
- **Tags**: OWASP_CRS
- **Actions**: id:959155, phase:3, pass, t:none, nolog, tag:OWASP_CRS, ver:OWASP_CRS/4.22.0-dev, setvar:tx.detection_outbound_anomaly_score=+%{tx.outbound_anomaly_score_pl4}

#### Rule 9: 959060
- **Phase**: 4
- **Variables**: TX:BLOCKING_PARANOIA_LEVEL
- **Operator**: @ge
- **Pattern**: 1
- **Is Chain**: False
- **Message**: 
- **Severity**: 
- **Tags**: OWASP_CRS
- **Actions**: id:959060, phase:4, pass, t:none, nolog, tag:OWASP_CRS, ver:OWASP_CRS/4.22.0-dev, setvar:tx.blocking_outbound_anomaly_score=+%{tx.outbound_anomaly_score_pl1}

#### Rule 10: 959160
- **Phase**: 4
- **Variables**: TX:DETECTION_PARANOIA_LEVEL
- **Operator**: @ge
- **Pattern**: 1
- **Is Chain**: False
- **Message**: 
- **Severity**: 
- **Tags**: OWASP_CRS
- **Actions**: id:959160, phase:4, pass, t:none, nolog, tag:OWASP_CRS, ver:OWASP_CRS/4.22.0-dev, setvar:tx.detection_outbound_anomaly_score=+%{tx.outbound_anomaly_score_pl1}

#### Rule 11: 959061
- **Phase**: 4
- **Variables**: TX:BLOCKING_PARANOIA_LEVEL
- **Operator**: @ge
- **Pattern**: 2
- **Is Chain**: False
- **Message**: 
- **Severity**: 
- **Tags**: OWASP_CRS
- **Actions**: id:959061, phase:4, pass, t:none, nolog, tag:OWASP_CRS, ver:OWASP_CRS/4.22.0-dev, setvar:tx.blocking_outbound_anomaly_score=+%{tx.outbound_anomaly_score_pl2}

#### Rule 12: 959161
- **Phase**: 4
- **Variables**: TX:DETECTION_PARANOIA_LEVEL
- **Operator**: @ge
- **Pattern**: 2
- **Is Chain**: False
- **Message**: 
- **Severity**: 
- **Tags**: OWASP_CRS
- **Actions**: id:959161, phase:4, pass, t:none, nolog, tag:OWASP_CRS, ver:OWASP_CRS/4.22.0-dev, setvar:tx.detection_outbound_anomaly_score=+%{tx.outbound_anomaly_score_pl2}

#### Rule 13: 959062
- **Phase**: 4
- **Variables**: TX:BLOCKING_PARANOIA_LEVEL
- **Operator**: @ge
- **Pattern**: 3
- **Is Chain**: False
- **Message**: 
- **Severity**: 
- **Tags**: OWASP_CRS
- **Actions**: id:959062, phase:4, pass, t:none, nolog, tag:OWASP_CRS, ver:OWASP_CRS/4.22.0-dev, setvar:tx.blocking_outbound_anomaly_score=+%{tx.outbound_anomaly_score_pl3}

#### Rule 14: 959162
- **Phase**: 4
- **Variables**: TX:DETECTION_PARANOIA_LEVEL
- **Operator**: @ge
- **Pattern**: 3
- **Is Chain**: False
- **Message**: 
- **Severity**: 
- **Tags**: OWASP_CRS
- **Actions**: id:959162, phase:4, pass, t:none, nolog, tag:OWASP_CRS, ver:OWASP_CRS/4.22.0-dev, setvar:tx.detection_outbound_anomaly_score=+%{tx.outbound_anomaly_score_pl3}

#### Rule 15: 959063
- **Phase**: 4
- **Variables**: TX:BLOCKING_PARANOIA_LEVEL
- **Operator**: @ge
- **Pattern**: 4
- **Is Chain**: False
- **Message**: 
- **Severity**: 
- **Tags**: OWASP_CRS
- **Actions**: id:959063, phase:4, pass, t:none, nolog, tag:OWASP_CRS, ver:OWASP_CRS/4.22.0-dev, setvar:tx.blocking_outbound_anomaly_score=+%{tx.outbound_anomaly_score_pl4}

#### Rule 16: 959163
- **Phase**: 4
- **Variables**: TX:DETECTION_PARANOIA_LEVEL
- **Operator**: @ge
- **Pattern**: 4
- **Is Chain**: False
- **Message**: 
- **Severity**: 
- **Tags**: OWASP_CRS
- **Actions**: id:959163, phase:4, pass, t:none, nolog, tag:OWASP_CRS, ver:OWASP_CRS/4.22.0-dev, setvar:tx.detection_outbound_anomaly_score=+%{tx.outbound_anomaly_score_pl4}

#### Rule 17: 959101
- **Phase**: 3
- **Variables**: TX:BLOCKING_OUTBOUND_ANOMALY_SCORE
- **Operator**: @ge
- **Pattern**: %{tx.outbound_anomaly_score_threshold}
- **Is Chain**: True
- **Message**: Outbound Anomaly Score Exceeded in phase 3 (Total Score: %{tx.blocking_outbound_anomaly_score})
- **Severity**: 
- **Tags**: anomaly-evaluation, OWASP_CRS
- **Actions**: id:959101, phase:3, deny, t:none, msg:Outbound Anomaly Score Exceeded in phase 3 (Total Score: %{tx.blocking_outbound_anomaly_score}), tag:anomaly-evaluation, tag:OWASP_CRS, ver:OWASP_CRS/4.22.0-dev, chain

#### Rule 18: Unknown
- **Phase**: Unknown
- **Variables**: TX:EARLY_BLOCKING
- **Operator**: @eq
- **Pattern**: 1
- **Is Chain**: False
- **Message**: 
- **Severity**: 

#### Rule 19: 959100
- **Phase**: 4
- **Variables**: TX:BLOCKING_OUTBOUND_ANOMALY_SCORE
- **Operator**: @ge
- **Pattern**: %{tx.outbound_anomaly_score_threshold}
- **Is Chain**: False
- **Message**: Outbound Anomaly Score Exceeded (Total Score: %{tx.blocking_outbound_anomaly_score})
- **Severity**: 
- **Tags**: anomaly-evaluation, OWASP_CRS
- **Actions**: id:959100, phase:4, deny, t:none, msg:Outbound Anomaly Score Exceeded (Total Score: %{tx.blocking_outbound_anomaly_score}), tag:anomaly-evaluation, tag:OWASP_CRS, ver:OWASP_CRS/4.22.0-dev

#### Rule 20: 959011
- **Phase**: 3
- **Variables**: TX:DETECTION_PARANOIA_LEVEL
- **Operator**: @lt
- **Pattern**: 1
- **Is Chain**: False
- **Message**: 
- **Severity**: 
- **Tags**: OWASP_CRS
- **Actions**: id:959011, phase:3, pass, nolog, tag:OWASP_CRS, ver:OWASP_CRS/4.22.0-dev, skipAfter:END-RESPONSE-959-BLOCKING-EVALUATION

#### Rule 21: 959012
- **Phase**: 4
- **Variables**: TX:DETECTION_PARANOIA_LEVEL
- **Operator**: @lt
- **Pattern**: 1
- **Is Chain**: False
- **Message**: 
- **Severity**: 
- **Tags**: OWASP_CRS
- **Actions**: id:959012, phase:4, pass, nolog, tag:OWASP_CRS, ver:OWASP_CRS/4.22.0-dev, skipAfter:END-RESPONSE-959-BLOCKING-EVALUATION

#### Rule 22: 959013
- **Phase**: 3
- **Variables**: TX:DETECTION_PARANOIA_LEVEL
- **Operator**: @lt
- **Pattern**: 2
- **Is Chain**: False
- **Message**: 
- **Severity**: 
- **Tags**: OWASP_CRS
- **Actions**: id:959013, phase:3, pass, nolog, tag:OWASP_CRS, ver:OWASP_CRS/4.22.0-dev, skipAfter:END-RESPONSE-959-BLOCKING-EVALUATION

#### Rule 23: 959014
- **Phase**: 4
- **Variables**: TX:DETECTION_PARANOIA_LEVEL
- **Operator**: @lt
- **Pattern**: 2
- **Is Chain**: False
- **Message**: 
- **Severity**: 
- **Tags**: OWASP_CRS
- **Actions**: id:959014, phase:4, pass, nolog, tag:OWASP_CRS, ver:OWASP_CRS/4.22.0-dev, skipAfter:END-RESPONSE-959-BLOCKING-EVALUATION

#### Rule 24: 959015
- **Phase**: 3
- **Variables**: TX:DETECTION_PARANOIA_LEVEL
- **Operator**: @lt
- **Pattern**: 3
- **Is Chain**: False
- **Message**: 
- **Severity**: 
- **Tags**: OWASP_CRS
- **Actions**: id:959015, phase:3, pass, nolog, tag:OWASP_CRS, ver:OWASP_CRS/4.22.0-dev, skipAfter:END-RESPONSE-959-BLOCKING-EVALUATION

#### Rule 25: 959016
- **Phase**: 4
- **Variables**: TX:DETECTION_PARANOIA_LEVEL
- **Operator**: @lt
- **Pattern**: 3
- **Is Chain**: False
- **Message**: 
- **Severity**: 
- **Tags**: OWASP_CRS
- **Actions**: id:959016, phase:4, pass, nolog, tag:OWASP_CRS, ver:OWASP_CRS/4.22.0-dev, skipAfter:END-RESPONSE-959-BLOCKING-EVALUATION

#### Rule 26: 959017
- **Phase**: 3
- **Variables**: TX:DETECTION_PARANOIA_LEVEL
- **Operator**: @lt
- **Pattern**: 4
- **Is Chain**: False
- **Message**: 
- **Severity**: 
- **Tags**: OWASP_CRS
- **Actions**: id:959017, phase:3, pass, nolog, tag:OWASP_CRS, ver:OWASP_CRS/4.22.0-dev, skipAfter:END-RESPONSE-959-BLOCKING-EVALUATION

#### Rule 27: 959018
- **Phase**: 4
- **Variables**: TX:DETECTION_PARANOIA_LEVEL
- **Operator**: @lt
- **Pattern**: 4
- **Is Chain**: False
- **Message**: 
- **Severity**: 
- **Tags**: OWASP_CRS
- **Actions**: id:959018, phase:4, pass, nolog, tag:OWASP_CRS, ver:OWASP_CRS/4.22.0-dev, skipAfter:END-RESPONSE-959-BLOCKING-EVALUATION


====================================================================================================

## File: RESPONSE-980-CORRELATION.conf

### File Summary
- Total rules: 19
- Chained rules: 0
- Non-chained rules: 19

### Detailed Rules

#### Rule 1: 980041
- **Phase**: 5
- **Variables**: TX:REPORTING_LEVEL
- **Operator**: @eq
- **Pattern**: 0
- **Is Chain**: False
- **Message**: 
- **Severity**: 
- **Tags**: OWASP_CRS
- **Actions**: id:980041, phase:5, pass, nolog, tag:OWASP_CRS, ver:OWASP_CRS/4.22.0-dev, skipAfter:END-REPORTING

#### Rule 2: 980042
- **Phase**: 5
- **Variables**: TX:REPORTING_LEVEL
- **Operator**: @ge
- **Pattern**: 5
- **Is Chain**: False
- **Message**: 
- **Severity**: 
- **Tags**: OWASP_CRS
- **Actions**: id:980042, phase:5, pass, nolog, tag:OWASP_CRS, ver:OWASP_CRS/4.22.0-dev, skipAfter:LOG-REPORTING

#### Rule 3: 980043
- **Phase**: 5
- **Variables**: TX:DETECTION_ANOMALY_SCORE
- **Operator**: @eq
- **Pattern**: 0
- **Is Chain**: False
- **Message**: 
- **Severity**: 
- **Tags**: OWASP_CRS
- **Actions**: id:980043, phase:5, pass, nolog, tag:OWASP_CRS, ver:OWASP_CRS/4.22.0-dev, skipAfter:END-REPORTING

#### Rule 4: 980044
- **Phase**: 5
- **Variables**: TX:BLOCKING_INBOUND_ANOMALY_SCORE
- **Operator**: @ge
- **Pattern**: %{tx.inbound_anomaly_score_threshold}
- **Is Chain**: False
- **Message**: 
- **Severity**: 
- **Tags**: OWASP_CRS
- **Actions**: id:980044, phase:5, pass, nolog, tag:OWASP_CRS, ver:OWASP_CRS/4.22.0-dev, skipAfter:LOG-REPORTING

#### Rule 5: 980045
- **Phase**: 5
- **Variables**: TX:BLOCKING_OUTBOUND_ANOMALY_SCORE
- **Operator**: @ge
- **Pattern**: %{tx.outbound_anomaly_score_threshold}
- **Is Chain**: False
- **Message**: 
- **Severity**: 
- **Tags**: OWASP_CRS
- **Actions**: id:980045, phase:5, pass, nolog, tag:OWASP_CRS, ver:OWASP_CRS/4.22.0-dev, skipAfter:LOG-REPORTING

#### Rule 6: 980046
- **Phase**: 5
- **Variables**: TX:REPORTING_LEVEL
- **Operator**: @lt
- **Pattern**: 2
- **Is Chain**: False
- **Message**: 
- **Severity**: 
- **Tags**: OWASP_CRS
- **Actions**: id:980046, phase:5, pass, nolog, tag:OWASP_CRS, ver:OWASP_CRS/4.22.0-dev, skipAfter:END-REPORTING

#### Rule 7: 980047
- **Phase**: 5
- **Variables**: TX:DETECTION_INBOUND_ANOMALY_SCORE
- **Operator**: @ge
- **Pattern**: %{tx.inbound_anomaly_score_threshold}
- **Is Chain**: False
- **Message**: 
- **Severity**: 
- **Tags**: OWASP_CRS
- **Actions**: id:980047, phase:5, pass, nolog, tag:OWASP_CRS, ver:OWASP_CRS/4.22.0-dev, skipAfter:LOG-REPORTING

#### Rule 8: 980048
- **Phase**: 5
- **Variables**: TX:DETECTION_OUTBOUND_ANOMALY_SCORE
- **Operator**: @ge
- **Pattern**: %{tx.outbound_anomaly_score_threshold}
- **Is Chain**: False
- **Message**: 
- **Severity**: 
- **Tags**: OWASP_CRS
- **Actions**: id:980048, phase:5, pass, nolog, tag:OWASP_CRS, ver:OWASP_CRS/4.22.0-dev, skipAfter:LOG-REPORTING

#### Rule 9: 980049
- **Phase**: 5
- **Variables**: TX:REPORTING_LEVEL
- **Operator**: @lt
- **Pattern**: 3
- **Is Chain**: False
- **Message**: 
- **Severity**: 
- **Tags**: OWASP_CRS
- **Actions**: id:980049, phase:5, pass, nolog, tag:OWASP_CRS, ver:OWASP_CRS/4.22.0-dev, skipAfter:END-REPORTING

#### Rule 10: 980050
- **Phase**: 5
- **Variables**: TX:BLOCKING_ANOMALY_SCORE
- **Operator**: @gt
- **Pattern**: 0
- **Is Chain**: False
- **Message**: 
- **Severity**: 
- **Tags**: OWASP_CRS
- **Actions**: id:980050, phase:5, pass, nolog, tag:OWASP_CRS, ver:OWASP_CRS/4.22.0-dev, skipAfter:LOG-REPORTING

#### Rule 11: 980051
- **Phase**: 5
- **Variables**: TX:REPORTING_LEVEL
- **Operator**: @lt
- **Pattern**: 4
- **Is Chain**: False
- **Message**: 
- **Severity**: 
- **Tags**: OWASP_CRS
- **Actions**: id:980051, phase:5, pass, nolog, tag:OWASP_CRS, ver:OWASP_CRS/4.22.0-dev, skipAfter:END-REPORTING

#### Rule 12: 980011
- **Phase**: 1
- **Variables**: TX:DETECTION_PARANOIA_LEVEL
- **Operator**: @lt
- **Pattern**: 1
- **Is Chain**: False
- **Message**: 
- **Severity**: 
- **Tags**: OWASP_CRS
- **Actions**: id:980011, phase:1, pass, nolog, tag:OWASP_CRS, ver:OWASP_CRS/4.22.0-dev, skipAfter:END-RESPONSE-980-CORRELATION

#### Rule 13: 980012
- **Phase**: 2
- **Variables**: TX:DETECTION_PARANOIA_LEVEL
- **Operator**: @lt
- **Pattern**: 1
- **Is Chain**: False
- **Message**: 
- **Severity**: 
- **Tags**: OWASP_CRS
- **Actions**: id:980012, phase:2, pass, nolog, tag:OWASP_CRS, ver:OWASP_CRS/4.22.0-dev, skipAfter:END-RESPONSE-980-CORRELATION

#### Rule 14: 980013
- **Phase**: 1
- **Variables**: TX:DETECTION_PARANOIA_LEVEL
- **Operator**: @lt
- **Pattern**: 2
- **Is Chain**: False
- **Message**: 
- **Severity**: 
- **Tags**: OWASP_CRS
- **Actions**: id:980013, phase:1, pass, nolog, tag:OWASP_CRS, ver:OWASP_CRS/4.22.0-dev, skipAfter:END-RESPONSE-980-CORRELATION

#### Rule 15: 980014
- **Phase**: 2
- **Variables**: TX:DETECTION_PARANOIA_LEVEL
- **Operator**: @lt
- **Pattern**: 2
- **Is Chain**: False
- **Message**: 
- **Severity**: 
- **Tags**: OWASP_CRS
- **Actions**: id:980014, phase:2, pass, nolog, tag:OWASP_CRS, ver:OWASP_CRS/4.22.0-dev, skipAfter:END-RESPONSE-980-CORRELATION

#### Rule 16: 980015
- **Phase**: 1
- **Variables**: TX:DETECTION_PARANOIA_LEVEL
- **Operator**: @lt
- **Pattern**: 3
- **Is Chain**: False
- **Message**: 
- **Severity**: 
- **Tags**: OWASP_CRS
- **Actions**: id:980015, phase:1, pass, nolog, tag:OWASP_CRS, ver:OWASP_CRS/4.22.0-dev, skipAfter:END-RESPONSE-980-CORRELATION

#### Rule 17: 980016
- **Phase**: 2
- **Variables**: TX:DETECTION_PARANOIA_LEVEL
- **Operator**: @lt
- **Pattern**: 3
- **Is Chain**: False
- **Message**: 
- **Severity**: 
- **Tags**: OWASP_CRS
- **Actions**: id:980016, phase:2, pass, nolog, tag:OWASP_CRS, ver:OWASP_CRS/4.22.0-dev, skipAfter:END-RESPONSE-980-CORRELATION

#### Rule 18: 980017
- **Phase**: 1
- **Variables**: TX:DETECTION_PARANOIA_LEVEL
- **Operator**: @lt
- **Pattern**: 4
- **Is Chain**: False
- **Message**: 
- **Severity**: 
- **Tags**: OWASP_CRS
- **Actions**: id:980017, phase:1, pass, nolog, tag:OWASP_CRS, ver:OWASP_CRS/4.22.0-dev, skipAfter:END-RESPONSE-980-CORRELATION

#### Rule 19: 980018
- **Phase**: 2
- **Variables**: TX:DETECTION_PARANOIA_LEVEL
- **Operator**: @lt
- **Pattern**: 4
- **Is Chain**: False
- **Message**: 
- **Severity**: 
- **Tags**: OWASP_CRS
- **Actions**: id:980018, phase:2, pass, nolog, tag:OWASP_CRS, ver:OWASP_CRS/4.22.0-dev, skipAfter:END-RESPONSE-980-CORRELATION


====================================================================================================

