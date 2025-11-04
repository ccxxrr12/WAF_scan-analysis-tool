* -*- coding: utf-8 -*-
  
```
  Copyright (C) 2024, WAFW00F Developers.
  See the LICENSE file for copying permission.
```

# How to build
开发者模式： make install
normal： make
详情见Makefile

# How to use
命令`wafw00f -h`查看帮助
```
  Usage: wafw00f url1 [url2 [url3 ... ]]
example: wafw00f http://www.victim.org/

Options:
  -h, --help            show this help message and exit
  -v, --verbose         Enable verbosity, multiple -v options increase
                        verbosity
  -a, --findall         Find all WAFs which match the signatures, do not stop
                        testing on the first one
  -r, --noredirect      Do not follow redirections given by 3xx responses
  -t TEST, --test=TEST  Test for one specific WAF
  -o OUTPUT, --output=OUTPUT
                        Write output to csv, json or text file depending on
                        file extension. For stdout, specify - as filename.
  -f FORMAT, --format=FORMAT
                        Force output format to csv, json or text.
  -i INPUT, --input-file=INPUT
                        Read targets from a file. Input format can be csv,
                        json or text. For csv and json, a `url` column name or
                        element is required.
  -l, --list            List all WAFs that WAFW00F is able to detect
  -p PROXY, --proxy=PROXY
                        Use an HTTP proxy to perform requests, examples:
                        http://hostname:8080, socks5://hostname:1080,
                        http://user:pass@hostname:8080
  -V, --version         Print out the current version of WafW00f and exit.
  -H HEADERS, --headers=HEADERS
                        Pass custom headers via a text file to overwrite the
                        default header set.
  -T TIMEOUT, --timeout=TIMEOUT
                        Set the timeout for the requests.
  --no-colors           Disable ANSI colors in output.
  ```