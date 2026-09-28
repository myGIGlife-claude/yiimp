#!/usr/bin/env bash
# crawl.sh <cookiejar-or-empty> <outfile>
S=/tmp/claude-0/-home-user/940fe17f-d697-51b7-8fd2-02f52b656791/scratchpad; T=$S/site
JAR=$1; OUT=$2; : > "$OUT"
Q='id=7&address=LTCaddr123456789012345678901234&symbol=LTC&algo=scrypt&height=2499990&txid=abc&coin=7&key=x&jobid=1&count=10&wallet=LTCaddr123456789012345678901234&en=1'
while read -r r; do
  case "$r" in thread/*|site/logout) continue;; esac
  : > $T/php_errors.log; : > $T/log/debug.log
  code=$(curl -s -m 30 ${JAR:+-b $JAR -c $JAR} -o $S/last.html -w "%{http_code}" "http://127.0.0.1:8083/$r?$Q")
  errs=$(grep -v -e RecursiveDOMIterator $T/php_errors.log | sed -E 's/^\[[^]]*\] //; s#/tmp/claude-0/[^ ]*/site/web/##g' | sort | uniq -c | sort -rn)
  dbg=$(grep -E "error|Error|exception|Exception" $T/log/debug.log | grep -v "^$" | sed -E 's/^\[[^]]*\] //' | sort -u | head -3)
  if [ -n "$errs$dbg" ] || [ "$code" != 200 ]; then
    { echo "=== $r [$code]"; [ -n "$errs" ] && echo "$errs"; [ -n "$dbg" ] && echo "DEBUG: $dbg"; } >> "$OUT"
  fi
done < $S/routes.txt
