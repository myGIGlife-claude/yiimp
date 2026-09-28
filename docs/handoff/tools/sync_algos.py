#!/usr/bin/env python3
"""Rebuild the web algo tables in yaamp.php from the stratum's g_algos[] and config.sample ports."""
import re, glob, os, sys
root = sys.argv[1]
strat = open(f'{root}/stratum/stratum.cpp').read()
table = strat[strat.index('YAAMP_ALGO g_algos[]'):]
table = table[:table.index('};')]
algos = []
for m in re.finditer(r'^\s*\{"([A-Za-z0-9_-]+)"', table, re.M):
    if m.group(1) not in algos: algos.append(m.group(1))
# ports from config.sample (file named after the algo wins)
ports = {}
for f in sorted(glob.glob(f'{root}/stratum/config.sample/*.conf')):
    s = open(f).read()
    a = re.search(r'^algo = (\S+)', s, re.M); p = re.search(r'^port = (\d+)', s, re.M)
    if not a or not p: continue
    name = os.path.basename(f)[:-5]
    if a.group(1) not in ports or name == a.group(1): ports[a.group(1)] = int(p.group(1))
new_colors = dict(x.split('=') for x in sys.argv[2:]) if len(sys.argv) > 2 else {}
p = f'{root}/web/yaamp/core/functions/yaamp.php'
php = open(p).read()

def replace_array(func, build):
    global php
    i = php.index(f'function {func}(')
    j = php.index('array(', i) + len('array(')
    k = php.index(');', j)
    php = php[:j] + build(php[j:k]) + php[k:]

def build_list(body):
    return '\n' + ''.join(f"        '{a}',\n" for a in sorted(algos, key=str.lower)).rstrip(',\n') + '\n    '

def build_map(existing_body, values, default=None, keep=()):
    old = dict(re.findall(r"'([^']+)'\s*=>\s*([^,\n]+?)\s*,?\s*(?://.*)?$", existing_body, re.M))
    out = {}
    for a in sorted(algos, key=str.lower):
        if a in values: out[a] = values[a]
        elif a in old: out[a] = old[a]
        elif default is not None: out[a] = default
    for k in keep:
        if k in old: out[k] = old[k]
    lines = [f"        '{k}' => {v}" for k, v in out.items()]
    return '\n' + ',\n'.join(lines) + '\n    '

replace_array('yaamp_get_algos', build_list)
replace_array('getAlgoColors', lambda b: build_map(b, {k: f"'{v}'" for k, v in new_colors.items()}, "'#e0e0e0'", keep=('MN', 'PoS')))
replace_array('getAlgoPort', lambda b: build_map(b, {a: str(v) for a, v in ports.items()}))
open(p, 'w').write(php)
missing = [a for a in algos if a not in ports]
print(len(algos), 'algos;', 'no config port:', missing)
