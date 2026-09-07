import json
from collections import defaultdict
from run_comprehensive_benchmark import build_test_cases

d = json.load(open('benchmark_results.json', 'r', encoding='utf-8'))
all_cases = build_test_cases()

p1_fails = {c['id']: c for c in d['phase1_local_only']['failed_cases']}
groq_caught = {c['id']: c for c in d['phase2_with_groq_judge']['groq_caught_cases']}

cat_stats = defaultdict(lambda: {'total': 0, 'p1_pass': 0, 'groq_caught': 0, 'fail': 0, 'failed_ids': [], 'passed_ids': []})

for c in all_cases:
    cid = c['id']
    cat = f"{c['category']} ({c['subcategory']})"
    cat_stats[cat]['total'] += 1
    
    if cid in groq_caught:
        cat_stats[cat]['groq_caught'] += 1
        cat_stats[cat]['passed_ids'].append(cid)
    elif cid in p1_fails:
        cat_stats[cat]['fail'] += 1
        cat_stats[cat]['failed_ids'].append(cid)
    else:
        cat_stats[cat]['p1_pass'] += 1
        cat_stats[cat]['passed_ids'].append(cid)

print(f"{'Category':<50} | {'Total':<5} | {'P1 Local':<8} | {'P2 Groq':<8} | {'Final Pass':<10} | {'Rate':<6}")
print("-" * 95)

for cat, s in cat_stats.items():
    fp = s['p1_pass'] + s['groq_caught']
    pct = f"{round((fp / s['total']) * 100)}%"
    print(f"{cat:<50} | {s['total']:<5} | {s['p1_pass']:<8} | +{s['groq_caught']:<7} | {fp:>3}/{s['total']:<6} | {pct:<6}")

print("\n" + "=" * 95)
print("SPECIFIC FAILED CASE IDS BY CATEGORY:")
print("=" * 95)
for cat, s in cat_stats.items():
    if s['failed_ids']:
        print(f"[-] {cat}: {len(s['failed_ids'])} failed -> IDs: {s['failed_ids']}")
    else:
        print(f"[+] {cat}: 100% PASSED")
