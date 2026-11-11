"""Separate untrusted-content signals from enforceable agent action policies."""
import json

import re, unicodedata
PATTERNS = [('instruction-override', r'ignore\s+(?:all\s+)?(?:previous|prior)\s+instructions'),
            ('secret-request', r'(?:send|reveal|print)\s+(?:the\s+)?(?:password|api key|secret)'),
            ('role-spoofing', r'(?:system|developer)\s*(?:message|override)\s*:')]
def analyze(data):
    text = unicodedata.normalize('NFKC',data.get('content','')).casefold()
    findings = [{'rule':name,'start':m.start(),'end':m.end()} for name,pattern in PATTERNS for m in re.finditer(pattern,text)]
    policy = data.get('policy',{})
    decisions = []
    for action in data.get('actions',[]):
        reasons = []
        if action['tool'] not in policy.get('allowed_tools',[]):
            reasons.append('tool-not-allowed')
        if action.get('destination') and action['destination'] not in policy.get('allowed_destinations',[]):
            reasons.append('destination-not-allowed')
        if action['tool'] in policy.get('approval_tools',[]) and not action.get('approved',False):
            reasons.append('approval-required')
        decisions.append({'id':action['id'],'allowed':not reasons,'reasons':reasons})
    return {'findings':findings,'decisions':decisions,'offset_basis':'normalized-content'}

if __name__ == '__main__':
    import argparse, sys
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('input', help='Path to a JSON scenario')
    args = parser.parse_args()
    try:
        with open(args.input, encoding='utf-8') as source:
            data = json.load(source)
        if not isinstance(data, dict):
            raise ValueError('Input must be a JSON object')
        print(json.dumps(analyze(data), indent=2, sort_keys=True))
    except (ValueError, TypeError, KeyError, OSError) as error:
        print('Input error: '+str(error), file=sys.stderr)
        sys.exit(2)
