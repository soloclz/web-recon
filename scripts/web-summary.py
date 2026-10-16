#!/usr/bin/env python3
"""Summarize saved curl files. Reads locally; sends no requests."""
import argparse
import base64
import binascii
import json
import re
from collections import defaultdict
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import unquote

HEADERS = {'location', 'content-type', 'content-encoding', 'content-length',
           'set-cookie', 'www-authenticate', 'allow', 'server', 'x-powered-by'}


def header_fingerprints(name, value):
    # Rules and upstream references: web/web-fingerprinting.md.
    # Match a cookie pair, never a substring in its attributes or another header.
    if name != 'set-cookie':
        return []
    pair = value.strip().split(';', 1)[0].strip()
    cookie, sep, raw = pair.partition('=')
    if not sep:
        return []
    cookie, raw = cookie.strip(), raw.strip()
    if raw.startswith('"') and raw.endswith('"'):
        raw = raw[1:-1]
    findings = []
    if cookie == 'JSESSIONID' and re.fullmatch(r'[A-Za-z0-9]+\.node0', raw):
        findings.append('Jetty: matched JSESSIONID suffix .node0 (workerName); version and deployment not determined')
    decoded = unquote(raw)
    if cookie == 'connect.sid' and re.fullmatch(r's:[^.\s;]+\.[A-Za-z0-9+/]{43}', decoded):
        findings.append('express-session: matched connect.sid and s:<ID>.<signature> format; signature not verified')
    if cookie.startswith('.AspNetCore.Antiforgery.') and cookie != '.AspNetCore.Antiforgery.':
        findings.append('ASP.NET Core antiforgery: matched default cookie name prefix; not a login session indicator')
    if cookie == 'PHPSESSID':
        findings.append('PHP session: matched default cookie name PHPSESSID; application framework not determined')
    if cookie in ('AWSALB', 'AWSALBCORS'):
        findings.append(f'AWS Application Load Balancer: matched {cookie} stickiness cookie name; backend framework not determined')
    if not raw:
        return [finding + '; cookie value is empty' for finding in findings]
    # Inspect cookie values only. The header plus key ID occupies 20 bytes.
    # Base64url decoding checks structure, not authenticity or token purpose.
    if re.fullmatch(r'[A-Za-z0-9_-]+={0,2}', decoded):
        try:
            payload = base64.b64decode(decoded + '=' * (-len(decoded) % 4), altchars=b'-_', validate=True)
        except (ValueError, binascii.Error):
            payload = b''
        if len(payload) >= 20 and payload.startswith(bytes.fromhex('09f0c9f0')):
            findings.append('ASP.NET Core Data Protection: matched cookie value magic bytes 09 F0 C9 F0; purpose and authenticity not determined')
    return findings


def html_fingerprints(tag, attrs):
    # Match parsed markup, not marker words quoted in text, comments or scripts.
    # Upstream references: web/web-fingerprinting.md.
    if tag == 'input' and (attrs.get('type') or '').lower() == 'hidden':
        if attrs.get('name') == '__VIEWSTATE':
            return ['ASP.NET Web Forms: matched hidden field __VIEWSTATE; inspect form state and submission']
        if attrs.get('name') == 'javax.faces.ViewState':
            return ['JavaServer Faces: matched hidden field javax.faces.ViewState (javax naming); exact version not determined']
        if attrs.get('name') == 'jakarta.faces.ViewState':
            return ['Jakarta Faces: matched hidden field jakarta.faces.ViewState; inspect view state and submission']
    if (tag == 'script' and attrs.get('id') == '__NEXT_DATA__'
            and (attrs.get('type') or '').lower() == 'application/json' and 'src' not in attrs):
        return ['Next.js Pages Router: matched inline JSON script id __NEXT_DATA__; inspect page data in source']
    if tag == 'meta' and (attrs.get('name') or '').lower() == 'generator':
        content = (attrs.get('content') or '').strip()
        if re.fullmatch(r'WordPress(?:\s+\S+)?', content, re.I):
            return [f'WordPress: generator declares {content}; version not independently verified']
    return []


def brief(value, width=220):
    text = ' '.join(str(value).split())
    text = ''.join(c if c.isprintable() else '?' for c in text)
    return text if len(text) <= width else text[:width] + ' … [truncated]'


def fields(attrs):
    return ' '.join(f'{key}={json.dumps(value, ensure_ascii=False)}'
                    for key, value in attrs.items())


class Page(HTMLParser):
    """Extract source attributes, without inferring browser submission behavior."""
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.rows = defaultdict(list)
        self.form = None
        self.form_count = 0
        self.capture = None
        self.text_elements = {}

    def add(self, group, value, pos=None):
        line, column = pos or self.getpos()
        self.rows[group].append(f'L{line}:{column + 1} {value}')

    def handle_starttag(self, tag, pairs):
        attrs = dict(pairs)
        for finding in html_fingerprints(tag, attrs):
            self.add('FINGERPRINT', finding)
        if tag in ('script', 'style', 'title', 'textarea'):
            self.text_elements.setdefault(tag, self.getpos())
        if tag in ('title', 'h1', 'h2'):
            self.capture = (tag, self.getpos(), [])
        if tag == 'form':
            self.form_count += 1
            self.form = f'form#{self.form_count}'
            self.add('FORM', self.form + ' ' + fields({k: attrs[k] for k in
                     ('id', 'action', 'method', 'enctype') if k in attrs}))
        elif tag in ('input', 'select', 'textarea', 'button'):
            owner = ('id:' + str(attrs['form'])) if 'form' in attrs else (self.form or 'unknown')
            picked = {k: attrs[k] for k in ('name', 'type', 'formaction', 'formmethod',
                      'formenctype', 'disabled', 'multiple') if k in attrs}
            self.add('FIELD', f'{tag} owner={owner} ' + fields(picked))
        elif tag in ('base', 'a', 'area', 'link', 'iframe', 'img'):
            picked = {k: attrs[k] for k in ('href', 'src', 'rel', 'target') if k in attrs}
            if picked:
                self.add('BASE' if tag == 'base' else 'LINK', tag + ' ' + fields(picked))
        elif tag == 'script':
            self.add('SCRIPT', fields({k: attrs[k] for k in ('id', 'src', 'type') if k in attrs})
                     + (' [inline; inspect source]' if 'src' not in attrs else ''))
        elif tag == 'meta':
            self.add('META', fields({k: attrs[k] for k in
                     ('name', 'http-equiv', 'content', 'charset') if k in attrs}))
        data = {k: v for k, v in attrs.items() if k.startswith('data-')}
        if data:
            self.add('DATA', tag + ' ' + fields(data))

    def handle_endtag(self, tag):
        self.text_elements.pop(tag, None)
        if self.capture and self.capture[0] == tag:
            name, pos, chunks = self.capture
            self.add('TITLE', name + ' ' + ''.join(chunks), pos)
            self.capture = None
        if tag == 'form':
            self.form = None

    def handle_data(self, data):
        if self.capture:
            self.capture[2].append(data)

    def handle_comment(self, data):
        self.add('COMMENT', data)


class Report:
    def __init__(self, prefix=None, jsonl=False, sections=(), body_file=None):
        self.prefix = prefix
        self.body_file = body_file
        self.jsonl = jsonl
        self.sections = set(sections)
        self.url = None

    def record(self, group, text, source=None, line=None, column=None):
        print(json.dumps({'kind': group, 'source_url': self.url,
                          'source_file': source, 'line': line,
                          'column': column, 'text': text}, ensure_ascii=False))

    def note(self, text=''):
        if self.jsonl:
            if text:
                self.record('NOTICE', str(text).strip())
        else:
            print(text)

    def show(self, group, rows, limit, source_suffix=None):
        if self.sections and group not in self.sections and group not in ('TRANSFER', 'ERRORS'):
            return
        if self.jsonl:
            suffix = {"TRANSFER": ".meta", "ERRORS": ".errors",
                      "HEADERS": ".headers", "OTHER HEADERS": ".headers", "FINGERPRINT": ".headers"}.get(group, '.body')
            suffix = source_suffix or suffix
            source = str(Path(str(self.prefix) + suffix).resolve()) if self.prefix else None
            if suffix == '.body' and self.body_file is not None:
                source = str(self.body_file.resolve())
            for row in rows:
                pos = re.match(r'^L(\d+):(\d+) ', row)
                self.record(group, row, source,
                            int(pos[1]) if pos else None, int(pos[2]) if pos else None)
            return
        visible = rows if limit == 0 else rows[:limit]
        label = group
        if group == 'FINGERPRINT':
            origin = 'HEADERS'
            if source_suffix == '.body':
                origin = 'HTML (derived body)' if self.body_file is not None else 'HTML'
            label = f'{group} / {origin}'
        print(f'\n[{label}: {len(rows)} items, showing {len(visible)}]')
        for row in visible:
            print(brief(row))
        if len(visible) < len(rows):
            print(f'… {len(rows) - len(visible)} omitted; use --limit 0 to show all items')


def shape(value):
    if isinstance(value, dict):
        return f'object ({len(value)} keys)'
    if isinstance(value, list):
        return f'array ({len(value)} items)'
    if value is None:
        return 'null'
    if isinstance(value, bool):
        return 'boolean'
    if isinstance(value, str):
        return f'string ({len(value)} characters)'
    return 'number'


def summarize(prefix, mode, encoding, limit, report=None, body_file=None):
    report = report or Report(prefix, body_file=body_file)
    show = report.show
    print = report.note
    def read(suffix):
        path = body_file if suffix == '.body' and body_file is not None else Path(str(prefix) + suffix)
        return path.read_bytes() if path.exists() else None

    meta = read('.meta')
    values = {}
    if meta and meta.strip():
        lines = meta.decode('utf-8', 'replace').splitlines()
        values = dict(line.split('=', 1) for line in lines if '=' in line)
        report.url = values.get('url')
        show('TRANSFER', [f'L{i}:1 {line}' for i, line in enumerate(lines, 1)], 0)
    else:
        print('NOTE: missing or empty .meta; transfer completion is unknown')
    exit_code = values.get('curl_exit', '')
    if not exit_code.isdecimal():
        print('NOTE: curl_exit missing or invalid; transfer completion is unknown')
    elif int(exit_code) != 0:
        print(f'NOTE: curl_exit={exit_code}; body may be incomplete. Check .errors and saved body before ruling out an entry.')
    errors = read('.errors')
    if errors:
        show('ERRORS', [f'L{i}:1 {line}' for i, line in enumerate(errors.decode('utf-8', 'replace').splitlines(), 1)], limit)
    elif errors is None:
        print('NOTE: missing .errors; error evidence unavailable')
    raw_headers = read('.headers')
    content_type = ''
    content_encoding = ''
    selected, other, fingerprints = [], [], []
    if raw_headers is None:
        print('NOTE: missing .headers; body format will be inferred')
    else:
        for number, line in enumerate(raw_headers.decode('iso-8859-1').splitlines(), 1):
            located = f'L{number}:1 {line}'
            key, sep, value = line.partition(':')
            key = key.lower()
            if line.upper().startswith('HTTP/'):
                # Representation headers belong to the latest response block.
                content_type = content_encoding = ''
                selected.append(located)
            elif sep:
                for finding in header_fingerprints(key, value):
                    fingerprints.append(f'L{number}:1 {finding}')
                if key in HEADERS:
                    selected.append(located)
                else:
                    other.append(located)
                if key == 'content-type':
                    content_type = value.strip()
                if key == 'content-encoding':
                    content_encoding = value.strip().lower()
        show('HEADERS', selected, 0)
        if other:
            show('OTHER HEADERS', other, limit)
        if fingerprints:
            show('FINGERPRINT', fingerprints, limit)
    body_path = body_file if body_file is not None else Path(str(prefix) + '.body')
    body = read('.body')
    if body is None:
        print(f'ERROR: body file not found: {body_path.resolve()}; no body summary generated')
        return 1
    if body_file is not None:
        print(f'NOTE: body read from derived file {body_path.resolve()}; transfer evidence remains from {prefix}.meta')
    print(f'\n[BODY: {len(body)} saved bytes; Content-Type={content_type or "unknown"}]')
    if not body:
        print('Empty saved body; check transfer result and HTTP status.')
        return 0
    if content_encoding and content_encoding != 'identity':
        print('NOTE: Content-Encoding=' + content_encoding + '; header alone does not establish whether the saved body is still compressed.')
    if body.startswith((b'\x1f\x8b', b'PK\x03\x04', b'%PDF')):
        print('Body appears compressed or binary; not parsed as HTML/JSON.')
        return 1
    charset = re.search(r'charset\s*=\s*["\x27]?([^\s;"\x27]+)', content_type, re.I)
    codec = encoding or (charset.group(1) if charset else 'utf-8-sig')
    try:
        text = body.decode(codec)
    except (UnicodeError, LookupError) as exc:
        print(f'ERROR: decoding with {codec} failed ({exc}); specify --encoding.')
        return 1
    if '\0' in text[:1024]:
        print('ERROR: decoded text contains NUL; check --encoding or use a binary reader.')
        return 1
    print(f'Encoding used: {codec}; override with --encoding if incorrect.')
    if mode == 'auto':
        mime = content_type.lower().split(';')[0]
        if 'json' in mime:
            mode = 'json'
        elif mime in ('text/html', 'application/xhtml+xml'):
            mode = 'html'
        elif text.lstrip().startswith(('{', '[')):
            mode = 'json'
        elif re.search(r'<(?:!doctype\s+html|html|title|form|a|div|script)\b', text[:2048], re.I):
            mode = 'html'
        else:
            mode = 'text'
        print('Format selected: ' + mode + '; override with --format if incorrect.')
    if mode == 'json':
        try:
            value = json.loads(text)
        except ValueError as exc:
            print(f'ERROR: JSON parsing failed: {exc}')
            return 1
        print('JSON root: ' + shape(value))
        if isinstance(value, dict):
            show('JSON KEYS', [f'{json.dumps(k, ensure_ascii=False)}: {shape(v)}' for k, v in value.items()], limit)
        elif isinstance(value, list):
            rows = [f'[{i}]: {shape(v)}' + (f' keys={json.dumps(list(v), ensure_ascii=False)}' if isinstance(v, dict) else '') for i, v in enumerate(value)]
            show('JSON ARRAY SAMPLE', rows, limit)
            print('Sampled elements do not establish the complete array schema.')
        else:
            show('JSON VALUE', [json.dumps(value, ensure_ascii=False)], limit)
    elif mode == 'html':
        page = Page()
        page.feed(text)
        page.close()
        for tag, (line, column) in page.text_elements.items():
            print(f'NOTE: unclosed <{tag}> at L{line}:{column + 1}; inspect body tail and transfer evidence. Source may be incomplete or malformed.')
        if not page.rows:
            print('No selected HTML items extracted; check curl_exit, saved bytes and source. Not evidence of absence.')
        if page.rows['FINGERPRINT']:
            show('FINGERPRINT', page.rows['FINGERPRINT'], limit, source_suffix='.body')
        for group in ('TITLE', 'BASE', 'FORM', 'FIELD', 'LINK', 'SCRIPT', 'META', 'DATA', 'COMMENT'):
            if page.rows[group]:
                show(group, page.rows[group], limit)
        print('\nSource attributes only; relative URLs unchanged. Values/options and JS behavior require source or browser checks.')
    else:
        print('No HTML/JSON extraction; inspect with a reader appropriate to the format.')
    print('Summary only: original files unchanged; truncated rows require source inspection.')
    return 0


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('prefix', type=Path, help='curl output prefix, without .body')
    parser.add_argument('--format', choices=('auto', 'html', 'json', 'text'), default='auto')
    parser.add_argument('--body-file', type=Path, help='read a derived body file while retaining the original prefix metadata and headers')
    parser.add_argument('--encoding', help='override the header charset / UTF-8 fallback')
    parser.add_argument('--limit', type=int, default=5, help='items per group; 0 shows all (default: 5)')
    parser.add_argument('--jsonl', action='store_true', help='emit all extracted items as JSON Lines without preview truncation')
    parser.add_argument('--section', help='comma-separated groups; TRANSFER, ERRORS and diagnostics remain visible')
    args = parser.parse_args()
    if args.limit < 0:
        parser.error('--limit must be 0 or greater')
    sections = [part.strip().upper() for part in args.section.split(',')] if args.section else []
    known = {'TRANSFER', 'ERRORS', 'HEADERS', 'OTHER HEADERS', 'FINGERPRINT', 'TITLE', 'BASE', 'FORM', 'FIELD', 'LINK', 'SCRIPT', 'META', 'DATA', 'COMMENT', 'JSON KEYS', 'JSON ARRAY SAMPLE', 'JSON VALUE'}
    if set(sections) - known:
        parser.error('unknown section: ' + ', '.join(sorted(set(sections) - known)))
    report = Report(args.prefix, args.jsonl, sections, args.body_file)
    try:
        return summarize(args.prefix, args.format, args.encoding, args.limit, report, args.body_file)
    except (OSError, ValueError, AssertionError) as exc:
        report.note(f'ERROR: {exc}')
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
