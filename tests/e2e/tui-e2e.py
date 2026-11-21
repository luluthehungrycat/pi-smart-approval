#!/usr/bin/env python3
"""Live check of the approval dialog in Pi's native TUI, driven through a pseudo-terminal.

Same isolation as rpc-e2e.mjs: temporary PI_CODING_AGENT_DIR and workspace, local scripted model on
127.0.0.1, and only inert `touch <marker>` commands inside the temporary workspace. Usage:
  python3 -I tests/e2e/tui-e2e.py   (PI_BIN overrides the pi executable)
"""
import json, os, pty, re, select, shutil, subprocess, sys, tempfile, threading, time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

REPO = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..'))
PI = os.environ.get('PI_BIN', 'pi')
root = tempfile.mkdtemp(prefix='smart-approval-tui-e2e-')
agent, ws = os.path.join(root, 'agent'), os.path.join(root, 'workspace')
os.makedirs(ws); os.makedirs(os.path.join(agent, 'smart-approval'), mode=0o700)
seq = [0]

class Model(BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def do_POST(self):
        body = json.loads(self.rfile.read(int(self.headers['content-length'])))
        last = body['messages'][-1]
        content = last.get('content')
        text = content if isinstance(content, str) else ''.join(p.get('text', '') for p in (content or []))
        self.send_response(200); self.send_header('content-type', 'text/event-stream'); self.end_headers()
        def send(o): self.wfile.write(b'data: ' + json.dumps(o).encode() + b'\n\n')
        if last.get('role') == 'user' and text.startswith('RUN '):
            seq[0] += 1
            send({'choices': [{'index': 0, 'delta': {'role': 'assistant', 'tool_calls': [{'index': 0, 'id': f'call_{seq[0]}', 'type': 'function', 'function': {'name': 'bash', 'arguments': json.dumps({'command': text[4:].strip()})}}]}}]})
            send({'choices': [{'index': 0, 'delta': {}, 'finish_reason': 'tool_calls'}]})
        else:
            send({'choices': [{'index': 0, 'delta': {'role': 'assistant', 'content': 'done'}}]})
            send({'choices': [{'index': 0, 'delta': {}, 'finish_reason': 'stop'}]})
        self.wfile.write(b'data: [DONE]\n\n')

srv = ThreadingHTTPServer(('127.0.0.1', 0), Model)
threading.Thread(target=srv.serve_forever, daemon=True).start()
json.dump({'providers': {'fake': {'baseUrl': f'http://127.0.0.1:{srv.server_address[1]}/v1', 'api': 'openai-completions', 'apiKey': 'inert-test-key', 'models': [{'id': 'scripted', 'name': 'scripted', 'contextWindow': 32000, 'maxTokens': 1000, 'cost': {'input': 0, 'output': 0, 'cacheRead': 0, 'cacheWrite': 0}}]}}}, open(os.path.join(agent, 'models.json'), 'w'))
fd = os.open(os.path.join(agent, 'smart-approval', 'config.json'), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
os.write(fd, json.dumps({'version': 1, 'smart': True, 'timeoutMs': 6000, 'reviewDeny': False, 'writable': [], 'readOnly': [], 'skillPaths': [], 'rules': [], 'trustedAgents': [], 'analysis': {'enabled': False, 'maxCalls': 10, 'maxInputChars': 4000, 'timeoutMs': 10000}, 'decisionModel': {'enabled': False, 'maxCalls': 10, 'maxInputChars': 4000, 'timeoutMs': 10000}}).encode()); os.close(fd)

env = {k: v for k, v in os.environ.items() if k not in ('CI', 'T3_MCP_URL', 'T3_MCP_BEARER_TOKEN', 'T3_PI_RUNTIME_MODE')}
env.update(PI_CODING_AGENT_DIR=agent, PI_OFFLINE='1', TERM='xterm-256color', COLUMNS='160', LINES='50')
pid, master = pty.fork()
if pid == 0:
    os.chdir(ws)
    os.execvpe(PI, [PI, '--no-session', '--no-extensions', '--offline', '--model', 'fake/scripted', '-e', os.path.join(REPO, 'src', 'index.ts')], env)
os.set_blocking(master, False)
import fcntl, termios, struct
fcntl.ioctl(master, termios.TIOCSWINSZ, struct.pack('HHHH', 50, 160, 0, 0))
buf = ['']
def pump(seconds):
    end = time.time() + seconds
    while time.time() < end:
        r, _, _ = select.select([master], [], [], 0.1)
        if r:
            try: buf[0] += os.read(master, 65536).decode('utf-8', 'replace')
            except OSError: return
def plain(): return re.sub(r'\x1b\[[0-9;?]*[ -/]*[@-~]|\x1b[()][A-Za-z0-9]|\x1b[=>]|\x1b\][^\x07]*\x07', '', buf[0])
def wait_for(pattern, seconds=30, since=0):
    end = time.time() + seconds
    while time.time() < end:
        pump(0.3)
        if re.search(pattern, plain()[since:]): return True
    return False
def type_line(s):
    os.write(master, s.encode()); time.sleep(0.3); os.write(master, b'\r')

results = []
def check(name, ok, detail=''):
    results.append(ok); print(('PASS ' if ok else 'FAIL ') + name + (f' — {detail}' if detail else ''))
marker = lambda n: os.path.exists(os.path.join(ws, n))
DOWN, ENTER = b'\x1b[B', b'\r'
def ask(cmd, keys, expect_prompt=True):
    since = len(plain())
    type_line('RUN ' + cmd)
    prompted = wait_for(r'Allow once', 25, since) if expect_prompt else not wait_for(r'Allow once', 6, since)
    if expect_prompt and prompted:
        for k in keys: os.write(master, k); time.sleep(0.4)
    pump(4)
    return prompted
try:
    check('TUI started with extension', wait_for(r'approval: soft protection', 40), '')
    ok = ask('touch t1', [ENTER])
    check('TUI select shown; Enter = Allow once runs the tool', ok and marker('t1'))
    os.unlink(os.path.join(ws, 't1'))
    ok = ask('touch t1', [ENTER])
    check('TUI Allow once created no grant (prompted again)', ok and marker('t1'))
    ok = ask('touch t2', [DOWN, ENTER])
    check('TUI Allow for session runs the tool', ok and marker('t2'))
    os.unlink(os.path.join(ws, 't2'))
    ok = ask('touch t2', [], expect_prompt=False)
    check('TUI repeated exact command: no prompt, tool ran (session grant)', ok and marker('t2'))
    ok = ask('touch t3', [DOWN, DOWN, DOWN, ENTER])
    check('TUI Deny blocks; tool did not run', ok and not marker('t3'))
    ok = ask('touch t4', [])
    pump(8)
    check('TUI timeout (no key pressed) blocks; tool did not run', ok and not marker('t4') and 'APPROVAL_TIMEOUT' in plain())
    ok = ask('touch t5', [DOWN, DOWN, ENTER])
    saved = wait_for(r'Save permanent exact rule', 10)
    os.write(master, ENTER); pump(4)
    rules = json.load(open(os.path.join(agent, 'smart-approval', 'config.json')))['rules']
    check('TUI Always allow: confirmation shown, rule saved, tool ran', ok and saved and len(rules) == 1 and marker('t5'))
finally:
    try: os.kill(pid, 15)
    except OSError: pass
    time.sleep(0.5); srv.shutdown(); shutil.rmtree(root, ignore_errors=True)
    if os.environ.get('TUI_E2E_DUMP'): open(os.environ['TUI_E2E_DUMP'], 'w').write(plain())
    print(f'\n{sum(results)}/{len(results)} checks passed')
    sys.exit(0 if all(results) and results else 1)
