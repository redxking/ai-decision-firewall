import json, threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from fleetsec.llm_eval import parse_action
from fleetsec.providers import ollama_response, ProviderError, openai_response

class Handler(BaseHTTPRequestHandler):
    def do_POST(self):
        length=int(self.headers.get('content-length','0'))
        _=self.rfile.read(length)
        body=json.dumps({'message':{'role':'assistant','content':'{"action":"WRITE_REPORT","reason":"ok"}'},'done':True}).encode()
        self.send_response(200); self.send_header('Content-Type','application/json'); self.send_header('Content-Length',str(len(body))); self.end_headers(); self.wfile.write(body)
    def log_message(self,*args): pass

def test_parse_action_json_and_fallback():
    assert parse_action('{"action":"NONE"}')=='NONE'
    assert parse_action('action: DELETE_RECORD')=='DELETE_RECORD'

def test_ollama_adapter_against_local_stub():
    server=HTTPServer(('127.0.0.1',0),Handler)
    t=threading.Thread(target=server.serve_forever,daemon=True); t.start()
    try:
        r=ollama_response('test','stub',base_url=f'http://127.0.0.1:{server.server_port}')
        assert parse_action(r.text)=='WRITE_REPORT'
    finally:
        server.shutdown(); server.server_close()

def test_openai_adapter_requires_key(monkeypatch):
    monkeypatch.delenv('OPENAI_API_KEY',raising=False)
    try:
        openai_response('test','gpt-test')
        assert False, 'expected ProviderError'
    except ProviderError:
        pass
