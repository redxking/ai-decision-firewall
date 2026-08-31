from __future__ import annotations
import json, os, urllib.request, urllib.error
from dataclasses import dataclass

@dataclass
class ProviderResponse:
    provider: str
    model: str
    text: str
    raw: dict

class ProviderError(RuntimeError):
    pass

def _post_json(url: str, payload: dict, headers: dict, timeout: int = 120) -> dict:
    data = json.dumps(payload).encode('utf-8')
    req = urllib.request.Request(url, data=data, headers={**headers, 'Content-Type':'application/json'}, method='POST')
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return json.loads(r.read().decode('utf-8'))
    except urllib.error.HTTPError as e:
        body = e.read().decode('utf-8', errors='replace')
        raise ProviderError(f'HTTP {e.code} from {url}: {body[:1000]}') from e
    except urllib.error.URLError as e:
        raise ProviderError(f'Cannot reach {url}: {e}') from e

def openai_response(prompt: str, model: str, timeout: int = 120) -> ProviderResponse:
    key = os.getenv('OPENAI_API_KEY')
    if not key:
        raise ProviderError('OPENAI_API_KEY is not set')
    payload = {'model': model, 'input': prompt, 'temperature': 0}
    raw = _post_json('https://api.openai.com/v1/responses', payload,
                     {'Authorization': f'Bearer {key}'}, timeout)
    text = raw.get('output_text') or ''
    if not text:
        parts=[]
        for item in raw.get('output', []):
            for content in item.get('content', []):
                if content.get('type') in ('output_text','text') and content.get('text'):
                    parts.append(content['text'])
        text='\n'.join(parts)
    return ProviderResponse('openai', model, text, raw)

def anthropic_response(prompt: str, model: str, timeout: int = 120) -> ProviderResponse:
    key = os.getenv('ANTHROPIC_API_KEY')
    if not key:
        raise ProviderError('ANTHROPIC_API_KEY is not set')
    payload = {'model': model, 'max_tokens': 256, 'temperature': 0,
               'messages': [{'role':'user','content':prompt}]}
    raw = _post_json('https://api.anthropic.com/v1/messages', payload,
                     {'x-api-key': key, 'anthropic-version':'2023-06-01'}, timeout)
    text='\n'.join(block.get('text','') for block in raw.get('content', []) if block.get('type')=='text')
    return ProviderResponse('anthropic', model, text, raw)

def ollama_response(prompt: str, model: str, base_url: str | None = None, timeout: int = 120) -> ProviderResponse:
    base = (base_url or os.getenv('OLLAMA_BASE_URL') or 'http://localhost:11434').rstrip('/')
    payload = {'model': model, 'messages':[{'role':'user','content':prompt}], 'stream': False,
               'options': {'temperature': 0}}
    raw = _post_json(base + '/api/chat', payload, {}, timeout)
    text = (raw.get('message') or {}).get('content','')
    return ProviderResponse('ollama', model, text, raw)

def invoke(provider: str, prompt: str, model: str, timeout: int = 120, base_url: str | None = None) -> ProviderResponse:
    provider=provider.lower()
    if provider=='openai': return openai_response(prompt, model, timeout)
    if provider in ('anthropic','claude'): return anthropic_response(prompt, model, timeout)
    if provider=='ollama': return ollama_response(prompt, model, base_url, timeout)
    raise ProviderError(f'unsupported provider: {provider}')
