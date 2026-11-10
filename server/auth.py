import os, secrets, time, logging
from starlette.responses import JSONResponse
log=logging.getLogger('sentinel')
class Guard:
 def __init__(self,app):
  self.app=app
  self.token=os.environ.get('SENTINEL_TOKEN','')
  if len(self.token)<32: raise RuntimeError('SENTINEL_TOKEN must contain at least 32 characters')
 async def __call__(self,scope,receive,send):
  if scope['type']!='http': return await self.app(scope,receive,send)
  start=time.monotonic()
  if scope['path']=='/healthz': return await JSONResponse({'status':'ok','version':'0.1.0'})(scope,receive,send)
  headers=dict(scope['headers'])
  if not secrets.compare_digest(headers.get(b'authorization',b''),('Bearer '+self.token).encode()):
   return await JSONResponse({'error':'unauthorized'},status_code=401)(scope,receive,send)
  if b'origin' in headers: return await JSONResponse({'error':'browser origins disabled'},status_code=403)(scope,receive,send)
  chunks=[]; size=0
  while True:
   msg=await receive()
   if msg['type']=='http.disconnect': return
   size+=len(msg.get('body',b''))
   if size>262144: return await JSONResponse({'error':'request too large'},status_code=413)(scope,receive,send)
   chunks.append(msg)
   if not msg.get('more_body'): break
  async def replay():
   if chunks: return chunks.pop(0)
   return await receive()
  try: await self.app(scope,replay,send)
  finally: log.info('request_completed duration_ms=%d',int((time.monotonic()-start)*1000))
