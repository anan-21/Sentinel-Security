import re
import ipaddress
from urllib.parse import urlsplit, parse_qs
from server.schemas import Finding, Report
RULES = [
 ('credential_request', r'(?:send|share|enter|provide).{0,30}(?:password|verification code|OTP)|(?:发送|提供|输入|告诉我).{0,12}(?:密码|验证码|银行卡)', '索取敏感认证信息', 'HIGH'),
 ('payment_pressure', r'(?:立即|马上|先).{0,10}(?:转账|充值|支付)|(?:transfer|pay).{0,20}(?:now|immediately)', '催促资金操作', 'MEDIUM'),
 ('investment', r'保本保收益|稳赚不赔|guaranteed returns|double your money', '保证投资回报', 'HIGH'),
 ('pretext', r'账户.{0,5}(?:冻结|异常)|中奖|领取退款|account suspended|claim your prize', '常见诱导情境，单独出现不能证明诈骗', 'MEDIUM'),
 ('impersonation', r'(?:银行|官方|平台).{0,4}客服|official bank support', '自称官方身份，身份尚未验证', 'MEDIUM'),
 ('prompt_injection', r'ignore (?:all |the )?(?:previous|prior|system) instructions|忽略.{0,8}(?:指令|规则)|绕过.{0,6}(?:审批|权限)|disable.{0,12}(?:safety|security)|system prompt.{0,15}(?:reveal|print)|reveal.{0,15}system prompt', '试图覆盖 Agent 指令或安全边界', 'HIGH'),
 ('exfiltration', r'(?:send|upload|forward).{0,35}(?:all emails|inbox|api keys|secrets)|(?:发送|上传|转发).{0,15}(?:所有邮件|全部邮件|密钥|通讯录)', '要求批量外传数据或秘密', 'HIGH'),
 ('download', r'(?:run|execute).{0,20}(?:attachment|\.exe)|运行附件|下载.{0,10}远程控制', '要求执行附件或远程控制软件', 'HIGH'),
]
def finding(kind,reason,field,text,start,end,severity='MEDIUM'):
 return Finding(type=kind,reason=reason,field=field,evidence=text[start:end],start=start,end=end,severity=severity)
def text_findings(text,field):
 return [finding(k,r,field,text,m.start(),m.end(),s) for k,pat,r,s in RULES for m in re.finditer(pat,text,re.I)]
def url_findings(url,field='url'):
 out=[]
 def add(k,r,severity='MEDIUM'): out.append(finding(k,r,field,url,0,len(url),severity))
 try:
  u=urlsplit(url); host=(u.hostname or '').lower(); port=u.port
  if u.scheme not in ('http','https') or not host: add('invalid_url','不是完整 HTTP(S) URL'); return out
  if u.username or u.password: add('userinfo','URL 包含易混淆的用户信息')
  try:
   ip=ipaddress.ip_address(host)
   add('ip_literal','IP 直连；没有执行网络访问')
   if not ip.is_global: add('private_address','私网或特殊用途地址；禁止作为抓取目标')
  except ValueError:
   if host=='localhost' or host.endswith(('.local','.localhost')): add('private_address','本地主机名')
  if 'xn--' in host or any(ord(c)>127 for c in host): add('idn','国际化域名需人工核实，不等于恶意')
  for brand,domain in [('paypal','paypal.com'),('google','google.com'),('microsoft','microsoft.com')]:
   if brand in host and not (host==domain or host.endswith('.'+domain)): add('brand_lookalike','域名含品牌字样但不在配置的官方域下')
  if len(host.split('.'))>5: add('deep_subdomain','子域层级较深，需核实真实主机')
  if any(k.lower() in ('password','otp','token','api_key','redirect','redirect_uri','url') for k in parse_qs(u.query)): add('sensitive_parameter','参数可能携带凭据或跳转目标')
 except ValueError: add('invalid_url','URL 解析失败')
 return out
def report(findings):
 types=sorted({f.type for f in findings})
 level='LOW'
 if findings: level='HIGH' if any(f.severity=='HIGH' for f in findings) or len(types)>=3 else 'MEDIUM'
 # No trusted threat feed or execution evidence: never invent CRITICAL certainty.
 return Report(risk_level=level,risk_types=types,findings=findings,recommendations=['暂停敏感操作，通过独立官方渠道核实；保留 Muse 审批。'] if findings else ['未命中当前规则；不代表安全保证。'],uncertainty=['静态启发式检测，可能误报或漏报；引用的攻击示例也可能命中。','未访问网址、未查询威胁情报、未验证发件人身份；不能拦截 Muse 全局工具调用。'])
def scan(fields,urls=()):
 fs=[]
 for name,text in fields.items():
  fs.extend(text_findings(text,name))
  for m in re.finditer(r'https?://[^\s<>"，。]+',text):
   fs.extend(url_findings(m.group(),name+':url'))
 for i,url in enumerate(urls): fs.extend(url_findings(url,f'links[{i}]'))
 return report(fs)
