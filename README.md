## 需求
对binance接口的请求都通过本代理发出,在本代理进行 ratelimit, 避免触发binance的封ip机制.

## 已知问题
mitmproxy的限制,mitmproxy可以作代理池，可以作https的自定义脚本规则，但是自定义规则是在发给upstream proxy后才生效，所以注意无法同时作代理池和自定义脚本规则.

## 使用
先安装 mitmproxy 和 本地 redis.

## mitmproxy证书
- py requests
requests库使用自己的ca,需要按照下边设置环境变量

> REQUESTS_CA_BUNDLE=/etc/ssl/certs/ca-certificates.crt python
https://github.com/mitmproxy/mitmproxy/issues/2547#issuecomment-399778481

- 系统级证书，不一定需要安装
[Certificates](https://docs.mitmproxy.org/stable/concepts-certificates/)

[User:Grawity/Adding a trusted CA certificate - ArchWiki](https://wiki.archlinux.org/title/User:Grawity/Adding_a_trusted_CA_certificate)

## 其他代理软件

### gost
可以作代理池
[负载均衡 | GOST v2](https://v2.gost.run/load-balancing/)

### proxy.py
可以作代理池，但是无法作https的自定义脚本规则
[abhinavsingh/proxy.py](https://github.com/abhinavsingh/proxy.py)

另外注意没有全局对象.
> Plugin instances are created for every request.
[proxy.py/welcome.ipynb at 96ec796a4eec0c50a5c85fe2097470a494da84e5 · abhinavsingh/proxy.py](https://github.com/abhinavsingh/proxy.py/blob/96ec796a4eec0c50a5c85fe2097470a494da84e5/tutorial/welcome.ipynb)

## binance rest api 频率限制
[API Frequently Asked Questions | Binance](https://www.binance.com/en/support/faq/api-frequently-asked-questions-360004492232)

比如市场深度，1000档，5000档频率限制不同
[binance-spot-api-docs/rest-api.md at master · binance/binance-spot-api-docs](https://github.com/binance/binance-spot-api-docs/blob/master/rest-api.md#order-book)
比如对于1000档行情，weight为50,那么实际的qps限制为1200/50=24/min
注意: 期货的限制也不同,weight为20[Order Book – Binance API Documentation](https://binance-docs.github.io/apidocs/futures/en/#order-book) ，实际测试weight应该为20.

请求频率过高可能封禁ip 12小时.
