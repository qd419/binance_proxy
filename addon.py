from mitmproxy import http
import redis

class RequestLimiter:
    def __init__(self, max_value, ttl):
        self.max_value = max_value
        self.ttl = ttl
        self.r = r = redis.Redis(host="localhost", port=6379, db=0)

    def inc(self):
        key = "count"
        # if expired
        if not self.r.exists(key):
            self.r.setex(key, self.ttl, 0)

        # full
        if int(self.r.get(key)) == self.max_value:
            return False

        # inc
        self.r.incr(key)
        return True

    def count(self):
        return self.r.get("count")


def request(flow: http.HTTPFlow):
    limiter = RequestLimiter(60, 60)
    if flow.request.path.startswith("/api/v3/depth"):
        if not limiter.inc():
            flow.response = http.Response.make(
                429, b"I'm a teapot",
            )
