#!/usr/local/bin/python3

import requests
import json
import os

from functools import lru_cache


class BearerAuth(requests.auth.AuthBase):
    def __init__(self, token):
        self.token = token

    def __call__(self, r):
        r.headers["authorization"] = "Bearer " + self.token
        return r


class Pingdom():
    api_url = "https://api.pingdom.com/api/3.1/"

    def __init__(self):
        token = os.environ.get('BEARER_TOKEN')
        auth = BearerAuth(token)
        self.s = requests.Session()
        self.s.auth = BearerAuth(token)
        self.s.headers['Content-type'] = 'application/json'

    @lru_cache(maxsize=16, typed=False)
    def checks(self):
        response = self.s.get(self.api_url + 'checks', json={})
        response.raise_for_status()
        # {
        #     "Date": "Mon, 01 Aug 2022 12:52:45 GMT",
        #     "Content-Type": "application/json",
        #     "Transfer-Encoding": "chunked",
        #     "Connection": "keep-alive",
        #     "Cache-Control": "no-cache",
        #     "req-limit-long": "Remaining: 6119845 Time until reset: 2544257",
        #     "req-limit-short": "Remaining: 33994 Time until reset: 3519",
        #     "server-time": "1659358365",
        #     "x-trace": "2B98646BA1ED60000DB69285D40CC1544F0B53C0340B6E2D2B16C47E5000",
        #     "CF-Cache-Status": "DYNAMIC",
        #     "Expect-CT": "max-age=604800, report-uri=\"https://report-uri.cloudflare.com/cdn-cgi/beacon/expect-ct\"",
        #     "Server": "cloudflare",
        #     "CF-RAY": "733eb6789c4268fb-FRA",
        #     "Content-Encoding": "gzip"
        # }
        self.api_status = dict(response.headers)

        # list of
        # {
        #     "id": 5811286,
        #     "created": 1582026671,
        #     "name": "office.example.com",
        #     "hostname": "office.example.com",
        #     "resolution": 1,
        #     "type": "ping",
        #     "ipv6": false,
        #     "verify_certificate": false,
        #     "lasterrortime": 1656032831,
        #     "lasttesttime": 1659384221,
        #     "lastresponsetime": 58,
        #     "lastdownstart": 1656032801,
        #     "lastdownend": 1656032861,
        #     "status": "up"
        # }
        return response.json()['checks']

    @lru_cache(maxsize=64, typed=False)
    def get_check(self, checkid: int):
        response = self.s.get(self.api_url + 'checks/' + str(checkid), json={})
        response.raise_for_status()
        # {
        #     "check": {
        #         "id": 11173154,
        #         "name": "dev.example.net",
        #         "resolution": 1,
        #         "sendnotificationwhendown": 2,
        #         "notifyagainevery": 10,
        #         "notifywhenbackup": true,
        #         "created": 1649763599,
        #         "type": {
        #             "http": {
        #                 "verify_certificate": true,
        #                 "url": "/healthz",
        #                 "encryption": true,
        #                 "port": 443,
        #                 "ssl_down_days_before": 3,
        #                 "shouldnotcontain": "unhealthy",
        #                 "requestheaders": {
        #                     "User-Agent": "Pingdom.com_bot_version_1.4_(http://www.pingdom.com/)"
        #                 }
        #             }
        #         },
        #         "hostname": "dev.example.net",
        #         "ipv6": false,
        #         "responsetime_threshold": 5000,
        #         "custom_message": "",
        #         "integrationids": [
        #             121110
        #         ],
        #         "lasterrortime": 1658425281,
        #         "lasttesttime": 1659383721,
        #         "lastresponsetime": 426,
        #         "lastdownstart": 1658408181,
        #         "lastdownend": 1658425341,
        #         "status": "up",
        #         "tags": [],
        #         "probe_filters": []
        #     }
        # }
        print(json.dumps(dict(response.json()), indent=4))


def main():
    p = Pingdom()
    for i in p.checks():
        print(json.dumps(i, indent=4))
    # p.get_check(checkid=11173154)


main()
