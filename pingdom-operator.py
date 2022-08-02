#!/usr/local/bin/python3

import requests
import json
import os

from cachetools import cached, TTLCache
from kubernetes import client, config
from kubernetes.client.rest import ApiException


class Kubernetes:
    class Ingress:
        def __init__(self, ingress):
            self.name = ingress.metadata.name
            self.namespace = ingress.metadata.namespace
            self.annotations = ingress.metadata.annotations
            if ingress.spec.tls:
                self.https = True
            self.hosts = []
            for rule in ingress.spec.rules:
                self.hosts.append(rule.host)

        def integrations(self):
            return self.annotations.get('pingdom-operator.io/integrations').split(',')

    def __init__(self):
        try:
            config.load_incluster_config()
        except config.ConfigException:
            try:
                config.load_kube_config()
            except config.ConfigException:
                raise Exception("Could not configure kubernetes python client")
        self.v1 = client.NetworkingV1Api()

    @cached(cache=TTLCache(maxsize=1, ttl=60))
    def list_ingress_for_all_namespaces(self):
        try:
            response = self.v1.list_ingress_for_all_namespaces()
        except ApiException as e:
            print(e)
            exit(1)

        return response.items

    def pingdom_ingresses(self):
        ingresses_list = []
        for ingress in self.list_ingress_for_all_namespaces():
            # Add only ingresses with pingdom operator annotations
            for annotation in self.Ingress(ingress).annotations:
                if annotation.startswith("pingdom-operator.io/"):
                    ingresses_list.append(self.Ingress(ingress))
                    break

        return ingresses_list


class Pingdom:
    class BearerAuth(requests.auth.AuthBase):
        def __init__(self, token):
            self.token = token

        def __call__(self, r):
            r.headers["authorization"] = "Bearer " + self.token
            return r

    def __init__(self, token):
        self.s = requests.Session()
        self.s.auth = self.BearerAuth(token)
        self.s.headers['Content-type'] = 'application/json'
        self.tags_filter = []

    def api_url(self, *args):
        url = "https://api.pingdom.com/api/3.1/"
        args_str = []
        for arg in args:
            args_str.append(str(arg))
        req_url = url + "/".join(args_str)
        return req_url.rstrip('/')

    # Pingdom supports resolution only one of 1m, 5m, 15m, 30m, 60m check intervals only
    def __check_interval(self, interval: int = 5):
        if interval < 1:
            raise Exception("Interval must be greater than 0")
        if interval >= 60:
            return 60
        if interval >= 30:
            return 30
        if interval >= 15:
            return 15
        if interval >= 5:
            return 5
        if interval >= 1:
            return 1

    # Enum: "http" "httpcustom" "tcp" "ping" "dns" "udp" "smtp" "pop3" "imap"
    def __type(self, type):
        if type not in ["http", "httpcustom", "tcp", "ping", "dns", "udp", "smtp", "pop3", "imap"]:
            raise Exception("Invalid check type")
        return type

    def __probe_filters(self, region=None):
        if region not in [None, 'EU', 'NA', 'APAC', 'LATAM']:
            raise Exception("Invalid region")
        return [
            'region: ' + region
        ]

    def __parse_headers(self, headers):
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
        self.req_limit_short = dict(headers)["req-limit-short"]
        self.req_limit_long = dict(headers)["req-limit-long"]

    @cached(cache=TTLCache(maxsize=32, ttl=600))
    def checks(self, *args):
        response = None
        url = self.api_url('checks')
        tags = []
        params = {}
        for i in args:
            tags.append(str(i))
        if tags:
            params["tags"] = ','.join(tags)
            response = self.s.get(url, params=params, json={})
        else:
            response = self.s.get(url, json={})
        response.raise_for_status()
        self.__parse_headers(response.headers)

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

    @cached(cache=TTLCache(maxsize=1024, ttl=600))
    def describe_check(self, checkid: int = 0, name: str = None, hostname: str = None):
        response = None
        checks = []
        if checkid < 1:
            checks = self.checks(*self.tags_filter)

        if checkid >= 1:
            url = self.api_url('checks', checkid)
            response = self.s.get(url, json={})
            response.raise_for_status()
            self.__parse_headers(response.headers)

            if response:
                return dict(response.json())
            return None

        if name is not None:
            for check in checks:
                if check['name'] == name:
                    return self.describe_check(checkid=check['id'])
        elif hostname is not None:
            for check in checks:
                if check['hostname'] == hostname:
                    return self.describe_check(checkid=check['id'])
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

        # {
        #     "check": {
        #         "id": 6126477,
        #         "name": "example.app/resource/get",
        #         "resolution": 1,
        #         "sendnotificationwhendown": 3,
        #         "notifyagainevery": 0,
        #         "notifywhenbackup": true,
        #         "created": 1590669421,
        #         "type": {
        #             "http": {
        #                 "verify_certificate": true,
        #                 "url": "/resource/get",
        #                 "encryption": true,
        #                 "port": 443,
        #                 "ssl_down_days_before": 7,
        #                 "postdata": "var=value&var2=value2",
        #                 "shouldcontain": "\"success\":1",
        #                 "requestheaders": {
        #                     "User-Agent": "Pingdom.com_bot_version_1.4_(http://www.pingdom.com/)"
        #                 }
        #             }
        #         },
        #         "hostname": "example.app",
        #         "ipv6": false,
        #         "responsetime_threshold": 30000,
        #         "custom_message": "",
        #         "integrationids": [
        #             103676,
        #             115348
        #         ],
        #         "lasterrortime": 1658593750,
        #         "lasttesttime": 1659482350,
        #         "lastresponsetime": 324,
        #         "lastdownstart": 1658593690,
        #         "lastdownend": 1658593810,
        #         "status": "up",
        #         "tags": [
        #             {
        #                 "name": "tag2",
        #                 "type": "u",
        #                 "count": "15"
        #             },
        #             {
        #                 "name": "tag1",
        #                 "type": "u",
        #                 "count": "4"
        #             }
        #         ],
        #         "probe_filters": [
        #             "region: EU"
        #         ]
        #     }
        # }



def main():
    token = os.environ.get('BEARER_TOKEN')
    cluster_name = os.environ.get('CLUSTER_NAME', "default-cluster")

    p = Pingdom(token)
    p.tags_filter = ['pingdom-operator', cluster_name]

    k = Kubernetes()
    for ingress in k.pingdom_ingresses():
        if ingress.annotations.get('pingdom-operator.io/name'):
            name = ingress.annotations.get('pingdom-operator.io/name')
            # print(json.dumps(p.describe_check(name=name), indent=2))
            break
        for host in ingress.hosts:
            # print(json.dumps(p.describe_check(hostname=host), indent=2))
            pass



main()
