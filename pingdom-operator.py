#!/usr/bin/env python3

import logging
import time
import json
import os

from library.kubernetes import Kubernetes
from library.pingdom import Pingdom

def main():
    logging.basicConfig(
        format='[%(asctime)s] [%(levelname)s] %(message)s',
        level=logging.INFO,
        force = True,
        datefmt='%Y-%m-%d %H:%M:%S'
    )

    token = os.environ.get('BEARER_TOKEN')
    cluster_name = os.environ.get('CLUSTER_NAME', "default-cluster")
    dry_run = os.environ.get('DRY_RUN', "False")
    integrations_mapping = json.loads(
        os.environ.get('INTEGRATIONS_MAPPING', '{}'))

    if dry_run.lower() in ['false', "0"]:
        dry_run = False

    p = Pingdom(token)
    p.tags_filter = ['pingdom-operator', cluster_name]
    p.dry_run = dry_run

    k = Kubernetes()

    print("Pingdom operator running")
    print("dry_run: {}".format(p.dry_run))
    print("cluster_name: {}".format(cluster_name))
    print("owner tags: {}".format(list(p.tags_filter)))
    print("integrations: {}".format(json.dumps(integrations_mapping)))

    pause_time = 60
    while True:
        for ingress in k.pingdom_ingresses(integrations_mapping):
            if name := ingress.annotations.get('pingdom-operator.io/name'):
                check = p.describe_check(name=name)
                if check:
                    checkid = check['id']
                    p.modify_check(checkid, ingress)
                    continue
            # Doesn't support several hosts in one ingress
            if ingress.hosts:
                host = ingress.hosts[0]
                check = p.describe_check(hostname=host)
                if check:
                    checkid = check['id']
                    p.modify_check(checkid, ingress)
                    continue

            p.create_check(ingress, p.tags_filter)

        check_list = p.checks(*p.tags_filter)
        check_dedup = {}
        for check in check_list:
            name = check['name']
            if check_dedup.get(name) is None:
                check_dedup[name] = check

            if check_dedup[name] != check:
                remove_id = None
                if check_dedup[name]["created"] < check["created"]:
                    remove_id = check['id']
                else:
                    remove_id = check_dedup[name]['id']
                    check_dedup[name] = check
                logging.info(f"Cleanup duplicated - orig: {check_dedup[name]['id']}, dup: {remove_id}")
                p.delete_check(remove_id)

            candidate_checkid = check_dedup[name]['id']
            for ingress in k.pingdom_ingresses(integrations_mapping):
                if ingress.hosts and check['hostname'] == ingress.hosts[0]:
                    candidate_checkid = None
                    break
            if candidate_checkid:
                p.delete_check(candidate_checkid)

        time.sleep(pause_time)


if __name__ == "__main__":
    main()
