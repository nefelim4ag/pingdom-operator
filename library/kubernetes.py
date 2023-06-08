#!/bin/python3

from kubernetes import client, config
from kubernetes.client.rest import ApiException

class Kubernetes:
    class HttpProxy:
        name = None
        namespace = None
        annotations: dict = None
        https = False
        hosts: list = None
        integrationids: list = None

        def __init__(self, httpproxy, integrations_mapping=None):
            self.name = httpproxy["metadata"]["name"]
            self.namespace = httpproxy["metadata"]["namespace"]
            self.annotations = httpproxy["metadata"]["annotations"]
            if httpproxy["spec"]["virtualhost"].get("tls"):
                self.https = True
            self.hosts = [httpproxy["spec"]["virtualhost"]["fqdn"]]
            self.integrationids = self.__integrations(integrations_mapping)

        def __integrations(self, integrations_mapping=None):
            annotation = 'pingdom-operator.io/integrations'
            value = self.annotations.get(annotation)

            integrationids = []
            for integrationid_str in value.split(','):
                integrationid = None
                try:
                    integrationid = int(integrationid_str)
                # Handle mapped values
                except ValueError as e:
                    if integrations_mapping:
                        try:
                            integrationid = integrations_mapping[integrationid_str]
                        except KeyError as e:
                            print("No mapping for integration: \"{}\"".format(
                                integrationid_str))
                            raise e
                    else:
                        print("Ingress: {}/{} ~ annotations.{}: {}".format(
                            self.namespace, self.name, annotation, value))
                        raise e
                if int(integrationid) not in integrationids:
                    integrationids.append(int(integrationid))
            return integrationids

        def json(self):
            return {
                'name': self.name,
                'namespace': self.namespace,
                'annotations': self.annotations,
                'https': self.https,
                'hosts': self.hosts,
                'integrationids': self.integrationids
            }

    class Ingress:
        name = None
        namespace = None
        annotations: dict = None
        https = False
        hosts: list = None
        integrationids: list = None

        def __init__(self, ingress, integrations_mapping=None):
            self.name = ingress.metadata.name
            self.namespace = ingress.metadata.namespace
            self.annotations = ingress.metadata.annotations
            if ingress.spec.tls:
                self.https = True
            self.hosts = []
            for rule in ingress.spec.rules:
                self.hosts.append(rule.host)
            self.integrationids = self.__integrations(integrations_mapping)

        def __integrations(self, integrations_mapping=None):
            annotation = 'pingdom-operator.io/integrations'
            value = self.annotations.get(annotation)

            integrationids = []
            for integrationid_str in value.split(','):
                integrationid = None
                try:
                    integrationid = int(integrationid_str)
                # Handle mapped values
                except ValueError as e:
                    if integrations_mapping:
                        integrationid = integrations_mapping[integrationid_str]
                    else:
                        print("Ingress: {}/{} ~ annotations.{}: {}".format(
                            self.namespace, self.name, annotation, value))
                        raise e
                if int(integrationid) not in integrationids:
                    integrationids.append(int(integrationid))
            return integrationids

        def json(self):
            return {
                'name': self.name,
                'namespace': self.namespace,
                'annotations': self.annotations,
                'https': self.https,
                'hosts': self.hosts,
                'integrationids': self.integrationids
            }

    def __init__(self):
        try:
            config.load_incluster_config()
        except config.ConfigException:
            try:
                config.load_kube_config()
            except config.ConfigException:
                raise Exception("Could not configure kubernetes python client")

        self.is_exists_httpProxy = False
        self.check_enable_crd()

    def list_namespaces(self):
        CoreV1Api = client.CoreV1Api()
        try:
            response = CoreV1Api.list_namespace()
        except ApiException as e:
            print(e)
            exit(1)

        for item in response.items:
            yield item.metadata.name

        return None

    def list_ingress_for_all_namespaces(self):
        NetworkingV1Api = client.NetworkingV1Api()
        for namespace in self.list_namespaces():
            try:
                response = NetworkingV1Api.list_namespaced_ingress(namespace)
            except ApiException as e:
                print(e)
                exit(1)

            for item in response.items:
                yield item

        return None

    def check_enable_crd(self):
        ApiextensionsV1Api = client.ApiextensionsV1Api()
        try:
            crd_list = ApiextensionsV1Api.list_custom_resource_definition()
        except ApiException as e:
            print(e)
            exit(1)

        for item in crd_list.items:
            if "httpproxies.projectcontour.io" == item.metadata.name:
                self.is_exists_httpProxy = True
                print("Contour HTTPProxy: support enabled")

    def list_httpproxy_for_all_namespaces(self):
        if not self.is_exists_httpProxy:
            return None

        group = "projectcontour.io"
        v = "v1"
        plural = "httpproxies"

        CustomObjectsApi = client.CustomObjectsApi()
        for namespace in self.list_namespaces():
            try:
                response = CustomObjectsApi.list_namespaced_custom_object(
                    group, v, namespace, plural)
            except ApiException as e:
                print(e)
                exit(1)

            for item in list(response.items())[1][1]:
                yield item

        return None

    def pingdom_ingresses(self, integrations_mapping=None):
        for ingress in self.list_ingress_for_all_namespaces():
            # Add only ingresses with pingdom operator annotations
            for annotation in ingress.metadata.annotations:
                if annotation.startswith("pingdom-operator.io/"):
                    yield self.Ingress(ingress, integrations_mapping)
                    break

        if self.is_exists_httpProxy:
            for httpproxy in self.list_httpproxy_for_all_namespaces():
                # Add only ingresses with pingdom operator annotations
                for annotation in httpproxy["metadata"].get("annotations", []):
                    if annotation.startswith("pingdom-operator.io/"):
                        yield self.HttpProxy(httpproxy, integrations_mapping)
                        break

        return None
