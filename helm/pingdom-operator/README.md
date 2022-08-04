# pingdom-operator

# TL;DR
```
helm repo add pingdom-operator https://nefelim4ag.github.io/pingdom-operator/
helm install pingdom-operator pingdom-operator/pingdom-operator
```

# Description

Deploy pingdom-operator controller which create/update/delete pingdom checks based on info from ingress objects

# Examples
pingdom-operator search ingresses by annotations, annootations are mapped to pingdom api fields [Pingdom API 3.1](https://docs.pingdom.com/api/#tag/Checks/paths/~1checks~1{checkid}/put):
```
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: artifactory-oss
  namespace: jfrog
  labels:
    app: artifactory
  annotations:
    cert-manager.io/cluster-issuer: zerossl
    ingress.kubernetes.io/force-ssl-redirect: 'true'
    kubernetes.io/ingress.class: contour
    pingdom-operator.io/integrations: '1245676'
    pingdom-operator.io/ipv6: 'true'
    pingdom-operator.io/name: artifactory.example.com
    pingdom-operator.io/probe_filters: 'region: EU'
    pingdom-operator.io/shouldnotcontain: no healthy upstream
spec:
  rules:
    - host: artifactory.example.com
      http:
        paths:
          - path: /
            pathType: ImplementationSpecific
            backend:
              service:
                name: artifactory
                port:
                  number: 8082
  # Evaluated as https true and enable ssl on pingdom
  tls:
    - hosts:
        - artifactory.example.com
      secretName: artifactory-tls
```
