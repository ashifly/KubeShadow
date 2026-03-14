# Troubleshooting Guide

This guide provides solutions for common issues you might encounter when using KubeShadow's sidecar module.

## Command Line Issues

### "No such file or directory" Error

If you see an error like this:
```bash
zsh: no such file or directory: pod-name
```

Solution:
- Replace `<pod-name>` with an actual pod name from your cluster
- Use `kubectl get pods` to list available pods
- Example: `kubeshadow sidecar --pod nginx-7c6f4b8f5d-2xq9m --namespace default --config sidecar-config.json`

### "Config file not found" Error

If you see an error like this:
```
Error: config file not found: sidecar-config.json
```

Solution:
- Ensure the config file exists in the specified path
- Use absolute path if needed: `--config /full/path/to/sidecar-config.json`
- Check file permissions: `ls -l sidecar-config.json`

## Kubernetes Issues

### Permission Denied

If you see an error like this:
```
Error: failed to update pod with sidecar: pods "my-pod" is forbidden: User "system:serviceaccount:default:default" cannot update resource "pods" in API group "" in the namespace "default"
```

Solution:
1. Create a service account with the necessary permissions:
```yaml
apiVersion: v1
kind: ServiceAccount
metadata:
  name: kubeshadow
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: kubeshadow
rules:
- apiGroups: [""]
  resources: ["pods"]
  verbs: ["get", "update", "patch"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: kubeshadow
subjects:
- kind: ServiceAccount
  name: kubeshadow
  namespace: default
roleRef:
  kind: ClusterRole
  name: kubeshadow
  apiGroup: rbac.authorization.k8s.io
```

2. Use the service account:
```bash
kubectl config set-context --current --user=system:serviceaccount:default:kubeshadow
```

### Image Pull Failed

If you see an error like this:
```
Error: failed to pull image "nginx:latest": rpc error: code = Unknown desc = failed to pull and unpack image "docker.io/library/nginx:latest": failed to resolve reference "docker.io/library/nginx:latest"
```

Solution:
1. Check image name and tag:
```bash
# Verify image exists
docker pull nginx:latest
```

2. Check image pull secrets:
```bash
# List image pull secrets
kubectl get secrets --namespace default

# Create image pull secret if needed
kubectl create secret docker-registry regcred \
  --docker-server=<your-registry-server> \
  --docker-username=<your-username> \
  --docker-password=<your-password> \
  --docker-email=<your-email>
```

### Pod Update Failed

If you see an error like this:
```
Error: failed to update pod with sidecar: pods "my-pod" is forbidden: pod updates may not add containers
```

Solution:
1. Check if the pod is in a terminating state:
```bash
kubectl get pod my-pod -o yaml | grep -A 5 status
```

2. Check for conflicting container names:
```bash
kubectl get pod my-pod -o yaml | grep -A 10 containers
```

3. Try recreating the pod:
```bash
kubectl delete pod my-pod
kubectl create -f pod.yaml
```

## Configuration Issues

### Invalid JSON

If you see an error like this:
```
Error: failed to parse config file: invalid character '}' after object key
```

Solution:
1. Validate your JSON:
```bash
# Install jq if needed
brew install jq

# Validate JSON
jq '.' sidecar-config.json
```

2. Check for common JSON errors:
- Missing commas between objects
- Trailing commas
- Unquoted keys
- Invalid escape sequences

### Missing Required Fields

If you see an error like this:
```
Error: sidecar image is required
```

Solution:
1. Check your configuration file:
```bash
cat sidecar-config.json
```

2. Ensure all required fields are present:
- `image` (required)
- `securityContext` (recommended)

## Debugging

### Enable Debug Logging

```bash
kubeshadow --log-level debug sidecar --pod my-pod --config sidecar-config.json
```

### Check Pod Status

```bash
# Get pod details
kubectl describe pod my-pod

# Check pod logs
kubectl logs my-pod -c kubeshadow-sidecar

# Check pod events
kubectl get events --field-selector involvedObject.name=my-pod
```

### Check Kubernetes API

```bash
# Check API server logs
kubectl logs -n kube-system -l component=kube-apiserver

# Check API server metrics
kubectl get --raw /metrics
```

## Getting Help

If you're still experiencing issues:

1. Check the [documentation](modules/sidecar.md)
2. Search [existing issues](https://github.com/your-repo/kubeshadow/issues)
3. Create a new issue with:
   - Error message
   - Configuration file
   - Pod details
   - Kubernetes version
   - KubeShadow version 