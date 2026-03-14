# KubeShadow Lab Module

This module provides the `lab` command — a lightweight delegator that provisions a Kubernetes cluster and hands off attack-lab deployment to [**kubeshadow-attack-labs**](https://github.com/ashifly/kubeshadow-attack-labs).

> KubeShadow itself contains **no YAML manifests**. All 24 attack-lab environments live in the dedicated `kubeshadow-attack-labs` repository and are managed by Terraform.

---

## Quick Start

```bash
# Deploy full lab (prompts to use default or custom labs repo)
kubeshadow lab apply --provider minikube

# Deploy to cloud
kubeshadow lab apply --provider aws --cluster-size minimal --use-spot
kubeshadow lab apply --provider gcp --region us-west2
kubeshadow lab apply --provider azure

# Deploy a single scenario only
kubeshadow lab apply --manifest 05-secrets.yaml

# Tear down
kubeshadow lab destroy --provider minikube
```

---

## How It Works

```
kubeshadow lab apply
  ↓
1. Prompt: use ashifly/kubeshadow-attack-labs? [Y/n]
   → Y: git clone → ../kubeshadow-attack-labs  (skips if already exists)
   → N: enter custom path
  ↓
2. terraform init && terraform apply -auto-approve
   (all 24 lab manifests deployed automatically)
```

---

## Flags

### `lab apply`

| Flag | Default | Description |
|---|---|---|
| `--provider` | `minikube` | `aws`, `gcp`, `azure`, `minikube`, `kind`, `local` |
| `--region` | *(provider default)* | Cloud region |
| `--cluster-name` | `kubeshadow-lab` | Cluster name |
| `--cluster-size` | `minimal` | `minimal`, `small`, `medium` |
| `--use-spot` | `false` | Use spot/preemptible instances |
| `--manifest` | *(all)* | Deploy only a single YAML (e.g. `05-secrets.yaml`) |
| `--labs-path` | *(auto)* | Path to a local `kubeshadow-attack-labs` checkout |

### `lab destroy`

| Flag | Default | Description |
|---|---|---|
| `--provider` | `minikube` | Provider used to provision the cluster |
| `--region` | *(provider default)* | Cloud region |
| `--cluster-name` | `kubeshadow-lab` | Cluster name |
| `--confirm` | `false` | Skip confirmation prompt |
| `--labs-path` | *(auto)* | Path to labs repo (for terraform destroy) |

---

## Lab Scenarios

All 24 attack environments are defined in [kubeshadow-attack-labs/manifests/](https://github.com/ashifly/kubeshadow-attack-labs/tree/main/manifests).

To add a new scenario: add a YAML to `manifests/` in `kubeshadow-attack-labs` and run `terraform apply`.

---

## Troubleshooting

**Cluster creation fails:**
```bash
aws sts get-caller-identity   # AWS
gcloud auth list               # GCP
az account show                # Azure
```

**Terraform apply fails:**
```bash
cd ../kubeshadow-attack-labs
terraform init
terraform plan
```

**Manual teardown:**
```bash
kubectl delete namespace kubeshadow-lab --ignore-not-found
eksctl delete cluster --name kubeshadow-lab  # AWS
gcloud container clusters delete kubeshadow-lab  # GCP
az aks delete --name kubeshadow-lab --resource-group kubeshadow-lab-rg  # Azure
```
