# Deploy on Azure

## Read-only service principal

```bash
az ad sp create-for-rbac --name secureops-reader \
  --role "Reader" \
  --scopes /subscriptions/$SUB
az role assignment create \
  --assignee <appId> \
  --role "Security Reader" \
  --scope /subscriptions/$SUB
```

## AKS platform install

```bash
az aks get-credentials --resource-group secureops-prod --name secureops-aks
kubectl create ns secureops
helm install secureops deploy/helm/ -n secureops \
  --set cloud.provider=azure \
  --set serviceAccount.azureClientId=<appId>
```

## Managed identity

Prefer User-Assigned Managed Identity over a service-principal secret. Bind it
to the K8s service account:

```yaml
serviceAccount:
  annotations:
    azure.workload.identity/client-id: <managed-identity-app-id>
```

## Self-healing

The Azure backend handles `azure.nsg_revoke_rule` (see
`playbooks/azure-nsg-open-rdp.yaml`). Additional ops (`storage.set_https_only`,
`keyvault.disable_public_access`) extend the `CloudAction` enum.
