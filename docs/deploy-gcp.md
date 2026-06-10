# Deploy on GCP

## Read-only service account

```bash
gcloud iam service-accounts create secureops-reader \
  --display-name="SecureOps read-only"
gcloud projects add-iam-policy-binding $PROJECT \
  --member="serviceAccount:secureops-reader@$PROJECT.iam.gserviceaccount.com" \
  --role="roles/viewer"
gcloud projects add-iam-policy-binding $PROJECT \
  --member="serviceAccount:secureops-reader@$PROJECT.iam.gserviceaccount.com" \
  --role="roles/iam.securityReviewer"
```

## GKE platform install

```bash
gcloud container clusters get-credentials secureops-prod --region us-central1
kubectl create ns secureops
helm install secureops deploy/helm/ -n secureops \
  --set cloud.provider=gcp \
  --set serviceAccount.workloadIdentity=secureops-reader@$PROJECT.iam.gserviceaccount.com
```

Annotate the K8s SA for Workload Identity:

```yaml
serviceAccount:
  annotations:
    iam.gke.io/gcp-service-account: secureops-reader@$PROJECT.iam.gserviceaccount.com
```

## Cloud Run (API-only)

```bash
gcloud run deploy secureops-api \
  --image=ghcr.io/<org>/secureops:<tag> \
  --command secureops-api \
  --set-env-vars REDIS_URL=$REDIS_URL,DATABASE_URL=$DB_URL \
  --service-account secureops-reader@$PROJECT.iam.gserviceaccount.com
```
