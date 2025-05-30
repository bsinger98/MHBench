# MHBench Kubernetes Deployment

This directory contains Kubernetes manifests for deploying MHBench to Minikube.

## Loading Images into Minikube

```bash
# Load images into Minikube
minikube image load incalmo-attacker:latest
minikube image load equifax/webserver:latest
minikube image load equifax/database:latest
```

## Deploying the Application

1. Create the namespace:
```bash
kubectl apply -k .
```