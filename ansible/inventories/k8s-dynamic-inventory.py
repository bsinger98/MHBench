#!/usr/bin/env python3
"""
Dynamic Ansible Inventory Script for Kubernetes
This script generates Ansible inventory by querying Kubernetes pods
Usage:
  python3 k8s-dynamic-inventory.py --list
  python3 k8s-dynamic-inventory.py --host <hostname>

Environment Variables:
  K8S_NAMESPACE: Target namespace (default: all namespaces)
  K8S_KUBECONFIG: Path to kubeconfig file (default: ~/.kube/config)
  K8S_CONTEXT: Kubernetes context to use (default: current context)
"""

import argparse
import json
import os
import sys
from kubernetes import client, config
from kubernetes.client.rest import ApiException


class K8sInventory:
    def __init__(self):
        self.inventory = {}
        self.load_k8s_config()
        self.namespace = os.environ.get("K8S_NAMESPACE", None)

    def load_k8s_config(self):
        """Load Kubernetes configuration"""
        try:
            # Try in-cluster config first
            config.load_incluster_config()
        except config.ConfigException:
            try:
                # Fall back to kubeconfig
                kubeconfig_path = os.environ.get("K8S_KUBECONFIG", None)
                config.load_kube_config(config_file=kubeconfig_path)
            except config.ConfigException:
                print("Error: Could not load Kubernetes configuration", file=sys.stderr)
                sys.exit(1)

        self.v1 = client.CoreV1Api()

    def get_pods(self):
        """Get all pods from specified namespace or all namespaces"""
        try:
            if self.namespace:
                pods = self.v1.list_namespaced_pod(namespace=self.namespace)
            else:
                pods = self.v1.list_pod_for_all_namespaces()
            return pods.items
        except ApiException as e:
            print(f"Error retrieving pods: {e}", file=sys.stderr)
            return []

    def generate_inventory(self):
        """Generate the complete inventory"""
        pods = self.get_pods()

        # Initialize inventory structure
        self.inventory = {"_meta": {"hostvars": {}}, "all": {"children": []}}

        # Group pods by various criteria
        groups = {
            "k8s_pods": {"hosts": [], "vars": {}},
            "running_pods": {"hosts": [], "vars": {}},
        }

        for pod in pods:
            if not pod.status.pod_ip:  # Skip pods without IP
                continue

            pod_name = pod.metadata.name
            namespace = pod.metadata.namespace
            app_label = (
                pod.metadata.labels.get("app", "unknown")
                if pod.metadata.labels
                else "unknown"
            )
            phase = pod.status.phase
            node_name = pod.spec.node_name

            # Host variables
            hostvars = {
                "ansible_host": pod.status.pod_ip,
                "ansible_connection": "kubernetes.core.kubectl",
                "ansible_kubectl_namespace": namespace,
                "ansible_python_interpreter": "/usr/bin/python3",
                "pod_name": pod_name,
                "pod_namespace": namespace,
                "app_label": app_label,
                "pod_phase": phase,
                "node_name": node_name,
                "k8s_labels": dict(pod.metadata.labels) if pod.metadata.labels else {},
                "k8s_annotations": (
                    dict(pod.metadata.annotations) if pod.metadata.annotations else {}
                ),
            }

            self.inventory["_meta"]["hostvars"][pod_name] = hostvars

            # Add to main groups
            groups["k8s_pods"]["hosts"].append(pod_name)
            if phase == "Running":
                groups["running_pods"]["hosts"].append(pod_name)

            # Group by namespace
            ns_group = f"namespace_{namespace}"
            if ns_group not in groups:
                groups[ns_group] = {
                    "hosts": [],
                    "vars": {"target_namespace": namespace},
                }
            groups[ns_group]["hosts"].append(pod_name)

            # Group by app label
            if app_label != "unknown":
                app_group = f"app_{app_label}"
                if app_group not in groups:
                    groups[app_group] = {"hosts": [], "vars": {"app_name": app_label}}
                groups[app_group]["hosts"].append(pod_name)

            # Group by node
            if node_name:
                node_group = f"node_{node_name.replace('-', '_').replace('.', '_')}"
                if node_group not in groups:
                    groups[node_group] = {"hosts": [], "vars": {"node_name": node_name}}
                groups[node_group]["hosts"].append(pod_name)

            # Group by phase
            phase_group = f"phase_{phase.lower()}"
            if phase_group not in groups:
                groups[phase_group] = {"hosts": [], "vars": {"pod_phase": phase}}
            groups[phase_group]["hosts"].append(pod_name)

        # Add groups to inventory
        for group_name, group_data in groups.items():
            if group_data["hosts"]:  # Only add groups with hosts
                self.inventory[group_name] = group_data
                if group_name not in self.inventory["all"]["children"]:
                    self.inventory["all"]["children"].append(group_name)

        return self.inventory

    def get_host(self, hostname):
        """Get host variables for a specific host"""
        inventory = self.generate_inventory()
        return inventory["_meta"]["hostvars"].get(hostname, {})


def main():
    parser = argparse.ArgumentParser(description="Kubernetes Dynamic Inventory")
    parser.add_argument("--list", action="store_true", help="List all inventory")
    parser.add_argument("--host", help="Get variables for specific host")

    args = parser.parse_args()

    k8s_inventory = K8sInventory()

    if args.list:
        inventory = k8s_inventory.generate_inventory()
        print(json.dumps(inventory, indent=2))
    elif args.host:
        hostvars = k8s_inventory.get_host(args.host)
        print(json.dumps(hostvars, indent=2))
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
