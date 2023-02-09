import subprocess
import re

def run_command(cmd):
    result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, shell=True, encoding='utf-8')
    return result.stdout + result.stderr

def audit_k8s():
    # Check if kubectl is installed
    result = run_command("which kubectl")
    if "kubectl not found" in result:
        print("kubectl is not installed on this system")
        return

    # Check if kubectl is connected to a cluster
    result = run_command("kubectl config current-context")
    if "No context found" in result:
        print("kubectl is not connected to a cluster")
        return

    # Check the version of the cluster
    result = run_command("kubectl version --short | grep Server | awk '{print $3}'")
    print("Kubernetes cluster version: " + result)

    # Check if there are any pods running as root
    result = run_command("kubectl get pods --all-namespaces -o json | jq '.items[] | select(.spec.securityContext.runAsUser == 0) | .metadata.namespace + \"/\" + .metadata.name'")
    if result:
        print("There are pods running as root: " + result)

    # Check for vulnerable images
    result = run_command("kubectl get pods --all-namespaces -o json | jq '.items[].spec.containers[].image' | tr -d '\"' | xargs -I {} sh -c 'curl --silent https://quay.io/v1/repository/{}/vulnerability' 2>/dev/null | jq 'select(.data.vulnerabilities.severity == \"high\") | .data.repository + \"/\" + .data.name + \": \" + .data.vulnerabilities.description'")
    if result:
        print("There are vulnerable images: " + result)

    # Check if Kubernetes API server is accessible only over HTTPS
    result = run_command("kubectl describe configmap -n kube-system kubeadm-config | grep -A1 apiServer | grep -- '--tls-cert-file'")
    if not result:
        print("Kubernetes API server is not accessible only over HTTPS")

    # Check for cluster-admin permissions granted to users or service accounts
    result = run_command("kubectl get clusterrolebinding | awk '{print $1}' | xargs -I {} sh -c 'kubectl describe clusterrolebinding {} | grep -A1 subjects | grep -v serviceaccounts | grep -v -E \"system:.*\"'")
    if result:
        print("Cluster-admin permissions are granted to users or service accounts: " + result)

if __name__ == "__main__":
    audit_k8s()
