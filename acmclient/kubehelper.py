import argparse

from dataclasses import dataclass

import kubernetes.client
import kubernetes.client.api
import kubernetes.client.api.core_v1_api
import kubernetes.config


@dataclass
class KubernetesArgs:
    kubeconfig: str | None = None
    namespace: str | None = None
    context: str | None = None


def get_corev1_client(
    config_file: str | None = None, context: str | None = None
) -> kubernetes.client.api.core_v1_api.CoreV1Api:
    kubernetes.config.load_kube_config(config_file=config_file, context=context)
    v1 = kubernetes.client.CoreV1Api()
    return v1


def current_context() -> dict[str, str]:
    return kubernetes.config.list_kube_config_contexts()[1].get("context", {})


def current_namespace() -> str:
    return current_context()["namespace"]


def add_kubernetes_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--kubeconfig",
        "-k",
        metavar="<kubeconfig-file>",
        help=f"Path to Kubernetes credentials file (Env: KUBECONFIG)",
    )
    parser.add_argument(
        "--context", help="Name of kubernetes configuration context to use"
    )
    parser.add_argument(
        "--namespace", "-n", help="Kubernetes namespace scope for this operation"
    )
