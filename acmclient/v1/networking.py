#   Licensed under the Apache License, Version 2.0 (the "License"); you may
#   not use this file except in compliance with the License. You may obtain
#   a copy of the License at
#
#        http://www.apache.org/licenses/LICENSE-2.0
#
#   Unless required by applicable law or agreed to in writing, software
#   distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#   WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#   License for the specific language governing permissions and limitations
#   under the License.

import argparse
import logging
import ipaddress
import kubernetes.client
import openstack.network.v2.port
import openstack.network.v2.floating_ip

import dataclasses
from dataclasses import dataclass, field

from osc_lib.exceptions import CommandError
from osc_lib.command import command
from osc_lib.i18n import _
from typing import override

from acmclient import kubehelper
from acmclient import openstack_helpers

LOG = logging.getLogger(__name__)


@dataclass
class PortForwardArgs(kubehelper.KubernetesArgs):
    all_services: bool = True
    service_type: str | None = None
    internal_ip: str | None = None
    internal_ip_network: str | None = None
    internal_ip_subnet: str | None = None
    external_ip: str | None = None
    external_ip_network: str | None = None
    service_names: list[str] = field(default_factory=list)

    @classmethod
    def from_args(cls, **kwargs):
        names = set([f.name for f in dataclasses.fields(cls)])
        return cls(**{k: v for k, v in kwargs.items() if k in names})


class PortForwardService(command.Lister):
    @override
    def get_parser(self, prog_name: str) -> argparse.ArgumentParser:
        parser = super().get_parser(prog_name)
        kubehelper.add_kubernetes_args(parser)

        parser.add_argument(
            "--all",
            dest="all_services",
            action="store_true",
            help=_("Create port forwards for all services in the target namespace"),
        )
        parser.add_argument(
            "--service-type",
            choices=["loadbalancer", "nodeport"],
            help=_("When using --all, consider only this type of service"),
        )
        parser.add_argument(
            "--internal-ip",
            "-i",
            help=_("Internal ip to use for NodePort services"),
        )
        parser.add_argument(
            "--internal-ip-network",
            help=_("Network from which to allocate ports for internal ips"),
        )
        parser.add_argument(
            "--internal-ip-subnet",
            help=_("Subnet from which to allocate ports for internal ips"),
        )
        parser.add_argument(
            "--external-ip",
            "-x",
            help=_("External ip for port forward"),
        )
        parser.add_argument(
            "--external-ip-network",
            default="external",
            help=_("Network from which to allocate floating ips"),
        )
        parser.add_argument(
            "service_names",
            nargs="*",
            help=_("List of individiual services for which to create port forwards"),
        )

        return parser

    @override
    def take_action(self, parsed_args: argparse.Namespace):
        self.args = args = PortForwardArgs.from_args(**vars(parsed_args))
        osnetwork = openstack_helpers.Network(self.app.client_manager.sdk_connection)

        if not args.service_names and not args.all_services:
            raise CommandError(
                "ERROR: you must either provide a list of services or --all"
            )

        self.kubeclient = kubehelper.get_corev1_client(
            config_file=args.kubeconfig, context=args.context
        )

        services = self.select_services()
        LOG.debug(
            "found services: %s",
            ",".join([service.metadata.name for service in services]),
        )

        fip = osnetwork.find_or_create_floating_ip(
            args.external_ip, external_ip_network=args.external_ip_network
        )
        LOG.debug("using floating ip address %s", fip)

        forwards = []
        for service in services:
            if service.spec.type == "LoadBalancer":
                target_ip = service.status.loadBalancer.ingress[0].ip
            elif self.args.internal_ip is not None:
                target_ip = self.args.internal_ip
            else:
                raise CommandError(
                    f"{service.metadata.name} is a {service.spec.type} service and you have not set --internal-ip"
                )

            internal_port = osnetwork.find_or_create_port(
                target_ip,
                internal_ip_network=args.internal_ip_network,
                internal_ip_subnet=args.internal_ip_subnet,
                description=f"service:{service.metadata.name}",
            )
            LOG.debug("using port %s", internal_port)

            for port in service.spec.ports:
                if service.spec.type == "LoadBalancer":
                    target_port = port.port
                else:
                    target_port = port.node_port

                protocol = port.protocol.lower()

                LOG.info(
                    "forward port %s from %s -> %s for service %s",
                    target_port,
                    args.internal_ip,
                    fip.name,
                    service.metadata.name,
                )

                fwd = self.app.client_manager.sdk_connection.network.create_floating_ip_port_forwarding(
                    fip,
                    internal_ip_address=args.internal_ip,
                    internal_port=target_port,
                    internal_port_id=internal_port.id,
                    external_port=target_port,
                    protocol=protocol,
                )
                forwards.append((service, fip, fwd))

        return ["ID", "Service", "Port", "Protocol", "Internal IP", "External IP"], [
            [
                fwd[2].id,
                fwd[0].metadata.name,
                fwd[2].internal_port,
                fwd[2].protocol,
                fwd[2].internal_ip_address,
                fwd[1].name,
            ]
            for fwd in forwards
        ]

    def select_services(self):
        namespace = (
            kubehelper.current_namespace()
            if self.args.namespace is None
            else self.args.namespace
        )

        services = self.kubeclient.list_namespaced_service(namespace)
        selected = []

        if self.args.all_services:
            selected = [
                service
                for service in services.items
                if (
                    (
                        self.args.service_type is not None
                        and service.spec.type.lower() == self.args.service_type
                    )
                    or (
                        self.args.service_type is None
                        and service.spec.type.lower() in ["nodeport", "loadbalancer"]
                    )
                )
                and (
                    self.args.all_services
                    or service.metadata.name in self.args.service_names
                )
            ]
        else:
            for service_name in self.args.service_names:
                try:
                    service = self.kubeclient.read_namespaced_service(
                        service_name, self.args.namespace
                    )
                except kubernetes.client.exceptions.ApiException as err:
                    if err.status == 404:
                        raise CommandError(_(f"ERROR: no service named {service_name}"))
                    raise err

                if service.spec.type.lower() not in ["loadbalancer", "nodeport"]:
                    raise CommandError(
                        f"ERROR: you can only forward NodePort and LoadBalancer services, service {service_name} is of type {service.spec.type}"
                    )

                selected.append(service)

        return selected
