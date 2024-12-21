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

from dataclasses import dataclass, field

from osc_lib.exceptions import CommandError
from osc_lib.command import command
from osc_lib.i18n import _
from typing import override

from acmclient import kubehelper

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


class PortForwardService(command.Command):
    def get_parser(self, prog_name: str) -> None:
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
        self.args = args = PortForwardArgs(**vars(parsed_args))
        self.network = None
        self.subnet = None

        if not args.service_names and not args.all_services:
            raise CommandError(
                _("ERROR: you must either provide a list of services or --all")
            )

        self.kubeclient = kubehelper.get_corev1_client(
            config_file=args.kubeconfig, context=args.context
        )

        services = self.select_services()
        print("found services", [service.metadata.name for service in services])

        for service in services:
            if service.spec.type == "LoadBalancer":
                target_ip = service.status.loadBalancer.ingress[0].ip
            elif self.args.internal_ip is not None:
                target_ip = self.args.internal_ip
            else:
                raise CommandError(
                    _(
                        f"{service.metadata.name} is a {service.spec.type} service and you have not set --internal-ip"
                    )
                )

            port = self.find_or_create_port(
                target_ip, f"service:{service.metadata.name}"
            )
            print("got port:", port)

    def find_or_create_port(self, ipaddr: str, description=None):
        conn = self.app.client_manager.sdk_connection
        ports = list(conn.network.ports(fixed_ips=f"ip_address={ipaddr}"))
        if len(ports) == 1:
            port = ports[0]
            LOG.info(f"using existing port {port.id} for address {ipaddr}")
            return port
        elif len(ports) > 1:
            raise CommandError(_(f"ERROR: found multiple ports with address {ipaddr}"))

        if self.network is None:
            if self.args.internal_ip_network is None:
                raise CommandError(
                    _(
                        "ERROR: unable to create a port because --internal-ip-network is unset"
                    )
                )

            network = conn.network.find_network(self.args.internal_ip_network)
            if network is None:
                raise CommandError(
                    _(f"ERROR: unable to find network {self.args.internal_ip_network}")
                )

            self.network = network

        assert self.network is not None
        if self.subnet is None:
            if self.args.internal_ip_subnet:
                subnet = conn.network.find_subnet(self.args.internal_ip_subnet)
                if subnet is None:
                    raise CommandError(
                        _(
                            f"ERROR: unable to find subnet {self.args.internal_ip_subnet}"
                        )
                    )
            else:
                _ipaddr = ipaddress.ip_address(ipaddr)
                for subnet in conn.network.subnets(network_id=self.network.id):
                    if subnet.ip_version != _ipaddr.version:
                        continue
                    cidr = ipaddress.ip_network(subnet.cidr)
                    if _ipaddr in cidr:
                        break
                else:
                    raise CommandError(
                        _(f"ERROR: unable to find a subnet for address {ipaddr}")
                    )

                LOG.debug(f"found subnet {subnet.id} for address {ipaddr}")
                self.subnet = subnet

        assert self.subnet is not None
        port = conn.network.create_port(
            name=description,
            network_id=self.network.id,
            fixed_ips=[{"subnet_id": self.subnet.id, "ip_address": ipaddr}],
        )
        LOG.info(
            f"created port {port.id} in subnet {self.subnet.name} for address {ipaddr}"
        )
        return port

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
