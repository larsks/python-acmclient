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

from dataclasses import dataclass
from enum import StrEnum

from osc_lib.exceptions import CommandError
from osc_lib.command import command
from osc_lib.i18n import _  # noqa
from typing import override

from acmclient import kubehelper
from acmclient import openstack_helpers

LOG = logging.getLogger(__name__)


class Protocol(StrEnum):
    TCP = "tcp"
    UDP = "udp"


@dataclass
class PortForward:
    internal_ip: ipaddress.IPv4Address | ipaddress.IPv6Address
    internal_port: int
    external_ip: ipaddress.IPv4Address | ipaddress.IPv6Address
    external_port: int
    protocol: Protocol = Protocol.TCP

    @classmethod
    def from_spec(cls, spec: str):
        if "/" in spec:
            spec, protocol = spec.split("/")
        else:
            protocol = "tcp"

        parts = spec.split(":")
        if len(parts) < 3 or len(parts) > 4:
            raise ValueError("invalid port forward specification")

        internal_ip, internal_port, external_ip = parts[:3]
        if len(parts) == 4:
            external_port = parts[3]
        else:
            external_port = internal_port

        return cls(
            internal_ip=ipaddress.ip_address(internal_ip),
            internal_port=int(internal_port),
            external_ip=ipaddress.ip_address(external_ip),
            external_port=int(external_port),
            protocol=Protocol(protocol),
        )


class PortForwardPurge(command.Lister):
    @override
    def get_parser(self, prog_name: str) -> argparse.ArgumentParser:
        parser = super().get_parser(prog_name)

        parser.add_argument(
            "--port",
            "-p",
            action="append",
            default=[],
            help="Delete only port forwards with this internal port",
        )

        parser.add_argument(
            "floating_ips",
            nargs="*",
            help=_("List of floating ips from which to remove port forwardings"),
        )

        return parser

    @override
    def take_action(self, parsed_args: argparse.Namespace):
        osnetwork = openstack_helpers.Network(self.app.client_manager.sdk_connection)
        forwards = []
        for ipaddr in parsed_args.floating_ips:
            fip = osnetwork.find_floating_ip(ipaddr)
            forwards.extend(
                (ipaddr, fip, fwd)
                for fwd in osnetwork.connection.network.floating_ip_port_forwardings(
                    fip
                )
            )

        for ipaddr, fip, fwd in forwards:
            LOG.info(
                "delete port forward %s %s:%d -> %s:%d",
                fwd.id,
                fwd.internal_ip_address,
                fwd.internal_port,
                fip.floating_ip_address,
                fwd.external_port,
            )
            osnetwork.connection.network.delete_floating_ip_port_forwarding(fip, fwd)

        return ["ID", "Port", "Protocol", "Internal IP", "External IP"], [
            [
                fwd[2].id,
                fwd[2].internal_port,
                fwd[2].protocol,
                fwd[2].internal_ip_address,
                fwd[0],
            ]
            for fwd in forwards
        ]


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
        osnetwork = openstack_helpers.Network(self.app.client_manager.sdk_connection)

        if not parsed_args.service_names and not parsed_args.all_services:
            raise CommandError(
                "ERROR: you must either provide a list of services or --all"
            )

        self.kubeclient = kubehelper.get_corev1_client(
            config_file=parsed_args.kubeconfig, context=parsed_args.context
        )

        services = self.select_services(
            namespace=parsed_args.namespace,
            all_services=parsed_args.all_services,
            service_type=parsed_args.service_type,
            service_names=parsed_args.service_names,
        )
        LOG.debug(
            "found services: %s",
            ",".join([service.metadata.name for service in services]),
        )

        fip = osnetwork.find_or_create_floating_ip(
            parsed_args.external_ip, external_ip_network=parsed_args.external_ip_network
        )
        LOG.debug("using floating ip address %s", fip)

        forwards = []
        for service in services:
            if service.spec.type == "LoadBalancer":
                target_ip = service.status.loadBalancer.ingress[0].ip
            elif parsed_args.internal_ip is not None:
                target_ip = parsed_args.internal_ip
            else:
                raise CommandError(
                    f"{service.metadata.name} is a {service.spec.type} service and you have not set --internal-ip"
                )

            internal_port = osnetwork.find_or_create_port(
                target_ip,
                internal_ip_network=parsed_args.internal_ip_network,
                internal_ip_subnet=parsed_args.internal_ip_subnet,
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
                    "create port forward %s:%s -> %s:%s for service %s",
                    parsed_args.internal_ip,
                    target_port,
                    fip.floating_ip_address,
                    target_port,
                    service.metadata.name,
                )

                fwd = self.app.client_manager.sdk_connection.network.create_floating_ip_port_forwarding(
                    fip,
                    internal_ip_address=parsed_args.internal_ip,
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

    def select_services(
        self, namespace=None, all_services=False, service_type=None, service_names=None
    ):
        namespace = kubehelper.current_namespace() if namespace is None else namespace
        services = self.kubeclient.list_namespaced_service(namespace)
        selected = []

        if all_services:
            selected = [
                service
                for service in services.items
                if (
                    (
                        service_type is not None
                        and service.spec.type.lower() == service_type
                    )
                    or (
                        service_type is None
                        and service.spec.type.lower() in ["nodeport", "loadbalancer"]
                    )
                )
                and (all_services or service.metadata.name in service_names)
            ]
        else:
            for service_name in service_names:
                try:
                    service = self.kubeclient.read_namespaced_service(
                        service_name, namespace
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


class PortForwardCreate(command.Lister):
    @override
    def get_parser(self, prog_name: str) -> argparse.ArgumentParser:
        parser = super().get_parser(prog_name)

        parser.add_argument(
            "--internal-ip-network",
            help=_("Network from which to allocate ports for internal ips"),
        )
        parser.add_argument(
            "--internal-ip-subnet",
            help=_("Subnet from which to allocate ports for internal ips"),
        )
        parser.add_argument(
            "--external-ip-network",
            default="external",
            help=_("Network from which to allocate floating ips"),
        )
        parser.add_argument("fwdspec", nargs="+")

        return parser

    @override
    def take_action(self, parsed_args: argparse.Namespace):
        osnetwork = openstack_helpers.Network(self.app.client_manager.sdk_connection)

        forwards = []
        for spec in parsed_args.fwdspec:
            parsed_spec = PortForward.from_spec(spec)

            fip = osnetwork.find_floating_ip(str(parsed_spec.external_ip))
            if fip is None:
                raise CommandError(
                    f"ERROR: unable to find floating ip {parsed_spec.external_ip}"
                )

            internal_port = osnetwork.find_or_create_port(
                str(parsed_spec.internal_ip),
                internal_ip_network=parsed_args.internal_ip_network,
                internal_ip_subnet=parsed_args.internal_ip_subnet,
            )
            LOG.debug("using port %s", internal_port)

            LOG.info(
                "create port forward %s:%s -> %s:%s",
                parsed_spec.internal_ip,
                parsed_spec.internal_port,
                fip.floating_ip_address,
                parsed_spec.external_port,
            )

            fwd = self.app.client_manager.sdk_connection.network.create_floating_ip_port_forwarding(
                fip,
                internal_ip_address=str(parsed_spec.internal_ip),
                internal_port=parsed_spec.internal_port,
                internal_port_id=internal_port.id,
                external_port=parsed_spec.external_port,
                protocol=parsed_spec.protocol.value,
            )
            forwards.append((fip, fwd))

        return ["ID", "Port", "Protocol", "Internal IP", "External IP"], [
            [
                fwd[1].id,
                fwd[1].internal_port,
                fwd[1].protocol,
                fwd[1].internal_ip_address,
                fwd[0].floating_ip_address,
            ]
            for fwd in forwards
        ]
