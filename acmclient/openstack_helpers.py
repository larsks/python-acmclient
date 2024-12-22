import logging
import ipaddress

import openstack.network.v2.floating_ip
import openstack.network.v2.port
import openstack.connection

from functools import cache

LOG = logging.getLogger(__name__)


class NetworkError(Exception):
    pass


class Network:
    def __init__(self, connection: openstack.connection.Connection):
        self.connection: openstack.connection.Connection = connection

    @cache
    def find_network(self, name_or_id: str):
        return self.connection.network.find_network(name_or_id)

    @cache
    def find_subnet(self, name_or_id: str):
        return self.connection.network.find_subnet(name_or_id)

    @cache
    def find_floating_ip(self, name_or_id: str):
        return self.connection.network.find_ip(name_or_id)

    def find_or_create_floating_ip(
        self,
        ipaddr: str | None = None,
        external_ip_network: str | None = None,
    ) -> openstack.network.v2.floating_ip.FloatingIP:
        conn = self.connection

        if ipaddr is not None:
            fip: openstack.network.v2.floating_ip.FloatingIP | None = (
                conn.network.find_ip(ipaddr)
            )
            if fip is not None:
                return fip

        if external_ip_network is None:
            raise NetworkError(
                "unable to create floating ip because --external-ip-network is unset"
            )

        network = self.find_network(external_ip_network)
        if network is None:
            raise NetworkError(
                "unable to find floating ip network {external_ip_network}"
            )

        fip = conn.network.create_ip(
            floating_network_id=network.id, floating_ip_address=ipaddr
        )
        if fip is None:
            raise NetworkError(
                f"ERROR: failed to create floating ip in network {external_ip_network}"
            )

        return fip

    def find_or_create_port(
        self,
        ipaddr: str,
        internal_ip_network: str | None = None,
        internal_ip_subnet: str | None = None,
        description: str | None = None,
    ) -> openstack.network.v2.port.Port:
        conn = self.connection
        port = next(conn.network.ports(fixed_ips=f"ip_address={ipaddr}"), None)
        if port is not None:
            LOG.info(f"using existing port {port.id} for address {ipaddr}")
            return port

        if internal_ip_network is None:
            raise NetworkError(
                "ERROR: unable to create a port because --internal-ip-network is unset"
            )

        network = self.find_network(internal_ip_network)
        if network is None:
            raise NetworkError(f"ERROR: unable to find network {internal_ip_network}")

        if internal_ip_subnet:
            subnet = conn.network.find_subnet(internal_ip_subnet)
            if subnet is None:
                raise NetworkError(f"ERROR: unable to find subnet {internal_ip_subnet}")
        else:
            _ipaddr = ipaddress.ip_address(ipaddr)
            for subnet in conn.network.subnets(network_id=network.id):
                if subnet.ip_version != _ipaddr.version:
                    continue
                cidr = ipaddress.ip_network(subnet.cidr)
                if _ipaddr in cidr:
                    break
            else:
                raise NetworkError(
                    f"ERROR: unable to find a subnet for address {ipaddr}"
                )

        LOG.debug(f"using subnet {subnet.id} for address service_namesipaddr")

        port = conn.network.create_port(
            network_id=network.id,
            fixed_ips=[{"subnet_id": subnet.id, "ip_address": ipaddr}],
        )
        LOG.info(f"create port {port.id} in subnet {subnet.name} for address {ipaddr}")
        return port
