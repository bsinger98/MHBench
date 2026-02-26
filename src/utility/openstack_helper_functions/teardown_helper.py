from concurrent.futures import ThreadPoolExecutor, as_completed

import openstack
from openstack.exceptions import SDKException


# Deleting instances
def delete_instances(conn):
    servers = conn.list_servers()
    for server in servers:
        current_sgs = server.security_groups

        if current_sgs:
            # Remove each security group from the server
            for sg in current_sgs:
                # Debug the structure of each security group object
                sg_name = sg.get("id")
                if sg_name:
                    conn.remove_server_security_groups(server, sg_name)

        conn.delete_server(server.id)


# Deleting floating ips
def delete_floating_ips(conn):
    floating_ips = conn.list_floating_ips()
    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = [executor.submit(conn.delete_floating_ip, fip.id) for fip in floating_ips]
        for future in as_completed(futures):
            try:
                future.result()
            except SDKException:
                pass


# Delete routers
def delete_routers(conn):
    # Fetch all router-interface ports once instead of once per router
    router_interface_ports = [
        p for p in conn.list_ports()
        if p.device_owner == "network:router_interface"
    ]
    for router in conn.list_routers():
        for port in router_interface_ports:
            subnet_id = port.fixed_ips[0]["subnet_id"]
            try:
                conn.remove_router_interface(router, subnet_id=subnet_id)
            except SDKException:
                print(
                    f"Error removing router interface {subnet_id} from router {router.id}"
                )
                continue

        # Finally, delete the router
        conn.delete_router(router.id)


# Delete all ports
def delete_ports(conn):
    ports = conn.list_ports()
    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = [executor.submit(conn.delete_port, port.id) for port in ports]
        for future in as_completed(futures):
            try:
                future.result()
            except SDKException:
                pass


subnet_exclude_list = [
    "shared-subnet",
    "external",
    "ext-subnet",
    "public-subnet",
    "ipv6-public-subnet",
]


def delete_subnets(conn):
    subnets = [s for s in conn.list_subnets() if s.name not in subnet_exclude_list]
    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = [executor.submit(conn.delete_subnet, subnet.id) for subnet in subnets]
        for future in as_completed(futures):
            try:
                future.result()
            except SDKException:
                pass


network_exclude_list = ["shared", "external", "public"]


def delete_networks(conn):
    networks = [n for n in conn.list_networks() if n.name not in network_exclude_list]
    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = [executor.submit(conn.delete_network, network.id) for network in networks]
        for future in as_completed(futures):
            try:
                future.result()
            except SDKException:
                pass


security_group_exclude_list = ["default"]


def delete_security_groups(conn):
    security_groups = [sg for sg in conn.list_security_groups() if sg.name not in security_group_exclude_list]
    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = [executor.submit(conn.delete_security_group, sg.id) for sg in security_groups]
        for future in as_completed(futures):
            try:
                future.result()
            except SDKException:
                pass
