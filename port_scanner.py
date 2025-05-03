import socket
from common_ports import ports_and_services
import ipaddress

def get_open_ports(target, port_range, verbose = False):
    open_ports = []
    # Supplying a raw and valid IP to socket.connect_ex() is more efficient
    # This try block checks if target is a valid IP or hostname
    try:
        target_ip = str(ipaddress.ip_address(target))
        # Try and acquire a hostname via the IP
        try:
            target_hostname, _, _ = socket.gethostbyaddr(target_ip)
        except socket.herror:
            target_hostname = None
    except ValueError:
        if all(char.isdigit() for char in target.split(".")):
            return f"Error: Invalid IP address"
        else:
        # Not a raw IP, try hostname:
            try:
                target_ip = socket.gethostbyname(target)
                target_hostname = target
            except socket.gaierror:
                return f"Error: Invalid hostname"
 
    # Print a message that the scan has begun
    print(f"Scanning port range {port_range[0]}-{port_range[1]}...")

    # The port scanning part (range is inclusive)
    for port in range(port_range[0]-1, port_range[1]+1):
        # Create a socket and set timeout           
        sckt = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sckt.settimeout(0.25)

        # connect_ex returns 0 on success
        result = sckt.connect_ex((target_ip, port))
        open_ports.append(port) if result == 0 else None
        sckt.close()

    # If verbose output is set to True
    if verbose:
        if target_hostname is None:
            open_ports_verbose = [f"Open ports for {target_ip}\nPORT     SERVICE"]
        else:
            open_ports_verbose = [f"Open ports for {target_hostname} ({target_ip})\nPORT     SERVICE"]
        # Compute the necessary strings
        for port in open_ports:
            service = ports_and_services.get(port, "unknown")
            open_ports_verbose.append(f"{port:<4}     {service}")
        # Return the computed strings alongside new lines
        return "\n".join(open_ports_verbose)

    return open_ports
    