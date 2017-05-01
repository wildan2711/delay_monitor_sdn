# Delay Monitor for Software-Defined Networking in Ryu
A delay monitoring Software-Defined Networking module using Ryu

This is an implementation of a delay monitor for Software-Defined Networks using the Ryu controller. 

You can configure the IP addresses of servers or hosts you want to monitor in the `self.server_ips` variable, and configure the edge switch connecting them in the `self.server_switch` variable.

The values of latency returned is not suitable for an absolute measurement and more suitable if you want to relatively compare between the hosts.

## Run the controller
To run the controller, use `ryu-manager --observe-links delay_monitor.py`.

## Run the example topology
To run the example topology using mininet, use `sudo python example_topo.py`.
