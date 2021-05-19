#!/bin/bash

pid="$1"

# 创建网桥
ip link add name bridge_name type bridge
# 启动网桥
ip link set dev bridge_name up
# 设置地址
ip addr add dev bridge_name 192.168.12.1/24

# 设置网络命名空间
# ip netns add ns0
ip netns attach ns0 $pid
# 设置虚拟链路
ip link add veth_name type veth peer name ethn1
# 设置veth为命名空间内部
ip link set veth_name netns ns0

# 命名空间内部设置
# 重命名
ip netns exec ns0 ip link set dev veth_name name neth0
# 启动网络
ip netns exec ns0 ip link set dev neth0 up
# 分配ip
ip netns exec ns0 ip addr add dev neth0 192.168.12.20/24
# 开启lo
ip netns exec ns0 ip link set dev lo up
# 设置路由
ip netns exec ns0 ip route add default via 192.168.12.1

# 外部设置
# 启用接口并添加到网桥
ip link set dev ethn1 promisc on
ip link set dev ethn1 up
ip link set dev ethn1 master bridge_name

# 允许接通外网
# 开启端口转发
echo 1 > /proc/sys/net/ipv4/ip_forward
# 启用iptables
iptables -t nat -A POSTROUTING -s 192.168.12.1/24 -o eth0 -j MASQUERADE
