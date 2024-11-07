#!/usr/bin/env python3

'''
Basic IPv4 router (static routing) in Python.
'''

import switchyard
from switchyard.lib.userlib import *
import time
import os

class Router(object):
    def __init__(self, net: switchyard.llnetbase.LLNetBase):
        self.net = net
        # 路由表，键是 (网络前缀, 子网掩码)，值是 (下一跳IP, 接口名称)
        self.forwarding_table = []
        # 存储接口的IP地址和MAC地址
        self.interfaces = { intf.ipaddr: intf.ethaddr for intf in self.net.interfaces() }
        # ARP表缓存，键为IP地址，值为 (MAC地址, 时间戳)
        self.arp_table = {}
        # ARP缓存条目的超时时间，单位为秒
        self.arp_timeout = 100  # 超时100秒

        # 初始化转发表
        self.init_forwarding_table()

    def init_forwarding_table(self):
        '''初始化转发表，包括接口列表和forwarding_table.txt中的条目'''
        # 从路由器接口中构建直接连接的网络条目
        for intf in self.net.interfaces():
            net_prefix = IPv4Network(f"{intf.ipaddr}/{intf.netmask}", strict=False)
            self.forwarding_table.append((net_prefix.network_address, net_prefix.netmask, None, intf.name))
        
        # 从 forwarding_table.txt 中读取转发表
        if os.path.exists('forwarding_table.txt'):
            with open('forwarding_table.txt', 'r') as f:
                for line in f:
                    net_addr, net_mask, next_hop, out_iface = line.strip().split()
                    net_addr = IPv4Address(net_addr)
                    net_mask = IPv4Address(net_mask)
                    next_hop = None if next_hop == '-' else IPv4Address(next_hop)
                    self.forwarding_table.append((net_addr, net_mask, next_hop, out_iface))

        log_info("Forwarding table initialized:")
        for entry in self.forwarding_table:
            log_info(f"Network: {entry[0]} Mask: {entry[1]} Next hop: {entry[2]} Interface: {entry[3]}")

    def handle_packet(self, recv: switchyard.llnetbase.ReceivedPacket):
        timestamp, ifaceName, packet = recv
        log_info(f"Received packet on {ifaceName}: {packet}")

        eth = packet.get_header(Ethernet)
        if eth is None:
            log_info("Received a non-Ethernet packet. Dropping.")
            return

        # 检查以太网目的地址是否为广播地址或者路由器的MAC地址
        if eth.dst != self.net.interface_by_name(ifaceName).ethaddr and not eth.dst.is_broadcast:
            log_info("Ethernet destination address is not broadcast or router's MAC. Dropping packet.")
            return

        # 检查是否是IP包
        ip = packet.get_header(IPv4)
        if ip is None:
            log_info("Not an IP packet. Dropping.")
            return

        # 如果数据包的目的地址是路由器的某个接口IP，丢弃该包
        if ip.dst in self.interfaces:
            log_info(f"Packet is addressed to the router itself ({ip.dst}). Dropping.")
            return

        # 转发表最长前缀匹配
        matched_entry = self.lookup_forwarding_table(ip.dst)
        if matched_entry is None:
            log_info(f"No matching route found for IP {ip.dst}. Dropping packet.")
            return

        next_hop, out_iface = matched_entry
        if next_hop is None:
            next_hop = ip.dst

        log_info(f"Forwarding packet to next hop {next_hop} via interface {out_iface}")

        # 获取ARP条目
        if next_hop in self.arp_table:
            next_hop_mac, _ = self.arp_table[next_hop]
        else:
            # 如果ARP表中没有，发送ARP请求
            self.send_arp_request(next_hop, out_iface)
            log_info(f"ARP request sent for {next_hop}. Dropping packet temporarily.")
            return

        # 修改以太网目的地址为下一跳MAC地址，并通过正确的接口转发
        eth.dst = next_hop_mac
        eth.src = self.net.interface_by_name(out_iface).ethaddr
        self.net.send_packet(out_iface, packet)

    def send_arp_request(self, ip: IPv4Address, ifaceName: str):
        '''发送ARP请求'''
        intf = self.net.interface_by_name(ifaceName)
        arp_request = create_ip_arp_request(intf.ethaddr, intf.ipaddr, ip)
        self.net.send_packet(ifaceName, arp_request)
        log_info(f"Sent ARP request for {ip} on {ifaceName}")

    def send_arp_reply(self, arp: Arp, ifaceName: str):
        '''生成并发送ARP响应包'''
        try:
            target_mac = self.interfaces[arp.targetprotoaddr]
        except KeyError:
            log_info(f"No interface with IP {arp.targetprotoaddr} found.")
            return

        reply = create_ip_arp_reply(target_mac, arp.senderhwaddr, arp.targetprotoaddr, arp.senderprotoaddr)
        log_info(f"Sending ARP reply: {reply}")

        self.net.send_packet(ifaceName, reply)

    def update_arp_table(self, ip: IPv4Address, mac: EthAddr):
        '''更新ARP表，记录时间戳，并检查超时条目'''
        current_time = time.time()

        # 更新ARP表缓存，记录MAC地址和当前时间戳
        self.arp_table[ip] = (mac, current_time)
        log_info(f"Updated ARP table: {ip} -> {mac} at time {current_time}")

        # 打印当前的ARP表
        self.print_arp_table()

        # 清除超时的ARP表条目
        self.clear_arp_table()

    def clear_arp_table(self):
        '''清除超过超时时间的ARP表条目'''
        current_time = time.time()
        to_remove = []

        # 找出超时的条目
        for ip, (mac, timestamp) in self.arp_table.items():
            if current_time - timestamp > self.arp_timeout:
                to_remove.append(ip)

        # 移除超时条目
        for ip in to_remove:
            log_info(f"Removing ARP table entry: {ip} -> {self.arp_table[ip][0]} due to timeout.")
            del self.arp_table[ip]

    def print_arp_table(self):
        '''打印ARP表的当前内容'''
        log_info("Current ARP Table:")
        for ip, (mac, timestamp) in self.arp_table.items():
            log_info(f"{ip} -> {mac} (added at {timestamp})")

    def lookup_forwarding_table(self, ip_addr: IPv4Address):
        '''执行最长前缀匹配来查找转发表中的合适条目'''
        longest_prefix = None
        best_entry = None

        for net_addr, net_mask, next_hop, out_iface in self.forwarding_table:
            network = IPv4Network(f"{net_addr}/{net_mask}", strict=False)
            if ip_addr in network:
                if longest_prefix is None or network.prefixlen > longest_prefix:
                    longest_prefix = network.prefixlen
                    best_entry = (next_hop, out_iface)

        return best_entry

    def start(self):
        '''A running daemon of the router.'''
        while True:
            try:
                recv = self.net.recv_packet(timeout=1.0)
            except NoPackets:
                continue
            except Shutdown:
                break

            self.handle_packet(recv)

        self.stop()

    def stop(self):
        self.net.shutdown()

def main(net):
    '''Main entry point for router.'''
    router = Router(net)
    router.start()
