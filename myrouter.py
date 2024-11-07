#!/usr/bin/env python3

'''
Basic IPv4 router (static routing) in Python.
'''

import switchyard
from switchyard.lib.userlib import *
import time
import os

class ArpQueueEntry:
    '''表示一个等待ARP解析的数据包'''
    def __init__(self, packet, next_hop_ip, out_iface, timestamp):
        self.packet = packet  # 等待转发的IP数据包
        self.next_hop_ip = next_hop_ip  # 下一跳的IP地址
        self.out_iface = out_iface  # 发送该包的接口
        self.timestamp = timestamp  # 最近一次发送ARP请求的时间
        self.retries = 0  # 已经发送的ARP请求次数

class Router(object):
    def __init__(self, net: switchyard.llnetbase.LLNetBase):
        self.net = net
        self.forwarding_table = []
        self.interfaces = { intf.ipaddr: intf.ethaddr for intf in self.net.interfaces() }
        self.arp_table = {}
        self.arp_timeout = 100  # ARP表超时100秒
        self.arp_queue = []  # 等待ARP解析的数据包队列
        self.arp_request_interval = 1.0  # 1秒发送一次ARP请求
        self.arp_max_retries = 5  # 最多重试5次ARP请求

        self.init_forwarding_table()

    def init_forwarding_table(self):
        '''初始化转发表'''
        for intf in self.net.interfaces():
            net_prefix = IPv4Network(f"{intf.ipaddr}/{intf.netmask}", strict=False)
            self.forwarding_table.append((net_prefix.network_address, net_prefix.netmask, None, intf.name))

        if os.path.exists('forwarding_table.txt'):
            with open('forwarding_table.txt', 'r') as f:
                for line in f:
                    net_addr, net_mask, next_hop, out_iface = line.strip().split()
                    net_addr = IPv4Address(net_addr)
                    net_mask = IPv4Address(net_mask)
                    next_hop = None if next_hop == '-' else IPv4Address(next_hop)
                    self.forwarding_table.append((net_addr, net_mask, next_hop, out_iface))

    def handle_packet(self, recv: switchyard.llnetbase.ReceivedPacket):
        timestamp, ifaceName, packet = recv
        log_info(f"Received packet on {ifaceName}: {packet}")

        eth = packet.get_header(Ethernet)
        if eth is None:
            log_info("Received a non-Ethernet packet. Dropping.")
            return

        if eth.dst != self.net.interface_by_name(ifaceName).ethaddr and not eth.dst.is_broadcast:
            log_info("Ethernet destination address is not broadcast or router's MAC. Dropping packet.")
            return

        ip = packet.get_header(IPv4)
        if ip is None:
            log_info("Not an IP packet. Dropping.")
            return

        if ip.dst in self.interfaces:
            log_info(f"Packet is addressed to the router itself ({ip.dst}). Dropping.")
            return

        ip.ttl -= 1  # 递减TTL字段
        log_info(f"Decremented TTL to {ip.ttl}")

        matched_entry = self.lookup_forwarding_table(ip.dst)
        if matched_entry is None:
            log_info(f"No matching route found for IP {ip.dst}. Dropping packet.")
            return

        next_hop, out_iface = matched_entry
        if next_hop is None:
            next_hop = ip.dst

        if next_hop in self.arp_table:
            next_hop_mac, _ = self.arp_table[next_hop]
            self.send_packet_with_arp(eth, ip, next_hop_mac, out_iface)
        else:
            log_info(f"ARP resolution needed for {next_hop}. Sending ARP request and adding to queue.")
            self.send_arp_request(next_hop, out_iface)
            entry = ArpQueueEntry(packet, next_hop, out_iface, time.time())
            self.arp_queue.append(entry)

    def send_packet_with_arp(self, eth, ip, next_hop_mac, out_iface):
        '''构造以太网报头并发送数据包'''
        eth.src = self.net.interface_by_name(out_iface).ethaddr
        eth.dst = next_hop_mac
        self.net.send_packet(out_iface, eth + ip)
        log_info(f"Packet sent to {ip.dst} via {out_iface}")

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
        '''更新ARP表，记录时间戳'''
        current_time = time.time()
        self.arp_table[ip] = (mac, current_time)
        log_info(f"Updated ARP table: {ip} -> {mac} at time {current_time}")

        # 处理等待队列中的数据包
        self.handle_queued_packets(ip, mac)

    def handle_queued_packets(self, ip: IPv4Address, mac: EthAddr):
        '''处理等待队列中等待ARP解析的数据包'''
        for entry in self.arp_queue:
            if entry.next_hop_ip == ip:
                self.send_packet_with_arp(entry.packet.get_header(Ethernet), entry.packet.get_header(IPv4), mac, entry.out_iface)
        # 移除已经处理的条目
        self.arp_queue = [entry for entry in self.arp_queue if entry.next_hop_ip != ip]

    def process_arp_queue(self):
        '''处理等待ARP响应的队列'''
        current_time = time.time()
        for entry in self.arp_queue:
            if current_time - entry.timestamp > self.arp_request_interval:
                if entry.retries >= self.arp_max_retries:
                    log_info(f"Maximum ARP retries reached for {entry.next_hop_ip}. Dropping packet.")
                    self.arp_queue.remove(entry)
                else:
                    log_info(f"Retrying ARP request for {entry.next_hop_ip}. Retry count: {entry.retries}")
                    self.send_arp_request(entry.next_hop_ip, entry.out_iface)
                    entry.retries += 1
                    entry.timestamp = current_time

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
                # 处理ARP队列中的条目
                self.process_arp_queue()
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
