#!/usr/bin/env python3

'''
Basic IPv4 router (static routing) in Python.
'''

import time
import switchyard
from switchyard.lib.packet import *
from switchyard.lib.address import *
from switchyard.lib.userlib import *

class ArpQueueEntry:
    def __init__(self, packet, next_hop, out_iface, timestamp):
        self.packet = packet        # 待发送的IP包
        self.next_hop = next_hop    # 下一跳的IP地址
        self.out_iface = out_iface  # 转发的接口名称
        self.timestamp = timestamp  # 发送时间戳
        self.retry_count = 0        # 重试次数

class Router(object):
    MAX_ARP_RETRIES = 4  # 最多ARP重试次数
    ARP_TIMEOUT = 1.5    # ARP超时时间为1.5秒
    ARP_CACHE_TIMEOUT = 100.0  # ARP缓存超时为100秒

    def __init__(self, net: switchyard.llnetbase.LLNetBase):
        self.net = net
        self.forwarding_table = self.build_forwarding_table()
        self.arp_table = {}  # IP -> (MAC, timestamp)
        self.arp_queue = []  # 等待ARP解析的包队列

    def build_forwarding_table(self):
        '''从文件和路由器接口构建转发表'''
        forwarding_table = []

        # 从路由器接口添加直连网络
        for intf in self.net.interfaces():
            net_addr = IPv4Address(intf.ipaddr)
            net_mask = IPv4Address(intf.netmask)
            forwarding_table.append((net_addr, net_mask, None, intf.name))

        # 从文件读取转发表项
        with open('forwarding_table.txt', 'r') as f:
            for line in f:
                parts = line.strip().split()
                net_addr, net_mask, next_hop, out_iface = parts
                forwarding_table.append((IPv4Address(net_addr), IPv4Address(net_mask), IPv4Address(next_hop), out_iface))

        return forwarding_table

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

        if best_entry:
            log_info(f"Forwarding table match: {ip_addr} -> {best_entry}")
        else:
            log_info(f"No match in forwarding table for {ip_addr}")
        
        return best_entry

    def check_arp_queue(self):
        '''检查ARP队列中是否有超时的项并重试ARP请求'''
        current_time = time.time()
        for entry in self.arp_queue:
            if current_time - entry.timestamp >= self.ARP_TIMEOUT:
                if entry.retry_count < self.MAX_ARP_RETRIES:
                    log_info(f"Retrying ARP request for {entry.next_hop} (Attempt {entry.retry_count + 1})")
                    self.send_arp_request(entry.next_hop, entry.out_iface)
                    entry.retry_count += 1
                    entry.timestamp = current_time
                else:
                    log_info(f"Max ARP retries reached for {entry.next_hop}. Dropping packet.")
                    self.arp_queue.remove(entry)

    def check_arp_cache(self):
        '''定期检查ARP缓存表，移除超时的ARP条目'''
        current_time = time.time()
        for ip, (mac, timestamp) in list(self.arp_table.items()):
            if current_time - timestamp >= self.ARP_CACHE_TIMEOUT:
                log_info(f"ARP cache entry for {ip} expired. Removing from cache.")
                del self.arp_table[ip]

    def send_arp_request(self, ip: IPv4Address, ifaceName: str):
        '''发送ARP请求'''
        intf = self.net.interface_by_name(ifaceName)
        arp_request = create_ip_arp_request(intf.ethaddr, intf.ipaddr, ip)
        self.net.send_packet(ifaceName, arp_request)
        log_info(f"Sent ARP request for {ip} on {ifaceName}")

    def send_arp_reply(self, arp: Arp, ifaceName: str, intf: Interface):
        '''发送ARP回复'''
        arp_reply = create_ip_arp_reply(intf.ethaddr, arp.senderhwaddr, intf.ipaddr, arp.senderprotoaddr)
        self.net.send_packet(ifaceName, arp_reply)
        log_info(f"Sent ARP reply to {arp.senderprotoaddr} on {ifaceName}")

    def send_packet_with_arp(self, packet, next_hop_mac, out_iface):
        '''构造以太网报头并发送数据包'''
        eth = packet.get_header(Ethernet)
        ip = packet.get_header(IPv4)

        eth.src = self.net.interface_by_name(out_iface).ethaddr
        eth.dst = next_hop_mac
        self.net.send_packet(out_iface, packet)
        log_info(f"Packet sent to {ip.dst} via {out_iface} with next hop MAC {next_hop_mac}")

    def process_arp_queue(self, ip_addr: IPv4Address):
        '''处理ARP队列中等待解析的包'''
        for entry in self.arp_queue:
            if entry.next_hop == ip_addr:
                log_info(f"Processing queued packet for {ip_addr}. Sending.")
                next_hop_mac, _ = self.arp_table[ip_addr]
                self.send_packet_with_arp(entry.packet, next_hop_mac, entry.out_iface)
                self.arp_queue.remove(entry)

    def handle_packet(self, recv: switchyard.llnetbase.ReceivedPacket):
        timestamp, ifaceName, packet = recv
        log_info(f"Received packet on {ifaceName}: {packet}")

        eth = packet.get_header(Ethernet)
        if eth is None:
            log_info("Received a non-Ethernet packet. Dropping.")
            return

        # 处理ARP包
        arp = packet.get_header(Arp)
        if arp is not None:
            if arp.operation == ArpOperation.Request:
                # 检查请求的目标IP是否是路由器接口的IP
                for intf in self.net.interfaces():
                    if arp.targetprotoaddr == intf.ipaddr:
                        log_info(f"Received ARP request for {arp.targetprotoaddr}. Sending ARP reply.")
                        self.send_arp_reply(arp, ifaceName, intf)
                        return
            elif arp.operation == ArpOperation.Reply:
                log_info(f"Received ARP reply from {arp.senderprotoaddr}. Updating ARP cache.")
                self.arp_table[arp.senderprotoaddr] = (arp.senderhwaddr, time.time())
                self.process_arp_queue(arp.senderprotoaddr)
                return

        # 处理IP包
        ip = packet.get_header(IPv4)
        if ip is None:
            log_info("Not an IP packet. Dropping.")
            return

        # 检查TTL字段并减1
        ip.ttl -= 1
        log_info(f"Decremented TTL to {ip.ttl}")

        # 检查数据包是否是发给路由器自己的
        for intf in self.net.interfaces():
            if ip.dst == intf.ipaddr:
                log_info(f"Packet is for the router itself. Dropping.")
                return

        # 执行转发表查找并处理
        matched_entry = self.lookup_forwarding_table(ip.dst)
        if matched_entry is None:
            log_info(f"No matching route found for IP {ip.dst}. Dropping packet.")
            return

        next_hop, out_iface = matched_entry
        if next_hop is None:
            next_hop = ip.dst

        if next_hop in self.arp_table:
            next_hop_mac, _ = self.arp_table[next_hop]
            self.send_packet_with_arp(packet, next_hop_mac, out_iface)
        else:
            log_info(f"ARP resolution needed for {next_hop}. Sending ARP request and adding to queue.")
            self.send_arp_request(next_hop, out_iface)
            entry = ArpQueueEntry(packet, next_hop, out_iface, time.time())
            self.arp_queue.append(entry)

    def start(self):
        '''运行路由器，持续接收和处理数据包'''
        while True:
            try:
                recv = self.net.recv_packet(timeout=self.ARP_TIMEOUT)
            except NoPackets:
                 # 每次循环都检查ARP队列是否需要重发请求
                self.check_arp_queue()
                continue
            except Shutdown:
                break

            self.handle_packet(recv)
             # 每次处理完包后也检查是否需要重发ARP请求
            self.check_arp_queue()

        self.stop()

    def stop(self):
        self.net.shutdown()

def main(net):
    '''路由器的主入口'''
    router = Router(net)
    router.start()
