#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import sys
import socket
import struct
import argparse
import time
import queue
import threading
import atexit


class Color():
    """
    Linux 控制台颜色输出
    """

    def __init__(self):
        self.SUCCESS = '\033[0;32m'
        self.INFO = '\033[0;34m'
        self.WARN = '\033[0;31m'
        self.END = '\033[0m'


class Worker(threading.Thread):
    """
    子线程类模板
    """

    def __init__(self, func, args):
        super(Worker, self).__init__()
        self.func = func
        self.args = args

    def run(self):
        self.func(*self.args)


class Scanner():
    """
    扫描器对象
    """

    def __init__(self, hosts=[], ports=[], thread=1, method='TCP', timeout=1, verbose=False):
        # 扫描环境设置
        self.__hosts = hosts
        self.__ports = ports
        self.__thread = thread
        self.__method = method
        self.__verbose = verbose
        self.count = 0
        # 线程锁
        self.__lock = threading.Lock()
        # 存放主机扫描结果
        # for show_result()
        self.__host_result_queue = queue.Queue()
        # for save_result()
        self.__host_result_dict = {}
        socket.setdefaulttimeout(timeout)
        if method == 'ICMP':
            self.__ports = [98]


    def start(self, thread=None, method=None, timeout=None, verbose=False, icmp_size=56):
        """
        需在设置了 hosts & ports 后调用
        """

        # 扫描环境设置
        self.__thread = thread or self.__thread
        self.__method = method or self.__method
        self.__verbose = verbose or self.__verbose
        if timeout:
            socket.setdefaulttimeout(timeout)
        if self.__method == 'ICMP':
            self.__ports = [98]
        if not (self.__hosts and self.__ports):
            return

        # 为每个目标主机分配一个扫描线程
        task = []
        for host in self.__hosts:
            # host, ports, method, timeout,
            # res_queue, icmp_size
            t = Worker(self.host_scan, (host, self.__ports, self.__method, None,
                                        self.__host_result_queue, icmp_size))
            # 将线程设置为非阻塞
            t.daemon = True
            task.append(t)
        self.__start_thread(task, self.__thread)
        for t in task:
            t.join()
        self.__host_result_queue.put(None)
        return True


    def __start_thread(self, threads, thread):
        thread_upper = len(threads)
        next_thread = thread if thread < thread_upper else thread_upper
        active_threads = threads[:next_thread]
        for t in active_threads:
            t.start()
        while active_threads:
            for t in active_threads:
                if not t.is_alive():
                    active_threads.remove(t)
                    if next_thread < thread_upper:
                        active_threads.append(threads[next_thread])
                        threads[next_thread].start()
                        next_thread += 1


    def host_scan(self, host=None, ports=None, method=None, timeout=None,
                  res_queue=None, icmp_size=56):
        """
        针对单个 host, 对 ports 中指定的所有端口进行扫描
        """

        # 端口连接设置
        self.__method = method or self.__method
        if timeout:
            socket.setdefaulttimeout(timeout)
        if self.__method == 'ICMP':
            self.__ports = [98]
        if not (self.__hosts and self.__ports):
            return

        port_result_dict = {}
        port_result_dict[host] = []

        task = []
        for id, port in enumerate(ports):
            # 为每个端口的检res_queue测任务分配唯一 ID (< 2bytes)
            id = (int(host.split('.')[-1]) * 100 + id) % 65535
            # host, port, method, timeout,
            # res_dict, verbose, id, [icmp_size]
            t = Worker(self.check_port, (host, port, method, None,
                                         port_result_dict, self.__verbose, id, icmp_size))
            task.append(t)
        self.__start_thread(task, self.__thread)

        if res_queue and port_result_dict[host]:
            with self.__lock:
                res_queue.put(port_result_dict)
                self.__host_result_dict[host] = port_result_dict[host]
                self.count += 1

        return port_result_dict[host]


    def check_port(self, host=None, port=None, method=None, timeout=None,
                   res_dict=None, verbose=False, id=0, icmp_size=56):
        """
        针对单个 host, 对指定的 port 进行检测
        """

        # 端口连接设置
        self.__method = method or self.__method
        if timeout:
            socket.setdefaulttimeout(timeout)
        if self.__method == 'ICMP':
            self.__ports = [98]
        if not (self.__hosts and self.__ports):
            return

        if self.__method == 'TCP':
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            if verbose:
                with self.__lock:
                    print(Color().INFO+'[*] Checking {}:{}'.format(host, port)+Color().END)
            try:
                s.connect((host, port))
            except Exception:
                status = False
            else:
                status = True
                with self.__lock:
                    if verbose:
                        print(Color().INFO+'[*] Connecting to {}:{}'.format(host, port)+Color().END)
                    if res_dict:
                        res_dict[host].append(port)
            finally:
                s.close()
            return status

        if self.__method == 'SYN':
            pass

        if self.__method == 'ACK':
            pass

        if self.__method == 'FIN':
            pass

        if self.__method == 'ICMP':
            socket.setdefaulttimeout(3)
            send_time = time.time()
            s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
            packet = self.__construct(method=self.__method, size=icmp_size, time=send_time, id=id)

            s.sendto(packet, (host, self.__ports[0]))

            if verbose:
                with self.__lock:
                    print(Color().INFO+'[*] PING {} {} bytes of data'.format(host, icmp_size)+Color().END)
            try:
                pong, addr  = s.recvfrom(2048)
            except Exception:
                status = False
            else:
                pong_send= struct.unpack('d', pong[28:36])[0]
                # time to live
                pong_ttl = pong[8]
                # fetch pong header
                pong_icmp = pong[20:]
                pong_header = pong[0:8]
                pong_type, pong_code, pong_cksum, pong_id, pong_seq = struct.unpack('bbHHh', pong_header)
                if send_time == pong_send:
                    pong_time = (time.time() - pong_send) * 1000
                    status = True
                else:
                    with self.__lock:
                        print(Color().INFO + '[*] From {} icmp_seq={} ttl={} Destination Host Unreachable'
                              .format(addr[0], pong_seq, pong_ttl) + Color().END)
                    return False

                with self.__lock:
                    if verbose:
                        print(Color().INFO+'[*] {} bytes from {}: icmp_seq={} ttl={} time={:.1f} ms'
                              .format(len(pong_icmp), host, pong_seq, pong_ttl, pong_time)+Color().END)
                    if res_dict:
                        reply = {}
                        reply['icmp_seq'] = pong_seq
                        reply['ttl'] = pong_ttl
                        reply['time'] = pong_time
                        res_dict[host].append(reply)
            finally:
                s.close()
            return status


    def __construct(self, method, size, time, id):
        """
        构造数据包
        """

        if method == 'ICMP':
            ICMP_TYPE = 8
            ICMP_CODE = 0
            ICMP_CHECKSUM = 0
            ICMP_ID = 0
            ICMP_SEQ = id
            DATA_SIZE = size
            SEND_TIME = time

            header = struct.pack('bbHHh', ICMP_TYPE, ICMP_CODE, ICMP_CHECKSUM, ICMP_ID, ICMP_SEQ)
            DATA_SIZE -= struct.calcsize('d')
            data = struct.pack('d', SEND_TIME) + (DATA_SIZE * b'0')

            # 计算数据包校验和后重新封包
            ICMP_CHECKSUM = self.__checksum(header+data)
            header = struct.pack('bbHHh', ICMP_TYPE, ICMP_CODE, ICMP_CHECKSUM, ICMP_ID, ICMP_SEQ)
            packet = header + data
            return packet


    def __checksum(self, packet):
        """
        Generates a checksum of a (ICMP) packet.
        Based on 'in_chksum' found in ping.c on FreeBSD.
        """

        # add byte if not dividable by 2
        if len(packet) & 1:
            packet = packet + '\0'
        # split into 16-bit word and insert into a binary array
        words = struct.iter_unpack('h', packet)
        sum = 0
        # perform ones complement arithmetic on 16-bit words
        for word in words:
            sum += (word[0] & 0xffff)
        hi = sum >> 16
        lo = sum & 0xffff
        sum = hi + lo
        sum = sum + (sum >> 16)
        return (~sum) & 0xffff

    def set_targets(self, hosts=[], ports=[], thread=1, method='TCP', timeout=1, verbose=False):
        self.__hosts = hosts
        self.__ports = ports
        self.__thread = thread
        self.__method = method
        self.__verbose = verbose


    def show_result(self):
        while True:
            res_dict = self.__host_result_queue.get()
            if not res_dict:
                break
            host = list(res_dict.keys())[0]
            if self.__method == 'ICMP':
                reply = res_dict[host][0]
                print()
                print('-' * 50)
                print('Host ({}) is up:'.format(host))
                print('-' * 50)
                print(Color().SUCCESS+'TTL: {}'.format(reply['ttl'])+Color().END)
                print(Color().SUCCESS + 'Cost: {} ms'.format(int(reply['time'])) + Color().END)
            else:
                ports = res_dict[host]
                print()
                print('-'*50)
                print('Result of host: {}'.format(host))
                print('-'*50)
                for port in ports:
                    print(Color().SUCCESS+'Port {:-5}: OPEN'.format(port)+Color().END)


    def save_result(self, filename):
        hosts = sorted(list(self.__host_result_dict.keys()))
        with open(filename, 'w') as f:
            if self.__method == 'ICMP':
                for host in hosts:
                    f.write(host+'\n')
            else:
                for host in hosts:
                    f.write(host+'\n')
                    ports = self.__host_result_dict[host]
                    ports = list(map(lambda x:str(x)+'\n', ports))
                    f.writelines(ports)
                    f.write('\n')
        return True


def get_hosts(arg_hosts):
    """
    将主机参数解析为字符串列表
    """

    if '-' in arg_hosts:
        m = arg_hosts.split('-')
        n = list(map(int, m[0].split('.')))
        return ['{}.{}.{}.{}'.format(n[0], n[1], n[2], x) for x in range(n[-1], int(m[1])+1)]
    return [arg_hosts]


def get_ports(arg_ports):
    """
    将端口参数解析为数字列表
    """

    if not arg_ports:
        return range(1024)
    elif len(arg_ports) == 1:
        if ',' in arg_ports[0]:
            return list(map(int, arg_ports[0].split(',')))
        elif '-' in arg_ports[0]:
            p = list(map(int, arg_ports[0].split('-')))
            return list(range(p[0], p[1]+1))
        else:
            return [int(arg_ports[0])]
    else:
        return list(map(int, arg_ports))


def _parse_args():
    """
    解析控制台参数
    """

    parser = argparse.ArgumentParser(description='This is a simple port scanner')

    group_mode = parser.add_argument_group('Scan mode')
    group_mode.add_argument('-sT', action='store_const', dest='scan_mode', default=False, const='TCP',
                            help='use TCP connect scan')
    # group_mode.add_argument('-sS', action='store_const', dest='scan_mode', default=False, const='SYN',
    #                         help='use TCP SYN scan')
    # group_mode.add_argument('-sA', action='store_const', dest='scan_mode', default=False, const='ACK',
    #                         help='use TCP ACK scan')
    # group_mode.add_argument('-sF', action='store_const', dest='scan_mode', default=False, const='FIN',
    #                         help='use TCP FIN scan')
    group_mode.add_argument('-sP', action='store_const', dest='scan_mode', default=False, const='ICMP',
                            help='use ICMP scan')
    group_mode.add_argument('-b', action='store', dest='icmp_size', default=56, type=int,
                            help='set the size of ICMP packet (default=56)')
    parser.add_argument('-p', '--port', action='append', dest='ports', default=[], type=str,
                        help='specify ports to scan (defalut=[0..1023])')
    parser.add_argument('-t', '--thread', action='store', dest='thread', default=1, type=int,
                        help='set thread of task (default=1)')
    parser.add_argument('-o', '--output', action='store', dest='output', default=None, type=str,
                        help='save result to file')
    parser.add_argument('-v', '--verbose', action='store_true', dest='verbose', default=False,
                        help='show verbose')
    parser.add_argument('host', action='store')
    parser.add_argument('--version', action='version', version='%(prog)s 1.0')
    results = parser.parse_args()
    return results


def _banner():
    print('TinyScanner')


def _atexit(start_time):
    global host_count

    sec = time.time() - start_time
    print('\nScan done: {} host scanned in {:.2f} seconds'.format(host_count, sec))


def _main():
    global host_count

    _banner()

    args = _parse_args()
    hosts = get_hosts(args.host)
    ports = get_ports(args.ports)
    icmp_size = args.icmp_size
    method = args.scan_mode
    out_file = args.output

    scan = Scanner()
    scan.set_targets(hosts=hosts, ports=ports, thread=args.thread,
                     method=method, timeout=1, verbose=args.verbose)

    host_count = 0
    start_time = time.time()
    atexit.register(_atexit, start_time)
    print('Starting scan at {}'.format(time.asctime()))

    try:
        scan.start(icmp_size=icmp_size)
    except KeyboardInterrupt:
        sys.exit()
    else:
        host_count = scan.count
        scan.show_result()
    if out_file and scan.save_result(out_file):
        print('\nOutput saved to {}'.format(out_file))


if __name__ == '__main__':
    _main()
