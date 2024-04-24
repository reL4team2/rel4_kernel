import socket
import threading
import time
import argparse

class ThreadSafeDynamicArray:
    def __init__(self):
        self._array = []
        self._lock = threading.Lock()

    def append(self, item):
        with self._lock:
            self._array.append(item)

    def __len__(self):
        with self._lock:
            return len(self._array)

    def mean(self):
        return sum(self._array) / self.__len__()

    def variance(self):
        mean = self.mean()
        return sum((x - mean) ** 2 for x in self._array) / self.__len__()
    def get(self):
        return self._array

    def save(self, connect_num):
        file_path = "./data/delay_data_" + str(connect_num)
        array_str = ','.join(map(str, self._array))
        with open(file_path, 'w') as file:
            file.write(array_str)


class AtomicInteger:
    def __init__(self, initial_value=0):
        self._value = initial_value
        self._lock = threading.Lock()

    def increment(self):
        with self._lock:
            self._value += 1

    def decrement(self):
        with self._lock:
            self._value -= 1

    def get(self):
        with self._lock:
            return self._value

    def set(self, value):
        with self._lock:
            self._value = value

parser = argparse.ArgumentParser()
parser.add_argument('--thread_num', type=int, help='the thread num of client.')

parser.add_argument('--send', action='store_true', help='Enable send action')

parser.add_argument('--recv', action='store_true', help='Enable recv action')
parser.add_argument('--save', action='store_true', help='Save delay data')
args = parser.parse_args()
def tcp_client(host, port):
    # start_time_out = time.time()
    cnt = 0
    try:
        # 创建TCP套接字
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client_socket.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        # 连接服务器
        client_socket.connect((host, port))

        # print(f"Connected to {host}:{port}")
        while TOTOAL_REQ.get() != 0:
            cnt += 1
            TOTOAL_REQ.decrement()
            # message = "connect ok?"
            message = "?"
            start_time = time.time() * 1000
            if args.send:
                client_socket.sendall(message.encode())
            if args.recv:
                data = client_socket.recv(1024)
                # print(data)
            end_time = time.time() * 1000
            REQ_DELAY.append(end_time - start_time)
            # print(data)
        if args.send:
            message = "."
            client_socket.sendall(message.encode())
        data = client_socket.recv(1024)
        # 关闭套接字
        client_socket.close()
    except Exception as e:
        print(f"Error: {e}")

    # end_time_out = time.time()
    # local_cost_time = end_time_out - start_time_out
    # print("local throughput: " + str(cnt / local_cost_time))

def statistic():
    print("delay avg: " + str(REQ_DELAY.mean()) + " ms")
    print("delay variance: " + str(REQ_DELAY.variance()))
    print("throughput: " + str(TOTOAL_REQ_NUM / TOTOAL_COST_TIME))
    if args.save:
        REQ_DELAY.save(args.thread_num)
    # print("delay " + str(REQ_DELAY.get()))


TOTOAL_REQ_NUM = 2048
THREAD_NUM = 0

TOTOAL_REQ = AtomicInteger(TOTOAL_REQ_NUM)
TOTOAL_COST_TIME = 0
REQ_DELAY = ThreadSafeDynamicArray()


if __name__ == "__main__":
    # 服务器地址和端口
    server_host = '127.0.0.1'
    server_port = 6201
    THREAD_NUM = args.thread_num
    threads = []
    start_time = time.time()
    for i in range(THREAD_NUM):
        # 创建线程
        thread = threading.Thread(target=tcp_client, args=(server_host, server_port))
        threads.append(thread)
        thread.start()

    for thread in threads:
        thread.join()
    end_time = time.time()
    TOTOAL_COST_TIME = end_time - start_time
    statistic()