import socket
import threading
import time

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

def tcp_client(host, port):
    try:
        # 创建TCP套接字
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # 连接服务器
        client_socket.connect((host, port))
        # print(f"Connected to {host}:{port}")
        while TOTOAL_REQ.get() != 0:
            TOTOAL_REQ.decrement()
            # message = '?' * 400
            message = "connect ok?"
            start_time = time.time() * 1000
            client_socket.sendall(message.encode())
            data = client_socket.recv(1024)
            end_time = time.time() * 1000
            REQ_DELAY.append(end_time - start_time)
            # print(data)


        # 关闭套接字
        client_socket.close()
    except Exception as e:
        print(f"Error: {e}")

def statistic():
    print("delay avg: " + str(REQ_DELAY.mean()) + " ms")
    print("delay variance: " + str(REQ_DELAY.variance()))
    print("throughput: " + str(TOTOAL_REQ_NUM / TOTOAL_COST_TIME))
    # print("delay " + str(REQ_DELAY.get()))

TOTOAL_REQ_NUM = 4096
THREAD_NUM = 1

TOTOAL_REQ = AtomicInteger(TOTOAL_REQ_NUM)
TOTOAL_COST_TIME = 0
REQ_DELAY = ThreadSafeDynamicArray()

if __name__ == "__main__":
    # 服务器地址和端口
    server_host = '127.0.0.1'
    server_port = 6201
    threads = []
    # 建立64个TCP连接
    start_time = time.time()
    for i in range(THREAD_NUM):
        # 创建线程
        thread = threading.Thread(target=tcp_client, args=(server_host, server_port))
        threads.append(thread)
        # 启动线程
        thread.start()
    for thread in threads:
        thread.join()
    end_time = time.time()
    TOTOAL_COST_TIME = end_time - start_time
    statistic()