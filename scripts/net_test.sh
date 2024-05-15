#!/bin/bash

echo "start test"

test_conn_num=(1 2 4 8 16 32)
timestamp=$(date +"%Y-%m-%d_%H-%M-%S")
res_file="test_res.txt"

test_single() {
  local thread_num="$1"
  echo $thread_num
  echo "test start"
  cd ../build && ./simulate -b ../../qemu-build/qemu-system-riscv64 -M virt --cpu-num 4 -n true &
  PID=$!
  sleep 2

  python3 net_test.py --thread_num $thread_num --send --recv --save >> $res_file
  echo "" >> $res_file

  kill_process_and_children() {
    local pid="$1"
    local children="$(pgrep -P "$pid")"

    for child in $children; do
      kill_process_and_children "$child"
    done
    kill -TERM "$pid"
  }

  kill_process_and_children "$PID"
  echo "test end"
}

for conn_num in "${test_conn_num[@]}"; do
  test_single "$conn_num"
done





