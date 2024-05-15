#!/bin/bash
scp /Users/ctrlz/workSpace/seL4/code/rel4test/rel4_kernel/build/opensbi/platform/axu15eg/firmware/fw_payload.bin zfl@10.242.0.5:~/ldh_test
ssh zfl@10.242.0.5 bash -s < "/Users/ctrlz/workSpace/seL4/code/rel4test/rel4_kernel/push_remote2.sh"