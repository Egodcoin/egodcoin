#!/bin/bash
# use testnet settings,  if you need mainnet,  use ~/.egodcoincore/egodcoind.pid file instead
egodcoin_pid=$(<~/.egodcoincore/testnet3/egodcoind.pid)
sudo gdb -batch -ex "source debug.gdb" egodcoind ${egodcoin_pid}
