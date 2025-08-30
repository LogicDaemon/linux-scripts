#!/bin/bash

# sudo apt-get install cgroup-tools
sudo cgcreate -g memory:/limitmem
sudo bash -c "echo '+memory' > /sys/fs/cgroup/cgroup.subtree_control"
echo "3G" | sudo tee /sys/fs/cgroup/limitmem/memory.max

for pid in $(pgrep -f "$HOME/.vscode-server"); do
    ps -f -p "$pid"
    echo "$pid" | sudo tee -a /sys/fs/cgroup/limitmem/cgroup.procs >/dev/null
done
