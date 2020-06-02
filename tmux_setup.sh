#!/bin/bash



tmux send-keys -t top-left "source coverage.py" Enter
sleep 1
tmux send-keys -t top-left "source compare.py" Enter
sleep 1
tmux send-keys -t top-left "start" Enter
sleep 1
tmux send-keys -t top-left "coveragestart" Enter
sleep 1
tmux send-keys -t top-left "pi gef_on_stop_hook(lambda x: gdb.execute(\"writepc\"))" Enter
sleep 1
tmux send-keys -t top-left "pi gef_on_stop_hook(hook_stop_handler)" Enter
sleep 1


tmux send-keys -t top-right "source compare.py" Enter
sleep 1
tmux send-keys -t top-right "start" Enter
sleep 1
tmux send-keys -t top-right "pi gef_on_continue_hook(lambda x: gdb.execute(\"readpc\"))" Enter
sleep 1
tmux send-keys -t top-right "pi gef_on_stop_hook(lambda x: gdb.execute(\"confirmregs\"))" Enter
sleep 1

