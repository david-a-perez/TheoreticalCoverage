#!/bin/bash

FILE=diff.txt
if [[ -f "$FILE" ]]; then
    echo "difference exists"
else
    tmux send-keys -t top-left "c" Enter
    sleep 1
    tmux send-keys -t top-right "c" Enter
    sleep 1
    tmux send-keys -t bottom "./tmux_continue.sh" Enter
fi

