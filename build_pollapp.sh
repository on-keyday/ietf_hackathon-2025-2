#!/bin/bash

clang -o ./polapp/polapp ./polapp/main.c -I./libnl/include \
    -L./libnl/lib -lnl-3 -lnl-genl-3 -I/usr/include

