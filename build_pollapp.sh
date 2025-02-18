#!/bin/bash

clang -o ./polapp/polapp ./polapp/main.c ./polapp/loader.c -I./libnl/include \
    -L./libnl/lib/.libs -lnl-3 -lnl-route-3 -lnl-genl-3 -I/usr/include\
    -I./libnftnl/include -L./libnftnl/lib/.libs -lnftnl -I./libmnl/include 
