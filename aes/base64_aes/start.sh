#!/bin/bash
gcc demo.c -o demo -I/usr/local/ssl/include/ -lssl -lcrypto  -ldl -L/usr/local/ssl/lib
./demo
