#!/bin/sh
gcc nanotoovod.c -c -o nanotoovod.o -I /opt/OV/include && gcc -L/opt/OV/lib -lopc_r nanotoovod.o -o nanotoovod
