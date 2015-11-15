#!/bin/bash

KSRC=../../zdm/linux
KPATH=${KSRC}/drivers/md

meld h/dm-zoned.h ${KPATH}/dm-zoned.h
meld lib/libzoned.c ${KPATH}/libzoned.c
