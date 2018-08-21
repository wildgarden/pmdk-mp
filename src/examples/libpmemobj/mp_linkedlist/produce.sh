#!/bin/bash
LD_LIBRARY_PATH=../../../debug PMEMOBJ_LOG_LEVEL=2 ./producer /tmp/ex_prodcon 1000000