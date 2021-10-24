#!/bin/bash

cd "$(dirname "$0")"

open_files_limit=$(ulimit -n)
ulimit -n 20000 # allow many simultaneously open files

go build throughput.go

p=8

echo 'doing warm up...'
hops=22
k=10
./throughput $p $k $hops n n

for enum in n c; do
    echo "enum = $enum..."
    for k in 05 10 15; do
        echo "k = $k..."
        {
            echo 'hops average'
            for hops in $(seq 2 4 22); do
                echo "$hops $(./throughput $p $k $hops $enum n)"
            done
        } > throughput_${k}_${enum}
    done
done

rm throughput

ulimit -n $open_files_limit # restore limit
