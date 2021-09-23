#!/bin/bash

cd "$(dirname "$0")"

go build throughput.go

hops=22

echo 'doing warm up...'
for p in {1..16}; do
    k=10
    echo "$p $(/usr/bin/time 2>&1 -f ' %M' ./throughput $p $k $hops n n)"
done

for enum in n c s; do
    echo "enum = $enum..."
    for k in 05 10 20; do
        echo "k = $k..."
        {
            echo 'workers n duration memory'
            for p in {1..16}; do
                echo "$p $(/usr/bin/time -f 2>&1 ' %M' ./throughput $p $k $hops $enum n)"
            done
        } > data/throughput_${k}_${enum}
    done
done

rm throughput
