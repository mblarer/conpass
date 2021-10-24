#!/bin/bash

cd "$(dirname "$0")"

go build latency.go

echo 'doing warm up...'
for hops in $(seq 2 4 22); do
    echo "$hops $(./latency 5 $hops n n)"
done

for enum in n c s; do
    echo "enum = $enum..."
    for k in 05 10 15; do
        echo "k = $k..."
        {
            echo 'hops n duration'
            for hops in $(seq 2 4 22); do
                echo "$hops $(./latency $k $hops $enum n)"
            done
        } > latency_${k}_${enum}
    done
done

rm latency
