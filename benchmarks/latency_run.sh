#!/bin/bash

cd "$(dirname "$0")"

echo 'doing warm up...'
for hops in {2..9}; do
    echo "$hops $(go run latency.go 5 $hops n n)"
done

for enum in n c s; do
    echo "enum = $enum..."
    for k in 05 10 20; do
        echo "k = $k..."
        {
            echo 'hops n duration'
            for hops in {2..64}; do
                echo "$hops $(go run latency.go $k $hops $enum n)"
            done
        } > data/latencies_${k}_${enum}
    done
done
