#!/bin/bash

cd "$(dirname "$0")"

go build message_size.go

for enum in n c s; do
    echo "enum = $enum..."
    for k in 05 10 15; do
        echo "k = $k..."
        {   echo 'hops send recv'
            for hops in $(seq 2 4 22); do
                echo "$hops $(./message_size $k $hops $enum)"
            done
        } > message_size_${k}_${enum} &
    done
done
wait

rm message_size
