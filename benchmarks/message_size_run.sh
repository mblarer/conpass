#!/bin/bash

for enum in n c s; do
    echo "enum = $enum..."
    for k in 05 10 20; do
        echo "k = $k..."
        {
            echo "hops send recv"
            for hops in {2..22}; do
                echo "$hops $(go run message_size.go $k $hops $enum)"
            done
        } > message_sizes_${k}_${enum}.data &
    done
done
wait
