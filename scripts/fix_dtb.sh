#!/bin/sh

IMAGE_PATH=build/zephyr

TEMPLATE=$1
TEMPLATE=${TEMPLATE:-gicv2.tmpl}
OUTPUT=$2
OUTPUT=${OUTPUT:-$IMAGE_PATH/virt_gicv2.dtb}
IMAGE=$3
IMAGE=${IMAGE:-$IMAGE_PATH/zephyr.bin}

SIZE=$(printf "0x%x\n" $(stat -c %s $IMAGE))
sed  s/\$SIZE/$SIZE/g < $TEMPLATE | dtc -o $OUTPUT
#dtc gicv2.dts -o $OUTPUT
