#!/bin/bash

if [ $# -eq 0 ]
then
	echo "usage: $0 [-c] drive-letters"
	exit 0
fi

for i in $*
do
	drives="$drives $i"
done

readonly KiB=$((1024 ** 1))
readonly MiB=$((1024 ** 2))
readonly GiB=$((1024 ** 3))
readonly TiB=$((1024 ** 4))

readonly lbasz=$((4 * KiB))
readonly sectorsz=512
readonly zonesz=$((256 * MiB))
readonly sectors_per_zone=$((zonesz / sectorsz))
readonly zone_offset=$((1 * lbasz))
readonly zones_per_iteration=127

# Force sudo validation early to avoid interference with output
sudo echo -n

trap "{ exit 0; }" SIGINT SIGTERM

for drive_id in $drives
do
	dev=/sys/block/sd${drive_id}
	sd_device=/dev/sd${drive_id}
	sectors=`cat ${dev}/size`
	zones=$((sectors / sectors_per_zone))

	echo "sectors per zone ${sectors_per_zone}"
	echo "${zones} zones"

	zone=0

	while [ ${zone} -lt ${zones} ]
	do
		echo "zone ${zone}"
		sector=$(( zone * sectors_per_zone ))
		sudo sg_rep_zones --start=${sector} ${sd_device}
		zone=$((zone + zones_per_iteration))
	done
done
