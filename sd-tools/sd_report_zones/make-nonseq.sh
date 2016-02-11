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

readonly blocksz=$((4 * KiB))
readonly sectorsz=512
readonly zonesz=$((256 * MiB))
readonly sectors_per_zone=$((zonesz / sectorsz))
readonly zone_offset=$((1 * blocksz))

# Force sudo validation early to avoid interference with output
sudo echo -n

trap "{ exit 0; }" SIGINT SIGTERM

for drive_id in $drives
do
	dev=/sys/block/sd${drive_id}
	sd_device=/dev/sd${drive_id}
	sectors=`cat ${dev}/size`
	zones=$((sectors / sectors_per_zone))

#	echo "sector size ${sectorsz}"
#	echo "zone size ${zonesz}"
#	echo "sectors ${sectors}"
#	echo "sectors per zone ${sectors_per_zone}"
#	echo "zones ${zones}"

	echo "${zones} zones"

	zone=0

	while [ ${zone} -lt ${zones} ]
	do
		offset=$(((zone * zonesz + zone_offset) / blocksz))
		sudo sh -c "dd if=/dev/zero of=/dev/sd${drive_id} \
			bs=4K count=1 seek=${offset}" > /dev/null 2>&1
		zone=$((zone + 1))
	done
done
