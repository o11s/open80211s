#!/bin/bash

# handle the case when using files for logging instead of
# real devices (with kvm, for example)
DD_OPTS="conv=notrunc"

if [ ! $# -eq 1 ]; then
	echo "Usage: $0 <dev>"
	exit 1
elif mount|fgrep -q $1; then
	echo Device appears to be mounted - aborting
	exit 1
else
	dd if=/dev/zero of=$1 bs=1M count=1 $DD_OPTS
	# The funky formatting is actually needed!
	UUID=`head -c4 /dev/urandom |hexdump -e '/4 "%08x"'`
	echo > /tmp/$UUID
	echo 'Linux blockconsole version 1.1' >> /tmp/$UUID
	echo "$UUID" >> /tmp/$UUID
	echo 00000000 >> /tmp/$UUID
	echo 00000000 >> /tmp/$UUID
	for i in `seq 452`; do echo -n " " >> /tmp/$UUID; done
	echo >> /tmp/$UUID

	dd if=/tmp/$UUID of=$1 $DD_OPTS
	rm /tmp/$UUID
	sync
	exit 0
fi
