if [ ! -s include/asterisk.h ] ; then
	echo "please cd into the directory where the asterisk source has been untarred"
	exit
fi
cp asterisk-func_nats/func_nats.c addons/
echo "edit addons/Makefile: add func_nats to the list of modules built"
