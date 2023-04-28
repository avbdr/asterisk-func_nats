# func_nats
func_nats is a asterisk module.
It's purpose is to create NATS consumer from the dialplan.


##  External library dependence
    - nats.c - https://github.com/nats-io/nats.c/releases

##  Module build
    - Install the dependencies
    - Move file func_nats.c to Astrisk source addons/ directory
    - Update addons/Makefile and add func_nats to the list of modules assigned to the ALL_C_MODS variable	
    - Update addons/Makefile and add line: func_nats.so: LIBS+=-lnats -I/usr/local/include
    - Configure asterisk with LDFLAGS option:  ./configure LDFLAGS=-lnats
    - Make & make menuselect & make install asterisk
    - Move file func_nats.conf.sample to /etc/asterisk/func_nats.conf and update settings


## Using func_nats from the Dialplan to publish an event
```
same => n,NoOp(NATS_PUBLISH(testsubject,key1=val1,key2=val2))
```
