# func_nats

1. Overview
    func_nats is a asterisk module to use NATS from the dialplan.


2. Dependencies

The following libraries  must be installed:
    nats.c - https://github.com/nats-io/nats.c/releases

3. Module build
    - Move file func_nats.c to Astrisk source addons/ directory
    - Update addons/Makefile and add func_nats to the list of modules assigned to the ALL_C_MODS variable	
    - Update addons/Makefile and add line: func_nats.so: LIBS+=-lnats -I/usr/local/include
    - configure asterisk with LDFLAGS option:  ./configure LDFLAGS=-lnats
    - make & make menuselect & make install asterisk


## Using func_nats

In order to use the func_nats you have to configure the settings for the module 
in the file func_nats.conf. There is an example in func_nats.conf.sample, if you 
run make samples it will copy this file to /etc/asterisk

NATS API doc: https://docs.nats.io/reference/reference-protocols/nats-protocol#pub

### Using func_nats from the Dialplan to publish an event
```
same => n,NoOp(NATS_PUBLISH(testsubject,key1=val1,key2=val2))
```
