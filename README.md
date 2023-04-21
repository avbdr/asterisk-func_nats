# func_nats

WARNING: its a WIP repo. Nothing builds yet

func_nats is a asterisk module to use NATS from the dialplan.

## Using func_nats

In order to use the func_nats you have to configure the settings for the module 
in the file func_nats.conf. There is an example in func_nats.conf.sample, if you 
run make samples it will copy this file to /etc/asterisk

NATS API doc: https://docs.nats.io/reference/reference-protocols/nats-protocol#pub

### Using func_nats from the Dialplan to publish an event
```
same => n,NoOp(NATS_PUBLISH(testsubject,key1=val1,key2=val2))
```
