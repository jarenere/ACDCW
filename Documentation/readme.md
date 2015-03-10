##Pin info
* Documentation base http://mc.pp.se/dc

Only add to the documentation of [controller](http://mc.pp.se/dc/controller.html) [maplewire](http://mc.pp.se/dc/maplewire.html) that pines:
* Pin 1 serial data
* Pin 3 serial data
high is +3V and not 5v

The bandwidth for each signal is just 1MHz,

##Sigrok
[Sigrok](http://sigrok.org/) is a Open-Source signal analysis software suite that supports various device types.
[The Saleae Logic](http://sigrok.org/wiki/Saleae_Logic) is an 8 channel 24MHz logic analyser, it is compatible with sigrok,
retails for $149, but you can find clones in Aliexpress by 7$

##How use Saleae Logic Analyser Clone (or not) witouth be root
Copy 60-libsigrok.rules in /etc/udev/rules.d/ (or where-ever your distribution stores udev rules files). And add your user to group "users".

If rules fail to reload automatically
```
# udevadm control --reload
```
To manually force udev to trigger your rules
```
# udevadm trigger
```

Plug in your Logic clone and do a:
```
sigrok-cli --scan
```
If all ok, you see:
```
$ sigrok-cli --scan
The following devices were found:
demo - Demo device with 12 channels: D0 D1 D2 D3 D4 D5 D6 D7 A0 A1 A2 A3
fx2lafw - Saleae Logic with 8 channels: 0 1 2 3 4 5 6 7
```

#Format SAMPLES
In SAMPLES directory you can find differents samples do with sigrok, format:
* lenght
* Info action (D_left-> digital button, pulse left)