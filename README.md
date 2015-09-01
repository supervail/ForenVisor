# ForenVisor
A lightweight hypervisor for forensics

## Installment
* Enable Intel VT-x in BIOS
* Install the ForenVisor driver
  * Download osrloader from http://www.osronline.com/article.cfm?article=157.
  * Select `bin/forenvisor.sys` in osrloader.
  * Register and start service. Note ForenVisor is not started at this stage.
* Start ForenVisor
  * Execute `bin/bpknock.exe 100` in cmd.
  * If a non-zero value is returned, ForenVisor is started and the target OS is turned into a VMM.
