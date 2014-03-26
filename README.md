snoop
=====

Author: Chris J Arges <christopherarges@gmail.com>

Copyright:  (C) 2014 Canonical Ltd., Chris J Arges <christopherarges@gmail.com>

License: GPLv2

install
-------
1. ensure headers are installed
2. build it
	* `$ make`
	* `$ sudo insmod snoop.ko`
3. turn on dynamic debug output
	* `$ echo "module snoop -p" > /sys/kernel/debug/dynamic_debug/control`

uninstall
---------
1. remove module
	* `$ sudo rmmod snoop`
