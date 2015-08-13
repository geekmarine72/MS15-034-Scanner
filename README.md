MS15-034-Scanner
====================

[![Build status](https://ci.appveyor.com/api/projects/status/wyo7192dklvlwc72/branch/master?svg=true)](https://ci.appveyor.com/project/geekmarine72/ms15-034-scanner/branch/master)

MS15-034-Scanner is a windows command line utility which scans one or more URLs for the [MS15-034] (https://technet.microsoft.com/en-us/library/security/ms15-034.aspx) vulnerability in a non-destructive manner.

This utility uses raw sockets to perform the scan, bypassing the limitations inherent in most native .NET web browser or clients (which block access to critical header values). 

Additionally, this solution provides full SSL support with header manipulation. 

Invoke the utility without arguments to see options.  

Accepts a list of one or more URL to scan.  Each url should be fully qualified, can include http or https, can use alternate ports, and can include virtual directories or subsites.

### Usage
------

The utility emits onscreen progress details and records to a log file (CSV) detailed results of scanning.

### License
-------

[MIT X11](http://en.wikipedia.org/wiki/MIT_License)

