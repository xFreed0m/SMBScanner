# SMBScanner
 Golang tool to scan for SMB version and signing status

## How to use it
Download the release for you OS from [here](https://github.com/xFreed0m/SMBScanner/releases)
```
Run the tool with the needed flags:
```
SMBscanner --targets [TARGETS_FILE] -d [DOMAIN] -u [USERNAME] -p [PASSWORD]
```

## Options to consider
* -l
  * Name of the logfile to use (the default is "SMBScan.log"
* --port
  * Port to use (the deafult is 445)
 

### Tested OS
Not tested yet, testers wanted!
please open an issue and list which release you used and which type of scans you ran

### TODO
* Update README with building from source instructions
* Add features listed in the bottom of SMBScan.go

### Issues, bugs and other code-issues
Yeah, I know, this code isn't the best. I'm fine with it as I'm not a developer and this is part of my learning process.
If there is an option to do some of it better, please, let me know.

_Not how many, but where._
