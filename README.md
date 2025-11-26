# pytrace
Route tracing and hop monitoring script. This is a multithreaded tracing/hop monitoring script.



## Example:
```bash
./pytrace google.com
```
Starts web viewer on 127.0.0.1:8000
Use an ssh tunnel to run on a server and access remotely


```bash
./pytrace -load logfile
```
Starts the web viewer with a previously saved log. No ping/tracing is done.



```bash
./pysetup.sh
```
Setup python venv. installed scapy module. Will ask user if they wish to give python access to capture packets without sudo.
