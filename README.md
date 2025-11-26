# pytrace
Route tracing and hop monitoring script. This is a multithreaded tracing/hop monitoring script.

<img width="2543" height="1276" alt="image" src="https://github.com/user-attachments/assets/9f316d42-ed68-44cf-b297-4ad6b9556509" />


## Example:
```bash
./pytrace google.com
```
Starts web viewer on 127.0.0.1:8000.<br/>
Use an ssh tunnel to run on a server and access remotely/


```bash
./pytrace -load logfile
```
Starts the web viewer with a previously saved log. No ping/tracing is done.



```bash
./pysetup.sh
```
Setup python venv. Installs scapy module.</br>
ill ask user if they wish to give python access to capture packets without sudo.</br>

## Todo:
- Should add setup for powershell/windows.
- lower left divs aren't ideal. Replace hop latency history with matching route for the hop, and have that clickable to update the main upper left div's last route.
