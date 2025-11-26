from scapy.all import sr1, IP, UDP, ICMP, TCP
import sys
from concurrent.futures import ThreadPoolExecutor
import time
import socket
import socketserver
import http.server
import urllib
import threading
import hashlib
import json
HTPORT = 8000

maxhops = 30
currentroute=None
routehash=None
routeupdatetime=None
routedict={}
nodedict={}
nodedict_lock = threading.Lock()

exitflag = threading.Event()
lastip=""

historylimit=500  #max history records per node
Banner=""

def spancolor(text,rgb):
    '''span with color'''
    r,g,b=rgb
    spanstart=f'<span style="color: rgb({r},{g},{b});">'
    spanend='</span>'
    return f'{spanstart}{text}{spanend}'


def divstart(height, width,bkcolorrgb, divid):
    '''start floating div with position and background color
    div height and width in percent of available area'''
    r,g,b=bkcolorrgb
    divtext=f'<div id="{divid}" style="float:left; height:{height}%; width:{width}%; background-color: rgb({r},{g},{b});">\n'
    return divtext


def divend():
    '''end div'''
    return '</div>\n'


def adddiv(height, width,bkcolorrgb, divid):
    '''add floating div with position and background color
    div height and width in percent of available area'''
    divtext=divstart(height, width,bkcolorrgb, divid)
    divtext+=divend()
    return divtext


def setdivcontent(divid, content):
    '''set div content'''
    divtext=f'<script>document.getElementById("{divid}").innerHTML=`{content}`;</script>\n'
    return divtext


def htmlpagestart():
    '''set style using monospace font, spacing for borders as 0
    body padding, borders to 0'''
    htmlstart='''<html><head><style>
    body { font-family: monospace; margin: 0; padding: 0; background-color: #000010; font-size: 1.2em; color: black; }
    table { border-collapse: collapse; }
    td, th { border: 0; padding: 0; text-align: left; }
    div { margin: 0; padding: 0; overflow: auto; }
    .tab1_header { background-color: #cdcd00; color: black; font-weight: bold; font-size: 1.3em; }
    .tab1_raca { background-color: #aaaa99; color: black; }
    .tab1_racb { background-color: #aaaabb; color: black; }
    .tab1_rbca { background-color: #bbbbaa; color: black; }
    .tab1_rbcb { background-color: #bbbbcc; color: black; }
    .tab2_header { background-color: #00cdcd; color: black; font-weight: bold; }
    .tab2_ra { background-color: #99aaaa; color: black; }
    .tab2_rb { background-color: #aabbbb; color: black; }
    #chartdiv { overflow: auto; height: 100%; }
    </style>
    <script>
    var lastHistory = [];  
    var lastMinLatency = 0;  
    var lastMaxLatency = 1.0;
    var lastMouseX = null;
    var lastMouseIdx = null;

    function drawLatencyGraph(history, minLatency, maxLatency) {  
        lastHistory = history;  
        lastMinLatency = minLatency;
        lastMaxLatency = maxLatency;  
        maxLatency *= 1.1;
        var canvas = document.getElementById('latencyCanvas');
        if (!canvas) return;
        var ctx = canvas.getContext('2d');
        ctx.clearRect(0, 0, canvas.width, canvas.height);
        for (var i = 0; i < history.length; i++) {
            var latency = history[i][1];
            if (latency < 0) continue;
            var x = (i / history.length) * canvas.width;
            //draw lines from bottom to top at each x
            var y = canvas.height - ((latency - minLatency) / (maxLatency - minLatency)) * canvas.height;
            ctx.beginPath();
            ctx.moveTo(x, canvas.height);
            ctx.lineTo(x, y);
            ctx.strokeStyle = '#804040';
            ctx.stroke();
        }
        ctx.beginPath();
        ctx.moveTo(0, canvas.height);
        for (var i = 0; i < history.length; i++) {
            var latency = history[i][1];
            if (latency < 0) continue;
            var x = (i / history.length) * canvas.width;
            var y = canvas.height - ((latency - minLatency) / (maxLatency - minLatency)) * canvas.height;
            ctx.lineTo(x, y);
        }
        ctx.strokeStyle = '#ff0000';
        ctx.stroke();
    
        // Draw marker if mouse position is set
        if (lastMouseX !== null && lastMouseIdx !== null && lastHistory[lastMouseIdx]) {
            ctx.beginPath();
            ctx.moveTo(lastMouseX, 0);
            ctx.lineTo(lastMouseX, canvas.height);
            ctx.strokeStyle = '#0000ff';
            ctx.setLineDash([4, 2]);
            ctx.stroke();
            ctx.setLineDash([]);  
            var latency = lastHistory[lastMouseIdx][1];
            var timestamp = lastHistory[lastMouseIdx][0];
            var cssWidth = canvas.clientWidth;
            ctx.fillStyle = '#000';
            ctx.font = '1.5em Monospace';
            ctx.fillText('Latency: ' + latency.toFixed(2) + ' ms', cssWidth / 4, 30);
            ctx.fillText('Timestamp: ' + epoch2YMDhms(timestamp), cssWidth / 4, 60);
        }
    }
    
    function epoch2YMDhms(epoch) {
        var date = new Date(epoch * 1000);
        return date.getUTCFullYear() + '-' +
            String(date.getUTCMonth() + 1).padStart(2, '0') + '-' +
            String(date.getUTCDate()).padStart(2, '0') + ' ' +
            String(date.getUTCHours()).padStart(2, '0') + ':' +
            String(date.getUTCMinutes()).padStart(2, '0') + ':' +
            String(date.getUTCSeconds()).padStart(2, '0');
    }
    
    function fetchAndDrawLatency() {  
        fetch('/syscallgraph')  
            .then(response => response.json())  
            .then(data => {  
                // data should contain the history and maxLatency  
                drawLatencyGraph(data.history, data.minLatency, data.maxLatency);  
            });  
    }

    setInterval(fetchAndDrawLatency, 5000);  
    fetchAndDrawLatency();

    document.addEventListener('DOMContentLoaded', function() {
        var canvas = document.getElementById('latencyCanvas');
        if (!canvas) return;
        canvas.addEventListener('mousemove', function(e) {
            if (!lastHistory || lastHistory.length === 0) return;
            var rect = canvas.getBoundingClientRect();
            var cssWidth = canvas.clientWidth;
            var actualWidth = canvas.width;
            var scaleX = actualWidth / cssWidth;
            var x = (e.clientX - rect.left) * scaleX;
            var idx = Math.floor((x / actualWidth) * lastHistory.length);
            if (idx < 0 || idx >= lastHistory.length) return;
            lastMouseX = x;
            lastMouseIdx = idx;
            drawLatencyGraph(lastHistory, lastMinLatency, lastMaxLatency);
        });
    });
    
    function drawLatencyGraphMouse(canvas, history, minlatency, maxLatency, x) {
        // Draw vertical marker
        var cssWidth = canvas.clientWidth;
        var cssHeight = canvas.clientHeight;
        var actualWidth = canvas.width;
        var actualHeight = canvas.height;
        var ctx = canvas.getContext('2d');
        ctx.beginPath();
        ctx.moveTo(x, 0);
        ctx.lineTo(x, actualHeight);
        ctx.strokeStyle = '#0000ff';
        ctx.setLineDash([4, 2]);
        ctx.stroke();
        ctx.setLineDash([]);
        ctx.fillStyle = '#000';
        ctx.font = '2em Monospace';
        ctx.fillText('Latency: ' + latency.toFixed(2) + ' ms', cssWidth/2, 30);
    }
    
    function showLatencyAtMouse(e, canvas) {
        if (!lastHistory || lastHistory.length === 0) return;
        var rect = canvas.getBoundingClientRect();
    
        // Get CSS and actual sizes
        var cssWidth = canvas.clientWidth;
        var cssHeight = canvas.clientHeight;
        var actualWidth = canvas.width;
        var actualHeight = canvas.height;
    
        // Scale mouse position
        var scaleX = actualWidth / cssWidth;
        var x = (e.clientX - rect.left) * scaleX;
    
        var idx = Math.floor((x / actualWidth) * lastHistory.length);
        if (idx < 0 || idx >= lastHistory.length) return;
        var latency = lastHistory[idx][1];
    
        // Redraw the graph
        drawLatencyGraph(lastHistory, lastMinLatency, lastMaxLatency);
        // Draw vertical marker and latency value
        drawLatencyGraphMouse(canvas, lastHistory, lastMinLatency, lastMaxLatency, x);
    }

    </script> 
    </head><body>\n'''
    return htmlstart


def divrefresh(divid, request, interval):
    '''javascript to refresh div content'''
    refreshtxt=f'''<script>
    setInterval(function() {{
        fetch('{request}')
        .then(response => response.text())
        .then(data => {{
            document.getElementById('{divid}').innerHTML = data;
        }});
    }}, {interval} );
    </script>\n'''
    return refreshtxt


def spanclickdivupdate(spantext, divid, request,interval=1000):
    '''span that when clicked updates div content'''
    spanclicktxt=f'''  
    <span style="cursor: pointer; text-decoration: none;"
    onmouseover="this.style.backgroundColor='#cccc40';"
    onmouseout="this.style.backgroundColor='transparent';"
    onclick="
        // Clear any existing interval  
        if (window.__refresh_{divid}) {{  
            clearInterval(window.__refresh_{divid});  
        }}
        // Function to refresh the div
        function update_{divid}() {{
            fetch('{request}')  
            .then(response => response.text())
            .then(data => {{  
                document.getElementById('{divid}').innerHTML = data;
                fetchAndDrawLatency();
            }});
        }}
        // Initial update  
        update_{divid}();
        // Set interval for repeated updates
        window.__refresh_{divid} = setInterval(update_{divid}, {interval});
    ">{spantext}</span>  
    '''  
    return spanclicktxt


def htmlpageend():
    '''end html page'''
    htmlend='</body></html>\n'
    return htmlend


def contentcreate_pagetexttable():
    '''create page text table for route'''
    global currentroute
    global nodedict
    spc='&nbsp;'*1
    pagetexttable='<table style="width:100%;height:100%;color: white;">\n'
    pagetexttable+=f'<tr class="tab1_header" style="height:2.5%;"><th>{spc}TTL</th><th>{spc}Hostname</th><th>{spc}IP Address</th><th>{spc}Latency (ms)</th><th style="width:20%">{spc}Route history count</th></tr>\n'
    rowindx=0
    if currentroute is not None:
        for hop in currentroute:
            rowindx+=1
            spc='&nbsp;'*1
            #ttl to 3 decimal places
            ttl=spc+str(hop['ttl'])+spc
            hostname=spc+hop['hostname']+spc
            ip=spc+hop['ip']+spc
            ip=spanclickdivupdate(ip, "node_details", f"/nodes/{hop['ip']}",500)
            hostname=spanclickdivupdate(hostname, "node_details", f"/nodes/{hop['ip']}",500)
            latency=spc+str(f"{hop['latency']:.3f}")+spc
            with nodedict_lock:
                history_count = len(nodedict[hop['ip']]["ttlhistory"]) if hop['ip'] in nodedict else ""
            if rowindx % 2 == 1:
                thisrowcolora="tab1_raca"
                thisrowcolorb="tab1_racb"
            else:
                thisrowcolora="tab1_rbca"
                thisrowcolorb="tab1_rbcb"
            pagetexttable+=f'<tr style="height:2.5%"><td class="{thisrowcolora}">{ttl}</td>'
            pagetexttable+=f'<td class="{thisrowcolorb}">{hostname}</td>'
            pagetexttable+=f'<td class="{thisrowcolora}">{ip}</td>'
            pagetexttable+=f'<td class="{thisrowcolorb}">{latency}</td>'
            pagetexttable+=f'<td class="{thisrowcolora}">{history_count}</td></tr>\n'
        hopcount=len(currentroute)
        remrows=maxhops - hopcount
        for _ in range(remrows):
            rowindx+=1
            if rowindx % 2 == 1:
                thisrowcolora="tab1_raca"
                thisrowcolorb="tab1_racb"
            else:
                thisrowcolora="tab1_rbca"
                thisrowcolorb="tab1_rbcb"
            pagetexttable+=f'<tr style="height:2.5%"><td class="{thisrowcolora}"></td>'
            pagetexttable+=f'<td class="{thisrowcolorb}"></td>'
            pagetexttable+=f'<td class="{thisrowcolora}"></td>'
            pagetexttable+=f'<td class="{thisrowcolorb}"></td>'
            pagetexttable+=f'<td class="{thisrowcolora}"></td></tr>\n'
    pagetexttable+='</table>\n'
    return pagetexttable


def hopstats(ip):
    '''return average, top 10%, bottom 10% latencies for hop, average jitter'''
    global nodedict
    if ip not in nodedict:
        return None
    with nodedict_lock:
        latencies = [latency for _, latency in nodedict[ip]['pinghistory']]
    if not latencies:
        return None
    sorted_latencies = sorted(latencies)
    positivelatencies = [lat for lat in sorted_latencies if lat >= 0]
    count=len(latencies)
    poscount=len(positivelatencies)
    if poscount > 1:
        avg_latency = sum(positivelatencies) / poscount if poscount > 0 else -1
        med_latency = positivelatencies[poscount // 2] if poscount > 0 else -1
        max_latency = positivelatencies[-1]
        min_latency = positivelatencies[0]
        top10percentile = positivelatencies[int(poscount * 0.9) - 1] if poscount >= 10 else max_latency
        bottom10percentile = positivelatencies[int(poscount * 0.1)] if poscount >= 10 else min_latency
        jitter = sum(abs(positivelatencies[i] - positivelatencies[i - 1]) for i in range(1, poscount)) / (poscount - 1)
        packetloss = (count - poscount) / count * 100
        return {
            'average': avg_latency,
            'median': med_latency,
            'max': max_latency,
            'min': min_latency,
            'top10': top10percentile,
            'low10': bottom10percentile,
            'jitter': jitter,
            'packetloss': packetloss,
            'count': count,
            'average_ttl': averagettl(ip)
        }
    else:
        return None
    
def canvaslatencygraph():  
    global lastip, nodedict  
    ip = lastip  
    if ip not in nodedict:  
        return json.dumps({"history": [], "maxLatency": 1})  
    node = nodedict[ip]  
    history = node["pinghistory"][-200:]
    max_latency = max((latency for _, latency in history if latency >= 0), default=1)
    min_latency = min((latency for _, latency in history if latency >= 0), default=0)
    if max_latency == min_latency:
        max_latency += 1  # Avoid division by zero
    return json.dumps({"history": history, "minLatency": min_latency*0.9, "maxLatency": max_latency*1.1})


def contentcreate_pageforgottennodes():
    '''create forgotten nodes page'''
    global nodedict
    spc='&nbsp;'*1
    pagetext='Past nodes not seen in the current route:<br/>\n'
    pagetext+=f'<table style="width:100%;">\n'
    pagetext+=f'<tr class="tab2_table"><th>{spc}IP Address</th>'
    pagetext+=f'<th>{spc}Hostname</th>'
    pagetext+=f'<th>{spc}Last Seen (UTC)</th>'
    pagetext+=f'<th>{spc}Ping history Count</th></tr>\n'
    pagetext+=f'<th>{spc}Average TTL</th></tr>\n'
    rowindx=0
    currentrouteips={hop['ip'] for hop in currentroute} if currentroute is not None else set()
    forgottenips=set(nodedict.keys()) - currentrouteips
    for ip in forgottenips:
        rowindx+=1
        node=nodedict[ip]
        history_count = len(node["pinghistory"])
        last_seen_time = time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime(node["last_seen"]))
        if rowindx % 2 == 1:
            thisrowcolor="tab2_ra"
        else:
            thisrowcolor="tab2_rb"
        clkip=spanclickdivupdate(ip, "node_details", f"/nodes/{ip}",500)
        clickhostname=spanclickdivupdate(node["hostname"], "node_details", f"/nodes/{ip}",500)
        pagetext+=f'<tr class="{thisrowcolor}">'
        pagetext+=f'<td>{spc}{clkip}</td>'
        pagetext+=f'<td>{spc}{clickhostname}</td>'
        pagetext+=f'<td>{spc}{last_seen_time} UTC</td>'
        pagetext+=f'<td>{spc}{history_count}</td>'
        pagetext+='</tr>\n'
    return pagetext


def contentcreate_hopinfopage(ip):
    '''create hop info page'''
    global nodedict
    global lastip
    lastip = ip
    spc='&nbsp;'*1
    if ip in nodedict:
        statsip=hopstats(ip)
        pagetext=divstart(100,50,(200,200,150),"chartdiv")
        pagetext+=f'<h3>{spc}Node details for {ip}</h3>\n'
        node=nodedict[ip]
        pagetext+=f'{spc}Hostname: {node["hostname"]}<br/>'
        pagetext+=f'{spc}Last seen: {time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime(node["last_seen"]))} UTC<br/>'
        pagetext+=f'{spc}History (epoch time, latency ms):<br/>'
        pagetext+=f'<table style="width:100%;">\n'
        pagetext+=f'<tr class="tab2_header"><th>{spc}UTC Time</th><th>Latency (ms)</th></tr>\n'
        rowindx=0
        reverserlastNhistory=reversed(node["pinghistory"][-25:])  #show last 25 records
        for record in reverserlastNhistory:
            rowindx+=1
            epochtime, latency = record
            if rowindx % 2 == 1:
                thisrowcolor="tab2_ra"
            else:
                thisrowcolor="tab2_rb"
            pagetext+=f'<tr class="{thisrowcolor}"><td>{spc}{epoch2YMDhms(epochtime)}</td><td>{latency:.3f}</td></tr>\n'
        pagetext+='</table>\n'
        pagetext+=divend()
        pagetext+=divstart(100,50,(150,200,200),"statsdiv")
        if statsip is not None:
            pagetext+=f'<h3>{spc}Statistics:</h3><br/><br/>'
            pagetext+=f'<table style="width:100%; font-size: 1.2em;" class="tab2_table">\n'
            pagetext+=f'<tr><td style="text-align: right; width:50%;">{spc}Average latency:{spc}</td><td>{spc}{statsip["average"]:.3f} ms</td></tr>\n'
            pagetext+=f'<tr><td style="text-align: right">{spc}Median latency:{spc}</td><td>{spc}{statsip["median"]:.3f} ms</td></tr>\n'
            pagetext+=f'<tr><td style="text-align: right">{spc}Max latency:{spc}</td><td>{spc}{statsip["max"]:.3f} ms</td></tr>\n'
            pagetext+=f'<tr><td style="text-align: right">{spc}Min latency:{spc}</td><td>{spc}{statsip["min"]:.3f} ms</td></tr>\n'
            pagetext+=f'<tr><td style="text-align: right">{spc}Top 10% latency:{spc}</td><td>{spc}{statsip["top10"]:.3f} ms</td></tr>\n'
            pagetext+=f'<tr><td style="text-align: right">{spc}Bottom 10% latency:{spc}</td><td>{spc}{statsip["low10"]:.3f} ms</td></tr>\n'
            pagetext+=f'<tr><td style="text-align: right">{spc}Average jitter:{spc}</td><td>{spc}{statsip["jitter"]:.3f} ms</td></tr>\n'
            pagetext+=f'<tr><td style="text-align: right">{spc}Packet loss:{spc}</td><td>{spc}{statsip["packetloss"]:.2f}%</td></tr>\n'
            pagetext+=f'<tr><td style="text-align: right">{spc}Total pings:{spc}</td><td>{spc}{statsip["count"]}</td></tr>\n'
            pagetext+=f'<tr><td style="text-align: right">{spc}Average TTL:{spc}</td><td>{spc}{statsip["average_ttl"]:.2f}</td></tr>\n'
            pagetext+='</table>\n'
        pagetext+=divend()
    else:
        pagetext=f'Select a hop IP for history.<br/>'
    #have this div refresh every second
    return pagetext


def routepage():
    '''generate route page'''
    global Banner
    pagetext=htmlpagestart()
    ##create a div for table
    pagetext+=adddiv(5, 100, (55, 55, 55), "Headerdiv")
    pagetext+=adddiv(50, 50, (180, 180, 180), "route_table")
    pagetext+=adddiv(50, 50, (180, 180, 200), "forgotten_nodes")
    pagetext+=adddiv(45, 50, (200, 200, 180), "node_details")
    pagetext+=adddiv(45, 50, (200, 200, 200), "graph_page")
    pagetext+=setdivcontent("graph_page",  "<canvas id='latencyCanvas' width=\"1200\" height=\"600\" style=\"width:100%; height:100%;\"></canvas>")  
    pagetexttable=contentcreate_pagetexttable()
    pagetext+=setdivcontent("Headerdiv", f'<h2 style="color: white;">{Banner}</h2>\n')
    pagetext+=setdivcontent("route_table", pagetexttable)
    pagetext+=divrefresh("route_table", "/syscallroute", 5000)  # refresh every 5 seconds
    pagetext+=divrefresh("forgotten_nodes", "/forgottennodes", 3000)  # refresh every 3 seconds
    pagetext+=htmlpageend()
    return pagetext


class Handler(http.server.BaseHTTPRequestHandler):
    '''   use our own handlers functions '''
    def sendtextinfo(self, code, text, content_type="text/html"):  
        self.send_response(code)  
        self.send_header('Content-type', content_type)  
        self.end_headers()  
        self.wfile.write((str(text)+"\n").encode())

    def do_GET(self):
        '''   handle get   '''
        message=""
        parsed_data = urllib.parse.urlparse(self.path)
        clientpath=parsed_data.geturl().lower()
        if (clientpath == "/route") or (clientpath == "/"): #default route page
            message = routepage()
        elif clientpath == "/routehash":
            if routehash is not None:
                message = f"Current route hash: {routehash}\n"
            else:
                message = "No route hash available.\n"
        elif clientpath.startswith("/nodes"):
            if nodedict:
                message+=contentcreate_hopinfopage(clientpath.split('/')[-1])
            else:
                message = "No node information available.\n"
        elif clientpath == "/syscallroute":
            if currentroute is not None:
                message+=contentcreate_pagetexttable()
            else:
                message = "No route information available.\n"
        elif clientpath == "/forgottennodes":
            message+=contentcreate_pageforgottennodes()
        elif clientpath == "/syscallgraph":
            message = canvaslatencygraph()
            self.sendtextinfo(200, message, "application/json")
            return
        elif clientpath == "/time":
            message = timeYMDhms()
        self.sendtextinfo(200,message)

class ThreadedHTTPServer(socketserver.ThreadingMixIn, http.server.HTTPServer):
    '''    Basic threaded server class    '''
    http.server.HTTPServer.request_queue_size = 128




def columnprint(text, sep='\t'):
    lines=text.strip().split('\n')
    splitlines=[line.split(sep) for line in lines]
    colwidth={}
    for line in splitlines:
        for colnum in range(len(line)):
            colwidth[colnum] = max(colwidth.get(colnum, 0), len(line[colnum]))
    for line in splitlines:
        spacedline=[]
        for colnum in range(len(line)):
            spacedline.append(line[colnum].rjust(colwidth[colnum]+2))
        print(''.join(spacedline))


def singlepacketcheck(destttlproto):
    '''handle single packet send/receive for traceroute'''
    dest, ttl, proto = destttlproto
    if proto == 'UDP':
        port = 33434 + ttl
        pkt = IP(dst=dest, ttl=ttl) / UDP(dport=port)
    elif proto == 'TCP':
        pkt = IP(dst=dest, ttl=ttl) / TCP(dport=80, flags="S")
    else:
        pkt = IP(dst=dest, ttl=ttl) / ICMP()
    timebefore = time.time()
    reply = sr1(pkt, verbose=0, timeout=2)
    hostname = "*"
    srcip = "*"
    destflag = False
    if reply is not None:
        srcip = reply.src
        try:
            hostname = socket.gethostbyaddr(reply.src)[0]
        except socket.herror:
            hostname = reply.src
        if reply.haslayer("ICMP"):
            icmp_layer = reply.getlayer("ICMP")
            if proto == "UDP" and icmp_layer.type == 3 and icmp_layer.code == 3:  
                destflag = True
            elif proto == "ICMP" and icmp_layer.type == 0:  
                destflag = True
            elif proto == "TCP" and icmp_layer.type == 3 and icmp_layer.code in [1,2,3]:  
                destflag = True
        elif proto == "TCP" and reply.haslayer("TCP"):
            tcp_layer = reply.getlayer("TCP")
            if tcp_layer.flags in ["R", "RA", "S", "SA"]:
                destflag = True
    timeafter = time.time()
    latency = (timeafter - timebefore) * 1000
    return ttl, latency, srcip, hostname, destflag


def ping_scapy(dest):
    print(f"Pinging {dest} with ICMP packets:")
    pkt = IP(dst=dest) / ICMP()
    timebefore = time.time()
    reply = sr1(pkt, verbose=0, timeout=2)
    timeafter = time.time()
    latency = (timeafter - timebefore) * 1000  
    if reply is None:
        latency = -1
    return latency, reply, dest


def threadedbatchjobs(function, joblist, max_workers=10):
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        results = list(executor.map(function, joblist))
    return results


def traceroute_scapy(dest, max_hops=maxhops, proto="UDP"):
    print(f"Hop monitoring to {dest}, {max_hops} hops max")
    dest_ttl_jobs = [(dest, ttl, proto) for ttl in range(1, max_hops + 1)] #setup job tuples
    results = threadedbatchjobs(singlepacketcheck, dest_ttl_jobs, max_workers=10) #threaded all jobs
    textout=""
    route=[]
    for ttl, latency, srcip, hostname, destflag in results:
        hop={}
        hop['ttl']=ttl
        hop['latency']=latency
        hop['ip']=srcip
        hop['hostname']=hostname
        route.append(hop)
        destination = ""
        if destflag:
            destination = "\t[Destination reached]"
        textout += f"{ttl}\t{hostname}\t({srcip})\t{latency:.3f} ms{destination}\n"
        if destflag:
            break
    columnprint(textout)
    return route


def route2md5(route):
    route_str = '-'.join(f"{hop['ip']}" for hop in route)
    route_hash = hashlib.md5(route_str.encode()).hexdigest()
    return route_hash


def averagettl(ip):
    global nodedict
    if ip not in nodedict:
        return None
    ttlhistory = nodedict[ip]['ttlhistory']
    ttlsum=0
    for epoch,ttl in ttlhistory:
        ttlsum+=ttl*1.0
    averagettl=ttlsum/len(ttlhistory) if len(ttlhistory)>0 else 0
    return averagettl


def timeYMDhms():
    tnow = time.time()
    return epoch2YMDhms(tnow)


def epoch2YMDhms(epochtime):
    gnow = time.strftime('%Y-%m-%d %H:%M:%S', time.gmtime(epochtime)) #Formatted UTC time
    return gnow


def backgroundHTTPserver():
    HTSERVER = ThreadedHTTPServer(('', HTPORT), Handler)
    HTSERVER.timeout = 1
    while not exitflag.is_set():  
        try:  
            HTSERVER.handle_request()  
        except Exception:  
            pass  # Optionally, handle/print exceptions  
    print("HTTP server exiting.")  


def updatehopswithcurrentroute():
    global currentroute
    global nodedict
    epochtime = time.time()
    thispasscheck=set()
    for hop in currentroute: #use set to avoid duplicates
        if hop['ip'] != "*":
            if hop['ip'] in thispasscheck:
                continue
            thispasscheck.add(hop['ip'])
            if hop['ip'] not in nodedict:
                nodedict[hop['ip']] = hop
                nodedict[hop['ip']]["pinghistory"] = []
                nodedict[hop['ip']]["lastpingtime"] = 0
                nodedict[hop['ip']]["ttlhistory"] = []
            nodedict[hop['ip']]['last_seen'] = epochtime
            nodedict[hop['ip']]["ttlhistory"].append((epochtime, hop['ttl']))


def backgroundupdateroute():
    global currentroute
    global routehist
    global routedict
    global nodedict
    global routehash
    sleeptime=10  # update route every 10 seconds
    while 1:
        for _i in range(sleeptime*10):
            time.sleep(0.1)  # Sleep for 10 seconds
            if exitflag.is_set():
                break
        if exitflag.is_set():
            break
        newroute = traceroute_scapy(dest)
        newroutehash = route2md5(newroute)
        epochtime = time.time()
        if currentroute is None or newroutehash != routehash:
            routedict[newroutehash] = newroute
            currentroute = newroute
            routehash = newroutehash
            routeupdatetime = timeYMDhms()
            print(f"Route updated at {routeupdatetime}. New route hash: {routehash}")
        updatehopswithcurrentroute()


def backgroundpinghops():
    global nodedict
    sleeptime=1
    while 1:
        for _i in range(sleeptime*10):
            time.sleep(0.1)  # Sleep for 1 second
            if exitflag.is_set():
                break
        if exitflag.is_set():
            break
        pingjobs=[]
        for ip in nodedict.keys():
            last_seen = nodedict[ip]['last_seen']
            tnow = time.time()
            if tnow - last_seen > 300:  # If not seen for more than 5 minutes, don't bother pinging
                continue
            if tnow - last_seen > 60:  # If not seen for more than 1 minute, ping slow
                if tnow - nodedict[ip]['lastpingtime'] < 5:
                    continue
            pingjobs.append(ip)
        pingresults = threadedbatchjobs(ping_scapy, pingjobs, max_workers=25)
        tnow = time.time()
        with nodedict_lock:
            for latency, reply, ip in pingresults:
                if ip in nodedict:
                    epochtime = time.time()
                    if not reply:
                        latency = -1  # Indicate no reply with -1 latency
                    nodedict[ip]['pinghistory'].append((epochtime, latency))
                    nodedict[ip]['lastpingtime'] = tnow


def savehistory(savefilename):
    global nodedict
    global currentroute
    global routedict
    print(f"Saving history to {savefilename}...")
    save_data = {
        'nodedict': nodedict,
        'currentroute': currentroute,
        'routedict': routedict,
        'timestamp': timeYMDhms()
    }
    with open(savefilename, 'w') as f:
        json.dump(save_data, f, indent=4)
    print("History saved.")


if __name__ == "__main__":
    args = sys.argv
    dest=args[1]

    if dest == "-load":
        loadfilename=args[2]
        print(f"Loading history from {loadfilename}...")
        with open(loadfilename, 'r') as f:
            load_data = json.load(f)
            nodedict = load_data.get('nodedict', {})
            currentroute = load_data.get('currentroute', None)
            routedict = load_data.get('routedict', {})
        print("History loaded.")
        Banner=f"Loaded monitoring hops from {loadfilename}"
        webthread=threading.Thread(target=backgroundHTTPserver)
        webthread.start()
        while 1:
            try:
                while not exitflag.is_set():
                    time.sleep(1)
            except KeyboardInterrupt:
                exitflag.set()
                print("Exiting...")
                break
    else: #assume serving page as normal
        currentroute=traceroute_scapy(dest)
        routehash = route2md5(currentroute)
        tnow = timeYMDhms().replace(' ', 'T').replace(':', '').replace('-', '')
        savefilename=f"log_{dest.replace('.', '_').replace(':', '_')}_{tnow}.json"
        Banner=f"Monitoring hops to {dest}. Save on exit to {savefilename}"
        updatehopswithcurrentroute()
        webthread=threading.Thread(target=backgroundHTTPserver)
        webthread.start()
        updatethread=threading.Thread(target=backgroundupdateroute)
        updatethread.start()
        pingthread=threading.Thread(target=backgroundpinghops)
        pingthread.start()
        while 1:
            try:
                while not exitflag.is_set():
                    time.sleep(1)
            except KeyboardInterrupt:
                exitflag.set()
                print("Exiting...")
                webthread.join()
                savehistory(savefilename)
                break
 