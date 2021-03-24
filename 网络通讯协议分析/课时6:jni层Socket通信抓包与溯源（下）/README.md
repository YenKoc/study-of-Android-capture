# 从上文而来的补充，获取ip和端口
- frida提供了可以通过套接字fd，获得通信的api，所以直接利用
```
function getsocketdetail(fd)
{
    var result="";
    var type=result.type(fd);
    if(type!=null)
    {
        result=result+"type:"+type;
        var address=Socket.peerAddress(fd);
        var local=Socket.localAddress(fd);
        result=result+",address:"+JSON.stringify(address)+",local:"+JSON.stringify(local);
    }else{
        result="unknown";
    }
    return result;
    
}
```

# 之前是从tcp的角度进行抓包，现在从UDP角度去抓
- 会有些差别，因为在实际调试过程中，发现第一个参数套接字，已经无法从中得到ip和端口了，所以只能从第4个参数进行hook，取出来，发现是一个结构体，一个字节一个字节的读取出来，然后再本地计算，拼接，就ok了。
```
function LogPrint(log) {
    var theDate = new Date();
    var hour = theDate.getHours();
    var minute = theDate.getMinutes();
    var second = theDate.getSeconds();
    var mSecond = theDate.getMilliseconds();

    hour < 10 ? hour = "0" + hour : hour;
    minute < 10 ? minute = "0" + minute : minute;
    second < 10 ? second = "0" + second : second;
    mSecond < 10 ? mSecond = "00" + mSecond : mSecond < 100 ? mSecond = "0" + mSecond : mSecond;
    var time = hour + ":" + minute + ":" + second + ":" + mSecond;
    var threadid = Process.getCurrentThreadId();
    console.log("[" + time + "]" + "->threadid:" + threadid + "--" + log);

}

function printNativeStack(context, name) {
    //Debug.
    var array = Thread.backtrace(context, Backtracer.ACCURATE);
    var first = DebugSymbol.fromAddress(array[0]);
    if (first.toString().indexOf('libopenjdk.so!NET_Send') < 0) {
        var trace = Thread.backtrace(context, Backtracer.ACCURATE).map(DebugSymbol.fromAddress).join("\n");
        LogPrint("-----------start:" + name + "--------------");
        LogPrint(trace);
        LogPrint("-----------end:" + name + "--------------");
    }

}

function printJavaStack(name) {
    Java.perform(function () {
        var Exception = Java.use("java.lang.Exception");
        var ins = Exception.$new("Exception");
        var straces = ins.getStackTrace();
        if (straces != undefined && straces != null) {
            var strace = straces.toString();
            var replaceStr = strace.replace(/,/g, " \n ");
            LogPrint("=============================" + name + " Stack strat=======================");
            LogPrint(replaceStr);
            LogPrint("=============================" + name + " Stack end======================= \n ");
            Exception.$dispose();
        }
    });
}

function isprintable(value) {
    if (value >= 32 && value <= 126) {
        return true;
    }
    return false;
}

function getsocketdetail(fd) {
    var result = "";
    var type = Socket.type(fd);
    if (type != null) {
        result = result + "type:" + type;
        var peer = Socket.peerAddress(fd);
        var local = Socket.localAddress(fd);
        result = result + ",address:" + JSON.stringify(peer) + ",local:" + JSON.stringify(local);
    } else {
        result = "unknown";
    }
    return result;

}

function getip(ip_ptr) {
    var result = ptr(ip_ptr).readU8() + "." + ptr(ip_ptr.add(1)).readU8() + "." + ptr(ip_ptr.add(2)).readU8() + "." + ptr(ip_ptr.add(3)).readU8()
    return result;
}

function getudpaddr(addrptr) {
    var port_ptr = addrptr.add(2);
    var port = ptr(port_ptr).readU8() * 256 + ptr(port_ptr.add(1)).readU8();
    var ip_ptr = addrptr.add(4);
    var ip_addr = getip(ip_ptr);
    return "peer:"+ip_addr+"--port:"+port;
}

function hooklibc() {
    var libcmodule = Process.getModuleByName("libc.so");
    var recvfrom_addr = libcmodule.getExportByName("recvfrom");
    var sendto_addr = libcmodule.getExportByName("sendto");
    console.log(recvfrom_addr + "---" + sendto_addr);
    //ssize_t recvfrom(int fd, void *buf, size_t n, int flags, struct sockaddr *addr, socklen_t *addr_len)
    Interceptor.attach(recvfrom_addr, {
        onEnter: function (args) {
            this.arg0 = args[0];
            this.arg1 = args[1];
            this.arg2 = args[2];
            this.arg3 = args[3];
            this.arg4 = args[4];
            this.arg5 = args[5];
            LogPrint("go into libc.so->recvfom");

            printNativeStack(this.context, "recvfom");
        }, onLeave(retval) {
            var size = retval.toInt32();
            if (size > 0) {
                var result = getsocketdetail(this.arg0.toInt32());
                if (result.indexOf('udp') >= 0) {
                    /*75struct sockaddr_in {
                    76	short	sin_family;
                    77	u_short	sin_port;
                    78	struct in_addr	sin_addr;
                    79	char	sin_zero[8];
                    80};*/
                    var sockaddr_in_ptr = this.arg4;
                    var sizeofsockaddr_in = this.arg5;

                    //02 00 22 b8 c0 a8 05 96 00 00 00 00 00 00 00 00
                    console.log("this is a recvfrom udp!->" + getudpaddr(sockaddr_in_ptr) + "---" + sizeofsockaddr_in);
                }
                console.log(Process.getCurrentThreadId()+result + "---libc.so->recvfrom:" + hexdump(this.arg1, {
                    length: size
                }));
            }

            LogPrint("leave libc.so->recvfom");
        }
    });
    //ssize_t sendto(int fd, const void *buf, size_t n, int flags, const struct sockaddr *addr, socklen_t addr_len)
    Interceptor.attach(sendto_addr, {
        onEnter: function (args) {
            this.arg0 = args[0];
            this.arg1 = args[1];
            this.arg2 = args[2];
            this.arg3 = args[3];
            this.arg4 = args[4];
            this.arg5 = args[5];
            LogPrint("go into libc.so->sendto");
            printNativeStack(this.context, "sendto");
        }, onLeave(retval) {
            var size = ptr(this.arg2).toInt32();
            if (size > 0) {
                var result = getsocketdetail(this.arg0.toInt32());
                if (result.indexOf('udp') >= 0) {
                    /*75struct sockaddr_in {
                    76	short	sin_family;
                    77	u_short	sin_port;
                    78	struct in_addr	sin_addr;
                    79	char	sin_zero[8];
                    80};*/
                    var sockaddr_in_ptr = this.arg4;
                    var sizeofsockaddr_in = this.arg5;

                    //02 00 22 b8 c0 a8 05 96 00 00 00 00 00 00 00 00
                    console.log("this is a sendto udp!->" + getudpaddr(sockaddr_in_ptr) + "---" + sizeofsockaddr_in);
                }
                console.log(Process.getCurrentThreadId()+"---"+result + "---libc.so->sendto:" + hexdump(this.arg1, {
                    length: size
                }));
            }

            LogPrint("leave libc.so->sendto");
        }
    });
}

function main() {
    hooklibc();
}

setImmediate(main);
```