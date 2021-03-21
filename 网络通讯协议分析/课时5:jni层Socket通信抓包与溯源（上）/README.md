# 概述
一些app并没有走java层开始发包，而是直接调用了native层的发包函数，所以如果我们再用之前的那套socket抓包，会发现无法抓到包，但是wireshark是可以抓到包的，所以我们需要在之前jni函数的hook下，继续往更底层的函数api，进行hook，还是挺有意思的

# 1. 抓包开始
- android的jni函数取名有规律，一般为类名_jni函数名，比如SocketInputStream_socketRead0，通过对mk文件追踪得知这些api在libopenjdk.so中，所以从/system/lib/目录下，进行pull下来，ida开始分析
- 因为这个jni函数在源码中并没有静态注册的特征，所以是动态注册，通过jni_onload的分析，发现了真正的函数所在，并通过找xref from图，找到了下一层调用的函数，下面将流程进一步补充
- 
java.net.Socket类构造函数: new Socket(ip,port);->Socket(InetAddress[] addresses,int port,SocketAddress localAddr,boolean stream)  
->impl->java.net.SocksSocketImpl->建立连接：connect(SocketAddress endpoint)  
jni:socketRead0->Net_Read->; ssize_t recvfrom(int fd, void *buf, size_t n, int flags, struct sockaddr *addr, socklen_t *addr_len)
extern:00028D60                 IMPORT __imp_recvfrom   ; CODE XREF: recvfrom+8↑j   

libc.so: recvfrom sycall: 
```

   EXPORT recvfrom
recvfrom
MOV             R12, SP
PUSH            {R4-R7}
LDM             R12, {R4-R6}
MOV             R7, #0x124
SVC             0
POP             {R4-R7}
CMN             R0, #0x1000
BXLS            LR
```
接收数据：java.net.SocketInputStream.read(byte[])->read(b,0,b.length)->read(b,off,length,impl.getTimeout())->socketRead(fd, b, off, length, timeout);(native)
发送数据: java.net.SocketOutputStream.write(byte[])->socketWrite(b,0,b.length)->socketWrite0(fd,b,off,len)

jni:socketWrite0->Net_Send->ssize_t sendto(int fd, const void *buf, size_t n, int flags, const struct sockaddr *addr, socklen_t addr_len)
libc.so: sendto
```
EXPORT sendto
sendto
MOV             R12, SP
PUSH            {R4-R7}
LDM             R12, {R4-R6}
MOVW            R7, #0x122
SVC             0
POP             {R4-R7}
CMN             R0, #0x1000
BXLS            LR
```

- 其他问题就是java层和jni层都会调用那个api，所以打印堆栈可能有重复，解决的方式就是通过比对调用栈的第一层函数，是谁，如果是libopenjdk开头，说明是java层的，则不打印就完事了，放下exp
```
function printNativeStack(context,name)
{
    //Debug
    var array=Thread.backtrace(context,Backtracer.ACCURATE).map(DebugSymbol.fromAddress).join("\n");
    var first=DebugSymbol.fromAddress(array[0]);

    if(first.indexOf("libopenjdk.so!NET_Send")<0)
    {
        var trace=Thread.backtrace(context,Backtracer.ACCURATE).map(DebugSymbol.fromAddress).join("\n");

        LogPrint("-------------start:"+name+"-----------------");
  
        LogPrint(trace);
        
        LogPrint("-------------end:"+name+"------------------");
    }
    
}
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
function hooklibc()
{
    var libcmodule=Process.getModuleByName("libc.so");
    var recvfrom_addr=libcmodule.getExportByName("recvfrom");
    var sendto_addr=libcmodule.getExportByName("sendto")
    //ssize_t recvfrom(int fd, void *buf, size_t n, int flags, struct sockaddr *addr, socklen_t *addr_len)
    Interceptor.attach(recvfrom_addr,{
        onEnter:function(args)
        {
            this.args0=args[0];
            this.args1=args[1];
            this.args2=args[2];
         LogPrint('go int libc.so->recvform');       
        },onLeave:function(retval)
        {
            var size=retval.toInt32();
            console.log("libc.so->recvfrom:"+hexdump(this.arg1,{
                length:size
            }));
            LogPrint('leave libc.so->recvform');
        }
    })
    Interceptor.attach(recvfrom_addr,{
        onEnter:function(args)
        {
            this.args0=args[0];
            this.args1=args[1];
            this.args2=args[2];
         LogPrint('go int libc.so->sendto');       
        },onLeave:function(retval)
        {
            var size=ptr(this.args2).toInt32();
            if(size>0)
            {
                console.log("libc.so->sendto:"+hexdump(this.arg1,{
                    length:size
                }));
            }
            
            LogPrint('leave libc.so->recvform');
        }
    })
}
function main()
{

}
setImmediate(main);
```