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

