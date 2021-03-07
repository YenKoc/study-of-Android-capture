# 解决问题
1. 如何对自定义协议进行逆向分析
2. 发送参数被加密，如何快速完成参数处理流程的定位
3. 加密算法复杂，如何主动调用完成对数据的处理和重放
# 目标
1. 掌握阅读和分析Android系统框架层网络数据包接收发送的源码逻辑
2. 掌握快速进行字段追踪溯源的技巧
3. 掌握基于frida、xposed、AndroidNativeEmu、Unidbg等的主动调用技巧
，从而完成对协议的枚举和爆破、甚至是数据的爬取

# 逆向分析的思想
1. 堆栈回溯思想
安卓开发分成java层和native层，同样的协议的加密，也是在这两层做的，只是安全系数高的app，会把更多的加密流程
放在native层中，至于堆栈回溯，也分为java层的堆栈，以及native的堆栈，这个看有，各自的技巧，目前我还没学到233，
不过通过堆栈找关键加密的逻辑是一件很方便的事情
2. 控制流分析与数据流分析相结合的思想
控制流分析和堆栈回溯是一个相互逆向的过程，不过控制流分析是正向的，一个输入的数据，是如何一步步的进行加密，经过了哪些函数，而堆栈回溯是从结果倒推上去，至于数据流分析，就是一个数据如何进入一个api后，进行加密，所以我们可以对系统框架层的api进行hook，例如okhttp。
3. 关键字符串、关键api
这个搜索关键字符串就不用多说了，老熟悉了233

# java层socket抓包之tcp抓包
1. 基本就是寒冰大佬自己实现的一个tcp通信，然后发现实际上还是调用了java层的socket的api，一步一步跟踪源码，太爽了
发现过程是这样的:  
java.net.Socket类构造函数: new Socket(ip,port);->Socket(InetAddress[] addresses,int port,SocketAddress localAddr,boolean stream)  
->impl->java.net.SocksSocketImpl->建立连接：connect(SocketAddress endpoint)  

接收数据：java.net.SocketInputStream.read(byte[])->read(b,0,b.length)->read(b,off,length,impl.getTimeout())->socketRead(fd, b, off, length, timeout);(native)
发送数据: java.net.SocketOutputStream.write(byte[])->socketWrite(b,0,b.length)->socketWrite0(fd,b,off,len)

2. hook关键api，并打印调用栈，里面一些字符串的转换需要注意，有点jni开发的感觉，靠,而且可以嫖一手打印堆栈的源码了233
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

function hooktcp() {
    Java.perform(function () {
        var SocketClass = Java.use('java.net.Socket');
        SocketClass.$init.overload('java.lang.String', 'int').implementation = function (arg0, arg1) {
            console.log("[" + Process.getCurrentThreadId() + "]new Socket connection:" + arg0 + ",port:" + arg1);
            printJavaStack('tcp connect...')
            return this.$init(arg0, arg1);
        }
        var SocketInputStreamClass = Java.use('java.net.SocketInputStream');
        //socketRead0
        SocketInputStreamClass.socketRead0.implementation = function (arg0, arg1, arg2, arg3, arg4) {
            var size = this.socketRead0(arg0, arg1, arg2, arg3, arg4);
            //console.log("[" + Process.getCurrentThreadId() + "]socketRead0:size:" + size + ",content:" + JSON.stringify(arg1));
            var bytearray = Java.array('byte', arg1);
            var content = '';
            for (var i = 0; i < size; i++) {
                if (isprintable(bytearray[i])) {
                    content = content + String.fromCharCode(bytearray[i]);
                }
            }
            var socketimpl = this.impl.value;
            var address = socketimpl.address.value;
            var port = socketimpl.port.value;

            console.log("\naddress:" + address + ",port" + port + "\n" + JSON.stringify(this.socket.value) + "\n[" + Process.getCurrentThreadId() + "]receive:" + content);
            printJavaStack('socketRead0')
            return size;
        }
        var SocketOutPutStreamClass = Java.use('java.net.SocketOutputStream');
        SocketOutPutStreamClass.socketWrite0.implementation = function (arg0, arg1, arg2, arg3) {
            var result = this.socketWrite0(arg0, arg1, arg2, arg3);
            //console.log("[" + Process.getCurrentThreadId() + "]socketWrite0:len:" + arg3 + "--content:" + JSON.stringify(arg1));
            var bytearray = Java.array('byte', arg1);
            var content = '';
            for (var i = 0; i < arg3; i++) {

                if (isprintable(bytearray[i])) {
                    content = content + String.fromCharCode(bytearray[i]);
                }
            }
            var socketimpl = this.impl.value;
            var address = socketimpl.address.value;
            var port = socketimpl.port.value;
            console.log("send address:" + address + ",port" + port + "[" + Process.getCurrentThreadId() + "]send:" + content);
            console.log("\n" + JSON.stringify(this.socket.value) + "\n[" + Process.getCurrentThreadId() + "]send:" + content);
            printJavaStack('socketWrite0')
            return result;
        }
    })
}

function main() {
    hooktcp();
}

setImmediate(main)
```