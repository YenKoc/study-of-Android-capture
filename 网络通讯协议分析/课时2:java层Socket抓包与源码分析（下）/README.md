# UDP socket分析
# 流程分析
java.net.DatagramSocket->receive  

PlainDatagramSocketImpl

发送数据
PlainDatagramSocketImpl.send->
IoBridge.sendto(fd, p.getData(), p.getOffset(), p.getLength(), 0, address, port);->  
Libcore.os.sendto(fd, bytes, byteOffset, byteCount, flags, inetAddress, port);->  
```
public final class Libcore {
20    private Libcore() { }
21
22    /**
23     * Direct access to syscalls. Code should strongly prefer using {@link #os}
24     * unless it has a strong reason to bypass the helpful checks/guards that it
25     * provides.
26     */
27    public static Os rawOs = new Linux();
28
29    /**
30     * Access to syscalls with helpful checks/guards.
31     */
32    public static Os os = new BlockGuardOs(rawOs);
33}
34```
->  
/libcore/luni/src/main/java/libcore/io/Linux.java  

```
  public int sendto(FileDescriptor fd, ByteBuffer buffer, int flags, InetAddress inetAddress, int port) throws ErrnoException, SocketException {
213        final int bytesSent;
214        final int position = buffer.position();
215
216        if (buffer.isDirect()) {
217            bytesSent = sendtoBytes(fd, buffer, position, buffer.remaining(), flags, inetAddress, port);
218        } else {
219            bytesSent = sendtoBytes(fd, NioUtils.unsafeArray(buffer), NioUtils.unsafeArrayOffset(buffer) + position, buffer.remaining(), flags, inetAddress, port);
220        }
221
222        maybeUpdateBufferPosition(buffer, position, bytesSent);
223        return bytesSent;
224    }
```

 private native int sendtoBytes(FileDescriptor fd, Object buffer, int byteOffset, int byteCount, int flags, InetAddress inetAddress, int port) throws ErrnoException, SocketException;
 private native int sendtoBytes(FileDescriptor fd, Object buffer, int byteOffset, int byteCount, int flags, SocketAddress address) throws ErrnoException, SocketException;
```
接收数据


```
  public int recvfrom(FileDescriptor fd, ByteBuffer buffer, int flags, InetSocketAddress srcAddress) throws ErrnoException, SocketException {
191        final int bytesReceived;
192        final int position = buffer.position();
193
194        if (buffer.isDirect()) {
195            bytesReceived = recvfromBytes(fd, buffer, position, buffer.remaining(), flags, srcAddress);
196        } else {
197            bytesReceived = recvfromBytes(fd, NioUtils.unsafeArray(buffer), NioUtils.unsafeArrayOffset(buffer) + position, buffer.remaining(), flags, srcAddress);
198        }
199
200        maybeUpdateBufferPosition(buffer, position, bytesReceived);
201        return bytesReceived;
202    }
203    public int recvfrom(FileDescriptor fd, byte[] bytes, int byteOffset, int byteCount, int flags, InetSocketAddress srcAddress) throws ErrnoException, SocketException {
204        // This indirection isn't strictly necessary, but ensures that our public interface is type safe.
205        return recvfromBytes(fd, bytes, byteOffset, byteCount, flags, srcAddress);
206    }
207    private native int recvfromBytes(FileDescriptor fd, Object buffer, int byteOffset, int byteCount, int flags, InetSocketAddress srcAddress) throws ErrnoException, SocketException;
```

# hook exp
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

function hookudp() {
    Java.perform(function () {
        var LinuxClass = Java.use('libcore.io.Linux');
        //private native int recvfromBytes(FileDescriptor fd, Object buffer, int byteOffset, int byteCount, int flags, InetSocketAddress srcAddress) throws ErrnoException, SocketException;
        LinuxClass.recvfromBytes.implementation = function (arg0, arg1, arg2, arg3, arg4, arg5) {
            var size = this.recvfromBytes(arg0, arg1, arg2, arg3, arg4, arg5);
            var bytearray = Java.array('byte', arg1);
            var content = "";
            for (var i = 0; i < size; i++) {

                if (isprintable(bytearray[i])) {
                    content = content + String.fromCharCode(bytearray[i]);
                }

            }
            console.log("address:" + arg5 + " [" + Process.getCurrentThreadId() + "]recvfromBytes:size:" + size + ",content:" + JSON.stringify(arg1) + "---content," + content);
            printJavaStack('recvfromBytes');
            return size;
        }
        //private native int sendtoBytes(FileDescriptor fd, Object buffer, int byteOffset, int byteCount, int flags, InetAddress inetAddress, int port) throws ErrnoException, SocketException;
        // private native int sendtoBytes(FileDescriptor fd, Object buffer, int byteOffset, int byteCount, int flags, SocketAddress address) throws ErrnoException, SocketException;
        LinuxClass.sendtoBytes.overload('java.io.FileDescriptor', 'java.lang.Object', 'int', 'int', 'int', 'java.net.InetAddress', 'int').implementation = function (arg0, arg1, arg2, arg3, arg4, arg5, arg6) {
            var size = this.sendtoBytes(arg0, arg1, arg2, arg3, arg4, arg5, arg6);
            var bytearray = Java.array('byte', arg1);
            var content = "";
            for (var i = 0; i < size; i++) {
                if (isprintable(bytearray[i])) {
                    content = content + String.fromCharCode(bytearray[i]);
                }

            }
            console.log("address:" + arg5 + ",port" + arg6 + " [" + Process.getCurrentThreadId() + "]LinuxClass11.sendtoBytes:len:" + size + "--content:" + JSON.stringify(arg1) + "--content:" + content);
            printJavaStack('LinuxClass11.sendtoBytes')
            return size;
        }
        LinuxClass.sendtoBytes.overload('java.io.FileDescriptor', 'java.lang.Object', 'int', 'int', 'int', 'java.net.SocketAddress').implementation = function (arg0, arg1, arg2, arg3, arg4, arg5) {
            var size = this.sendtoBytes(arg0, arg1, arg2, arg3, arg4, arg5);
            var bytearray = Java.array('byte', arg1);
            var content = "";
            for (var i = 0; i < size; i++) {
                if (isprintable(bytearray[i])) {
                    content = content + String.fromCharCode(bytearray[i]);
                }
            }
            console.log("address:" + arg5 + " [" + Process.getCurrentThreadId() + "]LinuxClass22.sendtoBytes:len:" + size + "--content:" + JSON.stringify(arg1) + ",content:" + content);
            printJavaStack('LinuxClass22.sendtoBytes')
            return size;
        }


    })

}

function main() {
    hookudp();
}

setImmediate(main)
```
