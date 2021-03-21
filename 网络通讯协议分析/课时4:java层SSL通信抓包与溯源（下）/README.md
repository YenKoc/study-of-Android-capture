1. 在idea中进行动调，跟到native函数，进行hook
2. exp:
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

function hooksslsocket() {
    Java.perform(function () {
        var SSLInputStreamClass = Java.use('com.android.org.conscrypt.OpenSSLSocketImpl$SSLInputStream');
        //public int read(byte[] buf, int offset, int byteCount)
        SSLInputStreamClass.read.overload().implementation = function () {
            var value = this.read();
            var sslsocketimplwrapper = this.this$0.value;
            console.log("SSLInputStreamClass.read 1obj->" + sslsocketimplwrapper);
            var socket = sslsocketimplwrapper.socket.value;
            console.log("SSLInputStreamClass.read 1socket->" + socket);
            //console.log("[" + Process.getCurrentThreadId() + "]SSLInputStreamClass.read:len:" + 4 + "--content:" + JSON.stringify(value));
            console.log("[" + Process.getCurrentThreadId() + "]sslsocket read a int:" + value);
            printJavaStack('sslInputStream.read()')
            return value;
        }

        SSLInputStreamClass.read.overload('[B', 'int', 'int').implementation = function (arg0, arg1, arg2) {
            var size = this.read(arg0, arg1, arg2);
            //内部类对象直接得到外部类对象的方法
            var sslsocketimplwrapper = this.this$0.value;
            console.log("SSLInputStreamClass.read 2obj->" + sslsocketimplwrapper);
            var socket = sslsocketimplwrapper.socket.value;
            console.log("SSLInputStreamClass.read 2socket->" + socket);
            //console.log("[" + Process.getCurrentThreadId() + "]SSLInputStreamClass.read:len:" + size + "--content:" + JSON.stringify(arg0));
            var bytearray = Java.array('byte', arg0);
            var content = '';
            for (var i = 0; i < size; i++) {
                if (isprintable(bytearray[i])) {
                    content = content + String.fromCharCode(bytearray[i]);
                }
            }
            /*            var socketimpl = this.impl.value;
                        var address = socketimpl.address.value;
                        var port = socketimpl.port.value;*/
            console.log("[" + Process.getCurrentThreadId() + "]sslsocket read:" + content);
            //console.log("\n" + JSON.stringify(this.socket.value) + "\n[" + Process.getCurrentThreadId() + "]send:" + content);
            printJavaStack('sslInputStream.read')
            return size;
        }

        var SSLOutputStreamClass = Java.use('com.android.org.conscrypt.OpenSSLSocketImpl$SSLOutputStream');
        SSLOutputStreamClass.write.overload('int').implementation = function (arg0) {
            var result = this.write(arg0);
            //通过内部类对象得到外部类对象
            var sslsocketimplwrapper = this.this$0.value;
            console.log("SSLOutputStream 1obj->" + sslsocketimplwrapper);
            var socket = sslsocketimplwrapper.socket.value;
            console.log("SSLOutputStream 1socket->" + socket);
            /*SSLOutputStream 2obj->SSL socket over Socket[address=portal.meirishanglai.com/240.0.0.21,port=443,localPort=37563]
              SSLOutputStream 2socket->Socket[address=portal.meirishanglai.com/240.0.0.21,port=443,localPort=37563]
            */
            console.log("[" + Process.getCurrentThreadId() + "]write(int):len:" + 4 + "--content:" + arg0);
            printJavaStack('sslOutputStream.write(int)')
            return result;
        }

        //public void write(byte[] buf, int offset, int byteCount)
        SSLOutputStreamClass.write.overload('[B', 'int', 'int').implementation = function (arg0, arg1, arg2) {
            var result = this.write(arg0, arg1, arg2);
            var sslsocketimplwrapper = this.this$0.value;
            console.log("SSLOutputStream 2obj->" + sslsocketimplwrapper);
            var socket = sslsocketimplwrapper.socket.value;
            console.log("SSLOutputStream 2socket->" + socket);
            //console.log("[" + Process.getCurrentThreadId() + "]socketWrite0:len:" + arg2 + "--content:" + JSON.stringify(arg0));
            var bytearray = Java.array('byte', arg0);
            var content = '';
            for (var i = 0; i < arg2; i++) {
                if (isprintable(bytearray[i])) {
                    content = content + String.fromCharCode(bytearray[i]);
                }

            }
            /*            var socketimpl = this.impl.value;
                        var address = socketimpl.address.value;
                        var port = socketimpl.port.value;*/
            console.log("[" + Process.getCurrentThreadId() + "]sslsocket send:" + content);
            //console.log("\n" + JSON.stringify(this.socket.value) + "\n[" + Process.getCurrentThreadId() + "]send:" + content);
            printJavaStack('sslOutputStream.write')
            return result;
        }
    })
}

function main() {
    hooksslsocket();
}

setImmediate(main)
```