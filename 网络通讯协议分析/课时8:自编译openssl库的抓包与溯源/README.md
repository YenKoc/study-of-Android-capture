# 前言: 
很多app用openssl自编译来进行接发包，如果使用上节课的，直接hook 系统自带的openssl的来收发包
# 笔记
- 用c编写openssl时，是需要进行绑定的，主要是通过这个SSL_set_fd函数进行绑定，参数一个为SSL *ssl,另一个为int fd，如果我们要获取通信的ip的话，我们需要直接对fd进行获取，然后再使用我们上一节的解析函数，使用frida的api进行获取ip和端口
- 发现在libssl中也有这个函数可以直接获取fd的，SSL_get_fd()，方法是可以直接返回的fd的，所以我们需要去主动调用它
```
 var libcmodule = Process.getModuleByName("libssl.so");
    var read_addr = libcmodule.getExportByName("SSL_read");
    var write_addr = libcmodule.getExportByName("SSL_write");
    var SSL_get_rfd_ptr=libcmodule.getExportByName("SSL_get_rfd");
    var SSL_get_rfd=new NativeFunction(SSL_get_rfd_ptr,'int',['pointer']);
```

# 自编译的openssl
感觉那个例子不太好，实际上不一定是ssl_write，自定义的库，直接抹符号，遍历不出来的，寒冰佬的libc中的write或者send函数，直接栈回溯才是真的，然后毕竟api的调用 是ssl_write-> BIO write-》libc write，后两个是密文的流量了，第一个才是明文，ssl_write找到在哪个so中，然后hook就完事了

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
    var trace = Thread.backtrace(context, Backtracer.FUZZY).map(DebugSymbol.fromAddress).join("\n");
    LogPrint("-----------start:" + name + "--------------");
    LogPrint(trace);
    LogPrint("-----------end:" + name + "--------------");

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

function hooklibc() {
    var libcmodule = Process.getModuleByName("libc.so");
    var read_addr = libcmodule.getExportByName("read");
    var write_addr = libcmodule.getExportByName("write");
    console.log(read_addr + "---" + write_addr);
    Interceptor.attach(read_addr, {
        onEnter: function (args) {
            this.arg0 = args[0];
            this.arg1 = args[1];
            this.arg2 = args[2];
            this.socketinfo = getsocketdetail(this.arg0.toInt32());
            LogPrint("go into libc.so->read_addr" + "---" + this.socketinfo);
            this.flag = false;
            if (this.socketinfo.indexOf("tcp") >= 0) {
                this.flag = true;
            }
            if (this.flag) {
                printNativeStack(this.context, Process.getCurrentThreadId() + "read");
            }


        }, onLeave(retval) {

            if (this.flag) {
                var size = retval.toInt32();
                if (size > 0) {
                    console.log(Process.getCurrentThreadId() + "---libc.so->read:" + hexdump(this.arg1, {
                        length: size
                    }));
                }
            }


            LogPrint("leave libc.so->read");
        }
    });
    Interceptor.attach(write_addr, {
        onEnter: function (args) {
            this.arg0 = args[0];
            this.arg1 = args[1];
            this.arg2 = args[2];

            this.socketinfo = getsocketdetail(this.arg0.toInt32());
            LogPrint("go into libc.so->write" + "---" + this.socketinfo);
            this.flag = false;
            if (this.socketinfo.indexOf("tcp") >= 0) {
                this.flag = true;
            }
            if (this.flag) {
                printNativeStack(this.context, Process.getCurrentThreadId() + "write");
                var size = ptr(this.arg2).toInt32();
                if (size > 0) {
                    console.log(Process.getCurrentThreadId() + "---libc.so->write:" + hexdump(this.arg1, {
                        length: size
                    }));
                }
            }


        }, onLeave(retval) {
            LogPrint("leave libc.so->write");
        }
    });
}

function hookssl() {
    //SSL_get_rfd
    //int SSL_get_rfd(const SSL *ssl)
    var libsslmodule = Process.getModuleByName("libssl.so");
    var read_addr = libsslmodule.getExportByName("SSL_read");
    var write_addr = libsslmodule.getExportByName("SSL_write");
    var bioread_addr = libsslmodule.getExportByName("BIO_read");
    var biowrite_addr = libsslmodule.getExportByName("BIO_write");
    var SSL_get_rfd_ptr = libsslmodule.getExportByName('SSL_get_rfd');
    var SSL_get_rfd = new NativeFunction(SSL_get_rfd_ptr, 'int', ['pointer']);
    Interceptor.attach(read_addr, {
        onEnter: function (args) {
            this.arg0 = args[0];
            this.arg1 = args[1];
            this.arg2 = args[2];
            LogPrint("go into libssl.so->SSL_read");
            printNativeStack(this.context, Process.getCurrentThreadId() + "SSL_read");
        }, onLeave(retval) {
            var size = retval.toInt32();
            if (size > 0) {
                var sockfd = SSL_get_rfd(this.arg0);
                var socketdetail = getsocketdetail(sockfd);
                console.log(socketdetail + "---" + Process.getCurrentThreadId() + "---libssl.so->SSL_read:" + hexdump(this.arg1, {
                    length: size
                }));
            }
            LogPrint("leave libssl.so->SSL_read");
        }
    });
    Interceptor.attach(write_addr, {
        onEnter: function (args) {
            this.arg0 = args[0];
            this.arg1 = args[1];
            this.arg2 = args[2];
            LogPrint("go into libssl.so->SSL_write");
            printNativeStack(this.context, Process.getCurrentThreadId() + "SSL_write");
            var size = ptr(this.arg2).toInt32();
            if (size > 0) {
                var sockfd = SSL_get_rfd(this.arg0);
                var socketdetail = getsocketdetail(sockfd);
                console.log(socketdetail + "---" + Process.getCurrentThreadId() + "---libssl.so->SSL_write:" + hexdump(this.arg1, {
                    length: size
                }));
            }
        }, onLeave(retval) {
            LogPrint("leave libssl.so->SSL_write");
        }
    });
    Interceptor.attach(bioread_addr, {
        onEnter: function (args) {
            this.arg0 = args[0];
            this.arg1 = args[1];
            this.arg2 = args[2];
            LogPrint("go into libssl.so->bioread_addr");
            printNativeStack(this.context, Process.getCurrentThreadId() + "bioread_addr");
        }, onLeave(retval) {
            var size = retval.toInt32();
            if (size > 0) {
                var sockfd = SSL_get_rfd(this.arg0);
                var socketdetail = getsocketdetail(sockfd);
                console.log(socketdetail + "---" + Process.getCurrentThreadId() + "---libssl.so->bioread_addr:" + hexdump(this.arg1, {
                    length: size
                }));
            }
            LogPrint("leave libssl.so->bioread_addr");
        }
    });
    Interceptor.attach(biowrite_addr, {
        onEnter: function (args) {
            this.arg0 = args[0];
            this.arg1 = args[1];
            this.arg2 = args[2];
            LogPrint("go into libssl.so->biowrite_addr");
            printNativeStack(this.context, Process.getCurrentThreadId() + "biowrite_addr");
            var size = ptr(this.arg2).toInt32();
            if (size > 0) {
                var sockfd = SSL_get_rfd(this.arg0);
                var socketdetail = getsocketdetail(sockfd);
                console.log(socketdetail + "---" + Process.getCurrentThreadId() + "---libssl.so->biowrite_addr:" + hexdump(this.arg1, {
                    length: size
                }));
            }
        }, onLeave(retval) {

            LogPrint("leave libssl.so->biowrite_addr");
        }
    });
}

function hookallssl() {
    var libsslmodule = Process.getModuleByName("libssl.so");
    var SSL_get_rfd_ptr = libsslmodule.getExportByName('SSL_get_rfd');
    var SSL_get_rfd = new NativeFunction(SSL_get_rfd_ptr, 'int', ['pointer']);
    Process.enumerateModules().forEach(function (module) {
        module.enumerateExports().forEach(function (symbol) {
            var name = symbol.name;
            if (name == 'SSL_read') {
                LogPrint(JSON.stringify(module) + JSON.stringify(symbol));
            }
            if (name == 'SSL_write') {
                LogPrint(JSON.stringify(module) + JSON.stringify(symbol));
                Interceptor.attach(symbol.address, {
                    onEnter: function (args) {
                        this.arg0 = args[0];
                        this.arg1 = args[1];
                        this.arg2 = args[2];
                        LogPrint("go into " + Process.getCurrentThreadId() + "---" + JSON.stringify(module) + "---" + JSON.stringify(symbol));
                        printNativeStack(this.context, Process.getCurrentThreadId() + "---" + JSON.stringify(module) + "---" + JSON.stringify(symbol));
                        var size = ptr(this.arg2).toInt32();
                        if (size > 0) {
                            var sockfd = SSL_get_rfd(this.arg0);
                            var socketdetail = getsocketdetail(sockfd);
                            console.log(socketdetail + "---" + Process.getCurrentThreadId() + "---" + JSON.stringify(module) + "---" + JSON.stringify(symbol) + hexdump(this.arg1, {
                                length: size
                            }));
                        }
                    }, onLeave(retval) {
                        LogPrint("leave " + Process.getCurrentThreadId() + "---" + JSON.stringify(module) + "---" + JSON.stringify(symbol));

                    }
                });
            }


        })
    })

}

function main() {
    hooklibc();
    hookssl();
    //hookallssl();
}

setImmediate(main);
```