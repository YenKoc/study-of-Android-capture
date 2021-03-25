# 

sslSocket->com.android.org.conscrypt.OpenSSLSocketImplWrapper  

发送数据:
 com.android.org.conscrypt.OpenSSLSocketImpl$SSLOutputStream
public void write(int oneByte);
public void write(byte[] buf,int offset,int byteCount) 

public static native void SSL_write(long sslNativePointer,FileDescriptor fd,SSLHandshakeCallbacks hsc,byte[] b,int off,int len, int write)

NativeCrypto.SSL_write;
 
 接收数据:
 com.android.org.conscrypt.OpenSSLSocketImpl$SSLInputStream  

 public int read()  
 public int read(byte[] buf,int offset,int byteCount)  

 org.conscrypt.NativeCrypto->SSL_read

 public static native int SSL_read()

 发送: com.android.org.conscrypt.OpenSSLSocketImpl$SSLOutputStream.write->
 static void NativeCrypto_SSL_write(JNIEnv* env, jclass, jlong ssl_address, jobject fdObject,
7544                                   jobject shc, jbyteArray b, jint offset, jint len,
7545                                   jint write_timeout_millis)->sslWrite(env, ssl, fdObject, shc, reinterpret_cast<const char*>(&buf[0]), len,
7584                           sslError, write_timeout_millis);
->   

openssl/boringssl
int result = SSL_write(ssl, buf, len);  
-->  int SSL_write(SSL *ssl, const void *buf, int num)  
/external/boringssl/src/ssl/  
--> int ssl3_write_app_data(SSL *ssl, const uint8_t *buf, int len)  
-->  int ret = do_ssl3_write(ssl, SSL3_RT_APPLICATION_DATA, &buf[tot], nw);  
-->  6static int do_ssl3_write(SSL *ssl, int type, const uint8_t *buf, unsigned len) {
-->  8static int ssl3_write_pending(SSL *ssl, int type, const uint8_t *buf,
239                              unsigned int len) {  
--> int ret = ssl_write_buffer_flush(ssl);  
```
int ssl_write_buffer_flush(SSL *ssl) {
298  if (ssl->wbio == NULL) {
299    OPENSSL_PUT_ERROR(SSL, SSL_R_BIO_NOT_SET);
300    return -1;
301  }
302
303  if (SSL_is_dtls(ssl)) {
304    return dtls_write_buffer_flush(ssl);
305  } else {
306    return tls_write_buffer_flush(ssl);
307  }
308}
```  
--> int BIO_write(BIO *bio, const void *in, int inl) {  
--> 0static int bio_io(BIO *bio, void *buf, int len, size_t method_offset,
131                  int callback_flags, size_t *num  

实际上之前tcp和udp跟着的源码来看，发现其实根本不是走的那个接口，否则至少密文还是抓的到的。。。后面发现跟源码，根本不走那个接口，（，而是走的是libc的read和write接口，所以连密文都没抓到，而且ssl有些是使用自己的ssl so文件，所以我们也可以通过read或者write进行栈回溯
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
            }


        }, onLeave(retval) {
            if (this.flag) {
                var size = ptr(this.arg2).toInt32();
                if (size > 0) {
                    console.log(Process.getCurrentThreadId() + "---libc.so->write:" + hexdump(this.arg1, {
                        length: size
                    }));
                }
            }

            LogPrint("leave libc.so->write");
        }
    });
}

function hookssl() {
    var libcmodule = Process.getModuleByName("libssl.so");
    var read_addr = libcmodule.getExportByName("SSL_read");
    var write_addr = libcmodule.getExportByName("SSL_write");
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
                console.log(Process.getCurrentThreadId() + "---libssl.so->SSL_read:" + hexdump(this.arg1, {
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


        }, onLeave(retval) {
            var size = ptr(this.arg2).toInt32();
            if (size > 0) {
                console.log(Process.getCurrentThreadId() + "---libssl.so->SSL_write:" + hexdump(this.arg1, {
                    length: size
                }));
            }

            LogPrint("leave libssl.so->SSL_write");
        }
    });
}

function main() {
    //hooklibc();
    hookssl();
}

setImmediate(main);
```