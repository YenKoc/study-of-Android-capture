# Socket通信抓包：TCP/IP之应用层HOOK
- Socket的本质：收发包的接口（单位的传达室）、高速公路、一条通道，跑的都是RAW DATA,纯binary
- socket抓包: 本质不是中间人抓包 -》网卡流量的dump转储下来
- TCP/IP之应用层：HTTP+SSL、SMPT/POP/IMAP、protobuf
- 转储的内容已经不是socket，而是ssl的接口（关键
- HOOK SSL框架直接得到明文

- com.android.org.consrcypt.SslWrapper.write(java.io.FileDescriptor,[B,int,int,int)
- com.android.org.consrcypt.SslWrapper.reader(java.io.FileDescriptor,[B,int,int,int)
- com.adnroid.org.conscrypt.C onscryptFileDescriptorSocket$SSLInputStream.read([B,int,int)
- com.adnroid.org.conscrypt.C onscryptFileDescriptorSocket$SSLOutputStream.write([B,int,int)
- SSL Framework中有哪些有趣的API
- HOOK native层直接得到明文
- ssl logger源码解析
# 实际操作
1. 打开httpsocketapp，因为是https通信所以我们要抓http到ssl中间到socket包，实际上ssl层就是一个软件算法，打包而已，所以我们需要hook ssl的接口，先用objection search下所有ssl类
2. 将search出的类，新建txt文件，复制进去，然后ctrl+shift+方向向下，类似全选，然后将android hook watch class复制粘贴，这样就变成一行一行的objection的命令，这样可以实现了批量hook
3. objection -g 包名 explore -c ssl.txt
4. 主要是查看write reader这些api，是否被调用，有没走这个接口，比较重要。
5. 
```



// com.android.org.conscrypt.SslWrapper.write(java.io.FileDescriptor, [B, int, int, int)
// com.android.org.conscrypt.SslWrapper.read(java.io.FileDescriptor, [B, int, int, int)
// com.android.org.conscrypt.ConscryptFileDescriptorSocket$SSLInputStream.read([B, int, int)
// com.android.org.conscrypt.ConscryptFileDescriptorSocket$SSLOutputStream.write([B, int, int)



function jhexdump(array,off,len) {
    var ptr = Memory.alloc(array.length);
    for(var i = 0; i < array.length; ++i)
        Memory.writeS8(ptr.add(i), array[i]);
    //console.log(hexdump(ptr, { offset: off, length: len, header: false, ansi: false }));
    console.log(hexdump(ptr, { offset: 0, length: array.length, header: false, ansi: false }));
}

function hook_socket(){
    Java.perform(function(){
        console.log("hook_socket;")
        

        Java.use("java.net.SocketOutputStream").write.overload('[B', 'int', 'int').implementation = function(bytearry,int1,int2){
            var result = this.write(bytearry,int1,int2);
            console.log("HTTP write result,bytearry,int1,int2=>",result,bytearry,int1,int2)
            var ByteString = Java.use("com.android.okhttp.okio.ByteString");
            //console.log("bytearray contents=>", ByteString.of(bytearry).hex())
            //console.log(jhexdump(bytearry,int1,int2));
            console.log(jhexdump(bytearry));
            return result;
        }
        

        Java.use("java.net.SocketInputStream").read.overload('[B', 'int', 'int').implementation = function(bytearry,int1,int2){
            var result = this.read(bytearry,int1,int2);
            console.log("HTTP read result,bytearry,int1,int2=>",result,bytearry,int1,int2)
            var ByteString = Java.use("com.android.okhttp.okio.ByteString");
            //console.log("bytearray contents=>", ByteString.of(bytearry).hex())
            //console.log(jhexdump(bytearry,int1,int2));
            console.log(jhexdump(bytearry));
            return result;
        }

    })
}


function hook_SSLsocketandroid8(){
    Java.perform(function(){
        console.log("hook_SSLsocket")
        
        Java.use("com.android.org.conscrypt.ConscryptFileDescriptorSocket$SSLOutputStream").write.overload('[B', 'int', 'int').implementation = function(bytearry,int1,int2){
            var result = this.write(bytearry,int1,int2);
            console.log("HTTPS write result,bytearry,int1,int2=>",result,bytearry,int1,int2)
            var ByteString = Java.use("com.android.okhttp.okio.ByteString");
            //console.log("bytearray contents=>", ByteString.of(bytearry).hex())
            //console.log(jhexdump(bytearry,int1,int2));
            console.log(jhexdump(bytearry));
            return result;
        }
        

        
        Java.use("com.android.org.conscrypt.ConscryptFileDescriptorSocket$SSLInputStream").read.overload('[B', 'int', 'int').implementation = function(bytearry,int1,int2){
            var result = this.read(bytearry,int1,int2);
            console.log("HTTPS read result,bytearry,int1,int2=>",result,bytearry,int1,int2)
            var ByteString = Java.use("com.android.okhttp.okio.ByteString");
            //console.log("bytearray contents=>", ByteString.of(bytearry).hex())
            //console.log(jhexdump(bytearry,int1,int2));
            console.log(jhexdump(bytearry));
            return result;
        }
        

    })
}



}



function main(){
    console.log("Main")
    hook_socket();
    hook_SSLsocketandroid8();
    //hook_SSLsocket2android10();
}
setImmediate(main)
```
6. android10的似乎不走android8的接口了，表哥好像翻车了，不过问题不大，实际上99%app用安卓的库的时候，那跟系统的版本就有很大关系了，android8和android10的接口就不太一样，这个得看源码进行分析，再根据代码进行hook
7. socket这个概念经过我的理解，是这样的，每一层之间有个通道，那个东西就叫socket的，至于socket本质是ip和端口套接字，我也明白，但是这里体现就是这个意思，所以https的包，我们需要在http和ssl之间的通道上进行抓取，这样才不是加密后的数据。