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

1. 表哥好像翻车了，不过问题不大，实际上99%app用安卓的库的时候，那跟系统的版本就有很大关系了，android8和android10的接口就不太一样，这个得看源码进行分析，再根据代码进行hook
2. socket这个概念经过我的理解，是这样的，每一层之间有个通道，那个东西就叫socket的，至于socket本质是ip和端口套接字，我也明白，但是这里体现就是这个意思，所以https的包，我们需要在http和ssl之间的通道上进行抓取，这样才不是加密后的数据。