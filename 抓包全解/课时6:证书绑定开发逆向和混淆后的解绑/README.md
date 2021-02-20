# HTTPS抓包详解: 解决混淆后的证书绑定
- SSL pinning: 对证书在代码中进行额外校验
    - 现象: 告诉你证书没配好，其实已经配好了，用aiqiyi去检验
    - 原因: 在代码中进行了二轮检验->bypass 进行hook代码
- 带有证书绑定的各种框架
- 各种证书绑定的绕过方法
- 混淆后的证书解绑定: 核心反混淆：从绕不过的底层
    - 确定它用的哪个框架
    - 过那个框架的hook源码-> 自己写一个


# 
1. objection过ssl pinning源码解析，发现已经将很多的ssl pinning框架的api研究过了，并实现了自动化，所以要用objection实现过ssl pinning只需要使用android sslpinning disable
，不过要注意一启动就要执行这个命令，所以需要-s 后面加入命令
2. 遇到发现objection和网上的bypass脚本无法直接运行时，大概率是被混淆了，所以我们最好反编译进去看，或者直接通过file来进行hook，打印调用栈，因为如果要使用证书验证，必然要打开签名文件，进行计算哈希，所以我们可以这样快速的定位到关键代码中
```
(agent) [ysbdoya1h9] Arguments java.io.File.File(/data/user/0/cn.ticktick.task/files/feed_backs, content.txt)                                                                                 
(agent) [ysbdoya1h9] Return Value: (none)
(agent) [ysbdoya1h9] Called java.io.File.File(java.io.File, java.lang.String)
(agent) [ysbdoya1h9] Backtrace:
        java.io.File.<init>(Native Method)
        android.security.net.config.DirectoryCertificateSource.findCert(DirectoryCertificateSource.java:174)
        android.security.net.config.DirectoryCertificateSource.findBySubjectAndPublicKey(DirectoryCertificateSource.java:93)
        android.security.net.config.SystemCertificateSource.findBySubjectAndPublicKey(Unknown Source:0)
        android.security.net.config.CertificatesEntryRef.findBySubjectAndPublicKey(CertificatesEntryRef.java:47)
        android.security.net.config.NetworkSecurityConfig.findTrustAnchorBySubjectAndPublicKey(NetworkSecurityConfig.java:123)
        android.security.net.config.TrustedCertificateStoreAdapter.getTrustAnchor(TrustedCertificateStoreAdapter.java:51)
        com.android.org.conscrypt.TrustManagerImpl.findTrustAnchorBySubjectAndPublicKey(TrustManagerImpl.java:945)
        com.android.org.conscrypt.TrustManagerImpl.checkTrusted(TrustManagerImpl.java:487)
        com.android.org.conscrypt.TrustManagerImpl.checkServerTrusted(TrustManagerImpl.java:321)
        android.security.net.config.NetworkSecurityTrustManager.checkServerTrusted(NetworkSecurityTrustManager.java:113)
        android.security.net.config.RootTrustManager.checkServerTrusted(RootTrustManager.java:131)
        java.lang.reflect.Method.invoke(Native Method)
        android.net.http.X509TrustManagerExtensions.checkServerTrusted(X509TrustManagerExtensions.java:103)
        java.lang.reflect.Method.invoke(Native Method)
        z1.k0.i.a$a.a(AndroidPlatform.java:2)
        z1.g.a(CertificatePinner.java:13)
        z1.k0.e.c.f(RealConnection.java:49)
        z1.k0.e.c.c(RealConnection.java:24)
        z1.k0.e.g.d(StreamAllocation.java:111)
        z1.k0.e.g.e(StreamAllocation.java:1)
        z1.k0.e.a.a(ConnectInterceptor.java:12)
        z1.k0.f.f.b(RealInterceptorChain.java:11)
        z1.k0.d.b.a(CacheInterceptor.java:105)
        z1.k0.f.f.b(RealInterceptorChain.java:11)
        z1.k0.f.a.a(BridgeInterceptor.java:36)
        z1.k0.f.f.b(RealInterceptorChain.java:11)
        z1.k0.f.h.a(RetryAndFollowUpInterceptor.java:11)
        z1.k0.f.f.b(RealInterceptorChain.java:11)
        z1.k0.f.f.a(RealInterceptorChain.java:1)
        z1.l0.a.a(HttpLoggingInterceptor.java:5)
        z1.k0.f.f.b(RealInterceptorChain.java:11)
        e.a.e.a.g.b.a(HttpResponseInterceptor.kt:7)
        z1.k0.f.f.b(RealInterceptorChain.java:11)
        e.a.e.a.g.a.a(HttpRequestInterceptor.kt:46)
        z1.k0.f.f.b(RealInterceptorChain.java:11)
        z1.k0.f.f.a(RealInterceptorChain.java:1)
        z1.z.c(RealCall.java:23)
        c2.p.S(OkHttpCall.java:34)
        e.a.e.a.f.a.S(EasyCall.kt:1)
        e.a.e.a.f.a.d(EasyCall.kt:1)
        e.a.a.d.q6.a(UserActivationHelper.kt:6)
        e.a.a.d.p6.run(Timer.kt:1)
        java.util.TimerThread.mainLoop(Timer.java:555)
        java.util.TimerThread.run(Timer.java:505)

```
类似这种，objection恐怖的是居然可以识别出源文件是啥，发现其实就是名字换了，那我们可以自己实现一波hook，就可以bypass了