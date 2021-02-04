# HTTPS抓包详解: HTTPS抓包之对抗手段
- Charles、Burp Suite开启SSL抓包
- 客户端校验服务器 vs 服务器校验客户端
- 密钥、证书自吐
- Charles配置客户端证书、过服务器校验
- HTTP抓包 -> 检测 -> VPN抓包 ->检测
- SSL pinning: 对证书在代码层面上进行额外校验

1. 导入charles证书，在任意浏览器上输入chls.pro/ssl，会自动下载证书，然后直接安装就好了，不过还需要将证书导入系统的信任区，需要一个magisk模块Move Certificates，事实证明低版本的面具根本没这个模块，但是高版本的面具edxposed又没法用，唉，不过我是安卓8，暂时还是认的
2. burp证书导入: openssl x509 -inform DER -in burpder1545.der -out burpder1545.pem，把der转化成pem，然后adb push到/sdcard/Download文件夹下，然后设置->安全性和位置信息->加密与凭据->从存储设备中进行安装，选择pem证书，即可安装到用户信任区，剩下将证书放入系统区的，
见看雪的一篇双向认证的文章就好了，我安卓8不需要233，安卓10的话，还是建议用面具的插件，自动化将用户证书搞入系统区还是挺香的。
https://bbs.pediy.com/thread-265404.htm
3. vpn抓包: 有些app会有noproxy的操作，让流量不走代理，那么我们还可以使用vpn抓包，要用到postern这个软件，先将配置代理设置到，服务器以及charles的socket proxy的端口一般默认是8889，代理类型就选socks5，然后配置代理规则，匹配所有地址，通过代理连接，将目标地址全选删除，再把wifi设置的代理关了，搞定