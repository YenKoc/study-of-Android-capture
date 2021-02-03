# HTTPS抓包详解: HTTPS抓包之对抗手段
- Charles、Burp Suite开启SSL抓包
- 客户端校验服务器 vs 服务器校验客户端
- 密钥、证书自吐
- Charles配置客户端证书、过服务器校验
- HTTP抓包 -> 检测 -> VPN抓包 ->检测
- SSL pinning: 对证书在代码层面上进行额外校验

1. 导入charles证书，在任意浏览器上输入chls.pro/ssl，会自动下载证书，然后直接安装就好了，不过还需要将证书导入系统的信任区，需要一个magisk模块Move Certificates，网速劝退，等明天再弄了