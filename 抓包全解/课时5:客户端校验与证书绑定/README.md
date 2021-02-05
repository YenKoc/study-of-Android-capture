## 坑点:
1. charles提示“SSL Proxying not enabled for this host: enable in Proxy Settings, SSL locations”，ssl proxy没开，先开启，然后将host和port全设为*
2. charles证书未加载到系统信任区，但是实际上已经把证书放入系统目录下，那么需要重新输入linux命令:mount -o remount,ro /system

# 抓包环节
1. 解决坑点后，发现s开头的app，还是无法发包，并在抓包信息中，发现>No required SSL certificate was sent
2. 说明服务端有校验客户端证书的情况，那么我们需要hook到客户端证书，并提取出p12文件，安装到我们的charles上，
```
function hook_KeyStore_load() {
    Java.perform(function () {
        var ByteString = Java.use("com.android.okhttp.okio.ByteString");
        var myArray=new Array(1024);
        var i = 0
        for (i = 0; i < myArray.length; i++) {
            myArray[i]= 0x0;
         }
        var buffer = Java.array('byte',myArray);
        
        var StringClass = Java.use("java.lang.String");
        var KeyStore = Java.use("java.security.KeyStore");
        KeyStore.load.overload('java.security.KeyStore$LoadStoreParameter').implementation = function (arg0) {
            console.log(Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Throwable").$new()));

            console.log("KeyStore.load1:", arg0);
            this.load(arg0);
        };
        KeyStore.load.overload('java.io.InputStream', '[C').implementation = function (arg0, arg1) {
            console.log(Java.use("android.util.Log").getStackTraceString(Java.use("java.lang.Throwable").$new()));

            console.log("KeyStore.load2:", arg0, arg1 ? StringClass.$new(arg1) : null);

            if (arg0){
                var file =  Java.use("java.io.File").$new("/sdcard/Download/"+ String(arg0)+".p12");
                var out = Java.use("java.io.FileOutputStream").$new(file);
                var r;
                while( (r = arg0.read(buffer)) > 0){
                    out.write(buffer,0,r)
                }
                console.log("save success!")
                out.close()
            }
            this.load(arg0, arg1);
        };

        console.log("hook_KeyStore_load...");

// android.content.res.AssetManager$AssetInputStream@9b10ad6 bxMAFPL9gc@ntKTqmV@A

// android.content.res.AssetManager$AssetInputStream@41ce8f6 }%2R+\OSsjpP!w%X

// android.content.res.AssetManager$AssetInputStream@54858e6 cods.org.cn

    });
}


function hook_ssl() {
    Java.perform(function() {
        var ClassName = "com.android.org.conscrypt.Platform";
        var Platform = Java.use(ClassName);
        var targetMethod = "checkServerTrusted";
        var len = Platform[targetMethod].overloads.length;
        console.log(len);
        for(var i = 0; i < len; ++i) {
            Platform[targetMethod].overloads[i].implementation = function () {
                console.log("class:", ClassName, "target:", targetMethod, " i:", i, arguments);
                //printStack(ClassName + "." + targetMethod);
            }
        }
    });
}



function main(){
    hook_KeyStore_load()    
    // hook_ssl()
}
setImmediate(main);
```
hook到了，证书路径以及密码 KeyStore.load2: android.content.res.AssetManager$AssetInputStream@541ed31 }%2R+\OSsjpP!w%X
但是证书没导入，直接从app里面解包，找到p12文件，尝试一下
3. 从app目录下得到client.p12证书，可以在window上打开，并输入密码是正确的，那么不需要上一话提的工具来操作了
直接导入这个证书就好了，发现再次发送验证码，发现抓包成功了2333，

注意点: 这个会自动dump到sd卡里面，所以需要app有读写sd卡权限，设置下，然后用ls -alit可以查看所有文件，mdsum an可以查看文件是否相同

4. 切换另一个app，发现爱奇艺可以发送验证码，证明证书是没问题的，那么就是在客户端有证书绑定，我们使用肉丝的ssl pinging bypass的hook，直接过掉，就可以正常抓包了