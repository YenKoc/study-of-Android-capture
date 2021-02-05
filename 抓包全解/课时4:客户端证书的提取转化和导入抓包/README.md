- 主要对上一节的知识补充，但是app好像炸了，没测出效果。。只能写一点操作流程了
- 先放个打印出本地证书以及密码的frida脚本
```
function hook_KeyStore_load() {
    Java.perform(function () {
        var StringClass = Java.use("java.lang.String");
        var KeyStore = Java.use("java.security.KeyStore");
        KeyStore.load.overload('java.security.KeyStore$LoadStoreParameter').implementation = function (arg0) {
            printStack("KeyStore.load1");
            console.log("KeyStore.load1:", arg0);
            this.load(arg0);
        };
        KeyStore.load.overload('java.io.InputStream', '[C').implementation = function (arg0, arg1) {
            printStack("KeyStore.load2");
            console.log("KeyStore.load2:", arg0, arg1 ? StringClass.$new(arg1) : null);
            this.load(arg0, arg1);
        };

        console.log("hook_KeyStore_load...");
    });
}
function main()
{
    hook_KeyStore_load();
}
setImmediate(main);
```
- 下一步根据打印出的文件路径以及密码，利用github上的一个工具KeyStore Explorer进行提取p12文件，然后再把导出的p12文件，导入charles中ssl proxy setting下的client certificates，进行添加