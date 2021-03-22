# 从上文而来的补充，获取ip和端口
- frida提供了可以通过套接字fd，获得通信的api，所以直接利用
```
function getsocketdetail(fd)
{
    var result="";
    var type=result.type(fd);
    if(type!=null)
    {
        result=result+"type:"+type;
        var address=Socket.peerAddress(fd);
        var local=Socket.localAddress(fd);
        result=result+",address:"+JSON.stringify(address)+",local:"+JSON.stringify(local);
    }else{
        result="unknown";
    }
    return result;
    
}
```

# 之前是从tcp的角度进行抓包，现在从UDP角度去抓
- 会有些差别，因为在实际调试过程中，发现第一个参数套接字，已经无法从中得到ip和端口了，所以只能从第4个参数进行hook，取出来，发现是一个结构体，一个字节一个字节的读取出来，然后再本地计算，拼接，就ok了。