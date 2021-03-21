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