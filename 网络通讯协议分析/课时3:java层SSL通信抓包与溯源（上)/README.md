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