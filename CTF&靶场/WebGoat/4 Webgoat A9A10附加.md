# （四）A9-日志安全 & A10-SSRF & 客户端 & 挑战

## 1 日志安全

### 1.1 随便一试

随便试了一个admin密码随便写就过了？这是在干嘛？
![](../../images/Pasted%20image%2020241212164352.png)

### 1.2 看日志找密码

总之就是看日志找密码

```shell
sudo docker logs bd81a8dd1ea8 |grep admin
```
![](../../images/Pasted%20image%2020241212165719.png)

直接输入不对，看起来好像Base64加密了
解密得到 `7d7fe054-fcf5-42d7-97df-43a988a77dfc`
输入还是不对emmmm，有点像key id之类的东西

不好意思原来有很多log，看来每次重启日志都在
![](../../images/Pasted%20image%2020241212171052.png)

还需要注意用户名不是admin是Admin
![](../../images/Pasted%20image%2020241212171216.png)

用最新的提交
![](../../images/Pasted%20image%2020241212171150.png)

## 2 SSRF

> 很好的题解参考
> https://blog.csdn.net/seanyang_/article/details/134377110
### 2.1 从其他地方跳转

我理解是从其他服务器访问就可以？
于是放在之前的评论里
![](../../images/Pasted%20image%2020241212172833.png)

但点击进去是
![](../../images/Pasted%20image%2020241212172935.png)

原来这样写是GET，需要构造一个POST
在自己的tomcat网站下面新建一个test.html

```html
<!DOCTYPE html>  
<html lang="en">  
<head>  
    <meta charset="UTF-8">  
    <meta name="viewport" content="width=device-width, initial-scale=1.0">  
    <title>Send POST Request</title>  
</head>  
<body>  
    <form action="http://192.168.137.42:8080/WebGoat/csrf/basic-get-flag" method="POST">  
        <input type="hidden" name="csrf" value="false"> <!-- 根据需要添加参数 -->  
        <button type="submit">View my Pictures!</button>  
    </form>  
</body>  
</html>  
```

点击就可以得到
![](../../images/Pasted%20image%2020241212174430.png)


看看请求的区别
![](../../images/Pasted%20image%2020241212175427.png)
![](../../images/Pasted%20image%2020241212175413.png)
看起来来自Refer

### 2.2 从其他地方发评论

直接修改Refer
![](../../images/Pasted%20image%2020241212175645.png)

或许这样有点作弊了？应该通过跳转比较好
跳转也可以
![](../../images/Pasted%20image%2020241212180030.png)
现在的Html是

```html
<!DOCTYPE html>  
<html lang="en">  
<head>  
    <meta charset="UTF-8">  
    <meta name="viewport" content="width=device-width, initial-scale=1.0">  
    <title>Send POST Request</title>  
</head>  
<body>  
    <form action="http://192.168.137.42:8080/WebGoat/csrf/basic-get-flag" method="POST">  
        <input type="hidden" name="csrf" value="false"> <!-- 根据需要添加参数 -->  
        <button type="submit">basic-get-flag</button>  
    </form>  

<form action="http://192.168.137.42:8080/WebGoat/csrf/review" method="POST">  
        <input type="hidden" name="reviewText" value="testreview"> <!-- 根据需要添加参数 -->  
	<input type="hidden" name="stars" value="0"> <!-- 根据需要添加参数 -->  
	<input type="hidden" name="validateReq" value="2aa14227b9a13d0bede0388a7fba9aa9"> <!-- 根据需要添加参数 -->  
        <button type="submit">review</button>  
    </form>  
</body>  
</html>  
```

### 2.3 text/plain发json邮件

直接发一下
![](../../images/Pasted%20image%2020241213101751.png)

改refer好像也不行
![](../../images/Pasted%20image%2020241213102125.png)

按照上一章讲的添加了`navigator.sendBeacon`
![](../../images/Pasted%20image%2020241213103047.png)

但是发送的是OPTIONS
![](../../images/Pasted%20image%2020241213103123.png)

> 看起来很有用的CORS原理资料
> https://threezh1.com/2020/02/19/CORS%E5%8E%9F%E7%90%86%E5%8F%8A%E5%88%A9%E7%94%A8%E6%95%B4%E7%90%86/

当使用 `navigator.sendBeacon()` 方法发送数据时，通常会发送一个 HTTP POST 请求。
如果看到 OPTIONS 请求，通常与 CORS（跨源资源共享）和预检请求的机制有关。
- **CORS**：当您从一个源（例如 `http://example.com`）向另一个源（例如 `http://localhost:8083`）发送请求时，浏览器会执行 CORS 策略，以确保请求是安全的。
- **预检请求**：对于某些类型的请求（例如，使用非简单请求头或方法的请求），浏览器会首先发送一个 OPTIONS 请求，以询问目标服务器是否允许实际的请求。这称为预检请求。

查到了JSONP方法，但似乎不适用
![](../../images/Pasted%20image%2020241213114955.png)

在CORS机制中,客户端(浏览器)将请求分为两种:
简单请求(需同时满足以下条件)
- 请求方法是以下三种之一:GET,HEAD,POST
- HTTP的头信息不超出以下几种字段:Accept,Accept-Language,Content-Language,Last-Event-ID,Content-Type
- Content-Type的值仅限以下三种:text\plain,multipart/form-data,application/x-www-form-urlencoded
非简单请求，但凡不同时满足上面两个条件,就属于非简单请求
会触发浏览器发生预检请求,这是浏览器行为.“预检请求“的使用,可以避免跨域请求对服务器的用户数据产生未预期到影响.

根据提示使用text/plain 发布相同的消息
装作简单请求会出现这个
![](../../images/Pasted%20image%2020241213113528.png)

这个时候手动加上cookie就能过了
![](../../images/Pasted%20image%2020241213113817.png)

但是应该让它自动加上cookie

> 问gpt问不出来
> 去搜索了一下题解
> https://blog.csdn.net/seanyang_/article/details/134277976?spm=1001.2014.3001.5502

![](../../images/Pasted%20image%2020241213144341.png)


```html
<form enctype="text/plain" action="http://192.168.137.42:8080/WebGoat/csrf/feedback/message" METHOD="POST">
	<input type="hidden" name='{"name": "Testf", "email": "teddst1233@163.com", "subject": "service", "message":"' value='dsaffd"}'>
	<button type="submit">feedback-message2</button>  
</form>
```

构造出的包是
![](../../images/Pasted%20image%2020241213144718.png)

理解了实际上应该是text/plain应该是
name=value的格式
这个就是
![](../../images/Pasted%20image%2020241216094624.png)
理解了

### 2.4 CSRF使用攻击者身份登录

>也许有用的资料
>https://sudip-says-hi.medium.com/what-is-the-csrf-login-attack-7c63851676f3

#### 2.4.1 理解题目要求

有点无法理解
![](../../images/Pasted%20image%2020241217142836.png)

本人登录
![](../../images/Pasted%20image%2020241217135319.png)

旧浏览器改username csrf账号登录，这个应该是虚假的登录，没有关系
![](../../images/Pasted%20image%2020241217135424.png)

新浏览器csrf账号登录，这里发送后题目好像就绿了
![](../../images/Pasted%20image%2020241217135916.png)

新浏览器看到的
![](../../images/Pasted%20image%2020241217135633.png)

搜索了一下
登录 CSRF 攻击是通过强制用户登录攻击者控制的帐户来策划的。为了实现这一点，黑客使用他们的凭据向网站伪造状态更改请求，并将表单提交给受害者的浏览器。服务器验证浏览器请求并将用户登录到攻击者的帐户。当受害者提交登录攻击者帐户的敏感信息时，攻击者可以利用此信息执行多项不必要的操作，包括身份盗用。

也就是说csrf是攻击者的账户，我使用csrf-的账户点击这个按钮
所以是我使用csrf的cookie登录，打开看起来是testtest的用户界面

#### 2.4.2 burp登录cookie调用接口

很奇怪
如果是另一个浏览器的cookie发送csrflogin就可以完成题目
这个报错可能是搞前面的绿点时搞出了一些问题，推测就是用来让课程通过的操作
![](../../images/Pasted%20image%2020241217152017.png)

我自己Post一个login的cookie直接发送crsflogin就不行
![](../../images/Pasted%20image%2020241217152131.png)
明明用来访问页面是正常的
![](../../images/Pasted%20image%2020241217152348.png)

代码看起来很普通
查看请求中的名字，如果是crsf开头的就成功了
![](../../images/Pasted%20image%2020241217153751.png)
![](../../images/Pasted%20image%2020241217154214.png)
合理怀疑，cookie被认为没有登录


嗯嗯嗯嗯？？？
![](../../images/Pasted%20image%2020241217154509.png)
突然插入成功了，猝不及防，不过后面测试又不成功了
无所谓了能绿就行

破案了，自己用burp构造的登录cookie，需要选择指定课程才能调用成功课程内的接口
![](../../images/Pasted%20image%2020241217164833.png)
![](../../images/Pasted%20image%2020241217164841.png)
![](../../images/Pasted%20image%2020241217164850.png)

这样就成功了

#### 2.4.3 实际步骤

构造一个webgoat登录攻击者crsf账户的表单
```html
<form action="http://192.168.137.42:8080/WebGoat/login" method="POST">  
    <input type="hidden" name="username" value="csrf-testtest"> <!-- 根据需要添加参数 -->  
	<input type="hidden" name="password" value="testtest"> <!-- 根据需要添加参数 -->  
    <button type="submit">login</button>  
</form> 
```

打开一个原账户登录的页面
![](../../images/Pasted%20image%2020241217165404.png)

点击登录
![](../../images/Pasted%20image%2020241217165433.png)

刷新准备好的原账户页面
可以看到这些节点都还是绿的
![](../../images/Pasted%20image%2020241217165720.png)
点击csrf的登录，成功！
![](../../images/Pasted%20image%2020241217165633.png)

### 2.5 SSRF偷奶酪

测试一下
![](../../images/Pasted%20image%2020241217170847.png)

随便修改一下
![](../../images/Pasted%20image%2020241217172549.png)
![](../../images/Pasted%20image%2020241217172523.png)

也许有一个奶酪的图片？
看了一下源码
![](../../images/Pasted%20image%2020241217172814.png)

很明显了
![](../../images/Pasted%20image%2020241217172752.png)
图片的样子
![](../../images/Pasted%20image%2020241217172934.png)

### 2.6 SSRF获取信息

试一下
![](../../images/Pasted%20image%2020241217173023.png)

![](../../images/Pasted%20image%2020241217173101.png)

换成链接？
![](../../images/Pasted%20image%2020241217173247.png)

这个页面会输出访问者的公网IP地址、主机名（如果存在的话）、用户代理字符串、语言和编码信息。
不过这好像是外网才能访问的所以我的虚拟机不行

从源码上看只支持这个地址，属实是有些粗暴了
![](../../images/Pasted%20image%2020241217173835.png)

## 3 客户端

#### 3.1 要求做什么就不做什么

绕过字段限制

![](../../images/Pasted%20image%2020241217174352.png)

要求什么不干什么就可以了

![](../../images/Pasted%20image%2020241217174329.png)

就不符合正则
![](../../images/Pasted%20image%2020241217174653.png)

![](../../images/Pasted%20image%2020241217174610.png)

### 3.2 直接查看包

这个薪水包里全都有
直接看就可以

![](../../images/Pasted%20image%2020241217174958.png)

### 3.3 无密码付款

试一下
![](../../images/Pasted%20image%2020241217175121.png)

删除会报错
![](../../images/Pasted%20image%2020241217175158.png)

考虑到是客户端题，看看文件
![](../../images/Pasted%20image%2020241217175320.png)


```
<!--
                              Checkout code: webgoat, owasp, owasp-webgoat
                            -->
```

又看到了有趣的东西
![](../../images/Pasted%20image%2020241217175603.png)


拦截一个
![](../../images/Pasted%20image%2020241217175800.png)

修改服务器返回包也不行
![](../../images/Pasted%20image%2020241217180044.png)

搜了一下题解，可以通过这个接口看到
![](../../images/Pasted%20image%2020241217180323.png)

答案是
![](../../images/Pasted%20image%2020241217180456.png)

emmmmm？不理解这是什么逻辑？？
可能就是不要返回乱七八糟的信息吧

![](../../images/Pasted%20image%2020241217180523.png)

### 3.4 HTML 篡改

测试
![](../../images/Pasted%20image%2020241217181529.png)

直接修改包
![](../../images/Pasted%20image%2020241217181513.png)

## 4 挑战

### 4.1 管理员忘记密码

很好第一题就没有思路
试图sql注入，也翻了Html文件都没什么信息
去搜了题解
竟然在图片上
![](../../images/Pasted%20image%2020241217183542.png)

![](../../images/Pasted%20image%2020241217183619.png)

### 4.2 无密码登录Larry

很好这个是sql注入

![](../../images/Pasted%20image%2020241217183758.png)

根据报错可以看出原句是
```sql
select password from challenge_users where userid = 'Larry' and password = 'xxx'
```

![](../../images/Pasted%20image%2020241217184008.png)

说起来这个是会返回所有数据，也就是源码中应该是只校验有无返回结果，有结果就算查询成功

### 4.3 admin重置密码

发送一个邮件
![](../../images/Pasted%20image%2020241217184304.png)

给自己发送的
![](../../images/Pasted%20image%2020241217184745.png)
链接是
`http://192.168.137.42:8080/WebGoat/challenge/7/reset-password/18aa6e362a4ebea6d6fc506bcbc70710`

感觉和之前的题目很像，难道这个也有一个创建link的接口，可以传给wolf？

看看源码
![](../../images/Pasted%20image%2020241218113749.png)
![](../../images/Pasted%20image%2020241218162722.png)
Host是第一个字符串，后面的是创建的链接

> [!note] 
> 这里倒是理解了之前的创建链接为什么可以通过改host达到目的
> 其实就是把邮件生成的链接替换成点击会被自己的服务器捕获到的Url
> 

按道理来说应该是 `(new PasswordResetLink()).createPasswordReset(username, "webgoat")` 
username = admin时或许是一个固定的值，就可以用这个拿到了

于是写了代码模拟，虽然值是固定的，但是并不可以
![](../../images/Pasted%20image%2020241219092005.png)

于是又去看了代码，很好原来是写死的
![](../../images/Pasted%20image%2020241219092206.png)

那这个在干嘛？
![](../../images/Pasted%20image%2020241219092237.png)

总之拿到了
![](../../images/Pasted%20image%2020241219092309.png)

### 4.4 投票

> 参考
> https://docs.cycubix.com/application-security-series/web-application-security-essentials/solutions/challenges-or-cycubix-docs/challenges-or-without-account-or-cycubox-docs

点击这里似乎可以触发投票
![](../../images/Pasted%20image%2020241219092408.png)

看看包
![](../../images/Pasted%20image%2020241219092523.png)
![](../../images/Pasted%20image%2020241219092536.png)

根据参考使用HEAD查询，很好的思路，根本想不到
不理解有什么意义（）（）

![](../../images/Pasted%20image%2020241219092911.png)

总之很好的做完了！


---

THE END. 2024.12.20.
## @PHOEXINA