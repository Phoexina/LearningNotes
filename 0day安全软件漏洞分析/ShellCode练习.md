# ShellCode：汇编开发练习

---

## 1 shellcode编写环境

> nasm-2.16.03
> 
> VS2022 BuildTool
> 
> 010Editor写 + x32dbg调

首先编写一个简单的输出，最开始写的就是上一篇调用MessageBox的汇编，但是发现运行会卡住，应该需要手动导入dll才行。于是换成printf。

```nasm
extern printf
section .data  
    fmt db '%s', 0

section .text  
global main  

main:  
    XOR EBX, EBX
    PUSH EBX
    PUSH 0x54534554
    PUSH 0x44434241
    MOV EAX, ESP
    push eax
    push fmt
    call printf
    PUSH EBX
    MOV EAX, 0x7679D1D0
    CALL EAX
    ret
```

**使用nasm编译成obj**

需要--prefix 把所有函数名前加上下划线，这是window的要求。

相当于main->_main 和 printf->_printf

```shell
nasm -f win32 test.asm --prefix _ -o test.obj
```

**使用cl链接成可执行的exe**

libcmt.lib是必写的，没有这个会LINK : fatal error LNK1561: 必须定义入口点

legacy_stdio_definitions.lib是给_printf用的，没有会报error LNK2001: 无法解析的外部符号 _printf

```shell
cl test.obj /Fe:test.exe /link libcmt.lib legacy_stdio_definitions.lib
```

## 2 汇编开发

### 2.1 总体理解

终于写完了这段asm，从头整理一下重要的几个部分

- push栈数据：3个函数hash，2个位置的“user32”

- push预留函数指针位置：3个函数指针，这里分配了0x400感觉没必要

- 获取kernelbase基址：fs=TEB->PEB->LDR->dllList存储位置->dllList首地址->dllList[2]=kernel32.dll

- 大循环3次遍历函数hash：用小循环（匹配函数hash）找到字符串表的位次，在序号表中找到相应的序号，再用序号表找到地址表地址。其中[3]=MessageBox时，先调用找到的Load获取user32.dll的基址，放在原本放kernelbase基址的地方

- 小循环匹配函数hash：遍历字符串表的每一个字符串，在小小循环hash_loop遍历每个byte，通过al==ah判断是否为00，来判断字符串的结束，进入hash比较

- 普普通通的调用：调用之前保存地址的位置，函数没错就没啥问题。可能需要注意MessageBox调用完后eax和ecx会更改，重复使用参数时不要放在这里

### 2.2 详细注释的asm代码

直接放代码吧~~改变了书上的顺序，有点不理解书上的写法。还改了一下导出表的各个表地址的获取，感觉原来的代码写的很不可读（

注释里面写了进入大循环前的栈的状态

```nasm
extern printf
section .data  
    fmt db '%s', 0

section .text  
global main  

main: 
;抬高栈顶，将edi指向的更上层纳入栈顶下面
lea edi, [esp-0x0c] ;edi指向esp更顶的位置
xor ebx, ebx
mov bh, 0x04        ;bh是bx的高8位，相当于ebx=0x0400
sub esp, ebx        ;esp=esp-ebx

;写入user32
push 0x00003233
push 0x72657375
;写入hash，相当于一个数组{0x1e380a6a, 0xd3e32874, 0x0c917432}
push 0x1e380a6a    ;MessageBoxA
push 0xd3e32874    ;exit
push 0x0c917432    ;LoadLibraryA
mov esi, esp       ;加载数组尾地址


;ebp赋值为kernel32.dll基址
mov ecx, fs:[0x30]  ;x86中PEB指针位于fs=TEB结构体偏移0x30, x64中偏移为0x60
mov ecx, [ecx+0x0c] ;PEB结构体偏移0x0c到LDR
mov ecx, [ecx+0x1C] ;LDR偏移0x1c是dllList
mov ecx, [ecx]      ;ecx读取dllList首地址
mov ebp, [ecx+0x08] ;ebp读取dllList[2]=kernelbase.dll

;此时栈的状态
;低esp+04 08 0c 10 14 18 1c
; |0x0c917432| +00
; |0xd3e32874| +04
; |0x1e380a6a| +08
; |0x72657375| +0c
; |0x00003233| +10
;0x400{
;......
; |<-edi
; |
; |
;}
;高ebp-

;**************************************************大循环
find_lib_functions:
lodsd               ;eax=0x0c917432, esi指向数组下一位->[0xd3e32874]
cmp eax, 0x1e380a6a
jne find_functions
push esi
call [edi-0x08]
xchg eax, ebp    ;ebp=返回的user32.dll基址

;ebx保存导出名称表(字符串)地址, eax保存导出地址表(RVA)地址, ecx保存导出序号表
find_functions:
mov ebx, [ebp+0x3c]     ;dll基址偏移0x3c是PE头(相对基址的地址)
mov ecx, [ebp+ebx+0x78] ;PE头偏移0x78是导出表(相对基址的地址)
mov ebx, ecx            ;ebx=ecx=导出表

mov ebx, [ebp+ebx+0x20] ;导出表偏移0x20是导出名表(相对基址的地址)
add ebx, ebp            ;导出名称表相对地址+dll基址=实际地址

mov eax, [ebp+ecx+0x1c]
add eax, ebp            ;导出地址表(RVA)相对地址+dll基址=实际地址

mov ecx, [ebp+ecx+0x24]
add ecx, ebp            ;序号表相对地址+dll基址=实际地址


;----------------------------------------------小循环
push edi             ;没有pushad，全push了之后pop全覆盖了怎么存数据
push esi             ;总之这个地方懒得理解书上的写法
push eax
xor edi, edi
next_function_loop:
inc edi
mov esi, [ebx+edi*4] ;获取导出名称表中不同函数名字符串指针, edi为函数序号
add esi, ebp         ;字符串指针相对地址+dll基址=实际地址

cdq
hash_loop:
movsx eax, byte [esi]
cmp al, ah ;为什么不直接和0比较？应该只有al有值
je hash_compare
ror edx, 7
add edx, eax
inc esi
jmp hash_loop

hash_compare:
cmp edx, [esp+0x0c]     ;esp去掉保存的edi和esi后的栈顶，与hash比较
jne next_function_loop
mov edx, edi            ;edx接手edi,函数次序
pop eax
pop esi
pop edi
;---------------------------------------------小循环
;这里卡了很久！！！！
mov dx, [ecx+2*edx]   ;在序号表中找edx对应的序号读取，edx现在是序号了
mov eax, [eax+edx*4]  ;在地址表中偏移序号edx个指针
add eax, ebp          ;eax=函数地址
stosd                 ;将eax存入edi, edi指向下一个
pop eax               ;eax=栈顶，栈顶下降
cmp eax, 0x1e380a6a   ;不是最后一个就循环
jne find_lib_functions
;**************************************************大循环

fuction_call:
XOR EBX, EBX
PUSH EBX
PUSH 0x54534554
PUSH 0x44434241
mov esi, esp

;messagebox
push ebx
push esi
push esi
push ebx
call [edi-0x04]

;printf
push esi
push fmt
call printf

push ebx
call [edi-0x08]
ret
```

放一下第一次把MessageBox打出来的快乐截图

![](../images/2024-10-08-19-17-11-image.png)

### 2.3 有趣的调试

已知需要拿到的指针，需要找到指向这个指针需要的地址。

一开始没理解字符串表位次和地址表偏移量关系的时候逆向的推了一下。大概场景如下：

`dll基址: 760b0000  字符串表首: 762d56cc  地址表首: 762d37a8 函数地址：761FDDD0`

761FDDD0-760b0000=14DDD0(相对dll地址)  ==转换为存储顺序==> D0DD1400

可以通过xdbg右键>搜索>所有系统模块>匹配特征打开，在十六进制里写D0DD1400，可以搜到数据为这个的地址！

![](../images/2024-10-08-19-39-31-image.png)

![](../images/2024-10-08-19-41-26-image.png)

可以看到一共就76118F2B和762D4808，还有在地址表首: 762d37a8后面，就是762D4808，就能算出需要的相对偏移量是762D4808 - 762d37a8 = 1060

不过还是要通过序号表查找才通用（不是通过公式算的
