# ShellCode：

---

## 1 写shellcode

#### 1.1 配置asm编译环境

> nasm-2.16.03
> 
> VS2022 BuildTool

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

使用nasm编译成obj，需要--prefix 把所有函数名前加上下划线，这是window的要求。

相当于main->_main 和 printf->_printf

```shell
nasm -f win32 test.asm --prefix _ -o test.obj
```

使用cl链接成可执行的exe

libcmt.lib是必写的，没有这个会LINK : fatal error LNK1561: 必须定义入口点

legacy_stdio_definitions.lib是给_printf用的，没有会报error LNK2001: 无法解析的外部符号 _printf

```shell
cl test.obj /Fe:test.exe /link libcmt.lib legacy_stdio_definitions.lib
```


