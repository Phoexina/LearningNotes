# LearningNotes

## 内存保护

![](images/Pasted%20image%2020241108151756.png)
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
