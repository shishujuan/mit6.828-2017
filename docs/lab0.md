## 1 安装工具包

```
# sudo apt-get install -y build-essential libtool libglib2.0-dev libpixman-1-dev zlib1g-dev git libfdt-dev gcc-multilib gdb
```

## 2 安装qemu
下载qemu定制版本

```
# git clone http://web.mit.edu/ccutler/www/qemu.git -b 6.828-2.3.0
```

进入qemu目录，配置并编译安装：

```
# ./configure --disable-kvm --disable-sdl --target-list="i386-softmmu x86_64-softmmu"
# make -j8 && make install
```
下载实验代码仓库 

```
# git clone https://pdos.csail.mit.edu/6.828/2017/jos.git
```

运行：

```
# make qemu 
# make qemu-nox  (没有gui版本)
```


