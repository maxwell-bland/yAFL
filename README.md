# Yet Another AFL System Mode Fuzzer for QEMU

Yet-another-AFL: modifications to create an architecture-independent, fast, and
easy to use system mode QEMU fuzzer, along the lines of triforce AFL and
FirmAFL; version two of the Jetset fuzzer, used to build exploit for Boeing 737
components.

## Pre-Installing

Copy this directory to your qemu and patch your qemu:

```
cp -r * {path to your qemu}
cd {path to your qemu}
for f in ./patches/*; do
    patch -p1 < $f
done
```

## Installing 

```
arch={whichever qemu system you are building for}
sudo apt build-dep qemu
sudo apt install -y software-properties-common
sudo apt-add-repository ppa:criu/ppa 
sudo apt update 
sudo apt install -y criu
sudo apt install -y ninja-build
sudo apt install -y libprotobuf-c-dev

# Setup for AFL fuzzing
sudo su
echo core >/proc/sys/kernel/core_pattern
cd /sys/devices/system/cpu
echo performance | tee cpu*/cpufreq/scaling_governor
exit

cd sysmode-fuzzer/afl/
make -j$(nproc)
cd -

mkdir build
cd build
env QEMU_LDFLAGS='-lrt -lcriu' ../configure --target-list=${arch}-softmmu --enable-sysmode-fuzzer
make -j$(nproc)
cd -
```

## Usage

To use the fuzzer, we introduce four stages.

0. specifying inputs 
1. checkpointing 
2. running the fuzzer 
3. setting up an isolated `procfs`

### Specifying Inputs

The fuzzer API provides a single method: this checkpoints the qemu instance if it has not 
yet been checkpointed and supplies input to QEMU's state. It can be called multiple times 
to supply input multiple times. However, at the end of the first call, it signals to QEMU 
to start the time by sending the parent it's PID. This is easy to reconfigure if desired,
just move the call to that method to suit your needs.

To access these methods you will need to:

```
#include "sysmode-fuzzer/child.h"
```

At the top of the file where you would like to checkpoint or fuzz from. Then, the call is:

```
/* Fuzzes the destination pointer with a given number
   of bytes of input */
void sm_fuzzer_fuzz(uint8_t *dest, int num_bytes);
```

### Checkpointing

This branch contains augmentations for fuzzing system mode QEMU. The program
works in three sections. The toplevel is `sm-fuzzer` binary; this binary
coordinates between the emulated system and the afl forkserver. To do so, it
first requires you to generate a "snapshot" that is reloaded every time a new
set of fuzzer inputs should be provided:

```
sudo ./build/target-${arch}/qemu-system-$arch {whatever command line options you are using normally} \
        -fuzzer-syncdir {path to AFL's syncdir}/{name of fuzzer instance} \
        -fuzzer-checkpoint-dir {path to directory where you want to store the checkpoint} \
        -fuzzer-state-files myFileWithExtraState1,myFileWithExtraState2,...
```

The `-fuzzer-state-files` option is optional and allows you to save additional file state in
in the directory with the checkpoint. This is important: you should make sure you keep track of any 
extra state you may have programmed in to support the firmware. In this directory there will 
be `dump.log` and `restore.log` files that can be used to debug any failures when checkpointing or 
restoring the state.

*DO NOT* include -serial flags pointing to `/dev/` or similar, since CRIU cannot restore this 
type of file descriptor. You should instead modify your serial devices to print to stdout or 
stderr, or introspect the state using qemu. Or point them towards the `stdout` and `stderr` 
recorded in the syncdir like so:

```
-serial file:{path to syncdir}/{fuzzer name}/stdout
```

### Running the Fuzzer

Once this snapshot is generated, you can now run afl as you would normally, but now you 
supply a flag that specifies the location of the checkpoint directory specified in the 
prior step:

```
sudo ./sysmode-fuzzer/afl/afl-fuzz \
                -i {path to a directory with seed inputs for fuzzer} \
                -o {path to AFL's syncdir you want} \ # This must match the syncdir spec during checkpointing
                -t 30 \ # Time limit on fuzzer instances
                -m 5G \ # Memory limit of child process (shouldn't matter)
                -Q \ # MUST run in qemu mode
                -M \ # Specifies this fuzzer instance as a "master". See the AFL documentation
                myFuzzer \ # must be same name as used during the checkpointing step
                -c {cpu # to pin this fuzzer instance to} \
                -p {path to directory where the checkpoint was stored} \
                -- none
```

*NOTE* that this will run several cases and then eventually fail: if we run the following,

```
sudo cat {criu checkpoint dir}/restore.log 
```

We will see

```
(00.003845) 437206: Error (criu/files.c:1254): Can't open 0/fd on procfs: Not a directory   
(00.003891) Error (criu/cr-restore.c:2397): Restoring FAILED.                               
```

This is because the type of full-restore fuzzing we are doing is not easily handled by a linux
kernel running many other types of processes. It is at this point that we need to run the fuzzer
in a docker container that doesn't have much going on. This has a few  steps.

#### Setting up an isolated procfs and ram filesystem 

In order to maintain speed while running in docker, we are going to place our entire application 
into a ram filesystem. To do this, we need to first setup a ram tmpfs. To do this, as root, we 
run the following:

```
sudo mkdir /mnt/ramfs
sudo mount -t tmpfs tmpfs /mnt/ramfs -o size={The size of the tmpfs, e.g. 2G}
```

We then will create our docker container image by repeating the install process, but within the tmpfs.
From within the qemu's root directory

```
sudo docker pull ubuntu
sudo docker run -it --cap-add ALL \
            --privileged \
            --tmpfs /run \
            -v $(pwd):/usr/src/app \
            -v /mnt/ramfs:/mnt/ramfs \
            ubuntu bash
```

Then, from within the docker container, we will first copy everything into the tmpfs:

```
cp -r /usr/src/app/* /mnt/ramfs/
cd /mnt/ramfs/ 
rm -rf build 
```

Then we set up the container and add the sources necessary for qemu's build dependencies to 
the container

```
cp /etc/apt/sources.list /etc/apt/sources.list~
sed -Ei 's/^# deb-src /deb-src /' /etc/apt/sources.list
apt update
apt install sudo
{Repeat the install process above}
```

Then we will save the image snapshot (you should probably kill the running image after)

```
exit
sudo docker ps -a
sudo docker commit {the hash for your image} sysmode-fuzzer
```

We can then restore our snapshot whenever we want. 
We then set up the fuzzer as if in the _checkpointing_ section above.

```
sudo docker run -it --cap-add ALL \
            --privileged \
            --tmpfs /run \
            -v $(pwd):/usr/src/app \
            -v /mnt/ramfs:/mnt/ramfs \
            sysmode-fuzzer bash
cd /mnt/ramfs/ 
{create a criu checkpoint}
{start the fuzzer}
```

##### Fuzzing in Parallel

In order to fuzz in parallel, you may start several docker instances and in
each one, set a different criu checkpoint dir as well as give the fuzzer a
different name, but keep the same `syncdir`, and pin each to a different cpu.
