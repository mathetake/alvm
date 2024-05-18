# alvm: Apple Linux Virtual Machine

alvm allows you to run any Linux binary on MacOS machine without Linux VMs. This is just my experiment to build a low
level Linux emulator via Apple's Hypervisor.framework.

It simply runs the Linux ELF binary in a hypervisor VM without kernel, and handles the syscall `svc` instruction,
which is trapped as a hardware exception, in the user land Rust code.

## Example

```
$ ./tests/cases/c/hello_world.exe
zsh: exec format error: ./tests/cases/c/hello_world.exe

$ file ./tests/cases/c/hello_world.exe
./tests/cases/c/hello_world.exe: ELF 64-bit LSB executable, ARM aarch64, version 1 (SYSV), statically linked, with debug_info, not stripped

$ ./target/release/alvm -- ./tests/cases/c/hello_world.exe
Hello, World!
```
