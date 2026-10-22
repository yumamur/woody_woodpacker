void _start(void)
{
	const char msg[] = "haro evary nyan\n";
	unsigned long len = 16;
	__asm__ volatile (
        "syscall"
        : 
        : "a" (1),       // a = rax
          "D" (1),       // D = rdi
          "S" (msg),     // S = rsi
          "d" (len)      // d = rdx
        : "rcx", "r11", "memory" // syscall clobbers rcx and r11
    );

    // sys_exit (rax = 60)
    // exit_code = 0 (rdi)
    __asm__ volatile (
        "syscall"
        : 
        : "a" (60),      // a = rax
          "D" (0)        // D = rdi
        : "rcx", "r11", "memory"
    );
}