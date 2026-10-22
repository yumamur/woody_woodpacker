void _start(void)
{
    const char msg[] = "something\n";
    unsigned int len = sizeof(msg) - 1; 

    // sys_write (eax = 4)
    // fd = 1 (ebx)
    // buffer = msg (ecx)
    // length = len (edx)
    __asm__ volatile (
        "int $0x80"
        : 
        : "a" (4),       // a = eax
          "b" (1),       // b = ebx
          "c" (msg),     // c = ecx
          "d" (len)      // d = edx
        : "memory"
    );

    // sys_exit (eax = 1)
    // exit_code = 0 (ebx)
    __asm__ volatile (
        "int $0x80"
        : 
        : "a" (1),       // a = eax
          "b" (0)        // b = ebx
        : "memory"
    );
}