// A COM GUID or two in constant data: IID_IUnknown and CLSID_ShellLink,
// spelled the way the SDK's initialisers spell them.
struct guid_16 {
    unsigned int data1;
    unsigned short data2;
    unsigned short data3;
    unsigned char data4[8];
};

const struct guid_16 iid_iunknown = {
    0x00000000, 0x0000, 0x0000,
    {0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46},
};

const struct guid_16 clsid_shell_link = {
    0x00021401, 0x0000, 0x0000,
    {0xC0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x46},
};

int main(void) {
    return (int)(unsigned char)iid_iunknown.data4[7] + clsid_shell_link.data1;
}
