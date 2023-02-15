rule sus_onenote
{
    strings:
        $a1 = /https?\:\/\/.{1,100}\/\w+\.(dat|exe|dll)/
    condition:
        (uint32(0) == 0x7B5C52E4 and uint32(4) == 0x4DA7D88C and uint32(8) == 0x7853B1AE and uint32(12) == 0xD39629D0) and all of them
}
