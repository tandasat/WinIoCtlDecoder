WinIoCtlDecoder
===============

An IDA Pro plugin which decodes a Windows Device I/O control code into
DeviceType, FunctionCode, AccessType and MethodType.


Installation
-----------------
Copy the Python file in a /plugins directory to a (IDA)/plugins directory. It
should be located like this:

    C:\Program Files (x86)\IDA 6.x\plugins\WinIoCtlDecoder.py

Usage
-----------------
1. Select an interesting IOCTL code in the disassemble window.
2. Hit Ctrl-Alt-D or select Edit/Plugins/Windows IOCTL code decoder

You also can call 'winio_decode' function directly from the Python CLI window.

The result will be printed in the Outout window.

    Python>winio_decode(0x220086)
    winio_decode(0x00220086)
    Device   : FILE_DEVICE_UNKNOWN (0x22)
    Function : 0x21
    Method   : METHOD_OUT_DIRECT (2)
    Access   : FILE_ANY_ACCESS (0)

Supported Platforms
-----------------
- Windows
- IDA Pro Standard version 6 and later.

Hex-rays Decompiler plugins are not included and supported any more since the
author no longer has the license. Please refer to the v1.1 release for the last
version of the decompiler plugins.

    https://github.com/tandasat/WinIoCtlDecoder/releases/tag/v1.1

License
-----------------
This software is released under the MIT License, see LICENSE.
