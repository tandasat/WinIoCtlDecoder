WinIoCtlDecoder
===============

IDA Plugin which decodes Windows Device I/O control code into DeviceType, FunctionCode, AccessType and MethodType.


Installation
-----------------
Copy all files in a /plugins directory to a (IDA)/plugins directory. Files should be located like this:

    C:\Program Files (x86)\IDA 6.5\plugins\WinIoCtlDecoder.py
                                          \WinIoCtlDecoder.plw

Usage
-----------------
1. Select an interesting IOCTL code in the disassemble window.
2. Hit Ctrl-Alt-D or select Edit/Plugins/Windows IOCTL code decoder

The result will be printed in the Outout window.

    Python>decode(0x220086)
    Code = 0x00220086
    Device   : FILE_DEVICE_UNKNOWN (0x22)
    Function : 0x21
    Method   : METHOD_OUT_DIRECT (2)
    Access   : FILE_ANY_ACCESS (0)
    
You also can call 'decode' function directly from the Python CLI window, and when you are using Hex-rays Decompiler, you will see 'Decode as an IOCTL code' menu in a context-menu of a Pseudo window.   

Note
-----------------
- WinIoCtlDecoder.py is a plugin for IDA Pro. 
- WinIoCtlDecoder.plw is a plugin for Hex-rays Decompiler.

Supported Platforms
-----------------
- Windows 
- IDA Pro Standard version 6 and later.
- Hex-rays Decompiler version 1.8 and later.

License
-----------------
This software is released under the MIT License, see LICENSE.
