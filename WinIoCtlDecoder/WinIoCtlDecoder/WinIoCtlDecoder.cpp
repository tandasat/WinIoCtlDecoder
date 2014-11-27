// C/C++ standard headers
// Other external headers
#pragma warning(push, 0)
#include <hexrays.hpp>
#pragma warning(pop)


// Windows headers
// Original headers


////////////////////////////////////////////////////////////////////////////////
//
// macro utilities
//


////////////////////////////////////////////////////////////////////////////////
//
// constants and macros
//

static const char COMMENT[] =
    "Decodes Windows Device I/O control code into "
    "DeviceType, FunctionCode, AccessType and MethodType.";


////////////////////////////////////////////////////////////////////////////////
//
// types
//


////////////////////////////////////////////////////////////////////////////////
//
// prototypes
//

int idaapi plugin_init();

void idaapi plugin_term();

void idaapi plugin_run(
    int arg);

int idaapi plugin_callback(
    void* ud,
    hexrays_event_t event,
    va_list va);

bool idaapi plugin_on_decode_code(
    void *ud);

void winio_decode(
    uint32 ioctl_code);


////////////////////////////////////////////////////////////////////////////////
//
// variables
//

hexdsp_t *hexdsp = nullptr; // Hex-Rays API pointer
plugin_t PLUGIN =
{
    IDP_INTERFACE_VERSION,
    PLUGIN_HIDE,            // plugin flags
    plugin_init,            // initialize
    plugin_term,            // terminate. this pointer may be nullptr.
    plugin_run,             // invoke plugin
    COMMENT,                // long comment about the plugin
                            // it could appear in the status line or as a hint
    "",                     // multiline help about the plugin
    "Windows IOCTL code decoder",   // the preferred short name of the plugin
    ""                      // the preferred hotkey to run the plugin
};


static bool g_plugin_initialized = false;


////////////////////////////////////////////////////////////////////////////////
//
// implementations
//

// Initialization handler called when the decompiler starts
int idaapi plugin_init()
{
    if (!init_hexrays_plugin())
    {
        return PLUGIN_SKIP; // no decompiler
    }

    if (!install_hexrays_callback(plugin_callback, nullptr))
    {
        term_hexrays_plugin();
        return PLUGIN_SKIP;
    }

    msg("%s ready to use.\n", PLUGIN.wanted_name);
    g_plugin_initialized = true;
    return PLUGIN_KEEP;
}


// Termination handler
void idaapi plugin_term()
{
    if (!g_plugin_initialized)
    {
        return;
    }

    remove_hexrays_callback(plugin_callback, nullptr);
    term_hexrays_plugin();
    g_plugin_initialized = false;
}


// The handler invoked via Edit/Plugins/* or Hot-key
void idaapi plugin_run(
    int /*arg*/)
{
    // Never called because this plugin is markded as PLUGIN_HIDE,
    // and has no hot-key registration.
}


int idaapi plugin_callback(
    void* /*ud*/,
    hexrays_event_t event,
    va_list va)
{
    switch (event)
    {
    case hxe_right_click:
        {
            // If the current item is non zero number, then add the menu item
            auto window = va_arg(va, vdui_t*);
            const auto number_obj = window->get_number();
            if (number_obj && number_obj->_value)
            {
                add_custom_viewer_popup_item(
                    window->ct,
                    "Decode as an IOCTL code",
                    "",
                    plugin_on_decode_code,
                    window);
            }
        }
        break;

    default:
        break;
    }
    return 0;
}


bool idaapi plugin_on_decode_code(
    void *ud)
{
    const auto window = static_cast<vdui_t*>(ud);
    const auto number_obj = window->get_number();
    if (!number_obj)
    {
        return true;
    }
    // It is not IOCTL code if it is larger than the max 32bit value.
    if (number_obj->_value > std::numeric_limits<uint32>::max())
    {
        return true;
    }
    winio_decode(static_cast<uint32>(number_obj->_value));
    return true;
}


// Decodes IOCTL code and prints it.
void winio_decode(
    uint32 ioctl_code)
{
    const char* ACCESS_NAMES[] =
    {
        "FILE_ANY_ACCESS",
        "FILE_READ_ACCESS",
        "FILE_WRITE_ACCESS",
        "FILE_READ_ACCESS | FILE_WRITE_ACCESS",
    };
    const char* METHOD_NAMES[] =
    {
        "METHOD_BUFFERED",
        "METHOD_IN_DIRECT",
        "METHOD_OUT_DIRECT",
        "METHOD_NEITHER",
    };
    const char DEVICE_NAME_UNKNOWN[] = "<UNKNOWN>";
    const char* DEVICE_NAMES[] =
    {
        DEVICE_NAME_UNKNOWN,               // 0x00000000
        "FILE_DEVICE_BEEP",                // 0x00000001
        "FILE_DEVICE_CD_ROM",              // 0x00000002
        "FILE_DEVICE_CD_ROM_FILE_SYSTEM",  // 0x00000003
        "FILE_DEVICE_CONTROLLER",          // 0x00000004
        "FILE_DEVICE_DATALINK",            // 0x00000005
        "FILE_DEVICE_DFS",                 // 0x00000006
        "FILE_DEVICE_DISK",                // 0x00000007
        "FILE_DEVICE_DISK_FILE_SYSTEM",    // 0x00000008
        "FILE_DEVICE_FILE_SYSTEM",         // 0x00000009
        "FILE_DEVICE_INPORT_PORT",         // 0x0000000a
        "FILE_DEVICE_KEYBOARD",            // 0x0000000b
        "FILE_DEVICE_MAILSLOT",            // 0x0000000c
        "FILE_DEVICE_MIDI_IN",             // 0x0000000d
        "FILE_DEVICE_MIDI_OUT",            // 0x0000000e
        "FILE_DEVICE_MOUSE",               // 0x0000000f
        "FILE_DEVICE_MULTI_UNC_PROVIDER",  // 0x00000010
        "FILE_DEVICE_NAMED_PIPE",          // 0x00000011
        "FILE_DEVICE_NETWORK",             // 0x00000012
        "FILE_DEVICE_NETWORK_BROWSER",     // 0x00000013
        "FILE_DEVICE_NETWORK_FILE_SYSTEM", // 0x00000014
        "FILE_DEVICE_NULL",                // 0x00000015
        "FILE_DEVICE_PARALLEL_PORT",       // 0x00000016
        "FILE_DEVICE_PHYSICAL_NETCARD",    // 0x00000017
        "FILE_DEVICE_PRINTER",             // 0x00000018
        "FILE_DEVICE_SCANNER",             // 0x00000019
        "FILE_DEVICE_SERIAL_MOUSE_PORT",   // 0x0000001a
        "FILE_DEVICE_SERIAL_PORT",         // 0x0000001b
        "FILE_DEVICE_SCREEN",              // 0x0000001c
        "FILE_DEVICE_SOUND",               // 0x0000001d
        "FILE_DEVICE_STREAMS",             // 0x0000001e
        "FILE_DEVICE_TAPE",                // 0x0000001f
        "FILE_DEVICE_TAPE_FILE_SYSTEM",    // 0x00000020
        "FILE_DEVICE_TRANSPORT",           // 0x00000021
        "FILE_DEVICE_UNKNOWN",             // 0x00000022
        "FILE_DEVICE_VIDEO",               // 0x00000023
        "FILE_DEVICE_VIRTUAL_DISK",        // 0x00000024
        "FILE_DEVICE_WAVE_IN",             // 0x00000025
        "FILE_DEVICE_WAVE_OUT",            // 0x00000026
        "FILE_DEVICE_8042_PORT",           // 0x00000027
        "FILE_DEVICE_NETWORK_REDIRECTOR",  // 0x00000028
        "FILE_DEVICE_BATTERY",             // 0x00000029
        "FILE_DEVICE_BUS_EXTENDER",        // 0x0000002a
        "FILE_DEVICE_MODEM",               // 0x0000002b
        "FILE_DEVICE_VDM",                 // 0x0000002c
        "FILE_DEVICE_MASS_STORAGE",        // 0x0000002d
        "FILE_DEVICE_SMB",                 // 0x0000002e
        "FILE_DEVICE_KS",                  // 0x0000002f
        "FILE_DEVICE_CHANGER",             // 0x00000030
        "FILE_DEVICE_SMARTCARD",           // 0x00000031
        "FILE_DEVICE_ACPI",                // 0x00000032
        "FILE_DEVICE_DVD",                 // 0x00000033
        "FILE_DEVICE_FULLSCREEN_VIDEO",    // 0x00000034
        "FILE_DEVICE_DFS_FILE_SYSTEM",     // 0x00000035
        "FILE_DEVICE_DFS_VOLUME",          // 0x00000036
        "FILE_DEVICE_SERENUM",             // 0x00000037
        "FILE_DEVICE_TERMSRV",             // 0x00000038
        "FILE_DEVICE_KSEC",                // 0x00000039
        "FILE_DEVICE_FIPS",                // 0x0000003A
        "FILE_DEVICE_INFINIBAND",          // 0x0000003B
        DEVICE_NAME_UNKNOWN,               // 0x0000003C
        DEVICE_NAME_UNKNOWN,               // 0x0000003D
        "FILE_DEVICE_VMBUS",               // 0x0000003E
        "FILE_DEVICE_CRYPT_PROVIDER",      // 0x0000003F
        "FILE_DEVICE_WPD",                 // 0x00000040
        "FILE_DEVICE_BLUETOOTH",           // 0x00000041
        "FILE_DEVICE_MT_COMPOSITE",        // 0x00000042
        "FILE_DEVICE_MT_TRANSPORT",        // 0x00000043
        "FILE_DEVICE_BIOMETRIC",           // 0x00000044
        "FILE_DEVICE_PMI",                 // 0x00000045
    };

    const auto device = (ioctl_code >> 16) & 0xffff;
    const auto access = (ioctl_code >> 14) & 3;
    const auto function = (ioctl_code >> 2) & 0xfff;
    const auto method = ioctl_code & 3;

    const char* device_name = nullptr;
    if (device >= _countof(DEVICE_NAMES))
    {
        device_name = DEVICE_NAME_UNKNOWN;
    }
    else
    {
        device_name = DEVICE_NAMES[device];
    }

    msg("winio_decode(0x%08X)\n", ioctl_code);
    msg("Device   : %s (0x%X)\n", device_name, device);
    msg("Function : 0x%X\n", function);
    msg("Method   : %s (%d)\n", METHOD_NAMES[method], method);
    msg("Access   : %s (%d)\n", ACCESS_NAMES[access], access);
}

