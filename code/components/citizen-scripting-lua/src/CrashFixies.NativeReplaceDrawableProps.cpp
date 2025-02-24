#include <StdInc.h>
#include <Hooking.h>
#include <Hooking.Stubs.h>

static void (*g_orig_Citizen_InvokeNative)(uint64_t hash, ...);

static void Hooked_Citizen_InvokeNative(uint64_t hash, ...)
{
    if (hash == 0xd386a07b18792f21)
    {
        return;
    }

    va_list args;
    va_start(args, hash);
    g_orig_Citizen_InvokeNative(hash, args);
    va_end(args);
}

static HookFunction hookFunction([]()
{
    auto CitizenInvokePattern = hook::get_pattern("E8 ? ? ? ? 48 8B D8 48 8B CB E8 ? ? ? ? 48 8B C8", 0);
    g_orig_Citizen_InvokeNative = hook::trampoline(hook::get_call(CitizenInvokePattern), Hooked_Citizen_InvokeNative);
});
