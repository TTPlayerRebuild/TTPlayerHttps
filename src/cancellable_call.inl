// XP has synchronous PAC and DNS APIs. Keep their arguments/results owned by
// a bounded worker after the caller cancels. Never terminate a thread inside
// JScript/Winsock, never retain the caller's pointers, and hold this DLL until
// the worker has destroyed every C++ object. At most four unresolved calls.
struct BlockingCall {
    static inline std::atomic<unsigned> active{};
    std::atomic<unsigned> refs{2};
    HANDLE ready{CreateEventW(nullptr, TRUE, FALSE, nullptr)};
    HMODULE module{};
    std::function<void()> action;
    std::exception_ptr failure;
    ~BlockingCall() { if (ready) CloseHandle(ready); }
    void Release() { if (--refs == 0) delete this; }
    static DWORD WINAPI Run(void* context) {
        auto* self = static_cast<BlockingCall*>(context);
        const HMODULE module = self->module;
        const HRESULT com = CoInitializeEx(nullptr, COINIT_MULTITHREADED);
        try { self->action(); } catch (...) { self->failure = std::current_exception(); }
        self->action = {};
        if (SUCCEEDED(com)) CoUninitialize();
        SetEvent(self->ready);
        self->Release();
        --active;
        FreeLibraryAndExitThread(module, 0);
    }
};
template<class F> auto CancellableCall(F action, const Guard& guard) {
    using Result = decltype(action());
    struct State { std::optional<Result> result; };
    auto state = std::make_shared<State>();
    guard();
    for (;;) {
        guard();auto active=BlockingCall::active.load();
        if(active<4 && BlockingCall::active.compare_exchange_weak(active,active+1)) break;
        Sleep(25);
    }
    auto* call = new (std::nothrow) BlockingCall;
    if (!call) { --BlockingCall::active; throw std::bad_alloc{}; }
    try {
        if (!call->ready || !GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS,
                reinterpret_cast<LPCWSTR>(&BlockingCall::Run), &call->module))
            throw std::runtime_error("Cannot retain network resolver");
        call->action = [state, action = std::move(action)]() mutable { state->result.emplace(action()); };
        HANDLE thread = CreateThread(nullptr, 0, BlockingCall::Run, call, 0, nullptr);
        if (!thread) throw std::runtime_error("Cannot create network resolver");
        CloseHandle(thread);
    } catch (...) {
        if (call->module) FreeLibrary(call->module);
        delete call; --BlockingCall::active; throw;
    }
    struct Release { BlockingCall* p; ~Release() { p->Release(); } } release{call};
    for (;;) {
        guard();
        const auto wait = WaitForSingleObject(call->ready, 25);
        if (wait == WAIT_OBJECT_0) break;
        if (wait != WAIT_TIMEOUT) throw std::runtime_error("Network resolver wait failed");
    }
    guard();
    if (call->failure) std::rethrow_exception(call->failure);
    return std::move(*state->result);
}
