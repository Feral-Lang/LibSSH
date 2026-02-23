#include <libssh/libssh.h>
#include <VM/VM.hpp>

namespace fer
{

//////////////////////////////////////////////////////////////////////////////////////////////////
//////////////////////////////////////// VarSSHSession ///////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////////////////////////

class VarSSHSession : public Var
{
    VirtualMachine *vm;
    Var *logCB;
    VarInt *cbPrio;
    VarStr *cbFunc;
    VarStr *cbBuf;
    ssh_session val;

    void onCreate(VirtualMachine &vm) override;
    void onDestroy(VirtualMachine &vm) override;

public:
    VarSSHSession(ModuleLoc loc, ssh_session val);

    inline VirtualMachine *&getVM() { return vm; }
    inline Var *&getLogCB() { return logCB; }
    inline VarInt *&getLogCBPrio() { return cbPrio; }
    inline VarStr *&getLogCBFunc() { return cbFunc; }
    inline VarStr *&getLogCBBuf() { return cbBuf; }
    inline ssh_session &getVal() { return val; }
};

//////////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////// VarSSHKey /////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////////////////////////

class VarSSHKey : public Var
{
    ssh_key val;

    void onDestroy(VirtualMachine &vm) override;

public:
    VarSSHKey(ModuleLoc loc);

    inline ssh_key &getVal() { return val; }
};

} // namespace fer