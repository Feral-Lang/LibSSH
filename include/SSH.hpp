#include <libssh/libssh.h>
#include <VM/VM.hpp>

namespace fer
{

//////////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////// VarSSHKey /////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////////////////////////

class VarSSHKey : public Var
{
    ssh_key val;

    void onDestroy(VirtualMachine &vm) override;

public:
    VarSSHKey(ModuleLoc loc);

    inline int importPublic(VarStr *fileName)
    {
        clear();
        return ssh_pki_import_pubkey_file(fileName->getVal().c_str(), &val);
    }

    // passphrase can be nullptr
    inline int importPrivate(VarStr *fileName, VarStr *passphrase)
    {
        clear();
        return ssh_pki_import_privkey_file(fileName->getVal().c_str(),
                                           passphrase ? passphrase->getVal().c_str() : nullptr,
                                           nullptr, nullptr, &val);
    }

    inline const char *getError() { return ssh_get_error(val); }
    inline int getErrorCode() { return ssh_get_error_code(val); }

    inline void setVal(ssh_key newVal)
    {
        clear();
        val = newVal;
    }

    inline const ssh_key getVal() { return val; }

    inline void clear()
    {
        if(!val) return;
        ssh_key_free(val);
        val = nullptr;
    }
};

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
    bool connected;

    void onCreate(VirtualMachine &vm) override;
    void onDestroy(VirtualMachine &vm) override;

public:
    VarSSHSession(ModuleLoc loc, ssh_session val);

    int connect(VirtualMachine &vm);
    void disconnect();

    inline int setOpt(VirtualMachine &vm, ssh_options_e opt, const void *value)
    {
        this->vm = &vm;
        return ssh_options_set(val, opt, value);
    }

    inline int getPublicKey(VirtualMachine &vm, VarSSHKey *key)
    {
        this->vm       = &vm;
        ssh_key newKey = nullptr;
        int res        = ssh_get_server_publickey(val, &newKey);
        key->setVal(newKey);
        return res;
    }

    inline int updateKnownHosts(VirtualMachine &vm)
    {
        this->vm = &vm;
        return ssh_session_update_known_hosts(val);
    }

    inline int userAuthList(VirtualMachine &vm)
    {
        this->vm = &vm;
        return ssh_userauth_list(val, nullptr);
    }

    inline int userAuthNone(VirtualMachine &vm)
    {
        this->vm = &vm;
        return ssh_userauth_none(val, nullptr);
    }

    inline int userAuthTryPublicKey(VirtualMachine &vm, VarSSHKey *pubKey)
    {
        this->vm = &vm;
        return ssh_userauth_try_publickey(val, nullptr, pubKey->getVal());
    }

    inline int userAuthPublicKey(VirtualMachine &vm, VarSSHKey *privKey)
    {
        this->vm = &vm;
        return ssh_userauth_publickey(val, nullptr, privKey->getVal());
    }

    // passphrase can be nullptr
    inline int userAuthPublicKeyAuto(VirtualMachine &vm, VarStr *passphrase)
    {
        this->vm = &vm;
        return ssh_userauth_publickey_auto(val, nullptr,
                                           passphrase ? passphrase->getVal().c_str() : nullptr);
    }

    inline int userAuthPassword(VirtualMachine &vm, VarStr *password)
    {
        this->vm = &vm;
        return ssh_userauth_password(val, nullptr, password->getVal().c_str());
    }

    inline int userAuthKbdInt(VirtualMachine &vm)
    {
        this->vm = &vm;
        return ssh_userauth_kbdint(val, nullptr, nullptr);
    }

    inline int userAuthKbdIntGetNPrompts(VirtualMachine &vm)
    {
        this->vm = &vm;
        return ssh_userauth_kbdint_getnprompts(val);
    }

    inline const char *userAuthKbdIntGetName(VirtualMachine &vm)
    {
        this->vm = &vm;
        return ssh_userauth_kbdint_getname(val);
    }

    inline const char *userAuthKbdIntGetInstruction(VirtualMachine &vm)
    {
        this->vm = &vm;
        return ssh_userauth_kbdint_getinstruction(val);
    }

    inline const char *userAuthKbdIntGetPrompt(VirtualMachine &vm, VarInt *index, VarBool *echo)
    {
        this->vm        = &vm;
        char _echo      = 0;
        const char *res = ssh_userauth_kbdint_getprompt(val, index->getVal(), &_echo);
        echo->setVal(_echo);
        return res;
    }

    inline int userAuthKbdIntSetAnswer(VirtualMachine &vm, VarInt *index, VarStr *answer)
    {
        this->vm = &vm;
        return ssh_userauth_kbdint_setanswer(val, index->getVal(), answer->getVal().c_str());
    }

    // must free the returned char* IF NOT nullptr.
    inline char *getIssueBanner(VirtualMachine &vm)
    {
        this->vm = &vm;
        return ssh_get_issue_banner(val);
    }

    inline const char *getError() { return ssh_get_error(val); }
    inline int getErrorCode() { return ssh_get_error_code(val); }

    inline ssh_known_hosts_e isKnownServer() { return ssh_session_is_known_server(val); }

    inline VirtualMachine *&getVM() { return vm; }
    inline Var *&getLogCB() { return logCB; }
    inline VarInt *&getLogCBPrio() { return cbPrio; }
    inline VarStr *&getLogCBFunc() { return cbFunc; }
    inline VarStr *&getLogCBBuf() { return cbBuf; }
};

} // namespace fer