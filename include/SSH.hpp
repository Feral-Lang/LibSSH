#include <libssh/libssh.h>
#include <libssh/sftp.h>
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
//////////////////////////////////////// VarSSHChannel ///////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////////////////////////

// Just a ref - is not allocated or freed here. That part is done by VarSSHSession
class VarSSHChannelRef : public Var
{
    ssh_session ssh;
    ssh_channel val;
    bool valid;

    void onDestroy(VirtualMachine &vm) override;

public:
    VarSSHChannelRef(ModuleLoc loc, ssh_session ssh, ssh_channel val);

    int open();
    int close();

    int read(VarStr *output, bool readStderr);
    int write(StringRef data, bool writeStderr);

    inline int requestPty(VarInt *width, VarInt *height)
    {
        if(!isValid()) return SSH_ERROR;
        return ssh_channel_request_pty_size(val, "xterm", width->getVal(), height->getVal());
    }

    inline int requestShell()
    {
        if(!isValid()) return SSH_ERROR;
        return ssh_channel_request_shell(val);
    }

    inline int requestSFTP()
    {
        if(!isValid()) return SSH_ERROR;
        return ssh_channel_request_sftp(val);
    }

    inline int sendEof()
    {
        if(!isValid()) return SSH_ERROR;
        return ssh_channel_send_eof(val);
    }

    inline void invalidate() { valid = false; }

    inline bool isValid() { return valid; }
    inline bool isOpen() { return ssh_channel_is_open(val); }
    inline bool isEOF() { return ssh_channel_is_eof(val); }

    inline const char *getError() { return ssh_get_error(ssh); }
    inline int getErrorCode() { return ssh_get_error_code(ssh); }

    inline const ssh_channel getVal() { return val; }
};

//////////////////////////////////////////////////////////////////////////////////////////////////
///////////////////////////////////// VarSFTPFileHandle //////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////////////////////////

class VarSFTPFileHandle : public Var
{
    sftp_file val;
    bool isOpen;

    void onDestroy(VirtualMachine &vm) override;

public:
    VarSFTPFileHandle(ModuleLoc loc, sftp_file val);

    inline int close()
    {
        if(!isOpen) return SSH_OK;
        isOpen = false;
        return sftp_close(val);
    }

    inline const sftp_file getVal() { return val; }
};

//////////////////////////////////////////////////////////////////////////////////////////////////
///////////////////////////////////// VarSFTPDirHandle ///////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////////////////////////

class VarSFTPDirHandle : public Var
{
    sftp_dir val;
    bool isOpen;

    void onDestroy(VirtualMachine &vm) override;

public:
    VarSFTPDirHandle(ModuleLoc loc, sftp_dir val);

    inline int close()
    {
        if(!isOpen) return SSH_OK;
        isOpen = false;
        return sftp_closedir(val);
    }

    inline bool isEOF() { return sftp_dir_eof(val); }

    inline const sftp_dir getVal() { return val; }
};

//////////////////////////////////////////////////////////////////////////////////////////////////
///////////////////////////////////// VarSFTPSessionRef //////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////////////////////////

class VarSFTPSessionRef : public Var
{
    sftp_session val;
    bool valid;

    void onDestroy(VirtualMachine &vm) override;

public:
    VarSFTPSessionRef(ModuleLoc loc, sftp_session val);

    inline int initialize()
    {
        if(!isValid()) return SSH_ERROR;
        return sftp_init(val);
    }

    inline void invalidate()
    {
        valid = false;
        // freed by the SSH session, so this must be set to nullptr to prevent double free.
        val->channel = nullptr;
    }

    VarSFTPFileHandle *openFile(VirtualMachine &vm, ModuleLoc loc, VarStr *path, VarInt *mode,
                                VarInt *perms);

    VarSFTPDirHandle *openDir(VirtualMachine &vm, ModuleLoc loc, VarStr *path);

    int writeFile(VarSFTPFileHandle *file, VarStr *data);
    int readFile(VarSFTPFileHandle *file, VarStr *data);

    inline bool isValid() { return valid; }

    inline int getErrorCode() { return sftp_get_error(val); }

    inline const char *getSSHError() { return ssh_get_error(val->session); }
    inline int getSSHErrorCode() { return ssh_get_error_code(val->session); }

    inline const sftp_session getVal() { return val; }
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
    VarVec *channels;
    VarVec *sftpSessions;
    ssh_session val;
    bool connected;

    void onCreate(VirtualMachine &vm) override;
    void onDestroy(VirtualMachine &vm) override;

public:
    VarSSHSession(ModuleLoc loc, ssh_session val);

    int connect(VirtualMachine &vm);
    void disconnect(VirtualMachine &vm);

    VarSSHChannelRef *newChannel(VirtualMachine &vm, ModuleLoc loc);
    VarSFTPSessionRef *newSFTPSession(VirtualMachine &vm, ModuleLoc loc, VarSSHChannelRef *chan);

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