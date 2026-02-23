#include "SSH.hpp"

#include <libssh/callbacks.h>

namespace fer
{

//////////////////////////////////////////////////////////////////////////////////////////////////
/////////////////////////////////////////// Callbacks ////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////////////////////////

void SSHLoggingCallback(int priority, const char *function, const char *buffer, void *userdata)
{
    VarSSHSession *ssh = (VarSSHSession *)userdata;
    VirtualMachine *vm = ssh->getVM();
    Var *cb            = ssh->getLogCB();
    if(!cb) return;
    VarInt *prio = ssh->getLogCBPrio();
    VarStr *func = ssh->getLogCBFunc();
    VarStr *buf  = ssh->getLogCBBuf();
    prio->setVal(priority);
    func->setVal(function);
    buf->setVal(buffer);
    Array<Var *, 5> args = {nullptr, ssh, prio, func, buf};
    Var *res             = vm->callVar(cb->getLoc(), "SSHLoggingCallback", cb, args, nullptr);
    if(res) vm->decVarRef(res);
}

//////////////////////////////////////////////////////////////////////////////////////////////////
///////////////////////////////////////// VarSSHSession //////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////////////////////////

VarSSHSession::VarSSHSession(ModuleLoc loc, ssh_session val)
    : Var(loc, 0), vm(nullptr), logCB(nullptr), cbPrio(nullptr), cbFunc(nullptr), cbBuf(nullptr),
      val(val)
{}

void VarSSHSession::onCreate(VirtualMachine &vm)
{
    this->vm = &vm;
    cbPrio   = vm.incVarRef(vm.makeVar<VarInt>(getLoc(), 0));
    cbFunc   = vm.incVarRef(vm.makeVar<VarStr>(getLoc(), ""));
    cbBuf    = vm.incVarRef(vm.makeVar<VarStr>(getLoc(), ""));
    ssh_set_log_userdata(this);
}

void VarSSHSession::onDestroy(VirtualMachine &vm)
{
    if(val) ssh_free(val);
    vm.decVarRef(cbBuf);
    vm.decVarRef(cbFunc);
    vm.decVarRef(cbPrio);
    if(logCB) vm.decVarRef(logCB);
}

//////////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////// VarSSHKey /////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////////////////////////

VarSSHKey::VarSSHKey(ModuleLoc loc) : Var(loc, 0), val(nullptr) {}

void VarSSHKey::onDestroy(VirtualMachine &vm)
{
    if(val) ssh_key_free(val);
}

//////////////////////////////////////////////////////////////////////////////////////////////////
/////////////////////////////////////////// Functions ////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////////////////////////

//////////////////////////////////////// SSH Functions ///////////////////////////////////////////

FERAL_FUNC(sshGetLogLevel, 0, false,
           "  fn() -> Int\n"
           "Returns the log level of the SSH library as an Int.")
{
    return vm.makeVar<VarInt>(loc, ssh_get_log_level());
}

FERAL_FUNC(sshSetLogLevel, 0, false,
           "  fn(level) -> Nil\n"
           "Sets the log level to be `level` of the SSH library.")
{
    EXPECT(VarInt, args[1], "log level");
    ssh_set_log_level(as<VarInt>(args[1])->getVal());
    return vm.getNil();
}

///////////////////////////////////////// SSH Session ////////////////////////////////////////////

FERAL_FUNC(sshNew, 0, false,
           "  fn() -> SSHSession\n"
           "Creates and returns an SSH session object.")
{
    ssh_session val = ssh_new();
    if(!val) {
        vm.fail(loc, "failed to allocate an SSH session");
        return nullptr;
    }
    return vm.makeVar<VarSSHSession>(loc, val);
}

FERAL_FUNC(sshSessionSetOpt, 2, false,
           "  var.fn(option, value) -> Int\n"
           "Sets the `option` as `value` for the ssh session `var`. Returns `0` on success.")
{
    EXPECT(VarInt, args[1], "option");
    ssh_session ssh   = as<VarSSHSession>(args[0])->getVal();
    ssh_options_e opt = (ssh_options_e)as<VarInt>(args[1])->getVal();
    int res           = 0;
    switch(opt) {
    case SSH_OPTIONS_HOST:
    case SSH_OPTIONS_USER: {
        EXPECT(VarStr, args[2], "value");
        const String &val = as<VarStr>(args[2])->getVal();
        res               = ssh_options_set(ssh, opt, val.c_str());
        break;
    }
    case SSH_OPTIONS_PORT:
    case SSH_OPTIONS_LOG_VERBOSITY: {
        EXPECT(VarInt, args[2], "value");
        int val = as<VarInt>(args[2])->getVal();
        res     = ssh_options_set(ssh, opt, &val);
        break;
    }
    default:
        vm.fail(loc, "unknown option: ", (int)opt, " for setting ssh session option");
        return nullptr;
    }
    return vm.makeVar<VarInt>(loc, res);
}

FERAL_FUNC(sshSessionSetLogCB, 1, false,
           "  var.fn(callback) -> Nil\n"
           "Sets the log callback for `var` as `callback`.")
{
    VarSSHSession *ssh = as<VarSSHSession>(args[0]);
    Var *&logCB        = ssh->getLogCB();
    if(logCB) vm.decVarRef(logCB);
    logCB = vm.incVarRef(args[1]);
    return vm.getNil();
}

FERAL_FUNC(sshSessionConnect, 0, false,
           "  var.fn() -> Int\n"
           "Connects the SSH session `var`, returning `0` on success.")
{
    VarSSHSession *ssh = as<VarSSHSession>(args[0]);
    int res            = ssh_connect(ssh->getVal());
    return vm.makeVar<VarInt>(loc, res);
}

FERAL_FUNC(sshSessionDisconnect, 0, false,
           "  var.fn() -> Nil\n"
           "Disconnects the SSH session `var`.")
{
    VarSSHSession *ssh = as<VarSSHSession>(args[0]);
    ssh_disconnect(ssh->getVal());
    return vm.getNil();
}

FERAL_FUNC(sshSessionGetError, 0, false,
           "  var.fn() -> Str\n"
           "Returns the last error in SSH session `var` as a string.")
{
    VarSSHSession *ssh = as<VarSSHSession>(args[0]);
    return vm.makeVar<VarStr>(loc, ssh_get_error(ssh->getVal()));
}

FERAL_FUNC(sshSessionGetErrorCode, 0, false,
           "  var.fn() -> Int\n"
           "Returns the last error code in SSH session `var` as an Int.")
{
    VarSSHSession *ssh = as<VarSSHSession>(args[0]);
    return vm.makeVar<VarInt>(loc, ssh_get_error_code(ssh->getVal()));
}

FERAL_FUNC(sshSessionGetServerPublicKey, 1, false,
           "  var.fn(key) -> Int\n"
           "Sets the session `var`'s server's public key in `key` which should be of type SSHKey.\n"
           "Returns `0` on success.")
{
    EXPECT(VarSSHKey, args[1], "ssh key");
    VarSSHSession *ssh = as<VarSSHSession>(args[0]);
    VarSSHKey *key     = as<VarSSHKey>(args[1]);
    int res            = ssh_get_server_publickey(ssh->getVal(), &key->getVal());
    return vm.makeVar<VarInt>(loc, res);
}

FERAL_FUNC(sshSessionIsKnownServer, 0, false,
           "  var.fn() -> Int\n"
           "Returns the state as Int representing the status of the server being known.")
{
    VarSSHSession *ssh = as<VarSSHSession>(args[0]);
    return vm.makeVar<VarInt>(loc, ssh_session_is_known_server(ssh->getVal()));
}

////////////////////////////////////////// SSH Key ///////////////////////////////////////////////

FERAL_FUNC(sshNewKey, 0, false,
           "  fn() -> SSHKey\n"
           "Creates and returns an instance of SSH Key.")
{
    return vm.makeVar<VarSSHKey>(loc);
}

FERAL_FUNC(
    sshKeyGetPublicKeyHash, 1, false,
    "  var.fn(hash) -> Int\n"
    "Sets the ssh key `var`'s server's public key in `hash` which should be of type string.\n"
    "Returns `0` on success.")
{
    EXPECT(VarStr, args[1], "ssh key hash");
    VarSSHKey *key      = as<VarSSHKey>(args[0]);
    unsigned char *hash = nullptr;
    size_t len          = 0;
    int res = ssh_get_publickey_hash(key->getVal(), SSH_PUBLICKEY_HASH_SHA256, &hash, &len);
    if(res == 0) {
        char *hashStr = ssh_get_hexa(hash, len);
        as<VarStr>(args[1])->setVal(hashStr);
        ssh_string_free_char(hashStr);
        ssh_clean_pubkey_hash(&hash);
    }
    return vm.makeVar<VarInt>(loc, res);
}

INIT_DLL(SSH)
{
    ssh_set_log_callback(SSHLoggingCallback);

    vm.addLocalType<VarSSHSession>(loc, "SSHSession", "SSH session object");
    vm.addLocalType<VarSSHKey>(loc, "SSHKey", "SSH key object");

    vm.addLocal(loc, "new", sshNew);
    vm.addLocal(loc, "newKey", sshNewKey);

    vm.addLocal(loc, "getLogLevel", sshGetLogLevel);
    vm.addLocal(loc, "setLogLevel", sshSetLogLevel);

    vm.addTypeFn<VarSSHSession>(loc, "setOpt", sshSessionSetOpt);
    vm.addTypeFn<VarSSHSession>(loc, "setLogCB", sshSessionSetLogCB);
    vm.addTypeFn<VarSSHSession>(loc, "connect", sshSessionConnect);
    vm.addTypeFn<VarSSHSession>(loc, "disconnect", sshSessionDisconnect);
    vm.addTypeFn<VarSSHSession>(loc, "getError", sshSessionGetError);
    vm.addTypeFn<VarSSHSession>(loc, "getErrorCode", sshSessionGetErrorCode);
    vm.addTypeFn<VarSSHSession>(loc, "getServerPublicKey", sshSessionGetServerPublicKey);
    vm.addTypeFn<VarSSHSession>(loc, "isKnownServer", sshSessionIsKnownServer);

    vm.addTypeFn<VarSSHKey>(loc, "getPublicKeyHash", sshKeyGetPublicKeyHash);

    // error return codes
    vm.makeLocal<VarInt>(loc, "OK", "", SSH_OK);
    vm.makeLocal<VarInt>(loc, "ERROR", "", SSH_ERROR);
    vm.makeLocal<VarInt>(loc, "AGAIN", "", SSH_AGAIN);
    vm.makeLocal<VarInt>(loc, "EOF", "", SSH_EOF);
    // options
    vm.makeLocal<VarInt>(loc, "OPT_HOST", "", SSH_OPTIONS_HOST);
    vm.makeLocal<VarInt>(loc, "OPT_PORT", "", SSH_OPTIONS_PORT);
    vm.makeLocal<VarInt>(loc, "OPT_USER", "", SSH_OPTIONS_USER);
    vm.makeLocal<VarInt>(loc, "OPT_LOG_VERBOSITY", "", SSH_OPTIONS_LOG_VERBOSITY);
    // log levels
    vm.makeLocal<VarInt>(loc, "LOG_NOLOG", "No logging at all", SSH_LOG_NOLOG);
    vm.makeLocal<VarInt>(loc, "LOG_WARNING", "Only unrecoverable errors", SSH_LOG_WARNING);
    vm.makeLocal<VarInt>(loc, "LOG_PROTOCOL", "Information for the users", SSH_LOG_PROTOCOL);
    vm.makeLocal<VarInt>(loc, "LOG_PACKET", "Debug information, to see what is going on",
                         SSH_LOG_PACKET);
    vm.makeLocal<VarInt>(loc, "LOG_FUNCTIONS", "Trace information and recoverable error messages",
                         SSH_LOG_FUNCTIONS);
    // server known state
    vm.makeLocal<VarInt>(loc, "KNOWN_HOSTS_ERROR", "", SSH_KNOWN_HOSTS_ERROR);
    vm.makeLocal<VarInt>(loc, "KNOWN_HOSTS_NOT_FOUND", "", SSH_KNOWN_HOSTS_NOT_FOUND);
    vm.makeLocal<VarInt>(loc, "KNOWN_HOSTS_UNKNOWN", "", SSH_KNOWN_HOSTS_UNKNOWN);
    vm.makeLocal<VarInt>(loc, "KNOWN_HOSTS_OK", "", SSH_KNOWN_HOSTS_OK);
    vm.makeLocal<VarInt>(loc, "KNOWN_HOSTS_CHANGED", "", SSH_KNOWN_HOSTS_CHANGED);
    vm.makeLocal<VarInt>(loc, "KNOWN_HOSTS_OTHER", "", SSH_KNOWN_HOSTS_OTHER);
    return true;
}

} // namespace fer