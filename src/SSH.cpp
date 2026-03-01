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
    if(!vm || !vm->isReady()) return;
    Var *cb = ssh->getLogCB();
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
      val(val), connected(false)
{}

void VarSSHSession::onCreate(VirtualMachine &vm)
{
    cbPrio = vm.incVarRef(vm.makeVar<VarInt>(getLoc(), 0));
    cbFunc = vm.incVarRef(vm.makeVar<VarStr>(getLoc(), ""));
    cbBuf  = vm.incVarRef(vm.makeVar<VarStr>(getLoc(), ""));
    ssh_set_log_userdata(this);
}

void VarSSHSession::onDestroy(VirtualMachine &vm)
{
    disconnect();
    if(val) ssh_free(val);
    vm.decVarRef(cbBuf);
    vm.decVarRef(cbFunc);
    vm.decVarRef(cbPrio);
    if(logCB) vm.decVarRef(logCB);
}

int VarSSHSession::connect(VirtualMachine &vm)
{
    this->vm = &vm;
    int res  = ssh_connect(val);
    if(res == SSH_OK) connected = true;
    return res;
}

void VarSSHSession::disconnect()
{
    if(!connected) return;
    ssh_disconnect(val);
    connected = false;
}

//////////////////////////////////////////////////////////////////////////////////////////////////
////////////////////////////////////////// VarSSHKey /////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////////////////////////

VarSSHKey::VarSSHKey(ModuleLoc loc) : Var(loc, 0), val(nullptr) {}

void VarSSHKey::onDestroy(VirtualMachine &vm) { clear(); }

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

FERAL_FUNC(sessionSetLogCB, 1, false,
           "  var.fn(callback) -> Nil\n"
           "Sets the log callback for `var` as `callback`.")
{
    VarSSHSession *ssh = as<VarSSHSession>(args[0]);
    Var *&logCB        = ssh->getLogCB();
    if(logCB) vm.decVarRef(logCB);
    logCB = vm.incVarRef(args[1]);
    return vm.getNil();
}

FERAL_FUNC(sessionConnectNative, 0, false,
           "  var.fn() -> Int\n"
           "Connects the SSH session `var`, returning `0` on success.")
{
    VarSSHSession *ssh = as<VarSSHSession>(args[0]);
    int res            = ssh->connect(vm);
    return vm.makeVar<VarInt>(loc, res);
}

FERAL_FUNC(sessionDisconnect, 0, false,
           "  var.fn() -> Nil\n"
           "Disconnects the SSH session `var`.")
{
    VarSSHSession *ssh = as<VarSSHSession>(args[0]);
    ssh->disconnect();
    return vm.getNil();
}

FERAL_FUNC(sessionSetOptNative, 2, false,
           "  var.fn(option, value) -> Int\n"
           "Sets the `option` as `value` for the ssh session `var`. Returns `OK` on success.")
{
    EXPECT(VarInt, args[1], "option");
    VarSSHSession *ssh = as<VarSSHSession>(args[0]);
    ssh_options_e opt  = (ssh_options_e)as<VarInt>(args[1])->getVal();
    int res            = 0;
    switch(opt) {
    case SSH_OPTIONS_HOST:
    case SSH_OPTIONS_PORT_STR:
    case SSH_OPTIONS_USER: {
        EXPECT(VarStr, args[2], "value");
        const String &val = as<VarStr>(args[2])->getVal();
        res               = ssh->setOpt(vm, opt, val.c_str());
        break;
    }
    case SSH_OPTIONS_PORT:
    case SSH_OPTIONS_LOG_VERBOSITY: {
        EXPECT(VarInt, args[2], "value");
        int val = as<VarInt>(args[2])->getVal();
        res     = ssh->setOpt(vm, opt, &val);
        break;
    }
    default:
        vm.fail(loc, "unknown option: ", (int)opt, " for setting ssh session option");
        return nullptr;
    }
    return vm.makeVar<VarInt>(loc, res);
}

FERAL_FUNC(sessionGetServerPublicKeyNative, 1, false,
           "  var.fn(key) -> Int\n"
           "Sets the session `var`'s server's public key in `key` which should be of type SSHKey.\n"
           "Returns `OK` on success.")
{
    EXPECT(VarSSHKey, args[1], "ssh key");
    VarSSHSession *ssh = as<VarSSHSession>(args[0]);
    VarSSHKey *key     = as<VarSSHKey>(args[1]);
    int res            = ssh->getPublicKey(vm, key);
    return vm.makeVar<VarInt>(loc, res);
}

FERAL_FUNC(sessionUpdateKnownHostsNative, 0, false,
           "  var.fn() -> Int\n"
           "Updates the known hosts file with any new key for the remote.\n"
           "Returns `OK` on success.")
{
    VarSSHSession *ssh = as<VarSSHSession>(args[0]);
    return vm.makeVar<VarInt>(loc, ssh->updateKnownHosts(vm));
}

FERAL_FUNC(sessionAuthList, 0, false,
           "  var.fn() -> Int\n"
           "Returns the bitfield containing valid AUTH_METHOD_*s to authenticate with the server.")
{
    VarSSHSession *ssh = as<VarSSHSession>(args[0]);
    return vm.makeVar<VarInt>(loc, ssh->userAuthList(vm));
}

FERAL_FUNC(sessionAuthNoneNative, 0, false,
           "  var.fn() -> Int\n"
           "Attempts to perform user authentication without any credentials.\n"
           "Returns `AUTH_SUCCESS` on success.")
{
    VarSSHSession *ssh = as<VarSSHSession>(args[0]);
    return vm.makeVar<VarInt>(loc, ssh->userAuthNone(vm));
}

FERAL_FUNC(sessionAuthTryPublicKeyNative, 1, false,
           "  var.fn(publicKey) -> Int\n"
           "Checks if authentication can be performed using `publicKey`.\n"
           "If it succeeds, `userAuthPublicKey()` should be used to actually authenticate.\n"
           "Returns `AUTH_SUCCESS` on success.")
{
    VarSSHSession *ssh = as<VarSSHSession>(args[0]);
    EXPECT(VarSSHKey, args[1], "public key");
    return vm.makeVar<VarInt>(loc, ssh->userAuthTryPublicKey(vm, as<VarSSHKey>(args[1])));
}

FERAL_FUNC(sessionAuthPublicKeyNative, 1, false,
           "  var.fn(privateKey) -> Int\n"
           "Attempts to authenticate using `privateKey`.\n"
           "Returns `AUTH_SUCCESS` on success.")
{
    VarSSHSession *ssh = as<VarSSHSession>(args[0]);
    EXPECT(VarSSHKey, args[1], "private key");
    return vm.makeVar<VarInt>(loc, ssh->userAuthPublicKey(vm, as<VarSSHKey>(args[1])));
}

FERAL_FUNC(sessionAuthPublicKeyAutoNative, 1, false,
           "  var.fn(passphrase) -> Int\n"
           "Attempts to auto authenticate using public keys from the running ssh agent.\n"
           "A `passphrase` string can be provided if required to decrypt one of the private keys.\n"
           "Returns `AUTH_SUCCESS` on success.")
{
    VarSSHSession *ssh = as<VarSSHSession>(args[0]);
    EXPECT2(VarStr, VarNil, args[1], "passphrase");
    VarStr *passphrase = args[1]->is<VarStr>() ? as<VarStr>(args[1]) : nullptr;
    return vm.makeVar<VarInt>(loc, ssh->userAuthPublicKeyAuto(vm, passphrase));
}

FERAL_FUNC(sessionAuthPasswordNative, 1, false,
           "  var.fn(password) -> Int\n"
           "Attempts to authenticate using the given password.\n"
           "Returns `AUTH_SUCCESS` on success.")
{
    VarSSHSession *ssh = as<VarSSHSession>(args[0]);
    EXPECT(VarStr, args[1], "password");
    return vm.makeVar<VarInt>(loc, ssh->userAuthPassword(vm, as<VarStr>(args[1])));
}

FERAL_FUNC(sessionAuthKbdIntNative, 0, false,
           "  var.fn() -> Int\n"
           "Attempts to perform user authentication using keyboard-interactive method.\n"
           "Returns `AUTH_SUCCESS` on success, `AUTH_INFO` if the server asked some questions.")
{
    VarSSHSession *ssh = as<VarSSHSession>(args[0]);
    return vm.makeVar<VarInt>(loc, ssh->userAuthKbdInt(vm));
}

FERAL_FUNC(sessionAuthKbdIntGetNPrompts, 0, false,
           "  var.fn() -> Int\n"
           "Returns the number of prompts expected by the server.")
{
    VarSSHSession *ssh = as<VarSSHSession>(args[0]);
    return vm.makeVar<VarInt>(loc, ssh->userAuthKbdIntGetNPrompts(vm));
}

FERAL_FUNC(sessionAuthKbdIntGetName, 0, false,
           "  var.fn() -> Str\n"
           "Returns the name of the message block for the questions from the server.")
{
    VarSSHSession *ssh = as<VarSSHSession>(args[0]);
    return vm.makeVar<VarStr>(loc, ssh->userAuthKbdIntGetName(vm));
}

FERAL_FUNC(sessionAuthKbdIntGetInstruction, 0, false,
           "  var.fn() -> Str\n"
           "Returns the instruction of the message block for the questions from the server.")
{
    VarSSHSession *ssh = as<VarSSHSession>(args[0]);
    return vm.makeVar<VarStr>(loc, ssh->userAuthKbdIntGetInstruction(vm));
}

FERAL_FUNC(
    sessionAuthKbdIntGetPrompt, 2, false,
    "  var.fn(index, shouldEcho) -> Str\n"
    "Returns the prompt for the questions from the server for the given `index`.\n"
    "`shouldEcho` is set as `true` if the answer for the prompt should be hidden (like password).")
{
    VarSSHSession *ssh = as<VarSSHSession>(args[0]);
    EXPECT(VarInt, args[1], "prompt index");
    EXPECT(VarBool, args[2], "should echo");
    VarInt *index       = as<VarInt>(args[1]);
    VarBool *shouldEcho = as<VarBool>(args[2]);
    const char *res     = ssh->userAuthKbdIntGetPrompt(vm, index, shouldEcho);
    return vm.makeVar<VarStr>(loc, res);
}

FERAL_FUNC(sessionAuthKbdIntSetAnswerNative, 2, false,
           "  var.fn(index, answer) -> Int\n"
           "Sets the `answer` for the question at `index` in the message block.\n"
           "Returns `OK` on success.")
{
    VarSSHSession *ssh = as<VarSSHSession>(args[0]);
    EXPECT(VarInt, args[1], "prompt index");
    EXPECT(VarStr, args[2], "answer");
    VarInt *index  = as<VarInt>(args[1]);
    VarStr *answer = as<VarStr>(args[2]);
    int res        = ssh->userAuthKbdIntSetAnswer(vm, index, answer);
    return vm.makeVar<VarInt>(loc, res);
}

FERAL_FUNC(sessionGetIssueBanner, 0, false,
           "  var.fn() -> Str | Nil\n"
           "Returns the server banner as a string, or `nil` if one doesn't exist.\n"
           "Make sure `authNone()` is called before this function - should be done in "
           "`ssh.authenticate()` if using that.\n"
           "But also, `authNone()` must not be called more than once as that would cause the "
           "session to hang.")
{
    VarSSHSession *ssh = as<VarSSHSession>(args[0]);
    char *banner       = ssh->getIssueBanner(vm);
    if(banner) {
        Var *res = vm.makeVar<VarStr>(loc, banner);
        free(banner);
        return res;
    }
    return vm.getNil();
}

FERAL_FUNC(sessionGetError, 0, false,
           "  var.fn() -> Str\n"
           "Returns the last error in SSH session `var` as a string.")
{
    VarSSHSession *ssh = as<VarSSHSession>(args[0]);
    return vm.makeVar<VarStr>(loc, ssh->getError());
}

FERAL_FUNC(sessionGetErrorCode, 0, false,
           "  var.fn() -> Int\n"
           "Returns the last error code in SSH session `var` as an Int.")
{
    VarSSHSession *ssh = as<VarSSHSession>(args[0]);
    return vm.makeVar<VarInt>(loc, ssh->getErrorCode());
}

FERAL_FUNC(sessionIsKnownServer, 0, false,
           "  var.fn() -> Int\n"
           "Returns the state as Int representing the status of the server being known.")
{
    VarSSHSession *ssh = as<VarSSHSession>(args[0]);
    return vm.makeVar<VarInt>(loc, ssh->isKnownServer());
}

////////////////////////////////////////// SSH Key ///////////////////////////////////////////////

FERAL_FUNC(sshNewKey, 0, false,
           "  fn() -> SSHKey\n"
           "Creates and returns an instance of SSH Key.")
{
    return vm.makeVar<VarSSHKey>(loc);
}

FERAL_FUNC(
    keyGetPublicKeyHashNative, 1, false,
    "  var.fn(hash) -> Int\n"
    "Sets the ssh key `var`'s server's public key in `hash` which should be of type string.\n"
    "Returns `OK` on success.")
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

FERAL_FUNC(keyImportPublicNative, 1, false,
           "  var.fn(filePath) -> Int\n"
           "Imports a public key from the given `filePath`.\n"
           "Returns `OK` on success.")
{
    VarSSHKey *key = as<VarSSHKey>(args[0]);
    EXPECT(VarStr, args[1], "file path");
    key->clear();
    VarStr *filePath = as<VarStr>(args[1]);
    return vm.makeVar<VarInt>(loc, key->importPublic(filePath));
}

FERAL_FUNC(keyImportPrivateNative, 2, false,
           "  var.fn(filePath, passphrase) -> Int\n"
           "Imports a private key from the given `filePath`.\n"
           "Returns `OK` on success.")
{
    VarSSHKey *key = as<VarSSHKey>(args[0]);
    EXPECT(VarStr, args[1], "file path");
    EXPECT2(VarStr, VarNil, args[2], "passphrase");
    key->clear();
    VarStr *filePath   = as<VarStr>(args[1]);
    VarStr *passphrase = args[2]->is<VarStr>() ? as<VarStr>(args[2]) : nullptr;
    return vm.makeVar<VarInt>(loc, key->importPrivate(filePath, passphrase));
}

FERAL_FUNC(keyGetError, 0, false,
           "  var.fn() -> Str\n"
           "Returns the last error in SSH Key `var` as a string.")
{
    VarSSHKey *key = as<VarSSHKey>(args[0]);
    return vm.makeVar<VarStr>(loc, key->getError());
}

FERAL_FUNC(keyGetErrorCode, 0, false,
           "  var.fn() -> Int\n"
           "Returns the last error code in SSH Key `var` as an Int.")
{
    VarSSHKey *key = as<VarSSHKey>(args[0]);
    return vm.makeVar<VarStr>(loc, key->getErrorCode());
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

    // SSHSession
    vm.addTypeFn<VarSSHSession>(loc, "setLogCB", sessionSetLogCB);
    vm.addTypeFn<VarSSHSession>(loc, "connectNative", sessionConnectNative);
    vm.addTypeFn<VarSSHSession>(loc, "disconnect", sessionDisconnect);
    vm.addTypeFn<VarSSHSession>(loc, "setOptNative", sessionSetOptNative);
    vm.addTypeFn<VarSSHSession>(loc, "getServerPublicKeyNative", sessionGetServerPublicKeyNative);
    vm.addTypeFn<VarSSHSession>(loc, "updateKnownHostsNative", sessionUpdateKnownHostsNative);
    vm.addTypeFn<VarSSHSession>(loc, "authList", sessionAuthList);
    vm.addTypeFn<VarSSHSession>(loc, "authNoneNative", sessionAuthNoneNative);
    vm.addTypeFn<VarSSHSession>(loc, "authTryPublicKeyNative", sessionAuthTryPublicKeyNative);
    vm.addTypeFn<VarSSHSession>(loc, "authPublicKeyNative", sessionAuthPublicKeyNative);
    vm.addTypeFn<VarSSHSession>(loc, "authPublicKeyAutoNative", sessionAuthPublicKeyAutoNative);
    vm.addTypeFn<VarSSHSession>(loc, "authPasswordNative", sessionAuthPasswordNative);
    vm.addTypeFn<VarSSHSession>(loc, "authKbdIntNative", sessionAuthKbdIntNative);
    vm.addTypeFn<VarSSHSession>(loc, "authKbdIntGetNPrompts", sessionAuthKbdIntGetNPrompts);
    vm.addTypeFn<VarSSHSession>(loc, "authKbdIntGetName", sessionAuthKbdIntGetName);
    vm.addTypeFn<VarSSHSession>(loc, "authKbdIntGetPrompt", sessionAuthKbdIntGetPrompt);
    vm.addTypeFn<VarSSHSession>(loc, "authKbdIntSetAnswerNative", sessionAuthKbdIntSetAnswerNative);
    vm.addTypeFn<VarSSHSession>(loc, "getIssueBanner", sessionGetIssueBanner);
    vm.addTypeFn<VarSSHSession>(loc, "getError", sessionGetError);
    vm.addTypeFn<VarSSHSession>(loc, "getErrorCode", sessionGetErrorCode);
    vm.addTypeFn<VarSSHSession>(loc, "isKnownServer", sessionIsKnownServer);

    // SSHKey
    vm.addTypeFn<VarSSHKey>(loc, "getHashNative", keyGetPublicKeyHashNative);
    vm.addTypeFn<VarSSHKey>(loc, "importPublicNative", keyImportPublicNative);
    vm.addTypeFn<VarSSHKey>(loc, "importPrivateNative", keyImportPrivateNative);
    vm.addTypeFn<VarSSHKey>(loc, "getError", keyGetError);
    vm.addTypeFn<VarSSHKey>(loc, "getErrorCode", keyGetErrorCode);

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
    // auth results
    vm.makeLocal<VarInt>(loc, "AUTH_ERROR", "", SSH_AUTH_ERROR);
    vm.makeLocal<VarInt>(loc, "AUTH_DENIED", "", SSH_AUTH_DENIED);
    vm.makeLocal<VarInt>(loc, "AUTH_PARTIAL", "", SSH_AUTH_PARTIAL);
    vm.makeLocal<VarInt>(loc, "AUTH_SUCCESS", "", SSH_AUTH_SUCCESS);
    vm.makeLocal<VarInt>(loc, "AUTH_AGAIN", "", SSH_AUTH_AGAIN);
    // auth methods
    vm.makeLocal<VarInt>(loc, "AUTH_METHOD_NONE", "", SSH_AUTH_METHOD_NONE);
    vm.makeLocal<VarInt>(loc, "AUTH_METHOD_PUBLICKEY", "", SSH_AUTH_METHOD_PUBLICKEY);
    vm.makeLocal<VarInt>(loc, "AUTH_METHOD_HOSTBASED", "", SSH_AUTH_METHOD_HOSTBASED);
    vm.makeLocal<VarInt>(loc, "AUTH_METHOD_INTERACTIVE", "", SSH_AUTH_METHOD_INTERACTIVE);
    vm.makeLocal<VarInt>(loc, "AUTH_METHOD_PASSWORD", "", SSH_AUTH_METHOD_PASSWORD);
    return true;
}

} // namespace fer