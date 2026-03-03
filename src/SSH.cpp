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
////////////////////////////////////////// VarSSHKey /////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////////////////////////

VarSSHKey::VarSSHKey(ModuleLoc loc) : Var(loc, 0), val(nullptr) {}

void VarSSHKey::onDestroy(VirtualMachine &vm) { clear(); }

//////////////////////////////////////////////////////////////////////////////////////////////////
//////////////////////////////////////// VarSSHChannel ///////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////////////////////////

VarSSHChannelRef::VarSSHChannelRef(ModuleLoc loc, ssh_session ssh, ssh_channel val)
    : Var(loc, 0), ssh(ssh), val(val), valid(true)
{}

void VarSSHChannelRef::onDestroy(VirtualMachine &vm) { close(); }

int VarSSHChannelRef::open()
{
    if(!isValid()) return SSH_ERROR;
    return ssh_channel_open_session(val);
}

int VarSSHChannelRef::close()
{
    if(!isValid()) return SSH_ERROR;
    int res = ssh_channel_send_eof(val);
    if(res != SSH_OK) return res;
    return ssh_channel_close(val);
}

int VarSSHChannelRef::read(VarStr *output, bool readStderr)
{
    String &data = output->getVal();
    char buffer[128];
    int nbytes = sizeof(buffer);
    // Loop is so that if full buffer is read, assume more may be present and read it.
    while(nbytes == sizeof(buffer)) {
        nbytes = ssh_channel_read(val, buffer, sizeof(buffer), readStderr ? 1 : 0);
        if(nbytes > 0) data.append(buffer, nbytes);
    }
    return nbytes;
}

int VarSSHChannelRef::write(StringRef data, bool writeStderr)
{
    int nbytes = 0;
    if(writeStderr) nbytes = ssh_channel_write_stderr(val, data.data(), data.size());
    else nbytes = ssh_channel_write(val, data.data(), data.size());
    return nbytes;
}

//////////////////////////////////////////////////////////////////////////////////////////////////
///////////////////////////////////// VarSFTPFileHandle //////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////////////////////////

VarSFTPFileHandle::VarSFTPFileHandle(ModuleLoc loc, sftp_file val)
    : Var(loc, 0), val(val), isOpen(true)
{}
void VarSFTPFileHandle::onDestroy(VirtualMachine &vm) { close(); }

//////////////////////////////////////////////////////////////////////////////////////////////////
///////////////////////////////////// VarSFTPDirHandle ///////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////////////////////////

VarSFTPDirHandle::VarSFTPDirHandle(ModuleLoc loc, sftp_dir val)
    : Var(loc, 0), val(val), isOpen(true)
{}
void VarSFTPDirHandle::onDestroy(VirtualMachine &vm) { close(); }

//////////////////////////////////////////////////////////////////////////////////////////////////
//////////////////////////////////////// VarSFTPSession //////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////////////////////////

VarSFTPSessionRef::VarSFTPSessionRef(ModuleLoc loc, sftp_session val)
    : Var(loc, 0), val(val), valid(true)
{}

void VarSFTPSessionRef::onDestroy(VirtualMachine &vm) { sftp_free(val); }

VarSFTPFileHandle *VarSFTPSessionRef::openFile(VirtualMachine &vm, ModuleLoc loc, VarStr *path,
                                               VarInt *mode, VarInt *perms)
{
    sftp_file file = sftp_open(val, path->getVal().c_str(), mode->getVal(), perms->getVal());
    if(!file) {
        vm.fail(loc, "failed to open SFTP file `", path->getVal(), "`: ", getSSHError());
        return nullptr;
    }
    return vm.makeVar<VarSFTPFileHandle>(loc, file);
}

VarSFTPDirHandle *VarSFTPSessionRef::openDir(VirtualMachine &vm, ModuleLoc loc, VarStr *path)
{
    sftp_dir dir = sftp_opendir(val, path->getVal().c_str());
    if(!dir) {
        vm.fail(loc, "failed to open SFTP dir `", path->getVal(), "`: ", getSSHError());
        return nullptr;
    }
    return vm.makeVar<VarSFTPDirHandle>(loc, dir);
}

int VarSFTPSessionRef::writeFile(VarSFTPFileHandle *file, VarStr *data)
{
    StringRef s = data->getVal();
    int written = sftp_write(file->getVal(), s.data(), s.size());
    if(written != s.size()) return SSH_ERROR;
    return written;
}

int VarSFTPSessionRef::readFile(VarSFTPFileHandle *file, VarStr *data)
{
    // Good buffer size apparently.
    char buffer[16384];
    size_t prevSz = data->getVal().size();
    for(;;) {
        int nbytes = sftp_read(file->getVal(), buffer, sizeof(buffer));
        if(!nbytes) break; // EOF
        if(nbytes < 0) return SSH_ERROR;
        data->getVal().append(buffer, nbytes);
    }
    return data->getVal().size() - prevSz;
}

//////////////////////////////////////////////////////////////////////////////////////////////////
//////////////////////////////////////// VarSSHSession ///////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////////////////////////

VarSSHSession::VarSSHSession(ModuleLoc loc, ssh_session val)
    : Var(loc, 0), vm(nullptr), logCB(nullptr), cbPrio(nullptr), cbFunc(nullptr), cbBuf(nullptr),
      val(val), connected(false)
{}

void VarSSHSession::onCreate(VirtualMachine &vm)
{
    cbPrio       = vm.incVarRef(vm.makeVar<VarInt>(getLoc(), 0));
    cbFunc       = vm.incVarRef(vm.makeVar<VarStr>(getLoc(), ""));
    cbBuf        = vm.incVarRef(vm.makeVar<VarStr>(getLoc(), ""));
    channels     = vm.incVarRef(vm.makeVar<VarVec>(getLoc(), 0, true));
    sftpSessions = vm.incVarRef(vm.makeVar<VarVec>(getLoc(), 0, true));
    ssh_set_log_userdata(this);
}

void VarSSHSession::onDestroy(VirtualMachine &vm)
{
    disconnect(vm);
    if(val) ssh_free(val);
    vm.decVarRef(sftpSessions);
    vm.decVarRef(channels);
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

void VarSSHSession::disconnect(VirtualMachine &vm)
{
    if(!connected) return;
    // channels must be invalidated before disconnection.
    for(auto &s : sftpSessions->getVal()) as<VarSFTPSessionRef>(s)->invalidate();
    for(auto &c : channels->getVal()) as<VarSSHChannelRef>(c)->invalidate();
    sftpSessions->clear(vm);
    channels->clear(vm);
    ssh_disconnect(val);
    connected = false;
}

VarSSHChannelRef *VarSSHSession::newChannel(VirtualMachine &vm, ModuleLoc loc)
{
    ssh_channel rawChan = ssh_channel_new(val);
    if(!rawChan) {
        vm.fail(loc, "failed to allocate channel");
        return nullptr;
    }
    VarSSHChannelRef *chan = vm.makeVar<VarSSHChannelRef>(loc, val, rawChan);
    channels->push(vm, chan, true);
    return chan;
}

VarSFTPSessionRef *VarSSHSession::newSFTPSession(VirtualMachine &vm, ModuleLoc loc,
                                                 VarSSHChannelRef *chan)
{
    sftp_session rawSession = sftp_new_channel(val, chan->getVal());
    if(!rawSession) {
        vm.fail(loc, "failed to allocate SFTP session object");
        return nullptr;
    }
    VarSFTPSessionRef *sftp = vm.makeVar<VarSFTPSessionRef>(loc, rawSession);
    sftpSessions->push(vm, sftp, true);
    return sftp;
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
    ssh->disconnect(vm);
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

FERAL_FUNC(sessionIsKnownServer, 0, false,
           "  var.fn() -> Int\n"
           "Returns the state as Int representing the status of the server being known.")
{
    VarSSHSession *ssh = as<VarSSHSession>(args[0]);
    return vm.makeVar<VarInt>(loc, ssh->isKnownServer());
}

FERAL_FUNC(sessionNewChannelNative, 0, false,
           "  var.fn() -> SSHChannel\n"
           "Creates and returns an instance of SSH Channel, associated with the SSH Session `var`.")
{
    VarSSHSession *ssh = as<VarSSHSession>(args[0]);
    return ssh->newChannel(vm, loc);
}

FERAL_FUNC(sessionNewSFTPSessionNative, 1, false,
           "  var.fn(channel) -> SFTPSession\n"
           "Creates and returns an instance of SFTPSession, associated with the SSH Session `var` "
           "and using `channel`.")
{
    EXPECT(VarSSHChannelRef, args[1], "channel to use");
    VarSSHSession *ssh     = as<VarSSHSession>(args[0]);
    VarSSHChannelRef *chan = as<VarSSHChannelRef>(args[1]);
    return ssh->newSFTPSession(vm, loc, chan);
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
    return vm.makeVar<VarInt>(loc, key->getErrorCode());
}

///////////////////////////////////////// SSH Channel /////////////////////////////////////////////

FERAL_FUNC(channelOpenNative, 0, false,
           "  var.fn() -> Int\n"
           "Opens the channel `var`. Returns `OK` on success.")
{
    VarSSHChannelRef *chan = as<VarSSHChannelRef>(args[0]);
    return vm.makeVar<VarInt>(loc, chan->open());
}

FERAL_FUNC(channelCloseNative, 0, false,
           "  var.fn() -> Int\n"
           "Closes the channel `var`. Returns `OK` on success.")
{
    VarSSHChannelRef *chan = as<VarSSHChannelRef>(args[0]);
    return vm.makeVar<VarInt>(loc, chan->close());
}

FERAL_FUNC(channelRequestPtyNative, 2, false,
           "  var.fn(width = 80, height = 24) -> Int\n"
           "Request a PTY from the channel `var` of size `width` x `height`.\n"
           "Returns `OK` on success.")
{
    EXPECT(VarInt, args[1], "width");
    EXPECT(VarInt, args[2], "height");
    VarSSHChannelRef *chan = as<VarSSHChannelRef>(args[0]);
    VarInt *width          = as<VarInt>(args[1]);
    VarInt *height         = as<VarInt>(args[2]);
    return vm.makeVar<VarInt>(loc, chan->requestPty(width, height));
}

FERAL_FUNC(channelRequestShellNative, 0, false,
           "  var.fn() -> Int\n"
           "Request a shell from the channel `var`.\n"
           "Returns `OK` on success.")
{
    VarSSHChannelRef *chan = as<VarSSHChannelRef>(args[0]);
    return vm.makeVar<VarInt>(loc, chan->requestShell());
}

FERAL_FUNC(channelRequestSFTPNative, 0, false,
           "  var.fn() -> Int\n"
           "Request SFTP from the channel `var`.\n"
           "Returns `OK` on success.")
{
    VarSSHChannelRef *chan = as<VarSSHChannelRef>(args[0]);
    return vm.makeVar<VarInt>(loc, chan->requestSFTP());
}

FERAL_FUNC(channelReadNative, 2, false,
           "  var.fn(data, fromStderr = false) -> Int\n"
           "Read data from the channel `var` into `data`.\n"
           "If `fromStderr` is `true`, the data is read from `stderr`.\n"
           "Returns number of bytes read on success, SSH_ERROR on failure.")
{
    EXPECT(VarStr, args[1], "data");
    EXPECT(VarBool, args[2], "from stderr");
    VarSSHChannelRef *chan = as<VarSSHChannelRef>(args[0]);
    VarStr *data           = as<VarStr>(args[1]);
    VarBool *fromStderr    = as<VarBool>(args[2]);
    return vm.makeVar<VarInt>(loc, chan->read(data, fromStderr->getVal()));
}

FERAL_FUNC(channelWriteNative, 2, false,
           "  var.fn(data, toStderr = false) -> Int\n"
           "Writes `data` to the channel `var`.\n"
           "If `toStderr` is `true`, the data is written to `stderr`.\n"
           "Returns number of bytes written on success, SSH_ERROR on failure.")
{
    EXPECT(VarStr, args[1], "data");
    EXPECT(VarBool, args[2], "to stderr");
    VarSSHChannelRef *chan = as<VarSSHChannelRef>(args[0]);
    VarStr *data           = as<VarStr>(args[1]);
    VarBool *toStderr      = as<VarBool>(args[2]);
    return vm.makeVar<VarInt>(loc, chan->write(data->getVal(), toStderr->getVal()));
}

FERAL_FUNC(channelSendEof, 0, false,
           "  var.fn() -> Int\n"
           "Sends an EOF on the channel. No writing may be performed on the channel after this.\n"
           "Returns `OK` on success.")
{
    VarSSHChannelRef *chan = as<VarSSHChannelRef>(args[0]);
    return vm.makeVar<VarInt>(loc, chan->sendEof());
}

FERAL_FUNC(channelIsValid, 0, false,
           "  var.fn() -> Bool\n"
           "Returns `true` if the channel `var` is valid (not freed already by session).")
{
    VarSSHChannelRef *chan = as<VarSSHChannelRef>(args[0]);
    return chan->isValid() ? vm.getTrue() : vm.getFalse();
}

FERAL_FUNC(channelIsOpen, 0, false,
           "  var.fn() -> Bool\n"
           "Returns `true` if the channel `var` is open.")
{
    VarSSHChannelRef *chan = as<VarSSHChannelRef>(args[0]);
    return chan->isOpen() ? vm.getTrue() : vm.getFalse();
}

FERAL_FUNC(channelIsEOF, 0, false,
           "  var.fn() -> Bool\n"
           "Returns `true` if the channel `var` is not at EOF.")
{
    VarSSHChannelRef *chan = as<VarSSHChannelRef>(args[0]);
    return chan->isEOF() ? vm.getTrue() : vm.getFalse();
}

FERAL_FUNC(channelGetError, 0, false,
           "  var.fn() -> Str\n"
           "Returns the last error in SSH Key `var` as a string.")
{
    VarSSHChannelRef *chan = as<VarSSHChannelRef>(args[0]);
    return vm.makeVar<VarStr>(loc, chan->getError());
}

FERAL_FUNC(channelGetErrorCode, 0, false,
           "  var.fn() -> Int\n"
           "Returns the last error code in SSH channel `var` as an Int.")
{
    VarSSHChannelRef *chan = as<VarSSHChannelRef>(args[0]);
    return vm.makeVar<VarInt>(loc, chan->getErrorCode());
}

///////////////////////////////////////// SFTP Session ////////////////////////////////////////////

FERAL_FUNC(sftpSessionInitNative, 0, false,
           "  var.fn() -> Int\n"
           "Initializes the SFTP session `var`.\n"
           "Returns `OK` on success.")
{
    VarSFTPSessionRef *sftp = as<VarSFTPSessionRef>(args[0]);
    return vm.makeVar<VarInt>(loc, sftp->initialize());
}

FERAL_FUNC(sftpSessionOpenFileNative, 3, false,
           "  var.fn(path, mode, perms) -> SFTPFileHandle\n"
           "Opens and returns an SFTP file at `path` using session `var`, using `mode`, with "
           "`perms` permissions.")
{
    EXPECT(VarStr, args[1], "path");
    EXPECT(VarInt, args[2], "mode");
    EXPECT(VarInt, args[3], "permissions");
    VarSFTPSessionRef *sftp = as<VarSFTPSessionRef>(args[0]);
    VarStr *path            = as<VarStr>(args[1]);
    VarInt *mode            = as<VarInt>(args[2]);
    VarInt *perms           = as<VarInt>(args[3]);
    return sftp->openFile(vm, loc, path, mode, perms);
}

FERAL_FUNC(sftpSessionWriteFileNative, 2, false,
           "  var.fn(fileHandle, data) -> Int\n"
           "Writes `data` into file `fileHandle`.\n"
           "Returns number of written bytes or `ERROR` on failure.")
{
    EXPECT(VarSFTPFileHandle, args[1], "file handle");
    EXPECT(VarStr, args[2], "data");
    VarSFTPSessionRef *sftp = as<VarSFTPSessionRef>(args[0]);
    VarSFTPFileHandle *file = as<VarSFTPFileHandle>(args[1]);
    VarStr *data            = as<VarStr>(args[2]);
    return vm.makeVar<VarInt>(loc, sftp->writeFile(file, data));
}

FERAL_FUNC(sftpSessionReadFileNative, 2, false,
           "  var.fn(fileHandle, data) -> Int\n"
           "Reads file `fileHandle` into `data`.\n"
           "Returns number of read bytes or `ERROR` on failure.")
{
    EXPECT(VarSFTPFileHandle, args[1], "file handle");
    EXPECT(VarStr, args[2], "data");
    VarSFTPSessionRef *sftp = as<VarSFTPSessionRef>(args[0]);
    VarSFTPFileHandle *file = as<VarSFTPFileHandle>(args[1]);
    VarStr *data            = as<VarStr>(args[2]);
    return vm.makeVar<VarInt>(loc, sftp->readFile(file, data));
}

FERAL_FUNC(sftpSessionOpenDir, 1, false,
           "  var.fn(path) -> SFTPFileHandle\n"
           "Opens and returns an SFTP dir at `path` using session `var`.")
{
    EXPECT(VarStr, args[1], "path");
    VarSFTPSessionRef *sftp = as<VarSFTPSessionRef>(args[0]);
    VarStr *path            = as<VarStr>(args[1]);
    return sftp->openDir(vm, loc, path);
}

FERAL_FUNC(sftpSessionGetSSHError, 0, false,
           "  var.fn() -> Str\n"
           "Returns the last error in SSH session associated with SFTP session `var` as a string.")
{
    VarSFTPSessionRef *sftp = as<VarSFTPSessionRef>(args[0]);
    return vm.makeVar<VarStr>(loc, sftp->getSSHError());
}

FERAL_FUNC(
    sftpSessionGetSSHErrorCode, 0, false,
    "  var.fn() -> Int\n"
    "Returns the last error code in SSH session associated with SFTP session `var` as an Int.")
{
    VarSFTPSessionRef *sftp = as<VarSFTPSessionRef>(args[0]);
    return vm.makeVar<VarInt>(loc, sftp->getSSHErrorCode());
}

FERAL_FUNC(sftpSessionGetError, 0, false,
           "  var.fn() -> Str\n"
           "Returns the last error message in SFTP session `var` as a string.")
{
    VarSFTPSessionRef *sftp = as<VarSFTPSessionRef>(args[0]);
    StringRef msg           = "unknown";
    switch(sftp->getErrorCode()) {
    case SSH_FX_OK: msg = "no error"; break;
    case SSH_FX_EOF: msg = "end-of-file encountered"; break;
    case SSH_FX_NO_SUCH_FILE: msg = "file does not exist"; break;
    case SSH_FX_PERMISSION_DENIED: msg = "permission denied"; break;
    case SSH_FX_FAILURE: msg = "generic failure"; break;
    case SSH_FX_BAD_MESSAGE: msg = "garbage received from server"; break;
    case SSH_FX_NO_CONNECTION: msg = "no connection has been set up"; break;
    case SSH_FX_CONNECTION_LOST: msg = "there was a connection, but we lost it"; break;
    case SSH_FX_OP_UNSUPPORTED: msg = "operation not supported by libssh yet"; break;
    case SSH_FX_INVALID_HANDLE: msg = "invalid file handle"; break;
    case SSH_FX_NO_SUCH_PATH: msg = "no such file or directory path exists"; break;
    case SSH_FX_FILE_ALREADY_EXISTS: msg = "file or directory already exists"; break;
    case SSH_FX_WRITE_PROTECT: msg = "write-protected filesystem"; break;
    case SSH_FX_NO_MEDIA: msg = "no media was in remote drive"; break;
    }
    return vm.makeVar<VarStr>(loc, msg);
}

FERAL_FUNC(sftpSessionGetErrorCode, 0, false,
           "  var.fn() -> Int\n"
           "Returns the last error code in SFTP session `var` as an Int.")
{
    VarSFTPSessionRef *sftp = as<VarSFTPSessionRef>(args[0]);
    return vm.makeVar<VarInt>(loc, sftp->getErrorCode());
}

/////////////////////////////////////////// SFTP File /////////////////////////////////////////////

FERAL_FUNC(sftpFileCloseNative, 0, false,
           "  var.fn() -> Int\n"
           "Closes the SFTP file handle `var`.\n"
           "Returns `OK` on success, `ERROR` on failure.")
{
    VarSFTPFileHandle *handle = as<VarSFTPFileHandle>(args[0]);
    return vm.makeVar<VarInt>(loc, handle->close());
}

FERAL_FUNC(sftpFileGetSSHError, 0, false,
           "  var.fn() -> Str\n"
           "Returns the last error in SSH session associated with SFTP file `var` as a string.")
{
    VarSFTPFileHandle *handle = as<VarSFTPFileHandle>(args[0]);
    return vm.makeVar<VarStr>(loc, ssh_get_error(handle->getVal()->sftp->session));
}

FERAL_FUNC(sftpFileGetSSHErrorCode, 0, false,
           "  var.fn() -> Int\n"
           "Returns the last error code in SSH session associated with SFTP file `var` as Int.")
{
    VarSFTPFileHandle *handle = as<VarSFTPFileHandle>(args[0]);
    return vm.makeVar<VarStr>(loc, ssh_get_error_code(handle->getVal()->sftp->session));
}

/////////////////////////////////////////// SFTP Dir //////////////////////////////////////////////

FERAL_FUNC(sftpDirCloseNative, 0, false,
           "  var.fn() -> Int\n"
           "Closes the SFTP dir handle `var`.\n"
           "Returns `OK` on success, `ERROR` on failure.")
{
    VarSFTPDirHandle *handle = as<VarSFTPDirHandle>(args[0]);
    return vm.makeVar<VarInt>(loc, handle->close());
}

FERAL_FUNC(sftpDirIsEOF, 0, false,
           "  var.fn() -> Bool\n"
           "Returns `true` if SFTPDir `var` is at EOF.")
{
    VarSFTPDirHandle *handle = as<VarSFTPDirHandle>(args[0]);
    return handle->isEOF() ? vm.getTrue() : vm.getFalse();
}

FERAL_FUNC(sftpDirGetSSHError, 0, false,
           "  var.fn() -> Str\n"
           "Returns the last error in SSH session associated with SFTP dir `var` as a string.")
{
    VarSFTPDirHandle *handle = as<VarSFTPDirHandle>(args[0]);
    return vm.makeVar<VarStr>(loc, ssh_get_error(handle->getVal()->sftp->session));
}

FERAL_FUNC(sftpDirGetSSHErrorCode, 0, false,
           "  var.fn() -> Int\n"
           "Returns the last error code in SSH session associated with SFTP dir `var` as Int.")
{
    VarSFTPDirHandle *handle = as<VarSFTPDirHandle>(args[0]);
    return vm.makeVar<VarStr>(loc, ssh_get_error_code(handle->getVal()->sftp->session));
}

INIT_DLL(SSH)
{
    ssh_set_log_callback(SSHLoggingCallback);

    vm.addLocalType<VarSSHSession>(loc, "SSHSession", "SSH session object");
    vm.addLocalType<VarSSHKey>(loc, "SSHKey", "SSH key object");
    vm.addLocalType<VarSSHChannelRef>(loc, "SSHChannel", "SSH channel object");
    vm.addLocalType<VarSFTPSessionRef>(loc, "SFTPSession", "SFTP session object");
    vm.addLocalType<VarSFTPFileHandle>(loc, "SFTPFileHandle", "SFTP file handle object");
    vm.addLocalType<VarSFTPDirHandle>(loc, "SFTPDirHandle", "SFTP dir handle object");

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
    vm.addTypeFn<VarSSHSession>(loc, "isKnownServer", sessionIsKnownServer);
    vm.addTypeFn<VarSSHSession>(loc, "newChannelNative", sessionNewChannelNative);
    vm.addTypeFn<VarSSHSession>(loc, "newSFTPSessionNative", sessionNewSFTPSessionNative);
    vm.addTypeFn<VarSSHSession>(loc, "getError", sessionGetError);
    vm.addTypeFn<VarSSHSession>(loc, "getErrorCode", sessionGetErrorCode);

    // SSHKey
    vm.addTypeFn<VarSSHKey>(loc, "getHashNative", keyGetPublicKeyHashNative);
    vm.addTypeFn<VarSSHKey>(loc, "importPublicNative", keyImportPublicNative);
    vm.addTypeFn<VarSSHKey>(loc, "importPrivateNative", keyImportPrivateNative);
    vm.addTypeFn<VarSSHKey>(loc, "getError", keyGetError);
    vm.addTypeFn<VarSSHKey>(loc, "getErrorCode", keyGetErrorCode);

    // SSHChannel
    vm.addTypeFn<VarSSHChannelRef>(loc, "openNative", channelOpenNative);
    vm.addTypeFn<VarSSHChannelRef>(loc, "closeNative", channelCloseNative);
    vm.addTypeFn<VarSSHChannelRef>(loc, "requestPtyNative", channelRequestPtyNative);
    vm.addTypeFn<VarSSHChannelRef>(loc, "requestShellNative", channelRequestShellNative);
    vm.addTypeFn<VarSSHChannelRef>(loc, "requestSFTPNative", channelRequestSFTPNative);
    vm.addTypeFn<VarSSHChannelRef>(loc, "readNative", channelReadNative);
    vm.addTypeFn<VarSSHChannelRef>(loc, "writeNative", channelWriteNative);
    vm.addTypeFn<VarSSHChannelRef>(loc, "sendEOF", channelSendEof);
    vm.addTypeFn<VarSSHChannelRef>(loc, "isValid", channelIsValid);
    vm.addTypeFn<VarSSHChannelRef>(loc, "isOpen", channelIsOpen);
    vm.addTypeFn<VarSSHChannelRef>(loc, "isEOF", channelIsEOF);
    vm.addTypeFn<VarSSHChannelRef>(loc, "getError", channelGetError);
    vm.addTypeFn<VarSSHChannelRef>(loc, "getErrorCode", channelGetErrorCode);

    // SFTPSession
    vm.addTypeFn<VarSFTPSessionRef>(loc, "initNative", sftpSessionInitNative);
    vm.addTypeFn<VarSFTPSessionRef>(loc, "openFileNative", sftpSessionOpenFileNative);
    vm.addTypeFn<VarSFTPSessionRef>(loc, "writeFileNative", sftpSessionWriteFileNative);
    vm.addTypeFn<VarSFTPSessionRef>(loc, "readFileNative", sftpSessionReadFileNative);
    vm.addTypeFn<VarSFTPSessionRef>(loc, "openDir", sftpSessionOpenDir);
    vm.addTypeFn<VarSFTPSessionRef>(loc, "getError", sftpSessionGetError);
    vm.addTypeFn<VarSFTPSessionRef>(loc, "getErrorCode", sftpSessionGetErrorCode);
    vm.addTypeFn<VarSFTPSessionRef>(loc, "getSSHError", sftpSessionGetSSHError);
    vm.addTypeFn<VarSFTPSessionRef>(loc, "getSSHErrorCode", sftpSessionGetSSHErrorCode);

    // SFTPFileHandle
    vm.addTypeFn<VarSFTPFileHandle>(loc, "closeNative", sftpFileCloseNative);
    vm.addTypeFn<VarSFTPFileHandle>(loc, "getSSHError", sftpFileGetSSHError);
    vm.addTypeFn<VarSFTPFileHandle>(loc, "getSSHErrorCode", sftpFileGetSSHErrorCode);

    // SFTPDirHandle
    vm.addTypeFn<VarSFTPDirHandle>(loc, "closeNative", sftpDirCloseNative);
    vm.addTypeFn<VarSFTPDirHandle>(loc, "isEOF", sftpDirIsEOF);
    vm.addTypeFn<VarSFTPDirHandle>(loc, "getSSHError", sftpDirGetSSHError);
    vm.addTypeFn<VarSFTPDirHandle>(loc, "getSSHErrorCode", sftpDirGetSSHErrorCode);

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

    // SFTP

    // error codes
    vm.makeLocal<VarInt>(loc, "FX_OK", "no error", SSH_FX_OK);
    vm.makeLocal<VarInt>(loc, "FX_EOF", "end-of-file encountered", SSH_FX_EOF);
    vm.makeLocal<VarInt>(loc, "FX_NO_SUCH_FILE", "file does not exist", SSH_FX_NO_SUCH_FILE);
    vm.makeLocal<VarInt>(loc, "FX_PERMISSION_DENIED", "permission denied",
                         SSH_FX_PERMISSION_DENIED);
    vm.makeLocal<VarInt>(loc, "FX_FAILURE", "generic failure", SSH_FX_FAILURE);
    vm.makeLocal<VarInt>(loc, "FX_BAD_MESSAGE", "garbage received from server", SSH_FX_BAD_MESSAGE);
    vm.makeLocal<VarInt>(loc, "FX_NO_CONNECTION", "no connection has been set up",
                         SSH_FX_NO_CONNECTION);
    vm.makeLocal<VarInt>(loc, "FX_CONNECTION_LOST", "there was a connection, but we lost it",
                         SSH_FX_CONNECTION_LOST);
    vm.makeLocal<VarInt>(loc, "FX_OP_UNSUPPORTED", "operation not supported by libssh yet",
                         SSH_FX_OP_UNSUPPORTED);
    vm.makeLocal<VarInt>(loc, "FX_INVALID_HANDLE", "invalid file handle", SSH_FX_INVALID_HANDLE);
    vm.makeLocal<VarInt>(loc, "FX_NO_SUCH_PATH", "no such file or directory path exists",
                         SSH_FX_NO_SUCH_PATH);
    vm.makeLocal<VarInt>(loc, "FX_FILE_ALREADY_EXISTS",
                         "an attempt to create an already existing file or directory has been made",
                         SSH_FX_FILE_ALREADY_EXISTS);
    vm.makeLocal<VarInt>(loc, "FX_WRITE_PROTECT", "write-protected filesystem",
                         SSH_FX_WRITE_PROTECT);
    vm.makeLocal<VarInt>(loc, "FX_NO_MEDIA", "no media was in remote drive", SSH_FX_NO_MEDIA);
    return true;
}

} // namespace fer