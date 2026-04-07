//
// Created by dingjing on 2025/8/26.
//

#include "plugins.h"

#include <cstring>
#include <dfm-extension/dfm-extension.h>
#include <dfm-extension/menu/dfmextmenu.h>
#include <dfm-extension/menu/dfmextaction.h>
#include <dfm-extension/menu/dfmextmenuproxy.h>
#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>
#include <syslog.h>
#include <stdlib.h>
#include <string.h>
#include <sys/un.h>
#include <syscall.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <sys/socket.h>

#include "ipc.h"
#include "defines.h"


#define SAFE_FS_LOCK_DEVICE_TYPE                0x8812
#define MISC_DEV                                "/dev/safe_fs"

// 控制相关
#define SAFE_IOCTL_CTRL_PRIV_DEC                _IOR(SAFE_FS_LOCK_DEVICE_TYPE, 0x4, long)   // 是否允许特权解密
#define SAFE_IOCTL_CTRL_MANUAL_ENC              _IOR(SAFE_FS_LOCK_DEVICE_TYPE, 0x5, long)   // 是否允许手动加密

typedef struct
{
    const char*      src;
    const char*      dest;
} AndsecLanguage;

static bool         andsec_language_is_chinese  (void);
static bool         andsec_language_is_english  (void);
static const char*  andsec_translate            (const char* str);
static void         andsec_files_execute_cmd    (const std::list<std::string> files, bool enc);

#define STR_FREE(x) do { if (x) { free (x); x = NULL; } } while (0)

static inline long do_ioctl(unsigned long cmd, void* param)
{
    int fd = syscall(__NR_openat, -1, MISC_DEV, O_RDWR);
    if (fd < 0) {
        // syslog(LOG_ERR, "do_ioctl open error!");
        return -1;
    }

    if (syscall(__NR_ioctl, fd, cmd, param) < 0) {
        syscall(__NR_close, fd);
        // syslog(LOG_ERR, "do_ioctl %lx ioctl error!", cmd);
        return -1;
    }

    syscall(__NR_close, fd);

    return 0;
}


bool andsec_ioctl_priv_dec_enabled (void)
{
    long ret = 0;

    if (do_ioctl(SAFE_IOCTL_CTRL_PRIV_DEC, &ret) < 0) {
        ret = 0;
    }

    return (ret == 1);
}

bool andsec_ioctl_manual_enc_enabled (void)
{
    long ret = 0;

    if (do_ioctl(SAFE_IOCTL_CTRL_MANUAL_ENC, &ret) < 0) {
        ret = 0;
    }

    return (1 == ret);
}

static bool get_mouse_manual_encrypt()
{
    int res = (andsec_ioctl_manual_enc_enabled() ? 0 : -1);

    return (0 == res);
}

static bool get_priv_decrypt_enabled()
{
    int res = (andsec_ioctl_priv_dec_enabled() ? 0 : -1);

    return (0 == res);
}

static void send_data_to_daemon(IpcServerType type, short isCN, const char* files, unsigned int dataLen)
{
    int val = 1;
    int sockFd = 0;
    int timeout = 2000;
    int revTimeout = 31 * 1000;
    struct sockaddr_un address;

    if ((sockFd = socket(PF_UNIX, SOCK_STREAM, 0)) < 0) {
        return;
    }

    setsockopt(sockFd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
    setsockopt(sockFd, SOL_SOCKET, SO_RCVTIMEO, &revTimeout, sizeof(revTimeout));
    setsockopt(sockFd, SOL_SOCKET, SO_REUSEADDR, &val, sizeof(val));

    memset(&address, 0, sizeof(struct sockaddr_un));
    address.sun_family = AF_UNIX;
    snprintf(address.sun_path, 108, IPC_SERVER_SOCKET_PATH);
    const int len = sizeof(address);

    if (0 != connect(sockFd, reinterpret_cast<struct sockaddr*>(&address), len)) {
        close(sockFd);
        return;
    }

    struct IpcMessage msgBuf = {};
    struct PrivilegedDecAndEncData data = {};

    data.isCN = isCN;
    data.isPierec = 0;
    data.filesLen = dataLen;

    msgBuf.type = type;
    msgBuf.dataLen = sizeof(data) + dataLen + 1;

    const int allLen = dataLen + sizeof(data) + sizeof(msgBuf);
    char* sendBuf = (char*) malloc (allLen);
    if (sendBuf) {
        memset(sendBuf, 0, allLen);
        memcpy(sendBuf, &msgBuf, sizeof(msgBuf));
        memcpy(sendBuf + sizeof(msgBuf), &data, sizeof(data));
        memcpy(sendBuf + sizeof(msgBuf) + sizeof(data), files, dataLen);
        write(sockFd, sendBuf, allLen);
        free(sendBuf);
        sendBuf = nullptr;
    }

    close(sockFd);
}

static int send_data_to_daemon(IpcServerType type, const char* sendData, int sendDataLen, char* recvData, int recvDataBufLen)
{
    int res = 0;
    int val = 1;
    int sockFd = 0;
    int timeout = 2000;
    int revtimeout = 31 * 1000;
    struct sockaddr_un address;

    char* sendBuf = nullptr;
    char recvBuf[1024] = {0};

    if (sendDataLen < 0 || recvDataBufLen < 0) {
        syslog(LOG_ERR, "sendData: %p, recvData: %p, sendDataLen: %d, recvDataBufLen: %d", sendData, recvData, sendDataLen, recvDataBufLen);
        return -1;
    }

    do {
        if ((sockFd = socket(PF_UNIX, SOCK_STREAM, 0)) < 0) {
            syslog(LOG_ERR, "[IPC] socket() failed!");
            res = -1;
            break;
        }

        setsockopt(sockFd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
        setsockopt(sockFd, SOL_SOCKET, SO_RCVTIMEO, &revtimeout, sizeof(revtimeout));
        setsockopt(sockFd, SOL_SOCKET, SO_REUSEADDR, &val, sizeof(val));

        memset(&address, 0, sizeof(struct sockaddr_un));
        address.sun_family = AF_UNIX;
        snprintf(address.sun_path, 108, IPC_SERVER_SOCKET_PATH);
        int len = sizeof(address);

        if (0 != connect(sockFd, (struct sockaddr*)&address, len)) {
            syslog(LOG_ERR, "[IPC] connect error!");
            res = -1;
            break;
        }

        struct IpcMessage msgBuf;
        memset(&msgBuf, 0, sizeof(msgBuf));

        msgBuf.type = type;
        msgBuf.dataLen = sendDataLen;

        // 开始发送
        int allLen = (int) sizeof(struct IpcMessage) + sendDataLen;
        sendBuf = (char*) malloc (allLen);
        if (!sendBuf) {
            syslog(LOG_ERR, "[IPC] malloc is null!");
            res = -1;
            break;
        }
        memset(sendBuf, 0, allLen);
        memcpy(sendBuf, &msgBuf, sizeof(msgBuf));
        if (sendDataLen > 0) {
            memcpy(sendBuf + sizeof(msgBuf), sendData, sendDataLen);
        }
        write(sockFd, sendBuf, allLen);
        STR_FREE(sendBuf);

        // 开始接收
        if (recvData) {
            int ri = 0;

            ri = read(sockFd, recvBuf, sizeof(recvBuf));
            if (ri < sizeof(struct IpcMessage)) {
                res = -1;
                syslog(LOG_ERR, "[IPC] recvBuf len too small.");
            }
            else {
                struct IpcMessage* im = (struct IpcMessage*) recvBuf;
                memset(recvData, 0, recvDataBufLen);
                memcpy(recvData, im->data, im->dataLen);
            }
        }
    } while (0);

    if (sockFd >= 0) {
        close(sockFd);
    }

    STR_FREE(sendBuf);

    return res;
}

static int send_data_with_return_int(IpcServerType type, const char* sendData, int sendDataLen)
{
    int res = -1;

    char buf[8] = {0};

    if (0 == send_data_to_daemon(type, sendData, sendDataLen, buf, sizeof(buf) - 1)) {
        res = (int) strtol(buf, NULL, 10);
    }

    return res;
}

static bool check_is_encrypt_file(const char* file)
{
    DataInfo di;

    di.dataLen = strlen(file);
    int len = sizeof(DataInfo) + strlen(file) + 1;
    char* buffer = (char*) malloc (len);
    memset(buffer, 0, len);
    memccpy(buffer, &di, 1, sizeof(di));
    memccpy(buffer + sizeof(di), file, 1, strlen(file));

    const int ret = send_data_with_return_int(IPC_TYPE_TEST_ENCRYPT_FILE_SYNC, buffer, len);
    STR_FREE(buffer);

    return (1 == ret);
}

static const AndsecLanguage gsChinese[] = {
    { "Andsec", "数据卫士" },
    { "Manual encryption",      "手动加密"},
    { "Privileged decryption",  "特权解密"},
    { "Decryption success",     "解密成功"},
    { "Decryption failed",      "解密失败"},
    { "Encryption success",     "加密成功"},
    { "Encryption failed",      "加密失败"},
    { "Total file",             "文件总数"},
    {nullptr, nullptr},
};




EmblemIconPlugins::EmblemIconPlugins()
    : DFMEXT::DFMExtEmblemIconPlugin()
{
    registerLocationEmblemIcons([this](const std::string &filePath, int systemIconCount) {
        return locationEmblemIcons(filePath, systemIconCount);
    });
}

DFMEXT::DFMExtEmblem EmblemIconPlugins::locationEmblemIcons(const std::string &filePath, int systemIconCount) const
{
    DFMEXT::DFMExtEmblem emblem;

    if (systemIconCount >= 4) {
        return emblem;
    }

    struct stat fstat;
    if (0 != stat(filePath.c_str(), &fstat)) {
        syslog(LOG_ERR, "[IPC] stat error!");
        return emblem;
    }
    if (fstat.st_mode & S_IFREG) {
        // syslog(LOG_ERR, "[IPC] find any encrypted file: %s!", filePath.c_str());
        if (check_is_encrypt_file(filePath.c_str())) {
            std::vector<DFMEXT::DFMExtEmblemIconLayout> layouts;
            const std::string iconPath = "/usr/local/andsec/data/andsec_lock.png";
            DFMEXT::DFMExtEmblemIconLayout iconLayout { DFMEXT::DFMExtEmblemIconLayout::LocationType::BottomRight, iconPath };
            layouts.push_back(iconLayout);
            emblem.setEmblem(layouts);
        }
        else {
            std::vector<DFMEXT::DFMExtEmblemIconLayout> layouts;
            const std::string iconPath = "/usr/local/andsec/data/empty.png";
            DFMEXT::DFMExtEmblemIconLayout iconLayout { DFMEXT::DFMExtEmblemIconLayout::LocationType::BottomRight, iconPath };
            layouts.push_back(iconLayout);
            emblem.setEmblem(layouts);
        }
    }


    return emblem;
}


MenuPlugins::MenuPlugins()
    : DFMEXT::DFMExtMenuPlugin()
{
    registerInitialize([this](DFMEXT::DFMExtMenuProxy *proxy) {
        initialize(proxy);
    });

    registerBuildNormalMenu([this](DFMEXT::DFMExtMenu *main, const std::string &currentPath,
                                   const std::string &focusPath, const std::list<std::string> &pathList,
                                   bool onDesktop) {
        return buildNormalMenu(main, currentPath, focusPath, pathList, onDesktop);
    });
}

void MenuPlugins::initialize(DFMEXT::DFMExtMenuProxy *proxy)
{
    mProxy = proxy;
}

bool MenuPlugins::buildNormalMenu(DFMEXT::DFMExtMenu *main,
                     const std::string &currentPath,
                     const std::string &focusPath,
                     const std::list<std::string> &pathList,
                     bool onDesktop)
{
    if (!pathList.empty()) {
        bool e = get_mouse_manual_encrypt();
        bool d = get_priv_decrypt_enabled();

        if (e || d) {
            auto rootAction { mProxy->createAction() };
            rootAction->setText(andsec_translate("Andsec"));
            rootAction->registerHovered([this, pathList, e, d](DFMEXT::DFMExtAction *action) {
                if (!action->menu()->actions().empty()) {
                    return;
                }
                if (e) {
                    auto ea { mProxy->createAction() };
                    ea->setText(andsec_translate("Manual encryption"));
                    ea->registerTriggered([this, pathList](DFMEXT::DFMExtAction *, bool) {
                        andsec_files_execute_cmd(pathList, true);
                    });
                    action->menu()->addAction(ea);
                }

                if (d) {
                    auto da { mProxy->createAction() };
                    da->setText(andsec_translate("Privileged decryption"));
                    da->registerTriggered([this, pathList](DFMEXT::DFMExtAction *, bool) {
                        andsec_files_execute_cmd(pathList, false);
                    });
                    action->menu()->addAction(da);
                }
            });
            auto menu { mProxy->createMenu() };
            rootAction->setMenu(menu);
            main->addAction(rootAction);
            return true;
        }
    }

    (void)onDesktop;
    (void)currentPath;
    (void)focusPath;

    return true;
}


static bool andsec_language_is_english (void)
{
    const char* ls = getenv("LANG");

    return (!ls || (0 == strncmp(ls, "en_US", 5)));
}

static bool andsec_language_is_chinese (void)
{
    const char* ls = getenv("LANG");

    return (ls && (0 == strncmp(ls, "zh_CN", 5)));
}

static const char* andsec_translate (const char* str)
{
    if (andsec_language_is_chinese()) {
        int i = 0;
        for (i = 0; nullptr != gsChinese[i].src; ++i) {
            if (0 == strcmp(str, gsChinese[i].src)) {
                return gsChinese[i].dest;
            }
        }
    }

    return str;
}

static void andsec_files_execute_cmd (const std::list<std::string> files, bool enc)
{
    if (files.empty()) { return; }

    std::string allFiles;

    for (const auto & file : files) {
        if (0 == strncmp(file.c_str(), "file://", 7)) {
            allFiles += file.substr(7, file.size() - 7);
        }
        else {
            allFiles += file;
        }
        allFiles += "|";
    }

    if (!allFiles.empty()) {
        allFiles.pop_back();
    }

    // 发送文件
    send_data_to_daemon((enc ? IPC_TYPE_PRIVILEGED_ENCRYPT_FILES_SYNC : IPC_TYPE_PRIVILEGED_DECRYPT_FILES_SYNC), andsec_language_is_chinese(), allFiles.c_str(), allFiles.size());
}


static DFMEXT::DFMExtMenuPlugin *gsMenu { nullptr };
static DFMEXT::DFMExtEmblemIconPlugin* gsEmblemIcon { nullptr };


extern "C" void dfm_extension_initiliaze()
{
    gsMenu = new MenuPlugins;
    gsEmblemIcon = new EmblemIconPlugins;
}

extern "C" void dfm_extension_shutdown()
{
    delete gsMenu;
    delete gsEmblemIcon;
}

extern "C" DFMEXT::DFMExtEmblemIconPlugin* dfm_extension_emblem()
{
    return gsEmblemIcon;
}

extern "C" DFMEXT::DFMExtMenuPlugin *dfm_extension_menu()
{
    return gsMenu;
}