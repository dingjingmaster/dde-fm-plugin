#ifndef DEFINES_H
#define DEFINES_H

/**
 * @brief 此头文件中不引入任何其他头文件
 */

#define KERNEL_MODULE_NAME                  "sec_fs"
#define EXIT_CODE_WITH_RESTART              588
#define TIMEOUT_TRAY_MSG                    5  * 1000
#define CONNECT_TIME_OUT_NSEC	            (9 * 1000 * 10)

#define OFFLINE_CHECK_INTERVAL_S            60          // 离线检测间隔，单位是 秒

/* 登录状态 -- 开始 */
#define LOGIN_STATUS_ONLINE                 "1"
#define LOGIN_STATUS_LOGOUT	                "0"
#define LOGIN_STATUS_OFFLINE                "2"
/* 登录状态 -- 结束 */

/* 请求的服务器路径 -- 开始 */
#define URL_TEST_CONNECT                    "/index.html"
#define URL_TEST_UI_CONNECT                 "/desktop/"
/* 请求的服务器路径 -- 结束 */


#ifdef __APPLE__
#include <QStandardPaths>

#define VER_CLIENT                          "3.3.2"
#define VER_DRIVER                          "3.3.2"

#define DATA_RW_PATH                        QStandardPaths::writableLocation(QStandardPaths::GenericDataLocation)+"/andsec_"
#define PATH_FILE_POLICY                    DATA_RW_PATH+"policy.dat"
#define PATH_CLIENTID                       DATA_RW_PATH+"_clientid.dat"
#define PATH_CONFIG_INI                     DATA_RW_PATH+"config.ini"
#define MOUNT_DISABLE_CONFIG                DATA_RW_PATH+"_fs_disable"
#define MOUNT_POINT_CONFIG                  DATA_RW_PATH+"_fs_mountpoints"
#define ANDSEC_CAN_PRIV_DEC                 DATA_RW_PATH+"_menu_decrypt"
#define ANDSEC_NETSEC_POLICY                DATA_RW_PATH+"_netsec_policy.dat"
#define ANDSEC_FS_MOUNTED_KEYFILE           (DATA_RW_PATH+"_fs.cfg").toStdString().c_str()
#define WEBSOCKET_DEVICE_PATTERN            "MACOS;%1;AND_GUARD_MACOS;%2"

#define ANDSEC_SCAN_RESULT_IN               "/usr/local/andsec/log/scanResult_m.log"
#define ANDSEC_SCAN_RESULT_OUT              "/usr/local/andsec/log/scanResult.log"

#define IPC_FINDER_SOCKET_PORT              60024

#else


#define VER_CLIENT                          "3.2.12"
#define VER_DRIVER                          "3.2.12"

#define SCANNER_TASK_DIR                    "/usr/local/andsec/scan"
#define PATH_FILE_POLICY                    "/usr/policy/policy.dat"
#define PATH_CLIENTID                       "/usr/local/.clientid.dat"
#define ANDSEC_FS_MOUNTED_KEYFILE           "/usr/local/andsec/.fs.cfg"
#define PATH_CONFIG_INI                     "/usr/local/andsec/config.ini"
#define MOUNT_DISABLE_CONFIG                "/usr/local/andsec/.fs_disable"
#define MOUNT_POINT_CONFIG                  "/usr/local/andsec/.fs_mountpoints"
#define ANDSEC_CAN_PRIV_DEC                 "/usr/local/andsec/__andsec_menu_decrypt"
#define ANDSEC_CAN_PRIV_ENC                 "/usr/local/andsec/__andsec_menu_encrypt"
#define ANDSEC_NETSEC_POLICY                "/usr/local/andsec/netsec/.netsec_policy.dat"
#define WEBSOCKET_DEVICE_PATTERN            "LINUX;%1;AND_GUARD_LINUX;%2"

#define ANDSEC_SCAN_RESULT_IN               "/usr/local/andsec/log/scanResult_m.log"
#define ANDSEC_SCAN_RESULT_OUT              "/usr/local/andsec/log/scanResult.log"
#endif



#define ANDSEC_SANDBOX_SOCKET               "/usr/local/andsec/sandbox/data/sandbox.sock"
#define ANDSEC_SANDBOX_BIN                  "/usr/local/andsec/sandbox/bin/andsec-sandbox"
#define IPC_SERVER_SOCKET_PATH              "/usr/local/andsec/start/sec_daemon.sock"

#define IPC_CLIENT_SOCKET_PATH              "/usr/local/andsec/start/andsec_status.sock"

// cgroup v1 -- /sys/fs/cgroup/cpu/xxx/cgroup.procs
// cgroup v2 -- /sys/fs/cgroup/xxx/cgroup.procs
#define SANDBOX_CGROUP_PROCESS_MONITOR      "sandbox_process_monitor"
#define SANDBOX_NET_PATH                    "/sys/fs/cgroup/net_cls/sandbox_net_monitor"

#define ANDSEC_DEC_VIEW                     "/var/lib/andsec/mount"

#define IPC_SERVER_SOCKET_ADDR              "127.0.0.1"
#define IPC_CLIENT_SOCKET_ADDR              "127.0.0.1"
#define IPC_SERVER_SOCKET_PORT              60022
#define IPC_CLIENT_SOCKET_PORT              60023


#define CIPHERTEXT_MODE                     "0"         // 密文模式
#define PLAINTEXT_MODE                      "1"         // 明文模式

#define WEBSOCKET_PORT 		9099
#define CHECK_OFFLINE_TIME	5000


#endif // DEFINES_H
