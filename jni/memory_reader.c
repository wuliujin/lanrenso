#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <dirent.h>
#include <ctype.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

static pid_t g_pid = -1;
static int g_attached = 0;

// ---------- 附加/分离进程 ----------
pid_t get_pid_by_package(const char *package_name) {
    DIR *dir = opendir("/proc");
    if (!dir) return -1;
    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL) {
        if (!isdigit(entry->d_name[0])) continue;
        pid_t pid = atoi(entry->d_name);
        char cmdline_path[64];
        snprintf(cmdline_path, sizeof(cmdline_path), "/proc/%d/cmdline", pid);
        FILE *fp = fopen(cmdline_path, "r");
        if (fp) {
            char buf[256];
            if (fgets(buf, sizeof(buf), fp) && strstr(buf, package_name)) {
                fclose(fp);
                closedir(dir);
                return pid;
            }
            fclose(fp);
        }
    }
    closedir(dir);
    return -1;
}

// ---------- 获取模块基址，支持 type ----------
// uintptr_t get_module_base(const char *module_name, int type) {
//     if (!g_attached) return 0;

//     char filename[64], line[512];
//     snprintf(filename, sizeof(filename), "/proc/%d/maps", g_pid);
//     FILE *fp = fopen(filename, "r");
//     if (!fp) return 0;

//     const char *perm_type;
//     switch(type) {
//         case 0: perm_type = "r-xp"; break;  // 可执行段
//         case 1: perm_type = "rw-p"; break;  // 可读写段
//         case 2: perm_type = "r--p"; break;  // 只读段
//         case 3: perm_type = "rwxp"; break;  // 读写执行段
//         default: perm_type = "r-xp"; break;
//     }

//     uintptr_t addr = 0;
//     while (fgets(line, sizeof(line), fp)) {
//         // 找到 pathname
//         char *path = strchr(line, '/');
//         if (!path) continue;
//         if (strstr(path, module_name) == NULL) continue;

//         // 获取权限列
//         char perms[5] = {0};
//         if (sscanf(line, "%*lx-%*lx %4s", perms) == 1) {
//             if (strncmp(perms, perm_type, 4) != 0) continue; // 比较前4位
//         } else {
//             continue;
//         }

// #if UINTPTR_MAX == 0xffffffff
//         // 32 位系统
//         unsigned long start;
//         if (sscanf(line, "%lx-", &start) == 1) {
//             addr = (uintptr_t)start;
//             break;
//         }
// #else
//         // 64 位系统
//         unsigned long long start;
//         if (sscanf(line, "%llx-", &start) == 1) {
//             addr = (uintptr_t)start;
//             break;
//         }
// #endif
//     }

//     fclose(fp);
//     return addr;
// }


uintptr_t get_module_base(const char *module_name, int type) {
    if (!g_attached) return 0;
    char filename[64], line[1024];
    snprintf(filename, sizeof(filename), "/proc/%d/maps", g_pid);
    FILE *fp = fopen(filename, "r");
    if (!fp) return 0;

    const char *pref_perm = "r-xp";
    if (type==1) pref_perm="rw-p"; // etc.

    uintptr_t fallback = 0, best = 0;
    while (fgets(line, sizeof(line), fp)) {
        char *path = strchr(line, '/');
        if (!path) continue;
        // basename
        char *bname = strrchr(path, '/');
        if (bname) bname++;
        else bname = path;
        // compare basename first, then full path
        if (strstr(bname, module_name)==NULL && strstr(path, module_name)==NULL) continue;

        unsigned long long start=0, end=0;
        char perms[8] = {0};
        if (sscanf(line, "%llx-%llx %7s", &start, &end, perms) < 2) continue;
        if (start==0) continue;
        // 首选匹配权限
        if (strncmp(perms, pref_perm, 4) == 0) {
            best = (uintptr_t)start;
            break;
        }
        // 记录一个可用回退地址
        if (fallback == 0) fallback = (uintptr_t)start;
    }
    fclose(fp);
    return best ? best : fallback;
}


__attribute__((visibility("default")))
int attach_process_by_package(const char *package_name) {
    if (g_attached) return 1;
    pid_t pid = get_pid_by_package(package_name);
    if (pid <= 0) return -1;
    if (ptrace(PTRACE_ATTACH, pid, NULL, NULL) == -1) return -2;
    waitpid(pid, NULL, 0);
    g_pid = pid;
    g_attached = 1;
    return 0;
}

__attribute__((visibility("default")))
int detach_process() {
    if (!g_attached) return 1;
    if (ptrace(PTRACE_DETACH, g_pid, NULL, NULL) == -1) return -1;
    g_attached = 0;
    g_pid = -1;
    return 0;
}

// ---------- 内部读取指针 ----------
uintptr_t read_pointer(uintptr_t addr) {
    errno = 0;
    long data = ptrace(PTRACE_PEEKDATA, g_pid, (void*)addr, NULL);
    if (data == -1 && errno != 0) return 0;
#if UINTPTR_MAX == 0xffffffff
    return (uintptr_t)(data & 0xFFFFFFFF);
#else
    return (uintptr_t)data;
#endif
}

// ---------- 固定地址读取 ----------
__attribute__((visibility("default")))
long read_memory_at(uintptr_t addr, int type) {
    errno = 0;
    long data = ptrace(PTRACE_PEEKDATA, g_pid, (void*)addr, NULL);
    if (data == -1 && errno != 0) return -1;
    switch (type) {
        case 0: return (int)(data & 0xFFFFFFFF);
        case 1: return (short)(data & 0xFFFF);
        case 2: return (uint8_t)(data & 0xFF);
        case 3: return data;
        default: return data;
    }
}

// ---------- 多级指针读取 ----------
__attribute__((visibility("default")))
long read_chain_from_string(const char *chain_str, int type) {
    if (!g_attached || !chain_str) return -100;
    char buf[256];
    strncpy(buf, chain_str, sizeof(buf)-1);
    buf[sizeof(buf)-1] = '\0';

    char *token = strtok(buf, "|");
    if (!token) return -101;

    char module[128];
    strncpy(module, token, sizeof(module)-1);
    module[sizeof(module)-1] = '\0';

    token = strtok(NULL, "|");
    if (!token) return -102;
    uintptr_t base_offset = strtoul(token, NULL, 16);

    uintptr_t offsets[32];
    int depth = 0;
    while ((token = strtok(NULL, "|")) != NULL && depth < 32) {
        offsets[depth++] = strtoul(token, NULL, 16);
    }

    uintptr_t module_base = get_module_base(module, 0); // 默认 type=0
    if (!module_base) return -103;

    uintptr_t addr = module_base + base_offset;
    for (int i = 0; i < depth; i++) {
        addr = read_pointer(addr);
        if (!addr) return -104;
        addr += offsets[i];
    }

    return read_memory_at(addr, type);
}

// ---------- 读取内存块 ----------
__attribute__((visibility("default")))
char* read_bytes_hex(uintptr_t addr, size_t len) {
    if (len == 0) return NULL;
    char *hexstr = (char*)malloc(len * 2 + 1);
    if (!hexstr) return NULL;

    size_t read_bytes = 0;
    char *p = hexstr;
    while (read_bytes < len) {
        errno = 0;
        long data = ptrace(PTRACE_PEEKDATA, g_pid, (void*)(addr + read_bytes), NULL);
        if (data == -1 && errno != 0) {
            free(hexstr);
            return NULL;
        }

        uint8_t *bytes = (uint8_t*)&data;
        size_t remain = len - read_bytes;
        size_t copy_len = sizeof(long);
        if (copy_len > remain) copy_len = remain;

        for (size_t i = 0; i < copy_len; i++) {
            sprintf(p, "%02X", bytes[i]);
            p += 2;
        }
        read_bytes += copy_len;
    }
    *p = '\0';
    return hexstr;
}

// ---------- 新增导出函数 ----------

// 根据包名获取 PID（返回 int）
__attribute__((visibility("default")))
int get_pid_by_package_name(const char *package_name) {
    pid_t pid = get_pid_by_package(package_name);
    return (int)pid;
}

// 根据模块名获取基址（返回 16 进制字符串，可指定 type）
__attribute__((visibility("default")))
uintptr_t get_module_base_by_name(const char *module_name, int type) {
    uintptr_t base = get_module_base(module_name, type);
    if (base == 0) return 0; // 没找到模块直接返回 NULL
    return base;
}

// ---------- 根据偏移链字符串获取地址（不读取值） ----------
// chain_str 格式: module|baseOffsetHex|offset1Hex|offset2Hex|...
// 返回最终计算得到的地址，失败返回 0
__attribute__((visibility("default")))
uintptr_t get_chain_address_by_string(const char *chain_str) {
    if (!g_attached || !chain_str) return 0;
    char buf[256];
    strncpy(buf, chain_str, sizeof(buf)-1);
    buf[sizeof(buf)-1] = '\0';

    char *token = strtok(buf, "|");
    if (!token) return 0;

    char module[128];
    strncpy(module, token, sizeof(module)-1);
    module[sizeof(module)-1] = '\0';

    token = strtok(NULL, "|");
    if (!token) return 0;
    uintptr_t base_offset = (uintptr_t)strtoull(token, NULL, 16);

    uintptr_t offsets[32];
    int depth = 0;
    while ((token = strtok(NULL, "|")) != NULL && depth < 32) {
        offsets[depth++] = (uintptr_t)strtoull(token, NULL, 16);
    }

    uintptr_t module_base = get_module_base(module, 0);
    if (!module_base) return 0;

    uintptr_t addr = module_base + base_offset;
    for (int i = 0; i < depth; i++) {
        addr = read_pointer(addr);
        if (!addr) return 0;
        addr += offsets[i];
    }

    return addr;
}
