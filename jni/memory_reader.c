//D:\android-ndk-r19c\ndk-build.cmd NDK_PROJECT_PATH=. APP_BUILD_SCRIPT=./jni/Android.mk NDK_APPLICATION_MK=./jni/Application.mk
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <dirent.h>
#include <ctype.h>
#include <sys/types.h>
#include <unistd.h>
#include <fcntl.h>
#include <inttypes.h>  // 使用 SCNxPTR / PRIxPTR
#include <sys/stat.h>

static pid_t g_pid = -1;
static int g_mem_fd = -1;

// ---------- 附加/分离进程 ----------
pid_t get_pid_by_package(const char *package_name) {
    DIR *dir = opendir("/proc");
    if (!dir) return -1;
    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL) {
        if (!isdigit((unsigned char)entry->d_name[0])) continue;
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

uintptr_t get_module_base(const char *module_name, int type) {
    if (g_pid <= 0) return 0;
    char filename[64], line[1024];
    snprintf(filename, sizeof(filename), "/proc/%d/maps", g_pid);
    FILE *fp = fopen(filename, "r");
    if (!fp) return 0;

    const char *pref_perm = "r-xp";
    if (type==1) pref_perm="rw-p";

    uintptr_t fallback = 0, best = 0;
    while (fgets(line, sizeof(line), fp)) {
        char *path = strchr(line, '/');
        if (!path) continue;
        char *bname = strrchr(path, '/');
        if (bname) bname++;
        else bname = path;
        if (strstr(bname, module_name)==NULL && strstr(path, module_name)==NULL) continue;

        uintptr_t start=0, end=0;
        char perms[8] = {0};
        if (sscanf(line, "%" SCNxPTR "-%" SCNxPTR " %7s", &start, &end, perms) < 2) continue;
        if (start==0) continue;
        if (strncmp(perms, pref_perm, 4) == 0) {
            best = start;
            break;
        }
        if (fallback == 0) fallback = start;
    }
    fclose(fp);
    return best ? best : fallback;
}

__attribute__((visibility("default")))
int attach_process_by_package(const char *package_name) {
    if (g_mem_fd > 0) return 1;
    pid_t pid = get_pid_by_package(package_name);
    if (pid <= 0) return -1;

    char mem_path[64];
    snprintf(mem_path, sizeof(mem_path), "/proc/%d/mem", pid);
    int fd = open(mem_path, O_RDWR);
    if (fd < 0) return -2;

    g_pid = pid;
    g_mem_fd = fd;
    return 0;
}

__attribute__((visibility("default")))
int detach_process() {
    if (g_mem_fd > 0) {
        close(g_mem_fd);
        g_mem_fd = -1;
    }
    g_pid = -1;
    return 0;
}

// ---------- 内部读取指针 ----------
uintptr_t read_pointer(uintptr_t addr) {
    if (g_mem_fd < 0) return 0;
    uintptr_t val = 0;
    // 使用 pread64 并强转 off64_t 避免 32-bit off_t 截断
    ssize_t n = pread64(g_mem_fd, &val, sizeof(val), (off64_t)addr);
    if (n != (ssize_t)sizeof(val)) return 0;
    return val;
}

// ---------- 固定地址读取 ----------
__attribute__((visibility("default")))
long read_memory_at(uintptr_t addr, int type) {
    if (g_mem_fd < 0) return -1;
#if UINTPTR_MAX == 0xFFFFFFFF
    int32_t data = 0;
    ssize_t n = pread64(g_mem_fd, &data, sizeof(data), (off64_t)addr);
    if (n != sizeof(data)) return -1;
    switch (type) {
        case 0: return (int)data;
        case 1: return (short)data;
        case 2: return (uint8_t)data;
        case 3: return data;
        default: return data;
    }
#else
    int64_t data = 0;
    ssize_t n = pread64(g_mem_fd, &data, sizeof(data), (off64_t)addr);
    if (n != sizeof(data)) return -1;
    switch (type) {
        case 0: return (int)(data & 0xFFFFFFFF);
        case 1: return (short)(data & 0xFFFF);
        case 2: return (uint8_t)(data & 0xFF);
        case 3: return data;
        default: return data;
    }
#endif
}

// ---------- 多级指针读取 ----------
__attribute__((visibility("default")))
long read_chain_from_string(const char *chain_str, int type) {
    if (g_mem_fd < 0 || !chain_str) return -100;
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
    // 偏移使用 strtoull（16 进制）
    uintptr_t base_offset = (uintptr_t)strtoull(token, NULL, 16);

    uintptr_t offsets[32];
    int depth = 0;
    while ((token = strtok(NULL, "|")) != NULL && depth < 32) {
        offsets[depth++] = (uintptr_t)strtoull(token, NULL, 16);
    }

    uintptr_t module_base = get_module_base(module, 0);
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
    if (len == 0 || g_mem_fd < 0) return NULL;
    char *hexstr = (char*)malloc(len * 2 + 1);
    if (!hexstr) return NULL;

    unsigned char *buf = (unsigned char*)malloc(len);
    if (!buf) {
        free(hexstr);
        return NULL;
    }

    ssize_t n = pread64(g_mem_fd, buf, len, (off64_t)addr);
    if (n < 0) {
        free(hexstr);
        free(buf);
        return NULL;
    }

    char *p = hexstr;
    for (ssize_t i = 0; i < n; i++) {
        sprintf(p, "%02X", buf[i]);
        p += 2;
    }
    *p = '\0';

    free(buf);
    return hexstr;
}

// ---------- 新增导出函数 ----------
__attribute__((visibility("default")))
int get_pid_by_package_name(const char *package_name) {
    pid_t pid = get_pid_by_package(package_name);
    return (int)pid;
}

__attribute__((visibility("default")))
uintptr_t get_module_base_by_name(const char *module_name, int type) {
    return get_module_base(module_name, type);
}

__attribute__((visibility("default")))
uintptr_t get_chain_address_by_string(const char *chain_str) {
    if (g_mem_fd < 0 || !chain_str) return 0;
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

// ---------- 搜索两个连续 int 值的序列 ----------
static uintptr_t* g_prev_results = NULL;
static size_t g_prev_count = 0;

__attribute__((visibility("default")))
char* search_two_ints_sequence(int value1, int value2, int search_from_previous) {
    if (g_mem_fd < 0) return NULL;

    uintptr_t* results = NULL;
    size_t count = 0;

    if (search_from_previous && g_prev_results && g_prev_count > 0) {
        // 在上一次结果里继续过滤
        for (size_t i = 0; i < g_prev_count; i++) {
            uintptr_t addr = g_prev_results[i];
            int val1 = 0, val2 = 0;
            if (pread64(g_mem_fd, &val1, sizeof(val1), (off64_t)addr) == (ssize_t)sizeof(val1) &&
                pread64(g_mem_fd, &val2, sizeof(val2), (off64_t)(addr + sizeof(int))) == (ssize_t)sizeof(val2)) {
                if (val1 == value1 && val2 == value2) {
                    uintptr_t *tmp = (uintptr_t*)realloc(results, sizeof(uintptr_t) * (count + 1));
                    if (!tmp) continue;
                    results = tmp;
                    results[count++] = addr;
                }
            }
        }
    } else {
        // 全局内存搜索
        char maps_path[64];
        snprintf(maps_path, sizeof(maps_path), "/proc/%d/maps", g_pid);
        FILE *maps = fopen(maps_path, "r");
        if (!maps) return NULL;

        char line[512];
        while (fgets(line, sizeof(line), maps)) {
            uintptr_t start = 0, end = 0;
            char perms[8] = {0};

            if (sscanf(line, "%" SCNxPTR "-%" SCNxPTR " %7s", &start, &end, perms) < 2) continue;
            if (!strchr(perms, 'r')) continue;

            size_t size = (end > start) ? (end - start) : 0;
            if (size == 0) continue;

            unsigned char* buf = (unsigned char*)malloc(size);
            if (!buf) continue;

            ssize_t n = pread64(g_mem_fd, buf, size, (off64_t)start);
            if (n > 0) {
                for (size_t i = 0; i + 2 * sizeof(int) <= (size_t)n; i += sizeof(int)) {
                    int val1, val2;
                    memcpy(&val1, buf + i, sizeof(int));
                    memcpy(&val2, buf + i + sizeof(int), sizeof(int));
                    if (val1 == value1 && val2 == value2) {
                        uintptr_t *tmp = (uintptr_t*)realloc(results, sizeof(uintptr_t) * (count + 1));
                        if (!tmp) continue;
                        results = tmp;
                        results[count++] = start + i;
                    }
                }
            }
            free(buf);
        }
        fclose(maps);
    }

    // 更新全局结果
    if (g_prev_results) free(g_prev_results);
    g_prev_results = results;
    g_prev_count = count;

    if (count == 0) return NULL;

    // 生成字符串返回
    size_t buf_len = count * 32 + 1;
    char* str = (char*)malloc(buf_len);
    if (!str) return NULL;
    str[0] = '\0';

    for (size_t i = 0; i < count; i++) {
        char tmp[48];
        // 使用 PRIxPTR 保证跨平台正确打印 uintptr_t
        snprintf(tmp, sizeof(tmp), "%" PRIxPTR "|", (uintptr_t)results[i]);
        strncat(str, tmp, buf_len - strlen(str) - 1);
    }

    if (strlen(str) > 0) str[strlen(str) - 1] = '\0';  // 去掉最后一个 '|'
    return str;
}



// ---------- 搜索多个连续 int 值的序列 ----------
// 输入字符串格式： "1|2|3|..."  (任意数量)
__attribute__((visibility("default")))
char* search_ints_sequence_from_string(const char* values_str, int search_from_previous) {
    if (!values_str || g_mem_fd < 0) return NULL;

    // 1. 解析字符串 -> int 数组
    int* values = NULL;
    size_t value_count = 0;
    {
        char* str_copy = strdup(values_str);
        if (!str_copy) return NULL;
        char* token = strtok(str_copy, "|");
        while (token) {
            int val = atoi(token);
            int* tmp = (int*)realloc(values, sizeof(int) * (value_count + 1));
            if (!tmp) { free(values); free(str_copy); return NULL; }
            values = tmp;
            values[value_count++] = val;
            token = strtok(NULL, "|");
        }
        free(str_copy);
        if (value_count == 0) { free(values); return NULL; }
    }

    uintptr_t* results = NULL;
    size_t count = 0;

    if (search_from_previous && g_prev_results && g_prev_count > 0) {
        // 在上一次结果里继续过滤
        for (size_t i = 0; i < g_prev_count; i++) {
            uintptr_t addr = g_prev_results[i];
            int* buf = (int*)malloc(sizeof(int) * value_count);
            if (!buf) continue;
            if (pread64(g_mem_fd, buf, sizeof(int) * value_count, (off64_t)addr) == (ssize_t)(sizeof(int) * value_count)) {
                int match = 1;
                for (size_t j = 0; j < value_count; j++) {
                    if (buf[j] != values[j]) { match = 0; break; }
                }
                if (match) {
                    uintptr_t* tmp = (uintptr_t*)realloc(results, sizeof(uintptr_t) * (count + 1));
                    if (tmp) { results = tmp; results[count++] = addr; }
                }
            }
            free(buf);
        }
    } else {
        // 全局搜索
        char maps_path[64];
        snprintf(maps_path, sizeof(maps_path), "/proc/%d/maps", g_pid);
        FILE* maps = fopen(maps_path, "r");
        if (!maps) { free(values); return NULL; }

        char line[512];
        while (fgets(line, sizeof(line), maps)) {
            uintptr_t start = 0, end = 0;
            char perms[8] = {0};

            if (sscanf(line, "%" SCNxPTR "-%" SCNxPTR " %7s", &start, &end, perms) < 2) continue;
            if (!strchr(perms, 'r')) continue;

            size_t size = (end > start) ? (end - start) : 0;
            if (size < value_count * sizeof(int)) continue;

            unsigned char* buf = (unsigned char*)malloc(size);
            if (!buf) continue;

            ssize_t n = pread64(g_mem_fd, buf, size, (off64_t)start);
            if (n > 0) {
                for (size_t i = 0; i + value_count * sizeof(int) <= (size_t)n; i += sizeof(int)) {
                    int match = 1;
                    for (size_t j = 0; j < value_count; j++) {
                        int val;
                        memcpy(&val, buf + i + j * sizeof(int), sizeof(int));
                        if (val != values[j]) { match = 0; break; }
                    }
                    if (match) {
                        uintptr_t* tmp = (uintptr_t*)realloc(results, sizeof(uintptr_t) * (count + 1));
                        if (tmp) { results = tmp; results[count++] = start + i; }
                    }
                }
            }
            free(buf);
        }
        fclose(maps);
    }

    free(values);

    // 更新全局结果
    if (g_prev_results) free(g_prev_results);
    g_prev_results = results;
    g_prev_count = count;

    if (count == 0) return NULL;

    // 生成字符串返回
    size_t buf_len = count * 32 + 1;
    char* str = (char*)malloc(buf_len);
    if (!str) return NULL;
    str[0] = '\0';

    char* write_ptr = str;
    for (size_t i = 0; i < count; i++) {
        int len = snprintf(write_ptr, buf_len - (write_ptr - str), "%" PRIxPTR "|", (uintptr_t)results[i]);
        write_ptr += len;
    }

    if (write_ptr > str) *(write_ptr - 1) = '\0';  // 去掉最后一个 '|'
    return str;
}



// ---------- 写入一个 int 值到指定地址（兼容32/64） ----------
__attribute__((visibility("default")))
int write_int_to_address(uintptr_t addr, int value) {
    if (g_mem_fd < 0) return -1;

    // 写入的数据统一用 int32_t，int 在32/64下都是4字节
    int32_t data = (int32_t)value;

    // 使用 pwrite64，off64_t 强转避免32位 off_t 截断
    ssize_t n = pwrite64(g_mem_fd, &data, sizeof(data), (off64_t)addr);

    if (n != sizeof(data)) return -2;   // 写入失败
    return 0;                           // 成功
}


