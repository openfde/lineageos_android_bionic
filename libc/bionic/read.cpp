/*
 * Copyright (C) 2026
 *
 * Custom read wrapper for bionic.
 */

#include <errno.h>
#include <sys/types.h>
#include <unistd.h>
#include <string.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdlib.h>
#include <ctype.h>

#include "private/bionic_defs.h"

#define TYPE_UNKNOWN 0
#define TYPE_MOUNTS  1
#define TYPE_IGNORE  2 // 已检查过，不是我们要的文件

#define MAX_FDS 2048

struct FDState {
    int type;
    size_t index;
    char* cached_data;
    size_t cached_len;
};

FDState g_states[MAX_FDS];
pthread_mutex_t g_lock = PTHREAD_MUTEX_INITIALIZER;


extern "C" ssize_t __read(int fd, void* buf, size_t count);


static const char* FAKE_MOUNTS = "selinuxfs /sys/fs/selinux selinuxfs rw,relatime 0 0\n";
static const char* FAKE_CONTEXT = "u:r:untrusted_app:s0\n";

/*typedef struct {
    int type; // 1: mounts, 2: enforce, 3: context
    size_t index; 
} HookState;

static HookState g_states[MAX_FDS];
static pthread_mutex_t g_lock = PTHREAD_MUTEX_INITIALIZER;
*/

extern "C" void __register_selinux_fd(int fd, int type) {
    if (fd >= 0 && fd < MAX_FDS) {
        pthread_mutex_lock(&g_lock);
        g_states[fd].type = type;
        g_states[fd].index = 0;
        g_states[fd].cached_data = nullptr;
        pthread_mutex_unlock(&g_lock);
    }
}

extern "C" void __unregister_selinux_fd(int fd) {
    if (fd >= 0 && fd < MAX_FDS) {
      /*  pthread_mutex_lock(&g_lock);
        g_states[fd].type = 0;
        g_states[fd].index = 0;
        pthread_mutex_unlock(&g_lock);
        */
        pthread_mutex_lock(&g_lock);
        if (g_states[fd].cached_data) {
            free(g_states[fd].cached_data);
            g_states[fd].cached_data = nullptr;
        }
        g_states[fd].type = TYPE_UNKNOWN; // 重置类型
        g_states[fd].index = 0;           // 重置偏移
        pthread_mutex_unlock(&g_lock);
    }
}

// 过滤函数：从 src 中剔除包含 "fde_fs" 的行
static char* filter_mounts_primitive(const char* src, size_t src_len, size_t* out_len) {
    // 预分配一个同样大小的缓冲区，最坏情况是没有任何行被过滤
    char* dst = static_cast<char*>(malloc(src_len + 1));
    if (!dst) return NULL;

    size_t dst_idx = 0;
    const char* line_start = src;
    const char* src_end = src + src_len;

    while (line_start < src_end) {
        // 找到当前行的结束位置
        const char* line_end = static_cast<const char*>(memchr(line_start, '\n', src_end - line_start));
        size_t current_line_len;
        if (line_end) {
            current_line_len = line_end - line_start + 1; // 包含换行符
        } else {
            current_line_len = src_end - line_start;     // 最后一行没有换行符
        }

        // 检查当前行是否包含关键字 "fde_fs"
        // 使用 memmem 在指定长度内搜索子串（比 strstr 安全，因为 line_start 未必以 \0 结尾）
        void* found = memmem(line_start, current_line_len, "fde_fs", 6);
        if (!found)
            found = memmem(line_start, current_line_len, "fde_ptfs", 8);
        if (!found)
            found = memmem(line_start, current_line_len, "waydroid", 8);
        if (!found)
            found = memmem(line_start, current_line_len, "openfde", 7);
        if (!found)
            found = memmem(line_start, current_line_len, "cpuinfo", 7);
        if (!found)
            found = memmem(line_start, current_line_len, "vendor", 6);
        if (!found)
            found = memmem(line_start, current_line_len, "volumes", 7);
        if (!found)
            found = memmem(line_start, current_line_len, "tmpx11", 6);
        if (!found)
            found = memmem(line_start, current_line_len, "card0", 5);
        if (!found)
            found = memmem(line_start, current_line_len, "renderD128", 10);

        if (!found) {
            // 如果没找到关键字，将整行拷贝到目标缓冲区
            memcpy(dst + dst_idx, line_start, current_line_len);
            dst_idx += current_line_len;
        }

        if (!line_end) break;
        line_start = line_end + 1;
    }

    dst[dst_idx] = '\0';
    *out_len = dst_idx;
    
    // 缩小内存占用（可选）
    char* shrunk_dst = static_cast<char*>(realloc(dst, dst_idx + 1));
    return shrunk_dst ? shrunk_dst : dst;
}


/*static inline const char* get_fake_data_for_type(int type) {
  switch (type) {
    case 1: return FAKE_MOUNTS;
    case 2: return FAKE_CONTEXT;
    default: return nullptr;
  }
}
*/

static bool is_proc_pid_mounts(const char* pathname) {
    if (pathname == nullptr) return false;
    if (strcmp(pathname, "/proc/mounts") == 0) return true;

    static const char* kPrefix = "/proc/";
    static const char* kSuffix = "/mounts";

    size_t prefix_len = strlen(kPrefix);
    size_t suffix_len = strlen(kSuffix);
    size_t path_len = strlen(pathname);

    if (path_len <= prefix_len + suffix_len) return false;
    if (strncmp(pathname, kPrefix, prefix_len) != 0) return false;
    if (strcmp(pathname, "/proc/self/mounts") == 0) return true;
    if (strcmp(pathname + path_len - suffix_len, kSuffix) != 0) return false;

    const char* p = pathname + prefix_len;
    const char* end = pathname + path_len - suffix_len;

    if (p >= end) return false;

    while (p < end) {
        if (!isdigit(static_cast<unsigned char>(*p))) return false;
        ++p;
    }
    return true;
}

__BIONIC_WEAK_FOR_NATIVE_BRIDGE

ssize_t read(int fd, void* buf, size_t count) {
    if (fd < 0 || fd >= MAX_FDS) return __read(fd, buf, count);


    // 1. 延迟识别：如果是新 FD，识别路径
    if (g_states[fd].type == TYPE_UNKNOWN ) {
        char proc_path[64];
        char actual_path[512];
        snprintf(proc_path, sizeof(proc_path), "/proc/self/fd/%d", fd);
        
        ssize_t path_len = readlink(proc_path, actual_path, sizeof(actual_path) - 1);
        if (path_len > 0) {
            actual_path[path_len] = '\0';
            if ( is_proc_pid_mounts(actual_path)) {
                g_states[fd].type = TYPE_MOUNTS;
                g_states[fd].index = 0;
                g_states[fd].cached_data = NULL;
            } else {
                g_states[fd].type = TYPE_IGNORE;
            }
        }
    }

 // 2. 获取当前调用者的 UID
    uid_t current_uid = getuid();

    // 3. 判断逻辑：如果是普通 App (UID >= 10000)
    // 注意：系统定义的 AID_APP_START 通常是 10000
    if (current_uid >= 10000) {

    pthread_mutex_lock(&g_lock);
    // 2. 逻辑处理：如果是 mounts 文件
    if (g_states[fd].type == TYPE_MOUNTS) {
        // 如果缓存为空，读取原始数据并过滤
        if (g_states[fd].cached_data == NULL) {
            const int buffer_size = 128 * 1024;
            char* buffer = static_cast<char*>(malloc(buffer_size)); // 假设 mounts 最大 128KB
            // 使用 pread 确保从头开始读，且不干扰 fd 的当前偏移

            size_t offset = 0;
            ssize_t bytes_read;

            while (offset < buffer_size - 1) {
                bytes_read = pread(fd, buffer + offset, buffer_size - offset - 1, offset);
                if (bytes_read == -1) {
                    free(buffer);
                    pthread_mutex_unlock(&g_lock);
                    return 0;
                }

                if (bytes_read == 0) {
                    break;  // 读完
                }

                offset += bytes_read;
            }

            buffer[offset+1] = '\0';
            if (offset > 0) {
                g_states[fd].cached_data = filter_mounts_primitive(buffer, offset+1, &g_states[fd].cached_len);
            }
            free(buffer);
            buffer = NULL;
        }

        if (g_states[fd].cached_data) {
            size_t total = g_states[fd].cached_len;
            size_t curr = g_states[fd].index;

            if (curr >= total) {
                pthread_mutex_unlock(&g_lock);
                return 0; // EOF
            }

            size_t avail = total - curr;
            size_t to_copy = (count < avail) ? count : avail;
            memcpy(buf, g_states[fd].cached_data + curr, to_copy);
            g_states[fd].index += to_copy;

            pthread_mutex_unlock(&g_lock);
            return static_cast<ssize_t>(to_copy);
        }
    }

    pthread_mutex_unlock(&g_lock);
    }
    return __read(fd, buf, count);
}

/*ssize_t read(int fd, void* buf, size_t count) {
    if (count == 0) {
    return __read(fd, buf, count);
  }

  if (fd >= 0 && fd < MAX_FDS) {
    pthread_mutex_lock(&g_lock);

    int type = g_states[fd].type;
    size_t index = g_states[fd].index;

    if (type > 0) {
      const char* fake = get_fake_data_for_type(type);
      if (fake != nullptr) {
        size_t total_len = strlen(fake);

        if (index < total_len) {
          size_t remaining = total_len - index;
          size_t n = (count < remaining) ? count : remaining;
          memcpy(buf, fake + index, n);
          g_states[fd].index += n;
          pthread_mutex_unlock(&g_lock);
          return static_cast<ssize_t>(n);
        }

        pthread_mutex_unlock(&g_lock);
        if (strlen(fake) == strlen(FAKE_MOUNTS)){
            return __read(fd, buf, count);
        }else {
            return 0;
        }
      }
    }

    pthread_mutex_unlock(&g_lock);
  }

  return __read(fd, buf, count);
}
*/
