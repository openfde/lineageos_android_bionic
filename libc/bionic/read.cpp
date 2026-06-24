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
#define TYPE_SELINUX_ATTR  2
#define TYPE_IGNORE  4 

#define APP_UID_START 10000

#define MAX_FDS 2048

struct FDState {
    int type = TYPE_UNKNOWN;
    size_t index = 0 ;
    char* cached_data = NULL;
    size_t cached_len = 0;
};

FDState g_states[MAX_FDS];
pthread_mutex_t g_lock = PTHREAD_MUTEX_INITIALIZER;


extern "C" ssize_t __read(int fd, void* buf, size_t count);


static const char* FAKE_SELINUX_MOUNTS = "selinuxfs /sys/fs/selinux selinuxfs rw,relatime 0 0\n";
static const char* FAKE_SELINUX_CONTEXT = "u:r:untrusted_app:s0\n";

static bool is_proc_pid_attr_current(const char* pathname) {
    if (pathname == nullptr) return false;

    static const char* kPrefix = "/proc/";
    static const char* kSuffix = "/attr/current";

    size_t prefix_len = strlen(kPrefix);
    size_t suffix_len = strlen(kSuffix);
    size_t path_len = strlen(pathname);

    if (path_len <= prefix_len + suffix_len) return false;
    if (strncmp(pathname, kPrefix, prefix_len) != 0) return false;
    if (strcmp(pathname, "/proc/self/attr/current") == 0) return true;
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
        pthread_mutex_lock(&g_lock);
        if (g_states[fd].cached_data) {
            free(g_states[fd].cached_data);
            g_states[fd].cached_data = nullptr;
        }
        g_states[fd].type = TYPE_UNKNOWN; 
        g_states[fd].index = 0;           
        g_states[fd].cached_len = 0;           
        pthread_mutex_unlock(&g_lock);
    }
}

static char* filter_suppliment_mounts_primitive(const char* src, size_t src_len, size_t* out_len) {
    char* dst = static_cast<char*>(malloc(src_len +strlen(FAKE_SELINUX_MOUNTS) + 1));
    if (!dst) return NULL;

    size_t dst_idx = 0;
    const char* line_start = src;
    const char* src_end = src + src_len;

    while (line_start < src_end) {
        // find the end of the line
        const char* line_end = static_cast<const char*>(memchr(line_start, '\n', src_end - line_start));
        size_t current_line_len;
        if (line_end) {
            current_line_len = line_end - line_start + 1; 
        } else {
            current_line_len = src_end - line_start;    // there is no /n in the last line 
        }

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
            memcpy(dst + dst_idx, line_start, current_line_len);
            dst_idx += current_line_len;
        }

        if (!line_end) break;
        line_start = line_end + 1;
    }
    memcpy(dst + dst_idx, FAKE_SELINUX_MOUNTS, strlen(FAKE_SELINUX_MOUNTS));
    dst_idx += strlen(FAKE_SELINUX_MOUNTS);

    dst[dst_idx] = '\0';
    *out_len = dst_idx;
    
    char* shrunk_dst = static_cast<char*>(realloc(dst, dst_idx + 1));
    return shrunk_dst ? shrunk_dst : dst;
}


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
    uid_t current_uid = getuid();
    if (fd < 0 || fd >= MAX_FDS || current_uid < APP_UID_START) return __read(fd, buf, count);

    pthread_mutex_lock(&g_lock);
    if (g_states[fd].type == TYPE_UNKNOWN ) {
        char proc_path[64];
        char actual_path[512];
        snprintf(proc_path, sizeof(proc_path), "/proc/self/fd/%d", fd);
        
        ssize_t path_len = readlink(proc_path, actual_path, sizeof(actual_path) - 1);
        if (path_len > 0) {
            actual_path[path_len] = '\0';
            if ( is_proc_pid_mounts(actual_path)) {
                g_states[fd].type = TYPE_MOUNTS;
            } else if (is_proc_pid_attr_current(actual_path)) {
                g_states[fd].type = TYPE_SELINUX_ATTR;
            }
        }else {
            g_states[fd].type = TYPE_IGNORE;
        }
    }
    if (g_states[fd].type == TYPE_SELINUX_ATTR){
        const size_t fake_len = strlen(FAKE_SELINUX_CONTEXT);
        char* buf = static_cast<char*>(malloc(fake_len + 1));
        memcpy(buf, FAKE_SELINUX_CONTEXT, fake_len);
        buf[fake_len] = '\0';
        g_states[fd].cached_data = buf;
        g_states[fd].cached_len = fake_len;
    }else if (g_states[fd].type == TYPE_MOUNTS) {
        if (g_states[fd].cached_data == NULL) {
            const int buffer_size = 128 * 1024;
            char* buffer = static_cast<char*>(malloc(buffer_size)); 
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
                    break; 
                }

                offset += bytes_read;
            }

            buffer[offset+1] = '\0';
            if (offset > 0) {
                g_states[fd].cached_data = filter_suppliment_mounts_primitive(buffer, offset+1, &g_states[fd].cached_len);
            }
            free(buffer);
            buffer = NULL;
        }
    }
    if (g_states[fd].cached_data) {
        size_t total = g_states[fd].cached_len;
        size_t curr = g_states[fd].index;

        if (curr >= total) {
            pthread_mutex_unlock(&g_lock);
            return 0; 
        }

        size_t avail = total - curr;
        size_t to_copy = (count < avail) ? count : avail;
        memcpy(buf, g_states[fd].cached_data + curr, to_copy);
        g_states[fd].index += to_copy;

        pthread_mutex_unlock(&g_lock);
        return static_cast<ssize_t>(to_copy);
    }

    pthread_mutex_unlock(&g_lock);
    return __read(fd, buf, count);
}

