#ifndef __KSU_H_KERNEL_COMPAT
#define __KSU_H_KERNEL_COMPAT

#include <linux/fs.h>
#include <linux/version.h>

/*
 * Compatibility shims for building KernelSU-Next v3.1.0 on kernel 4.14.x
 */

/* task_work_add: 4.14 uses bool notify, 5.7+ uses enum task_work_notify_mode */
#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 7, 0)
#ifndef TWA_RESUME
#define TWA_RESUME true
#endif
#endif

/* mmap_read_trylock / mmap_read_unlock: 5.8+ API, 4.14 uses mmap_sem */
#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 8, 0)
#ifndef mmap_read_trylock
#define mmap_read_trylock(mm) down_read_trylock(&(mm)->mmap_sem)
#endif
#ifndef mmap_read_unlock
#define mmap_read_unlock(mm) up_read(&(mm)->mmap_sem)
#endif
#endif

/* close_fd: 5.11+ API, older kernels use ksys_close / sys_close */
#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 11, 0)
#include <linux/syscalls.h>
#ifndef close_fd
static inline int close_fd(unsigned int fd)
{
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 17, 0)
	return ksys_close(fd);
#else
	return sys_close(fd);
#endif
}
#endif
#endif

/* __poll_t: introduced in 4.16, older kernels use unsigned int */
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 16, 0)
typedef unsigned int __poll_t;
#endif

/* strscpy: not available on all 4.14 kernels */
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 16, 0)
#ifndef strscpy
#include <linux/string.h>
#define strscpy(dst, src, size) strlcpy(dst, src, size)
#endif
#endif

/* strncpy_from_user_nofault: 5.8+ API */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 8, 0)
#define ksu_strncpy_from_user_nofault strncpy_from_user_nofault
#elif LINUX_VERSION_CODE >= KERNEL_VERSION(5, 3, 0)
#define ksu_strncpy_from_user_nofault strncpy_from_unsafe_user
#else
static inline long ksu_strncpy_from_user_nofault(char *dst,
						  const void __user *unsafe_addr,
						  long count)
{
	mm_segment_t old_fs = get_fs();
	long ret;

	if (unlikely(count <= 0))
		return 0;

	set_fs(USER_DS);
	pagefault_disable();
	ret = strncpy_from_user(dst, unsafe_addr, count);
	pagefault_enable();
	set_fs(old_fs);

	if (ret >= count) {
		ret = count;
		dst[ret - 1] = '\0';
	} else if (ret > 0) {
		ret++;
	}

	return ret;
}
#endif

/* copy_{from,to}_user_nofault: introduced in 5.3 as probe_user_{read,write}, renamed in 5.8 */
#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 8, 0)
#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 3, 0)
#define copy_from_user_nofault probe_user_read
#define copy_to_user_nofault probe_user_write
#else
#include <linux/uaccess.h>
static inline long copy_from_user_nofault(void *dst, const void __user *src,
					  size_t size)
{
	mm_segment_t old_fs = get_fs();
	long ret;

	set_fs(USER_DS);
	pagefault_disable();
	ret = __copy_from_user_inatomic(dst, src, size);
	pagefault_enable();
	set_fs(old_fs);

	return ret ? -EFAULT : 0;
}

static inline long copy_to_user_nofault(void __user *dst, const void *src,
					size_t size)
{
	mm_segment_t old_fs = get_fs();
	long ret;

	set_fs(USER_DS);
	pagefault_disable();
	ret = __copy_to_user_inatomic(dst, src, size);
	pagefault_enable();
	set_fs(old_fs);

	return ret ? -EFAULT : 0;
}
#endif
#endif

/* path_umount compat: not available before 5.9 */
#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 9, 0)
int path_umount(struct path *path, int flags);
#endif

/* filp_open compat for namespace switching */
extern struct file *ksu_filp_open_compat(const char *filename, int flags,
					 umode_t mode);
extern void ksu_android_ns_fs_check(void);

/* access_ok compat */
static inline int ksu_access_ok(const void *addr, unsigned long size)
{
#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 0, 0)
	return access_ok(VERIFY_READ, addr, size);
#else
	return access_ok(addr, size);
#endif
}

/* session keyring compat */
#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 10, 0) || defined(CONFIG_KSU_ALLOWLIST_WORKAROUND)
#include <linux/key.h>
extern struct key *init_session_keyring;
#endif

#endif /* __KSU_H_KERNEL_COMPAT */
