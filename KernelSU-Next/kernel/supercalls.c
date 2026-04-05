#include <linux/anon_inodes.h>
#include <linux/capability.h>
#include <linux/cred.h>
#include <linux/err.h>
#include <linux/fdtable.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <linux/slab.h>
#include <linux/kprobes.h>
#include <linux/syscalls.h>
#include <linux/task_work.h>
#include <linux/uaccess.h>
#include <linux/version.h>
#include <linux/utsname.h> // utsname() and uts_sem

#include "supercalls.h"
#include "arch.h"
#include "allowlist.h"
#include "feature.h"
#include "klog.h" // IWYU pragma: keep
#include "ksu.h"
#include "ksud.h"
#include "kernel_umount.h"
#include "manager.h"
#include "selinux/selinux.h"
#include "file_wrapper.h"
#include "syscall_hook_manager.h"
#include "kernel_compat.h"

#include "tiny_sulog.c"

// Permission check functions
bool only_manager(void)
{
	return is_manager();
}

bool only_root(void)
{
	return current_uid().val == 0;
}

bool manager_or_root(void)
{
	return current_uid().val == 0 || is_manager();
}

bool always_allow(void)
{
	return true; // No permission check
}

bool allowed_for_su(void)
{
    bool is_allowed =
        is_manager() || ksu_is_allow_uid_for_current(current_uid().val);
    return is_allowed;
}

static int do_grant_root(void __user *arg)
{
	// we already check uid above on allowed_for_su()

    write_sulog('i'); // log ioctl escalation

    pr_info("allow root for: %d\n", current_uid().val);
    escape_with_root_profile();

	return 0;
}

static uint32_t ksuver_override = 0;

static int do_get_info(void __user *arg)
{
    struct ksu_get_info_cmd cmd = { .version = KERNEL_SU_VERSION, .flags = 0 };

#ifdef MODULE
	cmd.flags |= 0x1;
#endif

	if (ksuver_override)
	    cmd.version = ksuver_override;

	if (is_manager()) {
		cmd.flags |= 0x2;
	}
	cmd.features = KSU_FEATURE_MAX;

	if (copy_to_user(arg, &cmd, sizeof(cmd))) {
		pr_err("get_version: copy_to_user failed\n");
		return -EFAULT;
	}

	return 0;
}

static int do_report_event(void __user *arg)
{
	struct ksu_report_event_cmd cmd;

	if (copy_from_user(&cmd, arg, sizeof(cmd))) {
		return -EFAULT;
	}

	switch (cmd.event) {
	case EVENT_POST_FS_DATA: {
		static bool post_fs_data_lock = false;
		if (!post_fs_data_lock) {
			post_fs_data_lock = true;
			pr_info("post-fs-data triggered\n");
			on_post_fs_data();
		}
		break;
	}
	case EVENT_BOOT_COMPLETED: {
		static bool boot_complete_lock = false;
		if (!boot_complete_lock) {
			boot_complete_lock = true;
			pr_info("boot_complete triggered\n");
			on_boot_completed();
		}
		break;
	}
	case EVENT_MODULE_MOUNTED: {
		pr_info("module mounted!\n");
		on_module_mounted();
		break;
	}
	default:
		break;
	}

	return 0;
}

static int do_set_sepolicy(void __user *arg)
{
	struct ksu_set_sepolicy_cmd cmd;

	if (copy_from_user(&cmd, arg, sizeof(cmd))) {
		return -EFAULT;
	}

	return handle_sepolicy(cmd.cmd, (void __user *)cmd.arg);
}

static int do_check_safemode(void __user *arg)
{
	struct ksu_check_safemode_cmd cmd;

	cmd.in_safe_mode = ksu_is_safe_mode();

	if (cmd.in_safe_mode) {
		pr_warn("safemode enabled!\n");
	}

	if (copy_to_user(arg, &cmd, sizeof(cmd))) {
		pr_err("check_safemode: copy_to_user failed\n");
		return -EFAULT;
	}

	return 0;
}

static int do_new_get_allow_list_common(void __user *arg, bool allow)
{
    struct ksu_new_get_allow_list_cmd cmd;
    int *arr = NULL;
    int err = 0;

	if (copy_from_user(&cmd, arg, sizeof(cmd))) {
		return -EFAULT;
	}

    if (cmd.count) {
        arr = kmalloc(sizeof(int) * cmd.count, GFP_KERNEL);
        if (!arr) {
            return -ENOMEM;
        }
    }

    bool success =
        ksu_get_allow_list(arr, cmd.count, &cmd.count, &cmd.total_count, allow);

    if (!success) {
        err = -EFAULT;
        goto out;
    }

    if (copy_to_user(arg, &cmd, sizeof(cmd))) {
        pr_err("new_get_allow_list: copy_to_user count failed\n");
        err = -EFAULT;
        goto out;
    }

    if (cmd.count &&
        copy_to_user(&((struct ksu_new_get_allow_list_cmd *)arg)->uids, arr,
                     sizeof(int) * cmd.count)) {
        pr_err("new_get_allow_list: copy_to_user uids failed\n");
        err = -EFAULT;
    }

out:
    if (arr) {
        kfree(arr);
    }
    return err;
}

static int do_new_get_deny_list(void __user *arg)
{
    return do_new_get_allow_list_common(arg, false);
}

static int do_new_get_allow_list(void __user *arg)
{
    return do_new_get_allow_list_common(arg, true);
}

static int do_get_allow_list_common(void __user *arg, bool allow)
{
    int *arr = NULL;
    int err = 0;
    u16 count;
    u32 out_count;
    static const u16 kSize = 128;

    arr = kmalloc(sizeof(int) * kSize, GFP_KERNEL);
    if (!arr) {
        return -ENOMEM;
    }

    bool success = ksu_get_allow_list(arr, kSize, &count, NULL, allow);

    if (!success) {
        err = -EFAULT;
        goto out;
    }

    out_count = count;

    if (copy_to_user(arg + offsetof(struct ksu_get_allow_list_cmd, count),
                     &out_count, sizeof(u32))) {
        pr_err("get_allow_list: copy_to_user count failed\n");
        err = -EFAULT;
        goto out;
    }

    if (copy_to_user(arg, arr, sizeof(u32) * count)) {
        pr_err("get_allow_list: copy_to_user uids failed\n");
        err = -EFAULT;
    }

out:
    if (arr) {
        kfree(arr);
    }
    return err;
}

static int do_get_deny_list(void __user *arg)
{
    return do_get_allow_list_common(arg, false);
}

static int do_get_allow_list(void __user *arg)
{
    return do_get_allow_list_common(arg, true);
}

static int do_uid_granted_root(void __user *arg)
{
	struct ksu_uid_granted_root_cmd cmd;

	if (copy_from_user(&cmd, arg, sizeof(cmd))) {
		return -EFAULT;
	}

	cmd.granted = ksu_is_allow_uid_for_current(cmd.uid);

	if (copy_to_user(arg, &cmd, sizeof(cmd))) {
		pr_err("uid_granted_root: copy_to_user failed\n");
		return -EFAULT;
	}

	return 0;
}

static int do_uid_should_umount(void __user *arg)
{
	struct ksu_uid_should_umount_cmd cmd;

	if (copy_from_user(&cmd, arg, sizeof(cmd))) {
		return -EFAULT;
	}

	cmd.should_umount = ksu_uid_should_umount(cmd.uid);

	if (copy_to_user(arg, &cmd, sizeof(cmd))) {
		pr_err("uid_should_umount: copy_to_user failed\n");
		return -EFAULT;
	}

	return 0;
}

static int do_get_manager_appid(void __user *arg)
{
	struct ksu_get_manager_appid_cmd cmd;

	cmd.appid = ksu_get_manager_appid();

	if (copy_to_user(arg, &cmd, sizeof(cmd))) {
		pr_err("get_manager_appid: copy_to_user failed\n");
		return -EFAULT;
	}

	return 0;
}

static int do_get_app_profile(void __user *arg)
{
	struct ksu_get_app_profile_cmd cmd;

	if (copy_from_user(&cmd, arg, sizeof(cmd))) {
		pr_err("get_app_profile: copy_from_user failed\n");
		return -EFAULT;
	}

	if (!ksu_get_app_profile(&cmd.profile)) {
		return -ENOENT;
	}

	if (copy_to_user(arg, &cmd, sizeof(cmd))) {
		pr_err("get_app_profile: copy_to_user failed\n");
		return -EFAULT;
	}

	return 0;
}

static int do_set_app_profile(void __user *arg)
{
    struct ksu_set_app_profile_cmd cmd;
    int ret;

	if (copy_from_user(&cmd, arg, sizeof(cmd))) {
		pr_err("set_app_profile: copy_from_user failed\n");
		return -EFAULT;
	}

    ret = ksu_set_app_profile(&cmd.profile);
    if (!ret) {
        ksu_persistent_allow_list();
        ksu_mark_running_process();
    }
    return ret;
}

static int do_get_feature(void __user *arg)
{
	struct ksu_get_feature_cmd cmd;
	bool supported;
	int ret;

	if (copy_from_user(&cmd, arg, sizeof(cmd))) {
		pr_err("get_feature: copy_from_user failed\n");
		return -EFAULT;
	}


	ret = ksu_get_feature(cmd.feature_id, &cmd.value, &supported);
	cmd.supported = supported ? 1 : 0;

	if (ret && supported) {
		pr_err("get_feature: failed for feature %u: %d\n", cmd.feature_id, ret);
		return ret;
	}

	if (copy_to_user(arg, &cmd, sizeof(cmd))) {
		pr_err("get_feature: copy_to_user failed\n");
		return -EFAULT;
	}

	return 0;
}

static int do_set_feature(void __user *arg)
{
	struct ksu_set_feature_cmd cmd;
	int ret;

	if (copy_from_user(&cmd, arg, sizeof(cmd))) {
		pr_err("set_feature: copy_from_user failed\n");
		return -EFAULT;
	}


	ret = ksu_set_feature(cmd.feature_id, cmd.value);
	if (ret) {
		pr_err("set_feature: failed for feature %u: %d\n", cmd.feature_id, ret);
		return ret;
	}

	return 0;
}

static int do_get_wrapper_fd(void __user *arg)
{
    struct ksu_get_wrapper_fd_cmd cmd;

    if (!ksu_file_sid) {
        return -EINVAL;
    }

    if (copy_from_user(&cmd, arg, sizeof(cmd))) {
        pr_err("get_wrapper_fd: copy_from_user failed\n");
        return -EFAULT;
    }

    return ksu_install_file_wrapper(cmd.fd);
}

static int do_manage_mark(void __user *arg)
{
	struct ksu_manage_mark_cmd cmd;
	int ret = 0;

	if (copy_from_user(&cmd, arg, sizeof(cmd))) {
		pr_err("manage_mark: copy_from_user failed\n");
		return -EFAULT;
	}

	switch (cmd.operation) {
	case KSU_MARK_GET: {
		// Get task mark status
		ret = ksu_get_task_mark(cmd.pid);
		if (ret < 0) {
			pr_err("manage_mark: get failed for pid %d: %d\n", cmd.pid, ret);
			return ret;
		}
		cmd.result = (u32)ret;
		break;
	}
	case KSU_MARK_MARK: {
		if (cmd.pid == 0) {
			ksu_mark_all_process();
		} else {
			ret = ksu_set_task_mark(cmd.pid, true);
			if (ret < 0) {
				pr_err("manage_mark: set_mark failed for pid %d: %d\n", cmd.pid,
					ret);
				return ret;
			}
		}
		break;
	}
	case KSU_MARK_UNMARK: {
		if (cmd.pid == 0) {
			ksu_unmark_all_process();
		} else {
			ret = ksu_set_task_mark(cmd.pid, false);
			if (ret < 0) {
				pr_err("manage_mark: set_unmark failed for pid %d: %d\n",
					cmd.pid, ret);
				return ret;
			}
		}
		break;
	}
	case KSU_MARK_REFRESH: {
		ksu_mark_running_process();
		pr_info("manage_mark: refreshed running processes\n");
		break;
	}
	default: {
		pr_err("manage_mark: invalid operation %u\n", cmd.operation);
		return -EINVAL;
	}
	}
	if (copy_to_user(arg, &cmd, sizeof(cmd))) {
		pr_err("manage_mark: copy_to_user failed\n");
		return -EFAULT;
	}

	return 0;
}

static int do_get_hook_mode(void __user *arg)
{
	struct ksu_get_hook_mode_cmd cmd = {0};

	strscpy(cmd.mode, "Kprobes", sizeof(cmd.mode));

	if (copy_to_user(arg, &cmd, sizeof(cmd))) {
		pr_err("get_hook_mode: copy_to_user failed\n");
		return -EFAULT;
	}

	return 0;
}

static int do_get_version_tag(void __user *arg)
{
	struct ksu_get_version_tag_cmd cmd = {0};

	strscpy(cmd.tag, KERNEL_SU_VERSION_TAG, sizeof(cmd.tag));

	if (copy_to_user(arg, &cmd, sizeof(cmd))) {
		pr_err("get_version_tag: copy_to_user failed\n");
		return -EFAULT;
	}

	return 0;
}

static int do_nuke_ext4_sysfs(void __user *arg)
{
    struct ksu_nuke_ext4_sysfs_cmd cmd;
    char mnt[256];
    long ret;

    if (copy_from_user(&cmd, arg, sizeof(cmd)))
        return -EFAULT;

    if (!cmd.arg)
        return -EINVAL;

    memset(mnt, 0, sizeof(mnt));

    ret = strncpy_from_user(mnt, cmd.arg, sizeof(mnt));
    if (ret < 0) {
        pr_err("nuke ext4 copy mnt failed: %ld\n", ret);
        return -EFAULT; // 或者 return ret;
    }

    if (ret == sizeof(mnt)) {
        pr_err("nuke ext4 mnt path too long\n");
        return -ENAMETOOLONG;
    }

    pr_info("do_nuke_ext4_sysfs: %s\n", mnt);

    return nuke_ext4_sysfs(mnt);
}

struct list_head mount_list = LIST_HEAD_INIT(mount_list);
DECLARE_RWSEM(mount_list_lock);

static int add_try_umount(void __user *arg)
{
    struct mount_entry *new_entry, *entry, *tmp;
    struct ksu_add_try_umount_cmd cmd;
    char buf[256] = { 0 };

    if (copy_from_user(&cmd, arg, sizeof cmd))
        return -EFAULT;

    switch (cmd.mode) {
    case KSU_UMOUNT_WIPE: {
        struct mount_entry *entry, *tmp;
        down_write(&mount_list_lock);
        list_for_each_entry_safe (entry, tmp, &mount_list, list) {
            pr_info("wipe_umount_list: removing entry: %s\n",
                    entry->umountable);
            list_del(&entry->list);
            kfree(entry->umountable);
            kfree(entry);
        }
        up_write(&mount_list_lock);

        return 0;
    }

    case KSU_UMOUNT_ADD: {
        long len = strncpy_from_user(buf, (const char __user *)cmd.arg, 256);
        if (len <= 0)
            return -EFAULT;

        buf[sizeof(buf) - 1] = '\0';

        new_entry = kzalloc(sizeof(*new_entry), GFP_KERNEL);
        if (!new_entry)
            return -ENOMEM;

        new_entry->umountable = kstrdup(buf, GFP_KERNEL);
        if (!new_entry->umountable) {
            kfree(new_entry);
            return -ENOMEM;
        }

        down_write(&mount_list_lock);

        // disallow dupes
        // if this gets too many, we can consider moving this whole task to a kthread
        list_for_each_entry (entry, &mount_list, list) {
            if (!strcmp(entry->umountable, buf)) {
                pr_info("cmd_add_try_umount: %s is already here!\n", buf);
                up_write(&mount_list_lock);
                kfree(new_entry->umountable);
                kfree(new_entry);
                return -EEXIST;
            }
        }

        // now check flags and add
        // this also serves as a null check
        if (cmd.flags)
            new_entry->flags = cmd.flags;
        else
            new_entry->flags = 0;

        // debug
        list_add(&new_entry->list, &mount_list);
        up_write(&mount_list_lock);
        pr_info("cmd_add_try_umount: %s added!\n", buf);

        return 0;
    }

    // this is just strcmp'd wipe anyway
    case KSU_UMOUNT_DEL: {
        long len = strncpy_from_user(buf, (const char __user *)cmd.arg,
                                     sizeof(buf) - 1);
        if (len <= 0)
            return -EFAULT;

        buf[sizeof(buf) - 1] = '\0';

        down_write(&mount_list_lock);
        list_for_each_entry_safe (entry, tmp, &mount_list, list) {
            if (!strcmp(entry->umountable, buf)) {
                pr_info("cmd_add_try_umount: entry removed: %s\n",
                        entry->umountable);
                list_del(&entry->list);
                kfree(entry->umountable);
                kfree(entry);
            }
        }
        up_write(&mount_list_lock);

        return 0;
    }

    // this way userspace can deduce the memory it has to prepare.
    case KSU_UMOUNT_GETSIZE: {
        // check for pointer first
        if (!cmd.arg)
            return -EFAULT;
        
        size_t total_size = 0; // size of list in bytes

        down_read(&mount_list_lock);
        list_for_each_entry(entry, &mount_list, list) {
            total_size = total_size + strlen(entry->umountable) + 1; // + 1 for \0
        }
        up_read(&mount_list_lock);

        // debug
        // pr_info("cmd_add_try_umount: total_size: %zu\n", total_size);
            
        if (copy_to_user((size_t __user *)cmd.arg, &total_size, sizeof(total_size)))
            return -EFAULT;

        return 0;
    }
        
    // WARNING! this is straight up pointerwalking.
    // this way we dont need to redefine the ioctl defs.
    // this also avoids us needing to kmalloc
    // userspace have to send pointer to memory (malloc/alloca) or pointer to a VLA.
    case KSU_UMOUNT_GETLIST: {
        // check for pointer first
        if (!cmd.arg)
            return -EFAULT;
            
        char *user_buf = (char *)cmd.arg;

        down_read(&mount_list_lock);
        list_for_each_entry(entry, &mount_list, list) {

            //debug
            //pr_info("cmd_add_try_umount: entry: %s\n", entry->umountable);
            
            if (copy_to_user((char __user *)user_buf, entry->umountable, strlen(entry->umountable) + 1 )) {
                up_read(&mount_list_lock);
                return -EFAULT;
            }

            // walk it! +1 for null terminator
            user_buf = user_buf + strlen(entry->umountable) + 1;
        }
        up_read(&mount_list_lock);

        return 0;
    }

    default: {
        pr_err("cmd_add_try_umount: invalid operation %u\n", cmd.mode);
        return -EINVAL;
    }

    } // switch(cmd.mode)

    return 0;
}

// IOCTL handlers mapping table
static const struct ksu_ioctl_cmd_map ksu_ioctl_handlers[] = {
    { .cmd = KSU_IOCTL_GRANT_ROOT,
      .name = "GRANT_ROOT",
      .handler = do_grant_root,
      .perm_check = allowed_for_su },
    { .cmd = KSU_IOCTL_GET_INFO,
      .name = "GET_INFO",
      .handler = do_get_info,
      .perm_check = always_allow },
    { .cmd = KSU_IOCTL_REPORT_EVENT,
      .name = "REPORT_EVENT",
      .handler = do_report_event,
      .perm_check = only_root },
    { .cmd = KSU_IOCTL_SET_SEPOLICY,
      .name = "SET_SEPOLICY",
      .handler = do_set_sepolicy,
      .perm_check = only_root },
    { .cmd = KSU_IOCTL_CHECK_SAFEMODE,
      .name = "CHECK_SAFEMODE",
      .handler = do_check_safemode,
      .perm_check = always_allow },
    { .cmd = KSU_IOCTL_GET_ALLOW_LIST,
      .name = "GET_ALLOW_LIST",
      .handler = do_get_allow_list,
      .perm_check = manager_or_root },
    { .cmd = KSU_IOCTL_GET_DENY_LIST,
      .name = "GET_DENY_LIST",
      .handler = do_get_deny_list,
      .perm_check = manager_or_root },
    { .cmd = KSU_IOCTL_NEW_GET_ALLOW_LIST,
      .name = "NEW_GET_ALLOW_LIST",
      .handler = do_new_get_allow_list,
      .perm_check = manager_or_root },
    { .cmd = KSU_IOCTL_NEW_GET_DENY_LIST,
      .name = "NEW_GET_DENY_LIST",
      .handler = do_new_get_deny_list,
      .perm_check = manager_or_root },
    { .cmd = KSU_IOCTL_UID_GRANTED_ROOT,
      .name = "UID_GRANTED_ROOT",
      .handler = do_uid_granted_root,
      .perm_check = manager_or_root },
    { .cmd = KSU_IOCTL_UID_SHOULD_UMOUNT,
      .name = "UID_SHOULD_UMOUNT",
      .handler = do_uid_should_umount,
      .perm_check = manager_or_root },
    { .cmd = KSU_IOCTL_GET_MANAGER_APPID,
      .name = "GET_MANAGER_APPID",
      .handler = do_get_manager_appid,
      .perm_check = manager_or_root },
    { .cmd = KSU_IOCTL_GET_APP_PROFILE,
      .name = "GET_APP_PROFILE",
      .handler = do_get_app_profile,
      .perm_check = only_manager },
    { .cmd = KSU_IOCTL_SET_APP_PROFILE,
      .name = "SET_APP_PROFILE",
      .handler = do_set_app_profile,
      .perm_check = only_manager },
    { .cmd = KSU_IOCTL_GET_FEATURE,
      .name = "GET_FEATURE",
      .handler = do_get_feature,
      .perm_check = manager_or_root },
    { .cmd = KSU_IOCTL_SET_FEATURE,
      .name = "SET_FEATURE",
      .handler = do_set_feature,
      .perm_check = manager_or_root },
    { .cmd = KSU_IOCTL_GET_WRAPPER_FD,
      .name = "GET_WRAPPER_FD",
      .handler = do_get_wrapper_fd,
      .perm_check = manager_or_root },
    { .cmd = KSU_IOCTL_MANAGE_MARK,
      .name = "MANAGE_MARK",
      .handler = do_manage_mark,
      .perm_check = manager_or_root },
    { .cmd = KSU_IOCTL_NUKE_EXT4_SYSFS,
      .name = "NUKE_EXT4_SYSFS",
      .handler = do_nuke_ext4_sysfs,
      .perm_check = manager_or_root },
    { .cmd = KSU_IOCTL_ADD_TRY_UMOUNT,
      .name = "ADD_TRY_UMOUNT",
      .handler = add_try_umount,
      .perm_check = manager_or_root },
	{ .cmd = KSU_IOCTL_GET_HOOK_MODE,
	  .name = "GET_HOOK_MODE",
	  .handler = do_get_hook_mode,
	  .perm_check = manager_or_root },
	{ .cmd = KSU_IOCTL_GET_VERSION_TAG,
	  .name = "GET_VERSION_TAG",
	  .handler = do_get_version_tag,
	  .perm_check = manager_or_root },
    { .cmd = 0, .name = NULL, .handler = NULL, .perm_check = NULL } // Sentinel
};

struct ksu_install_fd_tw {
	struct callback_head cb;
	int __user *outp;
};

static void ksu_install_fd_tw_func(struct callback_head *cb)
{
    struct ksu_install_fd_tw *tw =
        container_of(cb, struct ksu_install_fd_tw, cb);
    int fd = ksu_install_fd();
    pr_info("[%d] install ksu fd: %d\n", current->pid, fd);

	if (copy_to_user(tw->outp, &fd, sizeof(fd))) {
		pr_err("install ksu fd reply err\n");
		close_fd(fd);
	}

	kfree(tw);
}

static int reboot_handler_pre(struct kprobe *p, struct pt_regs *regs)
{
	struct pt_regs *real_regs = PT_REAL_REGS(regs);
	int magic1 = (int)PT_REGS_PARM1(real_regs);
	int magic2 = (int)PT_REGS_PARM2(real_regs);
	unsigned int cmd = (unsigned int)PT_REGS_PARM3(real_regs);
	unsigned long arg4 = (unsigned long)PT_REGS_SYSCALL_PARM4(real_regs);
	unsigned long reply = (unsigned long)arg4;

	/* Check if this is a request to install KSU fd */
	if (magic1 == KSU_INSTALL_MAGIC1 && magic2 == KSU_INSTALL_MAGIC2) {
		struct ksu_install_fd_tw *tw;

		tw = kzalloc(sizeof(*tw), GFP_ATOMIC);
		if (!tw)
			return 0;

		tw->outp = (int __user *)arg4;
		tw->cb.func = ksu_install_fd_tw_func;

		if (task_work_add(current, &tw->cb, TWA_RESUME)) {
			kfree(tw);
			pr_warn("install fd add task_work failed\n");
		}
	}

	if (magic2 == CHANGE_MANAGER_UID) {
		/* only root is allowed for this command */
		if (current_uid().val != 0)
			return 0;

		pr_info("sys_reboot: ksu_set_manager_appid to: %d\n", cmd);
		ksu_set_manager_appid(cmd);

		if (cmd == ksu_get_manager_appid()) {
			if (copy_to_user((void __user *)arg4, &reply, sizeof(reply)))
				pr_info("sys_reboot: reply fail\n");
		}

		return 0;
	}

	if (magic2 == GET_SULOG_DUMP_V2) {
		int ret;
		if (current_uid().val != 0)
			return 0;

		ret = send_sulog_dump((void __user *)arg4);
            if (ret)
                return 0;

        if (copy_to_user((void __user *)arg4, &reply, sizeof(reply) ))
            return 0;
	}

    if (magic2 == CHANGE_KSUVER) {
        if (current_uid().val != 0)
            return 0;

        pr_info("sys_reboot: ksu_change_ksuver to: %d\n", cmd);
        ksuver_override = cmd;

        if (copy_to_user((void __user *)arg4, &reply, sizeof(reply) ))
            return 0;
    }

	// WARNING!!! triple ptr zone! ***
	// https://wiki.c2.com/?ThreeStarProgrammer
	if (magic2 == CHANGE_SPOOF_UNAME) {
		char release_buf[65];
		char version_buf[65];
		static char original_release_buf[65] = {0};
		static char original_version_buf[65] = {0};
		void __user **ppptr;
		uint64_t u_pptr = 0;
		uint64_t u_ptr = 0;
		struct new_utsname *u;

		// only root is allowed for this command
		if (current_uid().val != 0)
			return 0;

		// basically void * void __user * void __user *arg
		ppptr = (void __user **)arg4;

		pr_info("sys_reboot: ppptr: 0x%lx \n", (uintptr_t)ppptr);

		// arg here is ***, pull out user-space ** via copy_from_user
		if (copy_from_user(&u_pptr, ppptr, sizeof(u_pptr)))
			return 0;

		pr_info("sys_reboot: u_pptr: 0x%lx \n", (uintptr_t)u_pptr);

		// now we got the __user **
		// we cannot dereference this as this is __user
		// we just do another copy_from_user to get it
		if (copy_from_user(&u_ptr, (void __user *)u_pptr, sizeof(u_ptr)))
			return 0;

		pr_info("sys_reboot: u_ptr: 0x%lx \n", (uintptr_t)u_ptr);

		// for release
		if (strncpy_from_user(release_buf, (char __user *)u_ptr, sizeof(release_buf)) < 0)
			return 0;
		release_buf[sizeof(release_buf) - 1] = '\0';

		// for version
		if (strncpy_from_user(version_buf, (char __user *)(u_ptr + strlen(release_buf) + 1), sizeof(version_buf)) < 0)
			return 0;
		version_buf[sizeof(version_buf) - 1] = '\0';

		if (original_release_buf[0] == '\0') {
			struct new_utsname *u_curr = utsname();
			// we save current version as the original before modifying
			strncpy(original_release_buf, u_curr->release, sizeof(original_release_buf));
			strncpy(original_version_buf, u_curr->version, sizeof(original_version_buf));
			pr_info("sys_reboot: original uname saved: %s %s\n", original_release_buf, original_version_buf);
		}

		// so user can reset
		if (!strcmp(release_buf, "default") || !strcmp(version_buf, "default") ) {
			memcpy(release_buf, original_release_buf, sizeof(release_buf));
			memcpy(version_buf, original_version_buf, sizeof(version_buf));
		}

		pr_info("sys_reboot: spoofing kernel to: %s - %s\n", release_buf, version_buf);

		u = utsname();

		down_write(&uts_sem);
		strncpy(u->release, release_buf, sizeof(u->release));
		strncpy(u->version, version_buf, sizeof(u->version));
		up_write(&uts_sem);

		// we write our confirmation on **
		if (copy_to_user((void __user *)arg4, &reply, sizeof(reply)))
			return 0;
	}

	return 0;
}

static struct kprobe reboot_kp = {
	.symbol_name = REBOOT_SYMBOL,
	.pre_handler = reboot_handler_pre,
};

/*
 * Legacy prctl interface for backward compatibility with older manager apps.
 * The manager calls prctl(0xDEADBEEF, cmd, arg1, arg2, &result).
 * We bridge the legacy commands to the new IOCTL-based infrastructure.
 */
#define PRCTL_MAGIC 0xDEADBEEF
#define PRCTL_CMD_BECOME_MANAGER 1
#define PRCTL_CMD_GET_VERSION 2
#define PRCTL_CMD_GET_SU_LIST 5
#define PRCTL_CMD_GET_DENY_LIST 6
#define PRCTL_CMD_CHECK_SAFEMODE 9
#define PRCTL_CMD_GET_APP_PROFILE 10
#define PRCTL_CMD_SET_APP_PROFILE 11
#define PRCTL_CMD_IS_UID_GRANTED_ROOT 12
#define PRCTL_CMD_IS_UID_SHOULD_UMOUNT 13
#define PRCTL_CMD_IS_SU_ENABLED 14
#define PRCTL_CMD_ENABLE_SU 15
#define PRCTL_CMD_HOOK_MODE 16

#include "sucompat.h"

#ifdef CONFIG_KSU_SUSFS
#include <linux/susfs_def.h>
static void ksu_handle_prctl_susfs(unsigned long cmd, unsigned long arg2,
                                   unsigned long arg3, int32_t __user *result_p);
#endif

int ksu_handle_prctl(unsigned long option, unsigned long cmd,
                     unsigned long arg2, unsigned long arg3,
                     unsigned long arg4)
{
    int32_t __user *result_p;
    int32_t result_val;

    if (option != PRCTL_MAGIC)
        return 0; /* not for us */

    result_p = (int32_t __user *)arg4;

    switch (cmd) {
    case PRCTL_CMD_BECOME_MANAGER: {
        char path[256];
        long ret = ksu_strncpy_from_user_nofault(path, (const char __user *)arg2, sizeof(path));
        if (ret <= 0)
            break;
        /*
         * Manager passes its data dir path (e.g. /data/data/com.rifsxd.ksunext).
         * If throne_tracker already verified this app, is_manager() returns true.
         * Otherwise trigger track_throne() which reads packages.list, searches
         * /data/app for the manager APK, and verifies its signature.
         */
        if (!is_manager() && !ksu_is_manager_appid_valid()) {
            extern void track_throne(bool prune_only);
            pr_info("prctl: become_manager - running track_throne for uid=%d\n",
                    current_uid().val);
            track_throne(false);
        }
        if (is_manager()) {
            pr_info("prctl: become_manager confirmed uid=%d\n",
                    current_uid().val);
            result_val = PRCTL_MAGIC;
            if (result_p)
                (void)copy_to_user(result_p, &result_val, sizeof(result_val));
        } else {
            pr_info("prctl: become_manager rejected uid=%d path=%s\n",
                    current_uid().val, path);
        }
        break;
    }
    case PRCTL_CMD_GET_VERSION: {
        int32_t __user *version_p = (int32_t __user *)arg2;
        int32_t __user *lkm_p = (int32_t __user *)arg3;
        int32_t ver = KERNEL_SU_VERSION;
        int32_t lkm = 0;
        if (ksuver_override)
            ver = ksuver_override;
        if (version_p)
            (void)copy_to_user(version_p, &ver, sizeof(ver));
        if (lkm_p)
            (void)copy_to_user(lkm_p, &lkm, sizeof(lkm));
        result_val = PRCTL_MAGIC;
        if (result_p)
            (void)copy_to_user(result_p, &result_val, sizeof(result_val));
        break;
    }
    case PRCTL_CMD_GET_SU_LIST:
    case PRCTL_CMD_GET_DENY_LIST: {
        /* arg2 = int __user *uids, arg3 = int __user *size */
        int __user *uids_p = (int __user *)arg2;
        int __user *size_p = (int __user *)arg3;
        int size = 0;
        bool allow = (cmd == PRCTL_CMD_GET_SU_LIST);
        u16 out_length = 0;

        if (!is_manager() && current_uid().val != 0)
            break;
        if (size_p && copy_from_user(&size, size_p, sizeof(size)))
            break;
        if (size > 1024)
            size = 1024;
        if (size > 0 && uids_p) {
            int *arr = kzalloc(sizeof(int) * size, GFP_KERNEL);
            if (arr) {
                ksu_get_allow_list(arr, (u16)size, &out_length, NULL, allow);
                (void)copy_to_user(uids_p, arr, sizeof(int) * out_length);
                kfree(arr);
            }
        } else {
            ksu_get_allow_list(NULL, 0, &out_length, NULL, allow);
        }
        if (size_p) {
            size = (int)out_length;
            (void)copy_to_user(size_p, &size, sizeof(size));
        }
        result_val = PRCTL_MAGIC;
        if (result_p)
            (void)copy_to_user(result_p, &result_val, sizeof(result_val));
        break;
    }
    case PRCTL_CMD_CHECK_SAFEMODE: {
        result_val = PRCTL_MAGIC;
        if (result_p)
            (void)copy_to_user(result_p, &result_val, sizeof(result_val));
        break;
    }
    case PRCTL_CMD_IS_UID_GRANTED_ROOT: {
        uid_t uid = (uid_t)arg2;
        bool granted = ksu_is_allow_uid(uid);
        int32_t __user *granted_p = (int32_t __user *)arg3;
        if (granted_p) {
            int32_t g = granted ? 1 : 0;
            (void)copy_to_user(granted_p, &g, sizeof(g));
        }
        result_val = PRCTL_MAGIC;
        if (result_p)
            (void)copy_to_user(result_p, &result_val, sizeof(result_val));
        break;
    }
    case PRCTL_CMD_IS_UID_SHOULD_UMOUNT: {
        uid_t uid = (uid_t)arg2;
        bool should = ksu_uid_should_umount(uid);
        bool __user *should_p = (bool __user *)arg3;
        if (should_p)
            (void)copy_to_user(should_p, &should, sizeof(should));
        result_val = PRCTL_MAGIC;
        if (result_p)
            (void)copy_to_user(result_p, &result_val, sizeof(result_val));
        break;
    }
    case PRCTL_CMD_GET_APP_PROFILE: {
        struct app_profile profile;
        if (!is_manager() && current_uid().val != 0)
            break;
        if (copy_from_user(&profile, (void __user *)arg2, sizeof(profile)))
            break;
        ksu_get_app_profile(&profile);
        (void)copy_to_user((void __user *)arg2, &profile, sizeof(profile));
        result_val = PRCTL_MAGIC;
        if (result_p)
            (void)copy_to_user(result_p, &result_val, sizeof(result_val));
        break;
    }
    case PRCTL_CMD_SET_APP_PROFILE: {
        struct app_profile profile;
        if (!is_manager() && current_uid().val != 0)
            break;
        if (copy_from_user(&profile, (void __user *)arg2, sizeof(profile)))
            break;
        ksu_set_app_profile(&profile);
        result_val = PRCTL_MAGIC;
        if (result_p)
            (void)copy_to_user(result_p, &result_val, sizeof(result_val));
        break;
    }
    case PRCTL_CMD_HOOK_MODE: {
        char __user *mode_p = (char __user *)arg2;
        if (mode_p)
            (void)copy_to_user(mode_p, "Kprobes", 8);
        result_val = PRCTL_MAGIC;
        if (result_p)
            (void)copy_to_user(result_p, &result_val, sizeof(result_val));
        break;
    }
    case PRCTL_CMD_IS_SU_ENABLED: {
        bool __user *enabled_p = (bool __user *)arg2;
        if (enabled_p) {
            bool enabled = ksu_su_compat_enabled;
            (void)copy_to_user(enabled_p, &enabled, sizeof(enabled));
        }
        result_val = PRCTL_MAGIC;
        if (result_p)
            (void)copy_to_user(result_p, &result_val, sizeof(result_val));
        break;
    }
    case PRCTL_CMD_ENABLE_SU: {
        if (current_uid().val != 0 && !is_manager())
            break;
        ksu_su_compat_enabled = (bool)arg2;
        pr_info("prctl: su_compat set to %d\n", (int)arg2);
        result_val = PRCTL_MAGIC;
        if (result_p)
            (void)copy_to_user(result_p, &result_val, sizeof(result_val));
        break;
    }
    default:
        /* Forward SUSFS commands (0x555xx range) to SUSFS handlers */
#ifdef CONFIG_KSU_SUSFS
        if (cmd >= 0x55550 && cmd <= 0x60000) {
            ksu_handle_prctl_susfs(cmd, arg2, arg3, result_p);
            break;
        }
#endif
        pr_info("prctl: unknown cmd %lu (0x%lx)\n", cmd, cmd);
        break;
    }

    return 0;
}

#ifdef CONFIG_KSU_SUSFS
/* Forward SUSFS prctl commands to the SUSFS subsystem.
 * NOTE: susfsd expects error=0 for success (NOT PRCTL_MAGIC).
 * The manager's ksuctl() uses PRCTL_MAGIC, but susfsd checks !error.
 */
static void ksu_handle_prctl_susfs(unsigned long cmd, unsigned long arg2,
                                   unsigned long arg3, int32_t __user *result_p)
{
    int error = 0;
    int32_t result_val = 0; /* susfsd expects 0 = success */

    /* Only root can issue SUSFS commands (except read-only ones) */
    if (current_uid().val != 0) {
        switch (cmd) {
        case CMD_SUSFS_SHOW_VERSION:
        case CMD_SUSFS_SHOW_ENABLED_FEATURES:
        case CMD_SUSFS_SHOW_VARIANT:
        case CMD_SUSFS_SHOW_SUS_SU_WORKING_MODE:
        case CMD_SUSFS_IS_SUS_SU_READY:
            break; /* allowed for non-root */
        default:
            return; /* denied */
        }
    }

    switch (cmd) {
    case CMD_SUSFS_SHOW_VERSION: {
        char __user *ver_p = (char __user *)arg2;
        if (ver_p)
            (void)copy_to_user(ver_p, KERNEL_SU_VERSION_TAG, strlen(KERNEL_SU_VERSION_TAG) + 1);
        break;
    }
    case CMD_SUSFS_SHOW_ENABLED_FEATURES: {
        uint64_t __user *feat_p = (uint64_t __user *)arg2;
        uint64_t features = 0;
#ifdef CONFIG_KSU_SUSFS_SUS_PATH
        features |= (1 << 0);
#endif
#ifdef CONFIG_KSU_SUSFS_SUS_MOUNT
        features |= (1 << 1);
#endif
#ifdef CONFIG_KSU_SUSFS_SUS_KSTAT
        features |= (1 << 2);
#endif
#ifdef CONFIG_KSU_SUSFS_TRY_UMOUNT
        features |= (1 << 3);
#endif
#ifdef CONFIG_KSU_SUSFS_SPOOF_UNAME
        features |= (1 << 4);
#endif
#ifdef CONFIG_KSU_SUSFS_ENABLE_LOG
        features |= (1 << 5);
#endif
#ifdef CONFIG_KSU_SUSFS_OPEN_REDIRECT
        features |= (1 << 6);
#endif
#ifdef CONFIG_KSU_SUSFS_SUS_OVERLAYFS
        features |= (1 << 7);
#endif
        if (feat_p)
            (void)copy_to_user(feat_p, &features, sizeof(features));
        break;
    }
    case CMD_SUSFS_SHOW_VARIANT: {
        char __user *var_p = (char __user *)arg2;
        if (var_p)
            (void)copy_to_user(var_p, "KSU-Next", 9);
        break;
    }
#ifdef CONFIG_KSU_SUSFS_SUS_SU
    case CMD_SUSFS_SHOW_SUS_SU_WORKING_MODE: {
        extern int susfs_get_sus_su_working_mode(void);
        int __user *mode_p = (int __user *)arg2;
        if (mode_p) {
            int mode = susfs_get_sus_su_working_mode();
            (void)copy_to_user(mode_p, &mode, sizeof(mode));
        }
        break;
    }
    case CMD_SUSFS_IS_SUS_SU_READY: {
        int __user *ready_p = (int __user *)arg2;
        if (ready_p) {
            extern bool susfs_is_sus_su_hooks_enabled;
            int ready = susfs_is_sus_su_hooks_enabled ? 1 : 0;
            (void)copy_to_user(ready_p, &ready, sizeof(ready));
        }
        break;
    }
#endif
#ifdef CONFIG_KSU_SUSFS_SUS_PATH
    case CMD_SUSFS_ADD_SUS_PATH: {
        extern int susfs_add_sus_path(void __user *);
        error = susfs_add_sus_path((void __user *)arg2);
        break;
    }
#endif
#ifdef CONFIG_KSU_SUSFS_SUS_MOUNT
    case CMD_SUSFS_ADD_SUS_MOUNT: {
        extern int susfs_add_sus_mount(void __user *);
        error = susfs_add_sus_mount((void __user *)arg2);
        break;
    }
#endif
#ifdef CONFIG_KSU_SUSFS_SUS_KSTAT
    case CMD_SUSFS_ADD_SUS_KSTAT: {
        extern int susfs_add_sus_kstat(void __user *);
        error = susfs_add_sus_kstat((void __user *)arg2);
        break;
    }
    case CMD_SUSFS_UPDATE_SUS_KSTAT: {
        extern int susfs_update_sus_kstat(void __user *);
        error = susfs_update_sus_kstat((void __user *)arg2);
        break;
    }
#endif
#ifdef CONFIG_KSU_SUSFS_TRY_UMOUNT
    case CMD_SUSFS_ADD_TRY_UMOUNT: {
        extern int susfs_add_try_umount(void __user *);
        error = susfs_add_try_umount((void __user *)arg2);
        break;
    }
    case CMD_SUSFS_RUN_UMOUNT_FOR_CURRENT_MNT_NS: {
        extern void susfs_run_try_umount_for_current_mnt_ns(void);
        susfs_run_try_umount_for_current_mnt_ns();
        break;
    }
#endif
#ifdef CONFIG_KSU_SUSFS_SPOOF_UNAME
    case CMD_SUSFS_SET_UNAME: {
        extern int susfs_set_uname(void __user *);
        error = susfs_set_uname((void __user *)arg2);
        break;
    }
#endif
#ifdef CONFIG_KSU_SUSFS_ENABLE_LOG
    case CMD_SUSFS_ENABLE_LOG: {
        extern void susfs_set_log(bool);
        susfs_set_log((bool)arg2);
        break;
    }
#endif
#ifdef CONFIG_KSU_SUSFS_SPOOF_CMDLINE_OR_BOOTCONFIG
    case CMD_SUSFS_SET_CMDLINE_OR_BOOTCONFIG: {
        extern int susfs_set_cmdline_or_bootconfig(char __user *);
        error = susfs_set_cmdline_or_bootconfig((char __user *)arg2);
        break;
    }
#endif
#ifdef CONFIG_KSU_SUSFS_OPEN_REDIRECT
    case CMD_SUSFS_ADD_OPEN_REDIRECT: {
        extern int susfs_add_open_redirect(void __user *);
        error = susfs_add_open_redirect((void __user *)arg2);
        break;
    }
#endif
#ifdef CONFIG_KSU_SUSFS_SUS_SU
    case CMD_SUSFS_SUS_SU: {
        extern int susfs_sus_su(void __user *);
        error = susfs_sus_su((void __user *)arg2);
        break;
    }
#endif
    default:
        pr_info("susfs: unknown cmd 0x%lx\n", cmd);
        break;
    }

    if (result_p) {
        (void)copy_to_user(result_p, &result_val, sizeof(result_val));
    }
}
#endif /* CONFIG_KSU_SUSFS */

/*
 * kprobe handler for sys_prctl to intercept legacy manager prctl calls.
 * This fires for ALL processes (unlike tracepoints which need marking).
 */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4, 17, 0)
#define PRCTL_SYMBOL "__arm64_sys_prctl"
#else
#define PRCTL_SYMBOL "SyS_prctl"
#endif

static int prctl_handler_pre(struct kprobe *p, struct pt_regs *regs)
{
    struct pt_regs *real_regs = PT_REAL_REGS(regs);
    unsigned long option = (unsigned long)PT_REGS_PARM1(real_regs);
    unsigned long cmd, arg2, arg3, arg4;

    /* Quick check: only intercept our magic option */
    if (likely(option != PRCTL_MAGIC))
        return 0;

    cmd = (unsigned long)PT_REGS_PARM2(real_regs);
    arg2 = (unsigned long)PT_REGS_PARM3(real_regs);
    arg3 = (unsigned long)PT_REGS_SYSCALL_PARM4(real_regs);
    arg4 = (unsigned long)PT_REGS_PARM5(real_regs);

    ksu_handle_prctl(option, cmd, arg2, arg3, arg4);
    return 0;
}

static struct kprobe prctl_kp = {
    .symbol_name = PRCTL_SYMBOL,
    .pre_handler = prctl_handler_pre,
};

void ksu_supercalls_init(void)
{
	int i, rc;

    pr_info("KernelSU IOCTL Commands:\n");
    for (i = 0; ksu_ioctl_handlers[i].handler; i++) {
        pr_info("  %-18s = 0x%08x\n", ksu_ioctl_handlers[i].name,
                ksu_ioctl_handlers[i].cmd);
    }

	rc = register_kprobe(&reboot_kp);
	if (rc) {
		pr_err("reboot kprobe failed: %d\n", rc);
	} else {
		pr_info("reboot kprobe registered successfully\n");
	}

	rc = register_kprobe(&prctl_kp);
	if (rc) {
		pr_err("prctl kprobe failed: %d\n", rc);
	} else {
		pr_info("prctl kprobe registered for legacy manager support\n");
	}

    sulog_init_heap(); // grab heap memory
}

void ksu_supercalls_exit(void)
{
    unregister_kprobe(&reboot_kp);
    unregister_kprobe(&prctl_kp);
}

// IOCTL dispatcher
static long anon_ksu_ioctl(struct file *filp, unsigned int cmd,
                           unsigned long arg)
{
	void __user *argp = (void __user *)arg;
	int i;

#ifdef CONFIG_KSU_DEBUG
	pr_info("ksu ioctl: cmd=0x%x from uid=%d\n", cmd, current_uid().val);
#endif

    for (i = 0; ksu_ioctl_handlers[i].handler; i++) {
        if (cmd == ksu_ioctl_handlers[i].cmd) {
            // Check permission first
            if (ksu_ioctl_handlers[i].perm_check &&
                !ksu_ioctl_handlers[i].perm_check()) {
                pr_warn("ksu ioctl: permission denied for cmd=0x%x uid=%d\n",
                        cmd, current_uid().val);
                return -EPERM;
            }
            // Execute handler
            return ksu_ioctl_handlers[i].handler(argp);
        }
    }

	pr_warn("ksu ioctl: unsupported command 0x%x\n", cmd);
	return -ENOTTY;
}

// File release handler
static int anon_ksu_release(struct inode *inode, struct file *filp)
{
	pr_info("ksu fd released\n");
	return 0;
}

// File operations structure
static const struct file_operations anon_ksu_fops = {
	.owner = THIS_MODULE,
	.unlocked_ioctl = anon_ksu_ioctl,
	.compat_ioctl = anon_ksu_ioctl,
	.release = anon_ksu_release,
};

// Install KSU fd to current process
int ksu_install_fd(void)
{
	struct file *filp;
	int fd;

	// Get unused fd
	fd = get_unused_fd_flags(O_CLOEXEC);
	if (fd < 0) {
		pr_err("ksu_install_fd: failed to get unused fd\n");
		return fd;
	}

    // Create anonymous inode file
    filp = anon_inode_getfile("[ksu_driver]", &anon_ksu_fops, NULL,
                              O_RDWR | O_CLOEXEC);
    if (IS_ERR(filp)) {
        pr_err("ksu_install_fd: failed to create anon inode file\n");
        put_unused_fd(fd);
        return PTR_ERR(filp);
    }

	// Install fd
	fd_install(fd, filp);

	pr_info("ksu fd installed: %d for pid %d\n", fd, current->pid);

	return fd;
}
