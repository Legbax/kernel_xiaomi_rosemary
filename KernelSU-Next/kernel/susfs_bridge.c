/*
 * susfs_bridge.c - Bridge between SUSFS and KernelSU-Next v3.1.0
 *
 * Provides the legacy functions that SUSFS expects from the old core_hook.c
 * but implemented using the new KernelSU-Next API.
 */

#include <linux/version.h>
#include <linux/cred.h>
#include <linux/fs.h>
#include <linux/mount.h>
#include <linux/namei.h>
#include <linux/path.h>
#include <linux/printk.h>

#ifdef CONFIG_KSU_SUSFS

#include "allowlist.h"
#include "manager.h"
#include "app_profile.h"
#include "klog.h"

/* susfs_is_allow_su - called from sus_su.c to check if current process can use su */
bool susfs_is_allow_su(void)
{
	if (is_manager()) {
		return true;
	}
	return ksu_is_allow_uid(current_uid().val);
}

/* ksu_escape_to_root - called from sus_su.c to escalate to root */
void ksu_escape_to_root(void)
{
	escape_with_root_profile();
}

/* path_umount - kernel internal, may need extern */
extern int path_umount(struct path *path, int flags);

/*
 * ksu_try_umount - called from fs/susfs.c to unmount paths
 * This provides the legacy interface that SUSFS expects.
 */
void ksu_try_umount(const char *mnt, bool check_mnt, int flags, uid_t uid)
{
	struct path path;
	int err = kern_path(mnt, 0, &path);
	if (err) {
		return;
	}

	if (check_mnt && path.dentry != path.mnt->mnt_root) {
		path_put(&path);
		return;
	}

	err = path_umount(&path, flags);
	if (err) {
		pr_info("susfs: umount %s failed: %d\n", mnt, err);
	}
}

/*
 * susfs_try_umount_all - called from fs/namespace.c
 * Bridge to susfs_try_umount() which is the actual implementation in fs/susfs.c
 */
#ifdef CONFIG_KSU_SUSFS_TRY_UMOUNT
extern void susfs_try_umount(uid_t target_uid);

void susfs_try_umount_all(uid_t uid)
{
	susfs_try_umount(uid);
}
#endif

#endif /* CONFIG_KSU_SUSFS */
