#ifndef __KSU_OBJSEC_COMPAT_H
#define __KSU_OBJSEC_COMPAT_H

/*
 * Compatibility wrapper for accessing SELinux object security structures.
 * On kernels < 5.x, security blobs are stored directly in the object
 * (e.g., inode->i_security, cred->security).
 * On newer kernels, LSM blob infrastructure provides accessor functions.
 */

#include <linux/version.h>

/* Include the real objsec.h from the kernel's SELinux directory */
#include "../../security/selinux/include/objsec.h"

#if LINUX_VERSION_CODE < KERNEL_VERSION(5, 0, 0)

/* On 4.14, security data is stored directly in the objects */
static inline struct task_security_struct *selinux_cred(const struct cred *cred)
{
	return (struct task_security_struct *)cred->security;
}

static inline struct inode_security_struct *selinux_inode(const struct inode *inode)
{
	return (struct inode_security_struct *)inode->i_security;
}

#endif /* < 5.0.0 */

#endif /* __KSU_OBJSEC_COMPAT_H */
