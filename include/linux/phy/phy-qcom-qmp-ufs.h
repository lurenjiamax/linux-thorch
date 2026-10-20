/* SPDX-License-Identifier: GPL-2.0 */
#ifndef __PHY_QCOM_QMP_UFS_H__
#define __PHY_QCOM_QMP_UFS_H__

#include <linux/errno.h>
#include <linux/kconfig.h>
#include <linux/types.h>

struct phy;

#if IS_ENABLED(CONFIG_PHY_QCOM_QMP_UFS)
int qcom_qmp_ufs_ctrl_rx_linecfg(struct phy *phy, bool enable);
#else
static inline int qcom_qmp_ufs_ctrl_rx_linecfg(struct phy *phy, bool enable)
{
	return -EOPNOTSUPP;
}
#endif

#endif
