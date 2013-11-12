/*
 * arch/sh/kernel/cpu/sh2a/ubc.c
 *
 * On-chip UBC support for SH-2A CPUs.
 *
 * Copyright (C) 2009 - 2010  Paul Mundt
 *
 * This file is subject to the terms and conditions of the GNU General Public
 * License.  See the file "COPYING" in the main directory of this archive
 * for more details.
 */
#include <linux/init.h>
#include <linux/err.h>
#include <linux/clk.h>
#include <linux/io.h>
#include <asm/hw_breakpoint.h>

#define UBC_BAR(idx)	(0xfffc0400 + (0x10 * idx))
#define UBC_BAMR(idx)	(0xfffc0404 + (0x10 * idx))
#define UBC_BBR(idx)	(0xfffc04A0 + (0x10 * idx))
#define UBC_BDR(idx)	(0xfffc0408 + (0x10 * idx))
#define UBC_BDMR(idx)	(0xfffc040C + (0x10 * idx))

#define UBC_BRCR	0xfffc04C0

/* BBR */
#define UBC_BBR_UBID	(1 << 13)     /* User Break Interrupt Disable */
#define UBC_BBR_DBE	(1 << 12)     /* Data Break Enable */
#define UBC_BBR_CD_C	(1 << 6)      /* C Bus Cycle */
#define UBC_BBR_CD_I	(2 << 6)      /* I Bus Cycle */
#define UBC_BBR_ID_I	(1 << 4)      /* Break Condition is instruction fetch cycle */
#define UBC_BBR_ID_D	(2 << 4)      /* Break Condition is data access cycle */
#define UBC_BBR_ID_ID	(3 << 4)      /* Break Condition is instruction fetch or data access cycle */

#define UBC_CRR_BIE	(1 << 0)

/* CBR */
#define UBC_CBR_CE	(1 << 0)

static struct sh_ubc sh2a_ubc;

static void sh2a_ubc_enable(struct arch_hw_breakpoint *info, int idx)
{
	__raw_writel(UBC_BBR_DBE | UBC_BBR_CD_C | UBC_BBR_ID_ID |
		     info->len | info->type, UBC_BBR(idx));
	__raw_writel(info->address, UBC_BAR(idx));
}

static void sh2a_ubc_disable(struct arch_hw_breakpoint *info, int idx)
{
	__raw_writel(UBC_BBR_UBID, UBC_BBR(idx));
	__raw_writel(0, UBC_BAR(idx));
}

static void sh2a_ubc_enable_all(unsigned long mask)
{
	int i;

	for (i = 0; i < sh2a_ubc.num_events; i++)
		if (mask & (1 << i))
			__raw_writel(__raw_readl(UBC_BBR(i)) & ~UBC_BBR_UBID,
				     UBC_BBR(i));
}

static void sh2a_ubc_disable_all(void)
{
	int i;
	
	for (i = 0; i < sh2a_ubc.num_events; i++)
		__raw_writel(__raw_readl(UBC_BBR(i)) | UBC_BBR_UBID,
			     UBC_BBR(i));
}

static unsigned long sh2a_ubc_active_mask(void)
{
	unsigned long active = 0;
	int i;

	for (i = 0; i < sh2a_ubc.num_events; i++)
		if (!(__raw_readl(UBC_BBR(i)) & UBC_BBR_UBID))
			active |= (1 << i);

	return active;
}

static unsigned long sh2a_ubc_triggered_mask(void)
{
	unsigned int ret, mask;
	
	mask = 0;
	ret = __raw_readl(UBC_BRCR);
	if ((ret & (1 << 15)) || (ret & (1 << 13))) {
		mask |= (1 << 0); /* Match condition for channel 0 */
	} else 
		mask &= ~(1 << 0);
	
	if ((ret & (1 << 14)) || (ret & (1 << 12))) {
		mask |= (1 << 1); /* Match condition for channel 1 */
	} else 
		mask &= ~(1 << 1);

	return mask;
}

static void sh2a_ubc_clear_triggered_mask(unsigned long mask)
{
	if (mask & (1 << 0)) /* Channel 0 statisfied break condition */
		__raw_writel(__raw_readl(UBC_BRCR) &
			     ~((1 << 15) | (1 << 13)), UBC_BRCR);
	
	if (mask & (1 << 1)) /* Channel 1 statisfied break condition */
		__raw_writel(__raw_readl(UBC_BRCR) &
			     ~((1 << 14) | (1 << 12)), UBC_BRCR);
}

static struct sh_ubc sh2a_ubc = {
	.name			= "SH-2A",
	.num_events		= 2,
	.trap_nr		= 0x1e0,
	.enable			= sh2a_ubc_enable,
	.disable		= sh2a_ubc_disable,
	.enable_all		= sh2a_ubc_enable_all,
	.disable_all		= sh2a_ubc_disable_all,
	.active_mask		= sh2a_ubc_active_mask,
	.triggered_mask		= sh2a_ubc_triggered_mask,
	.clear_triggered_mask	= sh2a_ubc_clear_triggered_mask,
};

static int __init sh2a_ubc_init(void)
{
	struct clk *ubc_iclk = clk_get(NULL, "ubc0");
	int i;

	/*
	 * The UBC MSTP bit is optional, as not all platforms will have
	 * it. Just ignore it if we can't find it.
	 */
	if (IS_ERR(ubc_iclk))
		ubc_iclk = NULL;

	clk_enable(ubc_iclk);

	for (i = 0; i < sh2a_ubc.num_events; i++) {
		__raw_writel(0, UBC_BAMR(i));
		__raw_writel(0, UBC_BBR(i));
	}

	clk_disable(ubc_iclk);

	sh2a_ubc.clk = ubc_iclk;

	return register_sh_ubc(&sh2a_ubc);
}
arch_initcall(sh2a_ubc_init);
