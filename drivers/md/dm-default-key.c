// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2017 Google, Inc.
 * Adapted from Android common d2101e7384ec for the Linux 7.1 block API.
 */
#include <linux/blk-crypto.h>
#include <linux/device-mapper.h>
#include <linux/hex.h>
#include <linux/module.h>

#define DM_MSG_PREFIX "default-key"

static const struct dm_default_key_cipher {
	const char *name;
	enum blk_crypto_mode_num mode;
} dm_default_key_ciphers[] = {
	{ "aes-xts-plain64", BLK_ENCRYPTION_MODE_AES_256_XTS },
	{ "xchacha12,aes-adiantum-plain64", BLK_ENCRYPTION_MODE_ADIANTUM },
};

struct default_key_c {
	struct dm_dev *dev;
	sector_t start;
	const char *cipher;
	u64 iv_offset;
	unsigned int sector_size;
	unsigned int sector_bits;
	struct blk_crypto_key key;
	bool wrapped;
	bool key_started;
	u64 max_dun;
};

static void default_key_dtr(struct dm_target *ti)
{
	struct default_key_c *dkc = ti->private;

	if (dkc->dev) {
		if (dkc->key_started)
			blk_crypto_evict_key(dkc->dev->bdev, &dkc->key);
		dm_put_device(ti, dkc->dev);
	}
	kfree(dkc->cipher);
	kfree_sensitive(dkc);
}

static int default_key_options(struct dm_target *ti, unsigned int argc,
			       char **argv)
{
	struct default_key_c *dkc = ti->private;
	struct dm_arg_set as = { .argc = argc, .argv = argv };
	static const struct dm_arg args[] = {
		{ 0, 4, "Invalid number of feature args" },
	};
	unsigned int count;
	bool large = false;
	const char *opt;
	char dummy;
	int err;

	err = dm_read_arg_group(args, &as, &count, &ti->error);
	if (err)
		return err;
	if (as.argc != count) {
		ti->error = "Feature count does not match arguments";
		return -EINVAL;
	}
	while (count--) {
		opt = dm_shift_arg(&as);
		if (!strcmp(opt, "allow_discards")) {
			ti->num_discard_bios = 1;
		} else if (sscanf(opt, "sector_size:%u%c", &dkc->sector_size,
				  &dummy) == 1) {
			if (dkc->sector_size < SECTOR_SIZE ||
			    dkc->sector_size > 4096 ||
			    !is_power_of_2(dkc->sector_size)) {
				ti->error = "Invalid sector_size";
				return -EINVAL;
			}
		} else if (!strcmp(opt, "iv_large_sectors")) {
			large = true;
		} else if (!strcmp(opt, "wrappedkey_v0")) {
			dkc->wrapped = true;
		} else {
			ti->error = "Invalid feature argument";
			return -EINVAL;
		}
	}
	if (dkc->sector_size != SECTOR_SIZE && !large) {
		ti->error = "iv_large_sectors must be specified";
		return -EINVAL;
	}
	return 0;
}

static int default_key_ctr(struct dm_target *ti, unsigned int argc, char **argv)
{
	struct default_key_c *dkc;
	enum blk_crypto_mode_num mode = BLK_ENCRYPTION_MODE_INVALID;
	u8 raw_key[BLK_CRYPTO_MAX_ANY_KEY_SIZE];
	size_t key_size;
	unsigned long long start;
	unsigned int i;
	char dummy;
	int err = -EINVAL;

	if (argc < 5) {
		ti->error = "Not enough arguments";
		return -EINVAL;
	}
	dkc = kzalloc(sizeof(*dkc), GFP_KERNEL);
	if (!dkc)
		return -ENOMEM;
	ti->private = dkc;
	dkc->cipher = kstrdup(argv[0], GFP_KERNEL);
	if (!dkc->cipher) {
		err = -ENOMEM;
		goto bad;
	}
	for (i = 0; i < ARRAY_SIZE(dm_default_key_ciphers); i++)
		if (!strcmp(argv[0], dm_default_key_ciphers[i].name))
			mode = dm_default_key_ciphers[i].mode;
	if (mode == BLK_ENCRYPTION_MODE_INVALID) {
		ti->error = "Unsupported cipher";
		goto bad;
	}
	key_size = strlen(argv[1]);
	if (!key_size || key_size % 2 || key_size > 2 * sizeof(raw_key)) {
		ti->error = "Invalid key size";
		goto bad;
	}
	key_size /= 2;
	if (hex2bin(raw_key, argv[1], key_size)) {
		ti->error = "Malformed key string";
		goto bad;
	}
	if (sscanf(argv[2], "%llu%c", &dkc->iv_offset, &dummy) != 1 ||
	    sscanf(argv[4], "%llu%c", &start, &dummy) != 1 ||
	    start != (sector_t)start) {
		ti->error = "Invalid sector offset";
		goto bad;
	}
	dkc->start = start;
	dkc->sector_size = SECTOR_SIZE;
	if (argc > 5) {
		err = default_key_options(ti, argc - 5, argv + 5);
		if (err)
			goto bad;
	}
	err = -EINVAL;
	dkc->sector_bits = ilog2(dkc->sector_size);
	if (!ti->len || ti->len & ((dkc->sector_size >> SECTOR_SHIFT) - 1) ||
	    dkc->iv_offset > U64_MAX - (ti->len - 1)) {
		ti->error = "Invalid device length or IV range";
		goto bad;
	}
	dkc->max_dun = (dkc->iv_offset + ti->len - 1) >>
			(dkc->sector_bits - SECTOR_SHIFT);
	err = dm_get_device(ti, argv[3], dm_table_get_mode(ti->table), &dkc->dev);
	if (err) {
		ti->error = "Device lookup failed";
		goto bad;
	}
	err = blk_crypto_init_key(&dkc->key, raw_key, key_size,
			dkc->wrapped ? BLK_CRYPTO_KEY_TYPE_HW_WRAPPED :
				       BLK_CRYPTO_KEY_TYPE_RAW,
			mode, max_t(unsigned int, 1,
				    DIV_ROUND_UP(fls64(dkc->max_dun), 8)),
			dkc->sector_size);
	if (err) {
		ti->error = "Error initializing blk-crypto key";
		goto bad;
	}
	err = blk_crypto_start_using_key(dkc->dev->bdev, &dkc->key);
	if (err) {
		ti->error = "Device cannot use this blk-crypto key";
		goto bad;
	}
	dkc->key_started = true;
	ti->num_flush_bios = 1;
	memzero_explicit(raw_key, sizeof(raw_key));
	return 0;
bad:
	memzero_explicit(raw_key, sizeof(raw_key));
	default_key_dtr(ti);
	return err;
}

static int default_key_map(struct dm_target *ti, struct bio *bio)
{
	const struct default_key_c *dkc = ti->private;
	sector_t sector;
	u64 dun[BLK_CRYPTO_DUN_ARRAY_SIZE] = { 0 };

	bio_set_dev(bio, dkc->dev->bdev);
	if (!bio_sectors(bio))
		return DM_MAPIO_REMAPPED;
	sector = dm_target_offset(ti, bio->bi_iter.bi_sector);
	bio->bi_iter.bi_sector = dkc->start + sector;
	if (bio_should_skip_dm_default_key(bio) || !bio_has_data(bio))
		return DM_MAPIO_REMAPPED;
	if (WARN_ON_ONCE(bio_has_crypt_ctx(bio)))
		return DM_MAPIO_KILL;
	dun[0] = dkc->iv_offset + sector;
	if (dun[0] & ((dkc->sector_size >> SECTOR_SHIFT) - 1) ||
	    bio->bi_iter.bi_size & (dkc->sector_size - 1))
		return DM_MAPIO_KILL;
	dun[0] >>= dkc->sector_bits - SECTOR_SHIFT;
	if (WARN_ON_ONCE(dun[0] > dkc->max_dun))
		return DM_MAPIO_KILL;
	bio_crypt_set_ctx(bio, &dkc->key, dun, GFP_NOIO);
	/* Android mainline: newly attached contexts need fallback-aware submit. */
	if (__blk_crypto_submit_bio(bio))
		return DM_MAPIO_REMAPPED;
	return DM_MAPIO_SUBMITTED;
}

static void default_key_status(struct dm_target *ti, status_type_t type,
			       unsigned int flags, char *result, unsigned int maxlen)
{
	const struct default_key_c *dkc = ti->private;
	unsigned int sz = 0;
	unsigned int count = !!ti->num_discard_bios + !!dkc->wrapped +
			     2 * (dkc->sector_size != SECTOR_SIZE);

	if (type != STATUSTYPE_TABLE) {
		result[0] = '\0';
		return;
	}
	/* Never return key bytes through dmsetup table/status. */
	DMEMIT("%s - %llu %s %llu", dkc->cipher, dkc->iv_offset,
	       dkc->dev->name, (unsigned long long)dkc->start);
	if (count) {
		DMEMIT(" %u", count);
		if (ti->num_discard_bios)
			DMEMIT(" allow_discards");
		if (dkc->sector_size != SECTOR_SIZE)
			DMEMIT(" sector_size:%u iv_large_sectors", dkc->sector_size);
		if (dkc->wrapped)
			DMEMIT(" wrappedkey_v0");
	}
}

static int default_key_prepare_ioctl(struct dm_target *ti,
				     struct block_device **bdev,
				     unsigned int cmd, unsigned long arg,
				     bool *forward)
{
	const struct default_key_c *dkc = ti->private;

	*bdev = dkc->dev->bdev;
	return dkc->start || ti->len != bdev_nr_sectors(*bdev);
}

static int default_key_iterate_devices(struct dm_target *ti,
				       iterate_devices_callout_fn fn, void *data)
{
	const struct default_key_c *dkc = ti->private;

	return fn(ti, dkc->dev, dkc->start, ti->len, data);
}

static void default_key_io_hints(struct dm_target *ti, struct queue_limits *limits)
{
	const struct default_key_c *dkc = ti->private;

	limits->logical_block_size = max(limits->logical_block_size, dkc->sector_size);
	limits->physical_block_size = max(limits->physical_block_size, dkc->sector_size);
	limits->io_min = max(limits->io_min, dkc->sector_size);
}

static struct target_type default_key_target = {
	.name = "default-key",
	.version = { 2, 1, 0 },
	.features = DM_TARGET_PASSES_CRYPTO,
	.module = THIS_MODULE,
	.ctr = default_key_ctr,
	.dtr = default_key_dtr,
	.map = default_key_map,
	.status = default_key_status,
	.prepare_ioctl = default_key_prepare_ioctl,
	.iterate_devices = default_key_iterate_devices,
	.io_hints = default_key_io_hints,
};

static int __init dm_default_key_init(void)
{
	return dm_register_target(&default_key_target);
}

static void __exit dm_default_key_exit(void)
{
	dm_unregister_target(&default_key_target);
}

module_init(dm_default_key_init);
module_exit(dm_default_key_exit);
MODULE_AUTHOR("Paul Lawrence <paullawrence@google.com>");
MODULE_AUTHOR("Paul Crowley <paulcrowley@google.com>");
MODULE_AUTHOR("Eric Biggers <ebiggers@google.com>");
MODULE_DESCRIPTION(DM_NAME " target for encrypting filesystem metadata");
MODULE_LICENSE("GPL");
