/*-
 * Copyright (c) 2008 Joerg Sonnenberger
 * Copyright (c) 2009-2012 Michihiro NAKAJIMA
 * Copyright (c) 2015 Michal Ratajsky
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR(S) ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR(S) BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include "archive_platform.h"
__FBSDID("$FreeBSD: head/lib/libarchive/archive_write_set_format_mtree.c 201171 2009-12-29 06:39:07Z kientzle $");

#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif
#ifdef HAVE_SYS_STAT_H
#include <sys/stat.h>
#endif
#ifdef HAVE_ERRNO_H
#include <errno.h>
#endif
#ifdef HAVE_MTREE_H
#include <mtree.h>
#endif
#include <stdlib.h>
#include <string.h>

#include "archive.h"
#include "archive_digest_private.h"
#include "archive_entry.h"
#include "archive_private.h"
#include "archive_string.h"
#include "archive_write_private.h"

#ifdef HAVE_MTREE_H
/*
 * Signature written at the start of every mtree file.
 */
#define MTREE_SIGNATURE		"#mtree\n"

/*
 * Default set of written keywords that can be overriden by options.
 */
#define DEFAULT_KEYWORDS	(MTREE_KEYWORD_DEVICE |		\
				 MTREE_KEYWORD_FLAGS |		\
				 MTREE_KEYWORD_GID |		\
				 MTREE_KEYWORD_GNAME |		\
				 MTREE_KEYWORD_LINK |		\
				 MTREE_KEYWORD_MODE |		\
				 MTREE_KEYWORD_NLINK |		\
				 MTREE_KEYWORD_SIZE |		\
				 MTREE_KEYWORD_TIME |		\
				 MTREE_KEYWORD_TYPE |		\
				 MTREE_KEYWORD_UID |		\
				 MTREE_KEYWORD_UNAME)
/*
 * Define some custom constants depending on which digest types are
 * compiled in.
 *
 * libmtree defines several aliases for digest keywords. Pick just one
 * for each digest to avoid including the same digest multiple times when
 * user specifies the "all" option.
 */
#ifdef ARCHIVE_HAS_MD5
# define DEFAULT_MD5		MTREE_KEYWORD_MD5DIGEST
# define MASK_MD5		MTREE_KEYWORD_MASK_MD5
#else
# define DEFAULT_MD5		0ULL
# define MASK_MD5		0ULL
#endif
#ifdef ARCHIVE_HAS_RMD160
# define DEFAULT_RMD160		MTREE_KEYWORD_RMD160DIGEST
# define MASK_RMD160		MTREE_KEYWORD_MASK_RMD160
#else
# define DEFAULT_RMD160		0ULL
# define MASK_RMD160		0ULL
#endif
#ifdef ARCHIVE_HAS_SHA1
# define DEFAULT_SHA1		MTREE_KEYWORD_SHA1DIGEST
# define MASK_SHA1		MTREE_KEYWORD_MASK_SHA1
#else
# define DEFAULT_SHA1		0ULL
# define MASK_SHA1		0ULL
#endif
#ifdef ARCHIVE_HAS_SHA256
# define DEFAULT_SHA256		MTREE_KEYWORD_SHA256DIGEST
# define MASK_SHA256		MTREE_KEYWORD_MASK_SHA256
#else
# define DEFAULT_SHA256		0ULL
# define MASK_SHA256		0ULL
#endif
#ifdef ARCHIVE_HAS_SHA384
# define DEFAULT_SHA384		MTREE_KEYWORD_SHA384DIGEST
# define MASK_SHA384		MTREE_KEYWORD_MASK_SHA384
#else
# define DEFAULT_SHA384		0ULL
# define MASK_SHA384		0ULL
#endif
#ifdef ARCHIVE_HAS_SHA512
# define DEFAULT_SHA512		MTREE_KEYWORD_SHA512DIGEST
# define MASK_SHA512		MTREE_KEYWORD_MASK_SHA512
#else
# define DEFAULT_SHA512		0ULL
# define MASK_SHA512		0ULL
#endif

#define MASK_DIGEST		(MASK_MD5 |			\
				 MASK_RMD160 |			\
				 MASK_SHA1 |			\
				 MASK_SHA256 |			\
				 MASK_SHA384 |			\
				 MASK_SHA512)
#if MASK_DIGEST
#define HAS_DIGEST		1
#endif

/*
 * All supported checksum/digest keywords.
 */
#define SUM_KEYWORDS		(MTREE_KEYWORD_CKSUM | MASK_DIGEST)

/*
 * Keywords recognized with the "all" option.
 *
 * This includes all the keywords that we are able to handle excluding
 * digest aliases.
 *
 * MTREE_KEYWORD_MASK_STAT is used here as a mask because we are able
 * to pass the whole structure to libmtree and this allows potential
 * future extensions of libmtree to be propagated here.
 */
#define ALL_KEYWORDS		(MTREE_KEYWORD_CKSUM |		\
				 MTREE_KEYWORD_GNAME |		\
				 MTREE_KEYWORD_LINK |		\
				 MTREE_KEYWORD_UNAME |		\
				 MTREE_KEYWORD_MASK_STAT |	\
				 DEFAULT_MD5 |			\
				 DEFAULT_RMD160 |		\
				 DEFAULT_SHA1 |			\
				 DEFAULT_SHA256 |		\
				 DEFAULT_SHA384 |		\
				 DEFAULT_SHA512)
/*
 * All keywords we are able to work with.
 *
 * This is "all" keywords plus all the digests including aliases.
 */
#define PARSE_KEYWORDS		(ALL_KEYWORDS | MASK_DIGEST)

struct mtree_write {
	struct mtree_spec	*spec;
	struct mtree_entry	*entries;
	struct mtree_entry	*current;
	int			 summing;
	uint64_t		 keywords;
	uint64_t		 entry_bytes_remaining;
	/*
	 * If it is set, ignore all files except directory files,
	 * like mtree(8) -d option.
	 */
	int 			 dironly;

	struct mtree_sum {
		struct mtree_cksum	*cksum;
#ifdef ARCHIVE_HAS_MD5
		archive_md5_ctx		 md5ctx;
		unsigned char		 md5buf[16];
#endif
#ifdef ARCHIVE_HAS_RMD160
		archive_rmd160_ctx	 rmd160ctx;
		unsigned char		 rmd160buf[20];
#endif
#ifdef ARCHIVE_HAS_SHA1
		archive_sha1_ctx	 sha1ctx;
		unsigned char		 sha1buf[20];
#endif
#ifdef ARCHIVE_HAS_SHA256
		archive_sha256_ctx	 sha256ctx;
		unsigned char		 sha256buf[32];
#endif
#ifdef ARCHIVE_HAS_SHA384
		archive_sha384_ctx	 sha384ctx;
		unsigned char		 sha384buf[48];
#endif
#ifdef ARCHIVE_HAS_SHA512
		archive_sha512_ctx	 sha512ctx;
		unsigned char		 sha512buf[64];
#endif
	} sum;
};

static void
sum_init(struct mtree_sum *sum, uint64_t *keywords)
{

	if (*keywords & MTREE_KEYWORD_CKSUM) {
		if (sum->cksum == NULL)
			sum->cksum =
			    mtree_cksum_create(MTREE_CKSUM_DEFAULT_INIT);
		else
			mtree_cksum_reset(sum->cksum, MTREE_CKSUM_DEFAULT_INIT);
		if (sum->cksum == NULL)
			*keywords &= ~MTREE_KEYWORD_CKSUM;
	}

#ifdef ARCHIVE_HAS_MD5
	if (*keywords & MASK_MD5)
		if (archive_md5_init(&sum->md5ctx) != ARCHIVE_OK)
			*keywords &= ~MASK_MD5;
#endif
#ifdef ARCHIVE_HAS_RMD160
	if (*keywords & MASK_RMD160)
		if (archive_rmd160_init(&sum->rmd160ctx) != ARCHIVE_OK)
			*keywords &= ~MASK_RMD160;
#endif
#ifdef ARCHIVE_HAS_SHA1
	if (*keywords & MASK_SHA1)
		if (archive_sha1_init(&sum->sha1ctx) != ARCHIVE_OK)
			*keywords &= ~MASK_SHA1;
#endif
#ifdef ARCHIVE_HAS_SHA256
	if (*keywords & MASK_SHA256)
		if (archive_sha256_init(&sum->sha256ctx) != ARCHIVE_OK)
			*keywords &= ~MASK_SHA256;
#endif
#ifdef ARCHIVE_HAS_SHA384
	if (*keywords & MASK_SHA384)
		if (archive_sha384_init(&sum->sha384ctx) != ARCHIVE_OK)
			*keywords &= ~MASK_SHA384;
#endif
#ifdef ARCHIVE_HAS_SHA512
	if (*keywords & MASK_SHA512)
		if (archive_sha512_init(&sum->sha512ctx) != ARCHIVE_OK)
			*keywords &= ~MASK_SHA512;
#endif
}

static void
sum_update(struct mtree_sum *sum, uint64_t keywords, const void *buff, size_t n)
{

	if (keywords & MTREE_KEYWORD_CKSUM)
		mtree_cksum_update(sum->cksum, buff, n);

#ifdef ARCHIVE_HAS_MD5
	if (keywords & MASK_MD5)
		archive_md5_update(&sum->md5ctx, buff, n);
#endif
#ifdef ARCHIVE_HAS_RMD160
	if (keywords & MASK_RMD160)
		archive_rmd160_update(&sum->rmd160ctx, buff, n);
#endif
#ifdef ARCHIVE_HAS_SHA1
	if (keywords & MASK_SHA1)
		archive_sha1_update(&sum->sha1ctx, buff, n);
#endif
#ifdef ARCHIVE_HAS_SHA256
	if (keywords & MASK_SHA256)
		archive_sha256_update(&sum->sha256ctx, buff, n);
#endif
#ifdef ARCHIVE_HAS_SHA384
	if (keywords & MASK_SHA384)
		archive_sha384_update(&sum->sha384ctx, buff, n);
#endif
#ifdef ARCHIVE_HAS_SHA512
	if (keywords & MASK_SHA512)
		archive_sha512_update(&sum->sha512ctx, buff, n);
#endif
}

#ifdef HAS_DIGEST
static void
sum_str(struct archive_string *str, const unsigned char *bin, int n)
{
	static const char hex[] = "0123456789abcdef";
	int i;

	archive_string_empty(str);
	for (i = 0; i < n; i++) {
		archive_strappend_char(str, hex[bin[i] >> 4]);
		archive_strappend_char(str, hex[bin[i] & 0x0f]);
	}
}
#endif

static void
sum_write(struct mtree_sum *sum, uint64_t keywords, struct mtree_entry *entry)
{
#ifdef HAS_DIGEST
	struct archive_string str;
#endif
	if (keywords & MTREE_KEYWORD_CKSUM)
		mtree_entry_set_cksum(entry, mtree_cksum_get_result(sum->cksum));

#ifdef HAS_DIGEST
	archive_string_init(&str);
#ifdef ARCHIVE_HAS_MD5
	if (keywords & MASK_MD5) {
		archive_md5_final(&sum->md5ctx, sum->md5buf);
		sum_str(&str, sum->md5buf, sizeof(sum->md5buf));
		mtree_entry_set_md5digest(entry,
		    str.s,
		    keywords & MASK_MD5);
	}
#endif
#ifdef ARCHIVE_HAS_RMD160
	if (keywords & MASK_RMD160) {
		archive_rmd160_final(&sum->rmd160ctx, sum->rmd160buf);
		sum_str(&str, sum->rmd160buf, sizeof(sum->rmd160buf));
		mtree_entry_set_rmd160digest(entry,
		    str.s,
		    keywords & MASK_RMD160);
	}
#endif
#ifdef ARCHIVE_HAS_SHA1
	if (keywords & MASK_SHA1) {
		archive_sha1_final(&sum->sha1ctx, sum->sha1buf);
		sum_str(&str, sum->sha1buf, sizeof(sum->sha1buf));
		mtree_entry_set_sha1digest(entry,
		    str.s,
		    keywords & MASK_SHA1);
	}
#endif
#ifdef ARCHIVE_HAS_SHA256
	if (keywords & MASK_SHA256) {
		archive_sha256_final(&sum->sha256ctx, sum->sha256buf);
		sum_str(&str, sum->sha256buf, sizeof(sum->sha256buf));
		mtree_entry_set_sha256digest(entry,
		    str.s,
		    keywords & MASK_SHA256);
	}
#endif
#ifdef ARCHIVE_HAS_SHA384
	if (keywords & MASK_SHA384) {
		archive_sha384_final(&sum->sha384ctx, sum->sha384buf);
		sum_str(&str, sum->sha384buf, sizeof(sum->sha384buf));
		mtree_entry_set_sha384digest(entry,
		    str.s,
		    keywords & MASK_SHA384);
	}
#endif
#ifdef ARCHIVE_HAS_SHA512
	if (keywords & MASK_SHA512) {
		archive_sha512_final(&sum->sha512ctx, sum->sha512buf);
		sum_str(&str, sum->sha512buf, sizeof(sum->sha512buf));
		mtree_entry_set_sha512digest(entry,
		    str.s,
		    keywords & MASK_SHA512);
	}
#endif
	archive_string_free(&str);
#endif /* MASK_DIGEST */
}

static int
archive_write_mtree_free(struct archive_write *a)
{
	struct mtree_write *mtree = a->format_data;

	if (mtree == NULL)
		return (ARCHIVE_OK);

	/* Make sure we dot not leave any entries. */
	if (mtree->entries != NULL)
		mtree_entry_free_all(mtree->entries);
	if (mtree->sum.cksum != NULL)
		mtree_cksum_free(mtree->sum.cksum);

	mtree_spec_free(mtree->spec);
	free(mtree);

	a->format_data = NULL;
	return (ARCHIVE_OK);
}

static void
set_write_options(struct mtree_write *mtree, int options, int set)
{
	int current;

	current = mtree_spec_get_write_options(mtree->spec);
	if (set)
		current |= options;
	else
		current &= ~options;

	mtree_spec_set_write_options(mtree->spec, current);
}

static int
archive_write_mtree_options(struct archive_write *a, const char *key,
    const char *value)
{
	struct mtree_write *mtree = a->format_data;
	uint64_t keywords;

	if (strcmp(key, "dironly") == 0) {
		mtree->dironly = (value != NULL) ? 1 : 0;
		return (ARCHIVE_OK);
	}
	if (strcmp(key, "indent") == 0) {
		set_write_options(mtree, MTREE_WRITE_INDENT, value != NULL);
		return (ARCHIVE_OK);
	}
	if (strcmp(key, "use-set") == 0) {
		set_write_options(mtree, MTREE_WRITE_USE_SET, value != NULL);
		return (ARCHIVE_OK);
	}

	keywords = 0;
	if (strcmp(key, "all") == 0) {
		/*
		 * Only include one keyword for each digest.
		 *
		 * Users may still include the aliases by specifying the
		 * keywords by name.
		 */
		keywords = ALL_KEYWORDS;
	} else {
		keywords = mtree_keyword_parse(key);
		if ((keywords & PARSE_KEYWORDS) == 0)
			keywords = 0;
	}
	if (keywords != 0) {
		if (value != NULL)
			mtree->keywords |= keywords;
		else
			mtree->keywords &= ~keywords;
		return (ARCHIVE_OK);
	}

	/* Note: The "warn" return is just to inform the options
	 * supervisor that we didn't handle it.  It will generate
	 * a suitable error if no one used this option. */
	return (ARCHIVE_WARN);
}

static int
create_entry(struct archive_write *a, struct archive_entry *entry,
    struct mtree_entry **m_entry)
{
	struct mtree_write *mtree = a->format_data;
	struct mtree_entry *me;
	const struct stat *st;
	const char *s;

	me = mtree_entry_create(archive_entry_pathname(entry));
	if (me == NULL) {
		archive_set_error(&a->archive, errno,
		    "Can't allocate memory for mtree entry");
		*m_entry = NULL;
		return (ARCHIVE_FATAL);
	}
	st = archive_entry_stat(entry);
	if (st == NULL) {
		archive_set_error(&a->archive, ENOMEM,
		    "Can't allocate memory for stat");
		mtree_entry_free(me);
		*m_entry = NULL;
		return (ARCHIVE_FATAL);
	}

	/*
	 * Set keywords from stat.
	 *
	 * While libmtree includes flags in the stat mask, we don't set
	 * in the stat structure.
	 */
	mtree_entry_set_keywords_stat(me, st,
	    mtree->keywords & MTREE_KEYWORD_MASK_STAT & ~MTREE_KEYWORD_FLAGS, 0);

	/*
	 * Set remaining keywords.
	 *
	 * This should include everything not set from the stat or by
	 * the summing functions.
	 */
	if (mtree->keywords & MTREE_KEYWORD_UNAME) {
		if ((s = archive_entry_uname(entry)) != NULL)
			mtree_entry_set_uname(me, s);
	}
	if (mtree->keywords & MTREE_KEYWORD_GNAME) {
		if ((s = archive_entry_gname(entry)) != NULL)
			mtree_entry_set_gname(me, s);
	}
	if (mtree->keywords & MTREE_KEYWORD_FLAGS) {
		if ((s = archive_entry_fflags_text(entry)) != NULL)
			mtree_entry_set_flags(me, s);
	}
	if (mtree->keywords & MTREE_KEYWORD_LINK) {
		if ((s = archive_entry_symlink(entry)) != NULL)
			mtree_entry_set_link(me, s);
	}
	*m_entry = me;
	return (ARCHIVE_OK);
}

static int
archive_write_mtree_header(struct archive_write *a, struct archive_entry *entry)
{
	struct mtree_write *mtree = a->format_data;
	struct mtree_entry *me;
	int r;

	mtree->entry_bytes_remaining = archive_entry_size(entry);

	/* While directory only mode, we do not handle non directory files. */
	if (mtree->dironly && archive_entry_filetype(entry) != AE_IFDIR)
		return (ARCHIVE_OK);

	r = create_entry(a, entry, &me);
	if (r < ARCHIVE_WARN)
		return (r);

	mtree->entries = mtree_entry_prepend(mtree->entries, me);
	mtree->current = me;
	/*
	 * If the current file is a regular file, we have to compute the sum of
	 * its content. Initialize a bunch of sum check context.
	 */
	if (archive_entry_filetype(entry) == AE_IFREG &&
	    mtree->keywords & SUM_KEYWORDS) {
		sum_init(&mtree->sum, &mtree->keywords);
		if (mtree->keywords & SUM_KEYWORDS)
			mtree->summing = 1;
	}
	return (r);
}

static int
write_data(const char *data, size_t len, void *_a)
{
	struct archive_write *a = _a;
	int r;

	/*
	 * Write the output given by libmtree's writer.
	 *
	 * On success, return 0 to indicate that this function can be called
	 * again to write the next part of output.
	 *
	 * On error, libmtree expects either an errno (positive number), or
	 * -1 as a universal error indicator.
	 */
	r = __archive_write_output(a, data, len);
	if (r == ARCHIVE_OK)
		r = 0;
	else {
		r = archive_errno(&a->archive);
		if (r <= 0)
			r = -1;
	}
	return (r);
}

static int
archive_write_mtree_close(struct archive_write *a)
{
	struct mtree_write *mtree = a->format_data;
	struct mtree_entry *merged;
	struct mtree_entry *mismerged;
	int r;

	archive_write_set_bytes_in_last_block(&a->archive, 1);
	r = __archive_write_output(a, MTREE_SIGNATURE, strlen(MTREE_SIGNATURE));
	if (r != ARCHIVE_OK)
		return (r);
	if (mtree->entries != NULL) {
		/*
		 * Everything has been read, merge the entries to remove any
		 * duplicates, sort and write them.
		 *
		 * The entries are reversed first, because the list was created
		 * in reverse order and we want to make sure that merging
		 * gives precedence to the later entries as it should.
		 */
		mtree->entries = mtree_entry_reverse(mtree->entries);
		mismerged = NULL;
		merged = mtree_entry_merge(mtree->entries, NULL, 0, &mismerged);
		if (merged != NULL) {
			mtree_spec_set_entries(mtree->spec,
			    mtree_entry_sort_path(merged));
			r = mtree_spec_write_writer(mtree->spec, write_data, a);
			if (r == 0)
				r = ARCHIVE_OK;
			else {
				archive_set_error(&a->archive, errno,
				    "Failed to write the specfile");
				r = ARCHIVE_FATAL;
			}
		} else {
			if (mismerged != NULL)
				archive_set_error(&a->archive, errno,
				    "Found duplicate entries `%s' with different "
				    "types (%s and %s)",
				    mtree_entry_get_path(mismerged),
				    mtree_entry_type_string(
				        mtree_entry_get_type(mismerged)),
				    mtree_entry_type_string(
				        mtree_entry_get_type(
				            mtree_entry_get_next(mismerged))));
			else
				archive_set_error(&a->archive, errno,
				    "Found duplicate entries with different types");
			r = ARCHIVE_FATAL;
			mtree_entry_free_all(mtree->entries);
		}
		mtree->entries = NULL;
	}
	return (r);
}

static ssize_t
archive_write_mtree_data(struct archive_write *a, const void *buff, size_t n)
{
	struct mtree_write *mtree = a->format_data;

	if (n > mtree->entry_bytes_remaining)
		n = (size_t)mtree->entry_bytes_remaining;
	mtree->entry_bytes_remaining -= n;

	/*
	 * Compute file's sum if the current entry is a regular file.
	 */
	if (mtree->summing)
		sum_update(&mtree->sum, mtree->keywords, buff, n);

	return (n);
}

static int
archive_write_mtree_finish_entry(struct archive_write *a)
{
	struct mtree_write *mtree = a->format_data;

	if (mtree->summing) {
		sum_write(&mtree->sum, mtree->keywords, mtree->current);
		mtree->summing = 0;
	}
	return (ARCHIVE_OK);
}

static int
archive_write_set_format_mtree_default(struct archive *_a, const char *fn)
{
	struct archive_write *a = (struct archive_write *)_a;
	struct mtree_write *mtree;

	archive_check_magic(_a, ARCHIVE_WRITE_MAGIC, ARCHIVE_STATE_NEW, fn);

	if (a->format_free != NULL)
		(a->format_free)(a);

	if ((mtree = calloc(1, sizeof(struct mtree_write))) == NULL) {
		archive_set_error(&a->archive, errno,
		    "Can't allocate mtree data");
		return (ARCHIVE_FATAL);
	}
	mtree->spec = mtree_spec_create();
	if (mtree->spec == NULL) {
		archive_set_error(&a->archive, errno,
		    "Can't allocate mtree spec data");
		free(mtree);
		return (ARCHIVE_FATAL);
	}
	mtree->keywords = DEFAULT_KEYWORDS;

	a->format_data = mtree;
	a->format_free = archive_write_mtree_free;
	a->format_name = "mtree";
	a->format_options = archive_write_mtree_options;
	a->format_write_header = archive_write_mtree_header;
	a->format_close = archive_write_mtree_close;
	a->format_write_data = archive_write_mtree_data;
	a->format_finish_entry = archive_write_mtree_finish_entry;
	a->archive.archive_format = ARCHIVE_FORMAT_MTREE;
	a->archive.archive_format_name = "mtree";

	return (ARCHIVE_OK);
}

int
archive_write_set_format_mtree_classic(struct archive *_a)
{
	int r;

	r = archive_write_set_format_mtree_default(_a,
		"archive_write_set_format_mtree_classic");
	if (r == ARCHIVE_OK) {
		struct archive_write *a = (struct archive_write *)_a;
		struct mtree_write *mtree;

		mtree = (struct mtree_write *)a->format_data;
		/*
		 * Set to output a mtree archive in classic format.
		 */
		mtree_spec_set_write_format(mtree->spec, MTREE_FORMAT_1_0);
		set_write_options(mtree, MTREE_WRITE_USE_SET, 1);
	}
	return (r);
}

int
archive_write_set_format_mtree(struct archive *_a)
{
	int r;

	r = archive_write_set_format_mtree_default(_a,
		"archive_write_set_format_mtree");
	if (r == ARCHIVE_OK) {
		struct archive_write *a = (struct archive_write *)_a;
		struct mtree_write *mtree;

		mtree = (struct mtree_write *)a->format_data;
		/*
		 * Set to output a mtree archive in mtree -C format.
		 */
		mtree_spec_set_write_format(mtree->spec, MTREE_FORMAT_2_0);
		set_write_options(mtree, MTREE_WRITE_USE_SET, 0);
	}
	return (r);
}
#else /* HAVE_MTREE_H */
int
archive_write_set_format_mtree_classic(struct archive *_a)
{
	struct archive_write *a = (struct archive_write *)_a;

	archive_set_error(&a->archive, ARCHIVE_ERRNO_MISC,
	    "MTree not supported on this platform");
	return (ARCHIVE_WARN);
}

int
archive_write_set_format_mtree(struct archive *_a)
{
	struct archive_write *a = (struct archive_write *)_a;

	archive_set_error(&a->archive, ARCHIVE_ERRNO_MISC,
	    "MTree not supported on this platform");
	return (ARCHIVE_WARN);
}
#endif /* HAVE_MTREE_H */
