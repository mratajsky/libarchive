/*-
 * Copyright (c) 2003-2007 Tim Kientzle
 * Copyright (c) 2008 Joerg Sonnenberger
 * Copyright (c) 2011-2012 Michihiro NAKAJIMA
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
__FBSDID("$FreeBSD: head/lib/libarchive/archive_read_support_format_mtree.c 201165 2009-12-29 05:52:13Z kientzle $");

#ifdef HAVE_SYS_TYPES_H
#include <sys/types.h>
#endif
#ifdef HAVE_SYS_STAT_H
#include <sys/stat.h>
#endif
#ifdef HAVE_ERRNO_H
#include <errno.h>
#endif
#ifdef HAVE_FCNTL_H
#include <fcntl.h>
#endif
#ifdef HAVE_MTREE_H
#include <mtree.h>
#endif
#include <stddef.h>
#ifdef HAVE_STDLIB_H
#include <stdlib.h>
#endif
#ifdef HAVE_STRING_H
#include <string.h>
#endif

#include "archive.h"
#include "archive_entry.h"
#include "archive_private.h"
#include "archive_read_private.h"

#ifdef HAVE_MTREE_H
/*
 * Size of the buffer used in data reader.
 */
#define READ_DATA_BUFFSIZE	16384L
/*
 * Signature that writer writes at the start of every mtree file.
 */
#define MTREE_SIGNATURE		"#mtree"

#ifndef O_BINARY
#define O_BINARY		0
#endif
#ifndef O_CLOEXEC
#define O_CLOEXEC		0
#endif
#define MAX_BID_ENTRY		3

struct mtree_read {
	size_t			 parsed;
	char			*buff;
	size_t			 size;
	int64_t			 offset;
	int			 first;
	int			 bidden;
	int			 fd;
	int			 checkfs;
	struct mtree_spec	*spec;
	struct mtree_entry	*entry;
	struct archive_entry_linkresolver *resolver;
};

static int
read_filter(struct mtree_entry *entry, void *_a)
{
	struct archive_read *a = _a;
	struct mtree_read *mtree;

	(void)entry; /* UNUSED */

	mtree = (struct mtree_read *)a->format->data;
	mtree->bidden++;
	if (mtree->bidden >= MAX_BID_ENTRY) {
		/*
		 * Unset the filter once we have enough entries.
		 */
		mtree_spec_set_read_spec_filter(mtree->spec, NULL, NULL);
	}
	return (MTREE_FILTER_KEEP);
}

static int
mtree_bid(struct archive_read *a, int best_bid)
{
	struct mtree_read *mtree;
	const char *p;
	ssize_t avail;

	(void)best_bid; /* UNUSED */

	/*
	 * First try to verify the signature.
	 */
	p = __archive_read_ahead(a, strlen(MTREE_SIGNATURE), &avail);
	if (p == NULL)
		return (-1);
	if (strncmp(p, MTREE_SIGNATURE, strlen(MTREE_SIGNATURE)) == 0)
		return (8 * (int)strlen(MTREE_SIGNATURE));
	/*
	 * The signature is not mandatory, so let's feed the libmtree parser
	 * the input until it either finds a valid entry or returns an error.
	 *
	 * A filter is used to find out that an entry has been found as early
	 * as possible.
	 */
	mtree = (struct mtree_read *)a->format->data;
	mtree->parsed = 0;
	mtree->bidden = 0;
	mtree_spec_set_read_spec_filter(mtree->spec, read_filter, a);
	for (;;) {
		avail -= mtree->parsed;
		if (mtree_spec_read_spec_data(
		    mtree->spec, p + mtree->parsed, avail) != 0) {
			/* Error from the parser, surely invalid input. */
			return (0);
		}
		mtree->parsed += avail;
		if (mtree->bidden >= MAX_BID_ENTRY)
			break;
		p = __archive_read_ahead(a, mtree->parsed + 1, &avail);
		if (p == NULL)
			break;
	}
	return (mtree->bidden ? 32 : 0);
}

static int
mtree_options(struct archive_read *a, const char *key, const char *val)
{
	struct mtree_read *mtree;

	mtree = (struct mtree_read *)a->format->data;
	if (strcmp(key, "checkfs")  == 0) {
		/*
		 * Allows to read information missing in the mtree spec from
		 * the file system.
		 */
		if (val == NULL || val[0] == 0)
			mtree->checkfs = 0;
		else
			mtree->checkfs = 1;
		return (ARCHIVE_OK);
	}

	/* Note: The "warn" return is just to inform the options
	 * supervisor that we didn't handle it.  It will generate
	 * a suitable error if no one used this option. */
	return (ARCHIVE_WARN);
}

static unsigned int
filetype_from_mode(mode_t mode)
{
	switch (mode & S_IFMT) {
	case S_IFBLK:
		return (AE_IFBLK);
	case S_IFCHR:
		return (AE_IFCHR);
	case S_IFDIR:
		return (AE_IFDIR);
	case S_IFIFO:
		return (AE_IFIFO);
	case S_IFLNK:
		return (AE_IFLNK);
	case S_IFREG:
		return (AE_IFREG);
	case S_IFSOCK:
		return (AE_IFSOCK);
	default:
		return (0);
	}
}

static unsigned int
filetype_from_mtree_entry_type(mtree_entry_type type)
{
	switch (type) {
	case MTREE_ENTRY_BLOCK:
		return (AE_IFBLK);
	case MTREE_ENTRY_CHAR:
		return (AE_IFCHR);
	case MTREE_ENTRY_DIR:
		return (AE_IFDIR);
	case MTREE_ENTRY_FIFO:
		return (AE_IFIFO);
	case MTREE_ENTRY_FILE:
		return (AE_IFREG);
	case MTREE_ENTRY_LINK:
		return (AE_IFLNK);
	case MTREE_ENTRY_SOCKET:
		return (AE_IFSOCK);
	default:
		return (0);
	}
}

static int
process_entry(struct archive_read *a, struct archive_entry *entry,
    struct mtree_entry *me, int *use_next)
{
	struct archive_entry *sparse_entry;
	struct mtree_device *device;
	struct mtree_read *mtree;
	struct mtree_timespec *ts;
	uint64_t keywords;
	int fields;
	int r = ARCHIVE_OK;

	mtree = (struct mtree_read *)a->format->data;

	/* Initialize reasonable defaults. */
	archive_entry_set_filetype(entry, AE_IFREG);
	archive_entry_set_size(entry, 0);

	archive_entry_copy_pathname(entry, mtree_entry_get_path(me));

	keywords = mtree_entry_get_keywords(me);
	/*
	 * For device and resdevice set full device number if it's available,
	 * otherwise set the major and minor fields.
	 *
	 * We don't support the unit and subunit fields.
	 */
	if (keywords & MTREE_KEYWORD_DEVICE) {
		device = mtree_entry_get_device(me);
		fields = mtree_device_get_fields(device);
		if (fields & MTREE_DEVICE_FIELD_NUMBER)
			archive_entry_set_rdev(entry,
			    mtree_device_get_value(device,
			        MTREE_DEVICE_FIELD_NUMBER));
		else {
			if (fields & MTREE_DEVICE_FIELD_MAJOR)
				archive_entry_set_rdevmajor(entry,
				    mtree_device_get_value(device,
				        MTREE_DEVICE_FIELD_MAJOR));
			if (fields & MTREE_DEVICE_FIELD_MINOR)
				archive_entry_set_rdevminor(entry,
				    mtree_device_get_value(device,
				        MTREE_DEVICE_FIELD_MINOR));
		}
	}
	if (keywords & MTREE_KEYWORD_RESDEVICE) {
		device = mtree_entry_get_resdevice(me);
		fields = mtree_device_get_fields(device);
		if (fields & MTREE_DEVICE_FIELD_NUMBER)
			archive_entry_set_dev(entry,
			    mtree_device_get_value(device,
			        MTREE_DEVICE_FIELD_NUMBER));
		else {
			if (fields & MTREE_DEVICE_FIELD_MAJOR)
				archive_entry_set_devmajor(entry,
				    mtree_device_get_value(device,
				        MTREE_DEVICE_FIELD_MAJOR));
			if (fields & MTREE_DEVICE_FIELD_MINOR)
				archive_entry_set_devminor(entry,
				    mtree_device_get_value(device,
				        MTREE_DEVICE_FIELD_MINOR));
		}
	}

	if (keywords & MTREE_KEYWORD_FLAGS)
		archive_entry_copy_fflags_text(entry, mtree_entry_get_flags(me));
	if (keywords & MTREE_KEYWORD_GID)
		archive_entry_set_gid(entry, mtree_entry_get_gid(me));
	if (keywords & MTREE_KEYWORD_GNAME)
		archive_entry_copy_gname(entry, mtree_entry_get_gname(me));
	if (keywords & MTREE_KEYWORD_INODE)
		archive_entry_set_ino(entry, mtree_entry_get_inode(me));
	if (keywords & MTREE_KEYWORD_LINK)
		archive_entry_copy_symlink(entry, mtree_entry_get_link(me));
	if (keywords & MTREE_KEYWORD_MODE)
		archive_entry_set_perm(entry, mtree_entry_get_mode(me));
	if (keywords & MTREE_KEYWORD_NLINK)
		archive_entry_set_nlink(entry, mtree_entry_get_nlink(me));
	if (keywords & MTREE_KEYWORD_SIZE)
		archive_entry_set_size(entry, mtree_entry_get_size(me));
	if (keywords & MTREE_KEYWORD_TIME) {
		ts = mtree_entry_get_time(me);

		archive_entry_set_mtime(entry, ts->tv_sec, ts->tv_nsec);
	}
	if (keywords & MTREE_KEYWORD_TYPE) {
		unsigned int filetype;

		filetype = filetype_from_mtree_entry_type(
		    mtree_entry_get_type(me));
		if (filetype != 0)
			archive_entry_set_filetype(entry, filetype);
		else {
			archive_set_error(&a->archive,
			    ARCHIVE_ERRNO_FILE_FORMAT,
			    "Unrecognized file type of `%s'; assuming file",
			    archive_entry_pathname(entry));
			r = ARCHIVE_WARN;
		}
	}
	if (keywords & MTREE_KEYWORD_UID)
		archive_entry_set_uid(entry, mtree_entry_get_uid(me));
	if (keywords & MTREE_KEYWORD_UNAME)
		archive_entry_copy_uname(entry, mtree_entry_get_uname(me));

	if (mtree->checkfs) {
		struct stat st_storage, *st;
		const char *path;

		if (keywords & MTREE_KEYWORD_CONTENTS)
			path = mtree_entry_get_contents(me);
		else
			path = mtree_entry_get_path(me);
		/*
		 * Try to open and stat the file to get the real size and other
		 * file info. It would be nice to avoid this here so that getting
		 * a listing of an mtree wouldn't require opening every referenced
		 * contents file. But then we wouldn't know the actual contents size,
		 * so I don't see a really viable way around this.
		 * (Also, we may want to someday pull other unspecified info from
		 * the contents file on disk.)
		 */
		mtree->fd = -1;
		if (archive_entry_filetype(entry) == AE_IFREG ||
		    archive_entry_filetype(entry) == AE_IFDIR) {
			mtree->fd = open(path, O_RDONLY | O_BINARY | O_CLOEXEC);
			__archive_ensure_cloexec_flag(mtree->fd);
			if (mtree->fd == -1 &&
			    (errno != ENOENT ||
			     (keywords & MTREE_KEYWORD_CONTENTS) != 0)) {
				archive_set_error(&a->archive, errno,
				    "Can't open `%s'", path);
				r = ARCHIVE_WARN;
			}
		}

		st = &st_storage;
		if (mtree->fd >= 0) {
			if (fstat(mtree->fd, st) == -1) {
				archive_set_error(&a->archive, errno,
				    "Can't fstat `%s'", path);
				r = ARCHIVE_WARN;
				/* If we can't stat it, don't keep it open. */
				close(mtree->fd);
				mtree->fd = -1;
				st = NULL;
			}
		} else if (lstat(path, st) == -1)
			st = NULL;

		/*
		 * Check for a mismatch between the type in the specification and
		 * the type of the contents object on disk.
		 */
		if (st != NULL) {
			unsigned int filetype = filetype_from_mode(st->st_mode);

			if (archive_entry_filetype(entry) != filetype) {
				/* Types don't match; bail out gracefully. */
				if (mtree->fd >= 0) {
					close(mtree->fd);
					mtree->fd = -1;
				}
				if (keywords & MTREE_KEYWORD_OPTIONAL) {
					/*
					 * It's not an error for an optional entry
					 * not to match disk.
					 */
					*use_next = 1;
				} else if (r == ARCHIVE_OK) {
					archive_set_error(&a->archive,
					    ARCHIVE_ERRNO_MISC,
					    "Specification has different type of `%s'",
					    archive_entry_pathname(entry));
					r = ARCHIVE_WARN;
				}
				return (r);
			}

			/*
			 * If there is a contents file on disk, pick some of the
			 * metadata from that file. For most of these, we only set
			 * it from the contents if it wasn't already parsed from
			 * the specification.
			 */
			if (((keywords & MTREE_KEYWORD_DEVICE) == 0 ||
			     (keywords & MTREE_KEYWORD_NOCHANGE) != 0) &&
			    (archive_entry_filetype(entry) == AE_IFCHR ||
			     archive_entry_filetype(entry) == AE_IFBLK))
				archive_entry_set_rdev(entry, st->st_rdev);

			if ((keywords & MTREE_KEYWORD_MASK_GROUP) == 0 ||
			    (keywords & MTREE_KEYWORD_NOCHANGE) != 0)
				archive_entry_set_gid(entry, st->st_gid);
			if ((keywords & MTREE_KEYWORD_MASK_USER) == 0 ||
			    (keywords & MTREE_KEYWORD_NOCHANGE) != 0)
				archive_entry_set_uid(entry, st->st_uid);

			if ((keywords & MTREE_KEYWORD_TIME) == 0 ||
			    (keywords & MTREE_KEYWORD_NOCHANGE) != 0) {
#if HAVE_STRUCT_STAT_ST_MTIMESPEC_TV_NSEC
				archive_entry_set_mtime(entry, st->st_mtime,
				    st->st_mtimespec.tv_nsec);
#elif HAVE_STRUCT_STAT_ST_MTIM_TV_NSEC
				archive_entry_set_mtime(entry, st->st_mtime,
				    st->st_mtim.tv_nsec);
#elif HAVE_STRUCT_STAT_ST_MTIME_N
				archive_entry_set_mtime(entry, st->st_mtime,
				    st->st_mtime_n);
#elif HAVE_STRUCT_STAT_ST_UMTIME
				archive_entry_set_mtime(entry, st->st_mtime,
				    st->st_umtime * 1000);
#elif HAVE_STRUCT_STAT_ST_MTIME_USEC
				archive_entry_set_mtime(entry, st->st_mtime,
				    st->st_mtime_usec * 1000);
#else
				archive_entry_set_mtime(entry, st->st_mtime, 0);
#endif
			}
			if ((keywords & MTREE_KEYWORD_NLINK) == 0 ||
			    (keywords & MTREE_KEYWORD_NOCHANGE) != 0)
				archive_entry_set_nlink(entry, st->st_nlink);
			if ((keywords & MTREE_KEYWORD_MODE) == 0 ||
			    (keywords & MTREE_KEYWORD_NOCHANGE) != 0)
				archive_entry_set_perm(entry, st->st_mode);
			if ((keywords & MTREE_KEYWORD_SIZE) == 0 ||
			    (keywords & MTREE_KEYWORD_NOCHANGE) != 0)
				archive_entry_set_size(entry, st->st_size);

			archive_entry_set_ino(entry, st->st_ino);
			archive_entry_set_dev(entry, st->st_dev);

			archive_entry_linkify(mtree->resolver, &entry, &sparse_entry);
		} else if (keywords & MTREE_KEYWORD_OPTIONAL) {
			/*
			 * Couldn't open the entry, stat it or the on-disk type
			 * didn't match. If this entry is optional, just ignore it
			 * and read the next header entry.
			 */
			*use_next = 1;
			return (ARCHIVE_OK);
		}
	}

	mtree->size = archive_entry_size(entry);
	mtree->offset = 0;
	return (r);
}

/*
 * Read in the entire mtree file into memory on the first request.
 * Then use the next unused file to satisfy each header request.
 */
static int
mtree_read_header(struct archive_read *a, struct archive_entry *entry)
{
	struct mtree_read *mtree;
	const char *p;
	ssize_t bytes_read;
	int r, use_next;

	mtree = (struct mtree_read *)a->format->data;

	if (mtree->fd >= 0) {
		close(mtree->fd);
		mtree->fd = -1;
	}
	if (mtree->first == 0) {
		mtree->first = 1;
		mtree->resolver = archive_entry_linkresolver_new();
		if (mtree->resolver == NULL)
			return (ARCHIVE_FATAL);
		archive_entry_linkresolver_set_strategy(mtree->resolver,
		    ARCHIVE_FORMAT_MTREE);
		/*
		 * Consume what has already been processed while bidding.
		 */
		if (mtree->parsed > 0)
			__archive_read_consume(a, mtree->parsed);
		for (;;) {
			/*
			 * Read the archive and pass the data to the libmtree
			 * parser until there is nothing left.
			 */
			p = __archive_read_ahead(a, 1, &bytes_read);
			if (p == NULL)
				break;
			if (bytes_read < 0)
				return (ARCHIVE_FATAL);
			if (mtree_spec_read_spec_data(
			    mtree->spec, p, bytes_read) != 0) {
				archive_set_error(&a->archive, errno,
				    "%s",
				    mtree_spec_get_read_spec_error(mtree->spec));
				return (ARCHIVE_FATAL);
			}
			__archive_read_consume(a, bytes_read);
		}
		if (mtree_spec_read_spec_data_finish(mtree->spec) != 0) {
			archive_set_error(&a->archive, errno,
			    "%s",
			    mtree_spec_get_read_spec_error(mtree->spec));
			return (ARCHIVE_FATAL);
		}
		mtree->entry = mtree_spec_get_entries(mtree->spec);
	}

	a->archive.archive_format = ARCHIVE_FORMAT_MTREE;
	a->archive.archive_format_name = "mtree";

	for (;;) {
		if (mtree->entry == NULL) {
			r = ARCHIVE_EOF;
			break;
		}
		use_next = 0;
		r = process_entry(a, entry, mtree->entry, &use_next);
		mtree->entry = mtree_entry_get_next(mtree->entry);
		/*
		 * Keep going if the current entry is ignored.
		 */
		if (use_next == 0)
			break;
		archive_entry_clear(entry);
	}
	return (r);
}

static int
mtree_read_data(struct archive_read *a, const void **buff, size_t *size,
    int64_t *offset)
{
	struct mtree_read *mtree;
	size_t bytes_to_read;
	ssize_t n;
	int r = ARCHIVE_OK;

	mtree = (struct mtree_read *)a->format->data;

	if (mtree->fd < 0)
		r = ARCHIVE_EOF;
	else if (mtree->buff == NULL) {
		mtree->buff = malloc(READ_DATA_BUFFSIZE);
		if (mtree->buff == NULL) {
			archive_set_error(&a->archive, errno,
			    "Can't allocate memory for read buffer");
			r = ARCHIVE_FATAL;
		}
	}
	if (r != ARCHIVE_OK) {
		*buff = NULL;
		*size = 0;
		*offset = 0;
		return (r);
	}

	/*
	 * Read at most READ_DATA_BUFFSIZE from the referenced file
	 * and place it into the supplied buffer.
	 */
	if (READ_DATA_BUFFSIZE > mtree->size - mtree->offset)
		bytes_to_read = (size_t)(mtree->size - mtree->offset);
	else
		bytes_to_read = READ_DATA_BUFFSIZE;

	*buff = mtree->buff;
	*offset = mtree->offset;
	for (;;) {
		n = read(mtree->fd, mtree->buff, bytes_to_read);
		if (n > 0) {
			*size = n;
			mtree->offset += n;
			r = ARCHIVE_OK;
		} else {
			if (n < 0) {
#ifdef EINTR
				if (errno == EINTR)
					continue;
#endif
				archive_set_error(&a->archive, errno, "Can't read");
				r = ARCHIVE_WARN;
			} else /* n == 0 */
				r = ARCHIVE_EOF;
			*size = 0;
		}
		break;
	}
	return (r);
}

/*
 * Skip does nothing except possibly close the contents file.
 */
static int
mtree_read_data_skip(struct archive_read *a)
{
	struct mtree_read *mtree;

	mtree = (struct mtree_read *)a->format->data;

	if (mtree->fd >= 0) {
		close(mtree->fd);
		mtree->fd = -1;
	}
	return (ARCHIVE_OK);
}

static int
mtree_cleanup(struct archive_read *a)
{
	struct mtree_read *mtree;

	mtree = (struct mtree_read *)a->format->data;

	if (mtree->fd >= 0)
		close(mtree->fd);

	archive_entry_linkresolver_free(mtree->resolver);
	mtree_spec_free(mtree->spec);
	free(mtree->buff);
	free(mtree);

	a->format->data = NULL;
	return (ARCHIVE_OK);
}

int
archive_read_support_format_mtree(struct archive *_a)
{
	struct archive_read *a = (struct archive_read *)_a;
	struct mtree_read *mtree;
	int r;

	archive_check_magic(_a, ARCHIVE_READ_MAGIC,
	    ARCHIVE_STATE_NEW, "archive_read_support_format_mtree");

	mtree = (struct mtree_read *)calloc(1, sizeof(*mtree));
	if (mtree == NULL) {
		archive_set_error(&a->archive, errno,
		    "Can't allocate mtree data");
		return (ARCHIVE_FATAL);
	}
	mtree->spec = mtree_spec_create();
	if (mtree->spec == NULL) {
		archive_set_error(&a->archive, errno,
		    "Can't allocate mtree spec data");
		return (ARCHIVE_FATAL);
	}
	mtree_spec_set_read_spec_options(mtree->spec,
	    MTREE_READ_SORT |
	    MTREE_READ_MERGE_DIFFERENT_TYPES);
	mtree->fd = -1;

	r = __archive_read_register_format(a,
	    mtree,
	    "mtree",
	    mtree_bid,
	    mtree_options,
	    mtree_read_header,
	    mtree_read_data,
	    mtree_read_data_skip,
	    NULL,
	    mtree_cleanup,
	    NULL,
	    NULL);

	if (r != ARCHIVE_OK)
		free(mtree);

	return (r);
}
#else /* HAVE_MTREE_H */
int
archive_read_support_format_mtree(struct archive *_a)
{
	struct archive_read *a = (struct archive_read *)_a;

	archive_check_magic(_a, ARCHIVE_READ_MAGIC,
	    ARCHIVE_STATE_NEW, "archive_read_support_format_mtree");

	archive_set_error(&a->archive, ARCHIVE_ERRNO_MISC,
	    "MTree not supported on this platform");
	return (ARCHIVE_WARN);
}
#endif /* HAVE_MTREE_H */
