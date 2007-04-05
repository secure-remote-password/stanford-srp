/*
 * Copyright (C) 1993 Rick Sladkey <jrs@world.std.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU Library Public License as published by
 * the Free Software Foundation; either version 2, or (at your option)
 * any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Library Public License for more details.
 */

/* ftppath.c based on libc realpath.c without link processing
 * and with final CWD suppression
 * SB 01/16/02
 */
 
#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#ifdef USE_GLOB		/* Only need this if USE_GLOB defined in glob.c */

#include <sys/types.h>
#if defined(HAVE_UNISTD_H) || defined(STDC_HEADERS)
#include <unistd.h>
#endif
#include <stdio.h>
#ifdef HAVE_STRING_H
#include <string.h>
#else
#include <strings.h>
#endif
#ifdef _POSIX_VERSION
#include <limits.h>			/* for PATH_MAX */
#else
#include <sys/param.h>			/* for MAXPATHLEN */
#endif
#include <errno.h>
#ifndef STDC_HEADERS
extern int errno;
#endif

#ifndef PATH_MAX
#ifdef _POSIX_VERSION
#define PATH_MAX _POSIX_PATH_MAX
#else
#ifdef MAXPATHLEN
#define PATH_MAX MAXPATHLEN
#else
#define PATH_MAX 1024
#endif
#endif
#endif

char *ftppath(const char *path, char resolved_path [])
{
	char copy_path[PATH_MAX];
	char got_path [PATH_MAX];
	char *new_path = got_path;
	char *max_path;
	int wdl = 0;
	
	/* Make a copy of the source path since we may need to modify it. */
	if (strlen(path)>=PATH_MAX-2) {
		errno = ENAMETOOLONG;
		return NULL;
	}
	strcpy(copy_path, path);
	path = copy_path;
	max_path = copy_path + PATH_MAX - 2;
	/* If it's a relative pathname use getwd for starters. */
	if (*path != '/') {
		/* Ohoo... */
#ifdef HAVE_GETCWD
		getcwd(new_path, PATH_MAX - 1);
#else
		getwd(new_path);
#endif
		new_path += strlen(new_path);
		if (new_path[-1] != '/')
			*new_path++ = '/';
		wdl = new_path - got_path;
	}
	else {
		*new_path++ = '/';
		path++;
	}
	/* Expand each slash-separated pathname component. */
	while (*path != '\0') {
		/* Ignore stray "/". */
		if (*path == '/') {
			path++;
			continue;
		}
		if (*path == '.') {
			/* Ignore ".". */
			if (path[1] == '\0' || path[1] == '/') {
				path++;
				continue;
			}
			if (path[1] == '.') {
				if (path[2] == '\0' || path[2] == '/') {
					path += 2;
					/* Ignore ".." at root. */
					if (new_path == got_path + 1)
						continue;
					/* Handle ".." by backing up. */
					while ((--new_path)[-1] != '/')
						;
					continue;
				}
			}
		}
		/* Safely copy the next pathname component. */
		while (*path != '\0' && *path != '/') {
			if (path > max_path) {
				errno = ENAMETOOLONG;
				return NULL;
			}
			*new_path++ = *path++;
		}
		*new_path++ = '/';
	}
	/* Delete trailing slash but don't whomp a lone slash. */
	if (new_path != got_path + 1 && new_path[-1] == '/')
		new_path--;
	/* Make sure it's null terminated. */
	*new_path = '\0';
	strcpy (resolved_path, got_path + wdl);
	return resolved_path;
}

#endif /* USE_GLOB */
