
#include <config.h>

#include "rcsid.h"
RCSID("$Id: commonio.c,v 1.1 2000/12/17 05:34:10 tom Exp $")

#include "defines.h"
#include <sys/stat.h>
#include <utime.h>
#include <fcntl.h>
#include <errno.h>
#include <stdio.h>
#include <signal.h>
#include <pwd.h>

#include "commonio.h"

static int
check_link_count(file)
	const char *file;
{
	struct stat sb;

	if (stat(file, &sb) != 0)
		return 0;

	if (sb.st_nlink != 2)
		return 0;

	return 1;
}


static int
do_lock_file(file, lock)
	const char *file;
	const char *lock;
{
	int fd;
	int pid;
	int len;
	int retval;
	char buf[32];

	if ((fd = open(file, O_CREAT|O_EXCL|O_WRONLY, 0600)) == -1)
		return 0;

	pid = getpid();
	sprintf(buf, "%d", pid);
	len = strlen(buf) + 1;
	if (write (fd, buf, len) != len) {
		close(fd);
		unlink(file);
		return 0;
	}
	close(fd);

	if (link(file, lock) == 0) {
		retval = check_link_count(file);
		unlink(file);
		return retval;
	}

	if ((fd = open(lock, O_RDWR)) == -1) {
		unlink(file);
		errno = EINVAL;
		return 0;
	}
	len = read(fd, buf, sizeof(buf) - 1);
	close(fd);
	if (len <= 0) {
		unlink(file);
		errno = EINVAL;
		return 0;
	}
	buf[len] = '\0';
	if ((pid = strtol(buf, (char **) 0, 10)) == 0) {
		unlink(file);
		errno = EINVAL;
		return 0;
	}
	if (kill(pid, 0) == 0)  {
		unlink(file);
		errno = EEXIST;
		return 0;
	}
	if (unlink(lock) != 0) {
		unlink(file);
		return 0;
	}

	retval = 0;
	if (link(file, lock) == 0 && check_link_count(file))
		retval = 1;

	unlink(file);
	return retval;
}


static FILE *
fopen_set_perms(name, mode, sb)
	const char *name;
	const char *mode;
	const struct stat *sb;
{
	FILE *fp;
	int mask;

	mask = umask(0777);
	fp = fopen(name, mode);
	umask(mask);
	if (!fp)
		return NULL;

#ifdef HAVE_FCHMOD
	if (fchmod(fileno(fp), sb->st_mode & 0777))
		goto fail;
#else
	if (chmod(name, sb->st_mode & 0777))
		goto fail;
#endif

#ifdef HAVE_FCHOWN
	if (fchown(fileno(fp), sb->st_uid, sb->st_gid))
		goto fail;
#else
	if (chown(name, sb->st_mode))
		goto fail;
#endif
	return fp;

fail:
	fclose(fp);
	unlink(name);
	return NULL;
}


static int
create_backup(backup, fp)
	const char *backup;
	FILE *fp;
{
	struct stat sb;
	struct utimbuf ub;
	FILE *bkfp;
	int c, mask;

	if (fstat(fileno(fp), &sb))
		return -1;

	mask = umask(077);
	bkfp = fopen(backup, "w");
	umask(mask);
	if (!bkfp)
		return -1;

	/* TODO: faster copy, not one-char-at-a-time.  --marekm */
	rewind(fp);
	while ((c = getc(fp)) != EOF) {
		if (putc(c, bkfp) == EOF)
			break;
	}
	if (c != EOF || fflush(bkfp)) {
		fclose(bkfp);
		return -1;
	}
	if (fclose(bkfp))
		return -1;

	ub.actime = sb.st_atime;
	ub.modtime = sb.st_mtime;
	utime(backup, &ub);
	return 0;
}


static void
free_linked_list(db)
	struct commonio_db *db;
{
	struct commonio_entry *p;

	while (db->head) {
		p = db->head;
		db->head = p->next;

		if (p->line)
			free(p->line);

		if (p->entry)
			db->ops->free(p->entry);

		free(p);
	}
	db->tail = NULL;
}


int
commonio_setname(db, name)
	struct commonio_db *db;
	const char *name;
{
	strcpy(db->filename, name);
	return 1;
}


int
commonio_lock(db)
	struct commonio_db *db;
{
	char	file[1024];
	char	lock[1024];

	if (db->locked)
		return 1;

	sprintf(file, "%s.%ld", db->filename, (long) getpid());
	sprintf(lock, "%s.lock", db->filename);
	if (do_lock_file(file, lock)) {
		db->locked = 1;
		return 1;
	}
	return 0;
}

int
commonio_lock_all ()
{
  int fd;

#ifdef HAVE_LCKPWDF
  if (lckpwdf() == -1) return 0;
#endif

/*
  if ((fd = open ("/etc/ptmp", O_WRONLY|O_CREAT|O_EXCL, 0644)) < 0)
  {
    ulckpwdf ();
    return 0;
  }
*/

  close (fd);

  return 1;  /* success */
}

int
commonio_unlock_all ()
{
 
#ifdef HAVE_LCKPWDF
  ulckpwdf ();
#endif

/*
  unlink("/etc/ptmp");
*/

  return 1;
}

#ifdef HAVE_LCKPWDF

int
commonio_lock_first(db)
	struct commonio_db *db;
{
	/*
	 * When locking several files, *_lock_first() is called
	 * for the first one, and *_lock() for the others.
	 * If lckpwdf() is available, call it here (it may block
	 * for up to 15 seconds), and if it succeeds, call
	 * *_lock() once (no retries, it should always succeed).
	 */

	if (lckpwdf() == -1)
		return 0;  /* failure */

	if (!commonio_lock(db)) {
		ulckpwdf();
		return 0;  /* failure */
	}

	return 1;  /* success */
}

#else /* not HAVE_LCKPWDF */

int
commonio_lock_first(db)
	struct commonio_db *db;
{

	int i;

	/*
	 * No lckpwdf() - do it the old way.
	 */

#ifndef LOCK_TRIES
#define LOCK_TRIES 15
#endif
	for (i = 1; i < LOCK_TRIES; i++) {
		if (commonio_lock(db))
			return 1;  /* success */

		sleep(1);
	}

	/*
	 * Retry the last time...
	 */
	if (!commonio_lock(db)) {
		return 0;  /* failure */
	}
}

#endif /* not HAVE_LCKPWDF */


int
commonio_unlock(db)
	struct commonio_db *db;
{
	char	lock[1024];

	if (db->isopen) {
		db->readonly = 1;
		if (!commonio_close(db))
			return 0;
	}
  	if (db->locked) {
  		db->locked = 0;
		sprintf(lock, "%s.lock", db->filename);
		unlink(lock);
		return 1;
	}
	return 0;
}


static void
add_one_entry(db, p)
	struct commonio_db *db;
	struct commonio_entry *p;
{
	p->next = NULL;
	p->prev = db->tail;
	if (!db->head)
		db->head = p;
	if (db->tail)
		db->tail->next = p;
	db->tail = p;
}


int
commonio_open(db, mode)
	struct commonio_db *db;
	int mode;
{
	char	buf[8192];
	char	*cp;
	char *line;
	struct commonio_entry *p;
	void *entry;
	int flags = mode;

	mode &= ~O_CREAT;

	if (db->isopen || (mode != O_RDONLY && mode != O_RDWR)) {
		errno = EINVAL;
		return 0;
	}
	db->readonly = (mode == O_RDONLY);
	if (!db->readonly && !db->locked) {
		errno = EACCES;
		return 0;
	}

	db->head = db->tail = db->cursor = NULL;
	db->changed = 0;

	db->fp = fopen(db->filename, db->readonly ? "r" : "r+");

	/*
	 * If O_CREAT was specified and the file didn't exist, it will be
	 * created by commonio_close().  We have no entries to read yet.  --marekm
	 */
	if (!db->fp) {
		if ((flags & O_CREAT) && errno == ENOENT) {
			db->isopen++;
			return 1;
		}
		return 0;
	}

	while (db->ops->fgets(buf, sizeof buf, db->fp)) {
		if ((cp = strrchr(buf, '\n')))
			*cp = '\0';

		if (!(line = strdup(buf)))
			goto cleanup;

		if (*line == '+' || *line == '-') {
			entry = NULL;
		} else if ((entry = db->ops->parse(line))) {
			entry = db->ops->dup(entry);
			if (!entry)
				goto cleanup_line;
		}

		p = (struct commonio_entry *) malloc(sizeof *p);
		if (!p)
			goto cleanup_entry;

		p->entry = entry;
		p->line = line;
		p->changed = 0;

		add_one_entry(db, p);
	}

	db->isopen++;
	return 1;

cleanup_entry:
	if (entry)
		db->ops->free(entry);
cleanup_line:
	free(line);
cleanup:
	free_linked_list(db);
	fclose(db->fp);
	db->fp = NULL;
	errno = ENOMEM;
	return 0;
}

/*
 * The "plus on a line by itself" NIS entry (if any) is moved to
 * the end of the passwd file.  Other kinds of NIS entries are
 * left where they are.  This seems to be what other systems do
 * (at least HP-UX 10.01, anyway).  Use "+::::::" instead of "+"
 * if new users should be added _after_ the NIS entry (apparently
 * this has some uses).
 *
 * If you are running NIS, please tell me if this is good enough.
 * If not, suggestions and patches are welcome.  --marekm
 */
#ifndef KEEP_NIS_AT_END
#define KEEP_NIS_AT_END 1
#endif

#define PLUS "+"

static int
write_all(db)
	const struct commonio_db *db;
{
	const struct commonio_entry *p;
	void *entry;
#if KEEP_NIS_AT_END
	int plus = 0;
#endif

	for (p = db->head; p; p = p->next) {
		if (p->changed) {
			entry = p->entry;
			if (db->ops->put(entry, db->fp))
				return -1;
		} else if (p->line) {
#if KEEP_NIS_AT_END
			if (strcmp(p->line, PLUS) == 0) {
				plus++;
				continue;
			}
#endif
			if (db->ops->fputs(p->line, db->fp) == EOF)
				return -1;
			if (putc('\n', db->fp) == EOF)
				return -1;
		}
	}
#if KEEP_NIS_AT_END
	if (plus) {
		if (db->ops->fputs(PLUS, db->fp) == EOF)
			return -1;
		if (putc('\n', db->fp) == EOF)
			return -1;
	}
#endif
	return 0;
}


int
commonio_close(db)
	struct commonio_db *db;
{
	char buf[1024];
	int errors = 0;
	struct stat sb;

	if (!db->isopen) {
		errno = EINVAL;
		return 0;
	}
	db->isopen = 0;

	if (!db->changed || db->readonly) {
		fclose(db->fp);
		db->fp = NULL;
		goto success;
	}

	if (db->fp) {
		if (fstat(fileno(db->fp), &sb)) {
			fclose(db->fp);
			db->fp = NULL;
			goto fail;
		}

		/*
		 * Create backup file.
		 */
		sprintf(buf, "%s-", db->filename);

		if (create_backup(buf, db->fp))
			errors++;

		if (fclose(db->fp))
			errors++;

		if (errors) {
			db->fp = NULL;
			goto fail;
		}
	} else {
		/*
		 * Default permissions for new [g]shadow files.
		 * (passwd and group always exist...)
		 */
		sb.st_mode = 0400;
		sb.st_uid = 0;
		sb.st_gid = 0;
	}

	sprintf(buf, "%s+", db->filename);

	db->fp = fopen_set_perms(buf, "w", &sb);
	if (!db->fp)
		goto fail;

	if (write_all(db))
		errors++;

	if (fflush(db->fp))
		errors++;
#ifdef HAVE_FSYNC
	if (fsync(fileno(db->fp)))
		errors++;
#else
	sync();
#endif
	if (fclose(db->fp))
		errors++;

	db->fp = NULL;

	if (errors) {
		unlink(buf);
		goto fail;
	}

	if (rename(buf, db->filename))
		goto fail;

success:
	free_linked_list(db);
	return 1;

fail:
	free_linked_list(db);
	return 0;
}


static struct commonio_entry *
find_entry_by_name(db, name)
	struct commonio_db *db;
	const char *name;
{
	struct commonio_entry *p;
	void *ep;

	for (p = db->head; p; p = p->next) {
		ep = p->entry;
		if (ep && strcmp(db->ops->getname(ep), name) == 0)
			break;
	}
	return p;
}


int
commonio_update(db, entry)
	struct commonio_db *db;
	const void *entry;
{
	struct commonio_entry *p;
	void *nentry;

	if (!db->isopen || db->readonly) {
		errno = EINVAL;
		return 0;
	}
	if (!(nentry = db->ops->dup(entry))) {
		errno = ENOMEM;
		return 0;
	}
	p = find_entry_by_name(db, db->ops->getname(entry));
	if (p) {
		db->ops->free(p->entry);
		p->entry = nentry;
		p->changed = 1;
		db->cursor = p;

		db->changed = 1;
		return 1;
	}
	/* not found, new entry */
	p = (struct commonio_entry *) malloc(sizeof *p);
	if (!p) {
		db->ops->free(nentry);
		errno = ENOMEM;
		return 0;
	}

	p->entry = nentry;
	p->line = NULL;
	p->changed = 1;

	add_one_entry(db, p);

	db->changed = 1;
	return 1;
}


void
commonio_del_entry(db, p)
	struct commonio_db *db;
	const struct commonio_entry *p;
{
	if (p == db->cursor)
		db->cursor = p->next;

	if (p->prev)
		p->prev->next = p->next;
	else
		db->head = p->next;

	if (p->next)
		p->next->prev = p->prev;
	else
		db->tail = p->prev;

	db->changed = 1;
}


int
commonio_remove(db, name)
	struct commonio_db *db;
	const char *name;
{
	struct commonio_entry *p;

	if (!db->isopen || db->readonly) {
		errno = EINVAL;
		return 0;
	}
	p = find_entry_by_name(db, name);
	if (!p) {
		errno = ENOENT;
		return 0;
	}

	commonio_del_entry(db, p);

	if (p->line)
		free(p->line);

	if (p->entry)
		db->ops->free(p->entry);

	return 1;
}


const void *
commonio_locate(db, name)
	struct commonio_db *db;
	const char *name;
{
	struct commonio_entry *p;

	if (!db->isopen) {
		errno = EINVAL;
		return NULL;
	}
	p = find_entry_by_name(db, name);
	if (!p) {
		errno = ENOENT;
		return NULL;
	}
	db->cursor = p;
	return p->entry;
}


int
commonio_rewind(db)
	struct commonio_db *db;
{
	if (!db->isopen) {
		errno = EINVAL;
		return 0;
	}
	db->cursor = NULL;
	return 1;
}


const void *
commonio_next(db)
	struct commonio_db *db;
{
	void *entry;

	if (!db->isopen) {
		errno = EINVAL;
		return 0;
	}
	if (db->cursor == NULL)
		db->cursor = db->head;
	else
		db->cursor = db->cursor->next;

	while (db->cursor) {
		entry = db->cursor->entry;
		if (entry)
			return entry;

		db->cursor = db->cursor->next;
	}
	return NULL;
}
