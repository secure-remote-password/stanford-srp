/*
    SYNOPSIS
	login_fbtab(tty, uid, gid)
	char *tty;
	int uid;
	int gid;

    DESCRIPTION
	This module implements device security as described in the
	SunOS 4.1.x fbtab(5) and SunOS 5.x logindevperm(4) manual
	pages. The program first looks for /etc/fbtab. If that file
	cannot be opened it attempts to process /etc/logindevperm.
	We expect entries with the folowing format:

	    Comments start with a # and extend to the end of the line.

	    Blank lines or lines with only a comment are ignored.

	    All other lines consist of three fields delimited by
	    whitespace: a login device (/dev/console), an octal
	    permission number (0600), and a ":"-delimited list of
	    devices (/dev/kbd:/dev/mouse). All device names are
	    absolute paths. A path that ends in "/*" refers to all
	    directory entries except "." and "..".

	    If the tty argument (relative path) matches a login device
	    name (absolute path), the permissions of the devices in the
	    ":"-delimited list are set as specified in the second
	    field, and their ownership is changed to that of the uid
	    and gid arguments.

    DIAGNOSTICS
	Problems are reported via the syslog daemon with severity
	LOG_ERR.

    BUGS
	This module uses strtok(3), which may cause conflicts with other
	uses of that same routine.

    AUTHOR
	Wietse Venema (wietse@wzv.win.tue.nl)
	Eindhoven University of Technology
	The Netherlands
 */

#include <sys/types.h>
#include <stdio.h>
#include <syslog.h>
#include <string.h>
#include <errno.h>
#include <dirent.h>

#define	FBTAB		"/etc/fbtab"
#define LOGINDEVPERM	"/etc/logindevperm"
#define	WSPACE		" \t\n"

/* login_fbtab - apply protections specified in /etc/fbtab or logindevperm */

login_fbtab(tty, uid, gid)
char   *tty;
int     uid;
int     gid;
{
    FILE   *fp;
    char    buf[BUFSIZ];
    char   *devname;
    char   *cp;
    int     prot;
    char *table;

    if ((fp = fopen(table = FBTAB, "r")) == 0
    && (fp = fopen(table = LOGINDEVPERM, "r")) == 0)
	return;

    while (fgets(buf, sizeof(buf), fp)) {
	if (cp = strchr(buf, '#'))
	    *cp = 0;				/* strip comment */
	if ((cp = devname = strtok(buf, WSPACE)) == 0)
	    continue;				/* empty or comment */
	if (strncmp(devname, "/dev/", 5) != 0
	       || (cp = strtok((char *) 0, WSPACE)) == 0
	       || *cp != '0'
	       || sscanf(cp, "%o", &prot) == 0
	       || prot == 0
	       || (prot & 0777) != prot
	       || (cp = strtok((char *) 0, WSPACE)) == 0) {
	    syslog(LOG_ERR, "%s: bad entry: %s", table, cp ? cp : "(null)");
	    continue;
	}
	if (strcmp(devname + 5, tty) == 0) {
	    for (cp = strtok(cp, ":"); cp; cp = strtok((char *) 0, ":")) {
		login_protect(table, cp, prot, uid, gid);
	    }
	}
    }
    fclose(fp);
}

/* login_protect - protect one device entry */

login_protect(table, path, mask, uid, gid)
char *table;
char *path;
int mask;
int uid;
int gid;
{
    char    buf[BUFSIZ];
    int     pathlen = strlen(path);
    struct dirent *ent;
    DIR    *dir;

    if (strcmp("/*", path + pathlen - 2) != 0) {
	if (chmod(path, mask) && errno != ENOENT)
	    syslog(LOG_ERR, "%s: chmod(%s): %m", table, path);
	if (chown(path, uid, gid) && errno != ENOENT)
	    syslog(LOG_ERR, "%s: chown(%s): %m", table, path);
    } else {
	strcpy(buf, path);
	buf[pathlen - 1] = 0;
	if ((dir = opendir(buf)) == 0) {
	    syslog(LOG_ERR, "%s: opendir(%s): %m", table, path);
	} else {
	    while ((ent = readdir(dir)) != 0) {
		if (strcmp(ent->d_name, ".") != 0
		    && strcmp(ent->d_name, "..") != 0) {
		    strcpy(buf + pathlen - 1, ent->d_name);
		    login_protect(table, buf, mask, uid, gid);
		}
	    }
	    closedir(dir);
	}
    }
}
