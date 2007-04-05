#ifndef _GETDEF_H
#define _GETDEF_H

/* getdef.c */
#if __STDC__
extern int getdef_bool(const char *, int);
extern long getdef_long(const char *, long);
extern int getdef_num(const char *, int);
extern char *getdef_str(const char *, const char *);
#else
extern int getdef_bool();
extern long getdef_long();
extern int getdef_num();
extern char *getdef_str();
#endif

#endif /* _GETDEF_H */
