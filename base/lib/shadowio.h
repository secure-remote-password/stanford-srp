extern struct spwd *__spw_dup P_((const struct spwd *));
extern void __spw_set_changed P_((void));
extern int spw_close P_((void));
extern const struct spwd *spw_locate P_((const char *));
extern int spw_lock P_((void));
extern int spw_lock_first P_((void));
extern int spw_name P_((const char *));
extern const struct spwd *spw_next P_((void));
extern int spw_open P_((int));
extern int spw_remove P_((const char *));
extern int spw_rewind P_((void));
extern int spw_unlock P_((void));
extern int spw_update P_((const struct spwd *));
