#ifndef PERMISSIONS_H
#define PERMISSIONS_H

#include "persistence.h"

int is_mod_for_board(struct user *user, struct board *board);
int can_see_ban(struct user *user, struct ban *ban);
int can_make_thread(struct user *user, struct ip *ip, struct ip *x_real_ip,
                    array *x_forwarded_for, struct board *board);

#endif // PERMISSIONS_H
