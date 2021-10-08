/* $Id: access.h,v 1.2 2002/11/29 14:56:36 andreou Exp $ */

#ifndef HYDRA_SRC_ACCESS_H
#define HYDRA_SRC_ACCESS_H

#define ACCESS_DENY 0
#define ACCESS_ALLOW 1

void access_add(const char *, const char *, const int);
int access_allow(const char *, const char *);

#endif /* HYDRA_SRC_ACCESS_H */

/* EOF */
