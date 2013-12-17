/*
 * This file is part of user-session-units
 *
 * (C) Copyright 2013 Intel Corporation
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; version 2
 * of the License.
 */

#ifndef __PAM_H__
#define __PAM_H__

void setup_pam_session(char *seat, char *user);
void close_pam_session(void);

#endif /* __PAM_H_ */
