/*
 * This file is part of user-session
 *
 * (C) Copyright 2009 Intel Corporation
 * Authors:
 *     Auke Kok <auke@linux.intel.com>
 *     Arjan van de Ven <arjan@linux.intel.com>
 *     Michael Meeks <michael.meeks@novell.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; version 2
 * of the License.
 */

#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <pwd.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <security/pam_appl.h>
#include <security/pam_misc.h>

#include "pam.h"

static pam_handle_t *ph;
static struct pam_conv pc;

/*
 * Sometimes PAM likes to chat with you, before it is assured
 * enough to let you log-in: fun.
 */
static int
pam_conversation_fn(int msg_count,
		    const struct pam_message **messages,
		    struct pam_response      **responses,
		    void *user_data)
{
	int i;
	(void)user_data;

	printf("pam conversation with %d messages", msg_count);
	if (responses)
		*responses = NULL;

	if (msg_count < 1) /* ping */
		return PAM_SUCCESS;

	/* otherwise find any helpful data we can to print, and bail */
	if (!responses || !messages) {
		printf("pam conversation with no message, or response");
		return PAM_CONV_ERR;
	}
	*responses = calloc (msg_count, sizeof (struct pam_response));
	for (i = 0; i < msg_count; i++) {
		const struct pam_message *msg = messages[i];

		if (msg->msg_style == PAM_TEXT_INFO)
			printf("pam chats to us: '%s'", msg->msg);
		else if (msg->msg_style == PAM_ERROR_MSG)
			printf("Error: pam error msg '%s'", msg->msg);
		else
			printf("pam message %d style %d: '%s'",
				 i, msg->msg_style, msg->msg);
		(*responses)[i].resp = NULL;
		(*responses)[i].resp_retcode = PAM_SUCCESS;
	}

	return PAM_SUCCESS;
}

/*
 * Creating a PAM session. We need a pam "login" session so that the dbus
 * "at_console" logic will work correctly, as well as various /dev file
 * permissions.
 *
 * for at_console to work we need to set the PAM_TTY variable before we open
 * the session. "PAM_TTY" takes input in the form "ttyX".
 *
 * Additionally, for logind integration, set XDG_SEAT and XDG_VTNR.
 * pam_systemd.so may guess the variables correctly, but set them beforehand
 * just to be sure.
 */
void setup_pam_session(char *seat, char *user)
{
	int err;

	pc.conv = pam_conversation_fn;
	pc.appdata_ptr = NULL;

	err = pam_start("login", user, &pc, &ph);

	/* FIXME: do not hardcode the tty here; should check
	 * first to see if it's already taken. */
	err = pam_set_item(ph, PAM_TTY, "tty1");
	if (err != PAM_SUCCESS) {
		printf("pam_set_item PAM_TTY returned %d: %s\n", err, pam_strerror(ph, err));
		exit(EXIT_FAILURE);
	}

	err = pam_misc_setenv(ph, "XDG_SEAT", seat, 0);
	if (err != PAM_SUCCESS) {
		printf("pam_misc_setenv XDG_SEAT returned %d: %s\n", err, pam_strerror(ph, err));
		exit(EXIT_FAILURE);
	}

	/* FIXME: this variable should correspond to PAM_TTY */
	err = pam_misc_setenv(ph, "XDG_VTNR", "1", 0);
	if (err != PAM_SUCCESS) {
		printf("pam_misc_setenv XDG_VTNR returned %d: %s\n", err, pam_strerror(ph, err));
		exit(EXIT_FAILURE);
	}

	err = pam_open_session(ph, 0);
	if (err != PAM_SUCCESS) {
		printf("pam_open_session returned %d: %s\n", err, pam_strerror(ph, err));
		exit(EXIT_FAILURE);
	}
}

void close_pam_session(void)
{
	int err;

	err = pam_close_session(ph, 0);
	if (err)
		printf("pam_close_session returned %d: %s\n", err, pam_strerror(ph, err));
	pam_end(ph, err);
}
