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

#define _GNU_SOURCE

#include <errno.h>
#include <getopt.h>
#include <poll.h>
#include <pwd.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <systemd/sd-login.h>

#include "pam.h"

static char **seats;
static sd_login_monitor *mon;

static void handle_sig(int signal)
{
	close_pam_session();

	if (seats)
		free(seats);
	if (mon)
		sd_login_monitor_unref(mon);

	exit(EXIT_SUCCESS);
}

int main(int argc, char **argv)
{
	int fd;
	int ret = 0;
	struct pollfd fds[1];
	nfds_t nfds;
	struct sigaction sa;
	char *seat = NULL;
	char *user = NULL;
	char *sep = "-";
	long long int struid;
	char *endptr;
	struct passwd *pw;

	sigemptyset(&sa.sa_mask);
	sa.sa_flags = SA_RESTART;
	sa.sa_handler = handle_sig;

	if ((sigaction(SIGINT, &sa, NULL)) < 0) {
		perror("sigaction");
		goto fail;
	}
	if ((sigaction(SIGTERM, &sa, NULL)) < 0) {
		perror("sigaction");
		goto fail;
	}

	if (argc != 2) {
		fprintf(stderr, "One argument of form SEAT-UID required.\n");
		goto fail;
	}

	seat = strtok(argv[1], sep);
	if (!seat || !strstr(seat, "seat")) {
		fprintf(stderr, "SEAT name is invalid.\n");
		goto fail;
	}

	user = strtok(NULL, sep);
	if (user) {
		errno = 0;
		struid = strtoll(user, &endptr, 10);
		if (errno) {
			perror("strtol");
			goto fail;
		}
		if (endptr == user) {
			fprintf(stderr, "No digits found in UID.\n");
			goto fail;
		}
		if (*endptr != '\0') {
			fprintf(stderr, "Found malformed UID.\n");
			goto fail;
		}
	} else {
		fprintf(stderr, "UID not found.\n");
		goto fail;
	}

	errno = 0;
	pw = getpwuid((uid_t)struid);
	if (!pw) {
		if (errno)
			perror("getpwuid");
		else
			fprintf(stderr, "No matching passwd entry found.\n");
		goto fail;
	}
	user = pw->pw_name;

	/* Only monitor seats for now, since there should only
	 * be one graphical session per seat.
	 */
	if ((sd_login_monitor_new("seat", &mon)) < 0) {
		perror("sd_login_monitor_new");
		goto fail;
	}

	fd = sd_login_monitor_get_fd(mon);
	if (fd < 0) {
		perror("sd_login_monitor_get_fd");
		goto fail;
	}

	if ((sd_get_seats(&seats)) < 0) {
		perror("sd_get_seats");
		goto fail;
	}

	while (!seats) {
		/* logind has not initialized yet, so we poll()
		 * until /run/systemd/seats gains a seat */
		nfds = 1;
		fds[0].fd = fd;
		fds[0].events = POLLIN;
		ret = poll(fds, nfds, -1);

		if (ret < 0) {
			perror("poll");
			goto fail;
		}

		if (fds[0].revents & POLLIN) {
			ret = sd_get_seats(&seats);
			if (ret < 0) {
				perror("sd_get_seats");
				goto fail;
			}
			/* This is an unlikely scenario, but check
			 * to be safe */
			if (ret == 0 || !seats) {
				/* This resets the inotify fd for us */
				sd_login_monitor_flush(mon);
				continue;
			}
			/* A seat is available; so we know logind
			 * has initialized by now. */
			break;
		} else {
			fprintf(stderr, "Unexpected poll() error\n");
			goto fail;
		}
	}

	char **s = seats;
	for (; *s; s++) {
		if (strcmp(seat, *s) == 0) {
			/* The requested seat is available */
			setup_pam_session(seat, user);
		}
		free(*s);
	}

	/* We don't need to be privileged when the session closes */
	if (setresuid(pw->pw_uid, pw->pw_uid, pw->pw_uid) != 0)
		perror("setresuid");

	pause();

	/* unreachable */
	return 0;
fail:
	if (mon)
		sd_login_monitor_unref(mon);

	return 1;
}
