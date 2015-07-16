/*
 * Buxton
 *
 * Copyright (C) 2015 Samsung Electronics Co., Ltd.
 *
 * Licensed under the Apache License, Version 2.0 (the License);
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <getopt.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>

#include "daemon.h"

static const struct option const opts[] = {
	{ "config-file", required_argument, NULL, 'c' },
	{ "foreground",  no_argument,       NULL, 'f' },
	{ "help",        no_argument,       NULL, 'h' },
	{ NULL,          0,                 NULL, 0   },
};

static void usage(const char *name)
{
	printf(" Usage: %s [OPTION]\n\n", name);
	printf("  -c, --config-file=[FILE]  Path to configuration file\n");
	printf("  -f, --foreground          Don't daemonize\n");
	printf("  -h, --help                Display this help message\n");

	exit(EXIT_FAILURE);
}

int daemonize(void)
{
	pid_t p;
	int fd;
	int r;

	p = fork();
	if (p == -1) {
		perror("fork");
		return -1;
	}

	/* parent exit */
	if (p)
		exit(EXIT_SUCCESS);

	/* child process */
	r = chdir("/");
	if (r == -1)
		fprintf(stderr, "chdir failed: %d\n", errno);

	umask(022);
	setsid();

	close(STDIN_FILENO);
	close(STDOUT_FILENO);
	close(STDERR_FILENO);

	fd = open("/dev/null", O_RDWR);
	if (fd == -1)
		return 0;

	dup2(fd, STDIN_FILENO);
	dup2(fd, STDOUT_FILENO);
	dup2(fd, STDERR_FILENO);

	if (fd > STDERR_FILENO)
		close(fd);

	return 0;
}

int main(int argc, char *argv[])
{
	char const *confpath;
	int fg;
	int r;
	struct bxt_daemon bxtd = {
		.sigfd = -1,
		.sk = -1,
	};

	fg = 0;
	confpath = NULL;

	while (optind < argc) {
		int c;

		c = getopt_long(argc, argv, "c:fh", opts, NULL);
		if (c == -1)
			break;

		switch (c) {
		case 'c':
			confpath = optarg;
			break;
		case 'f':
			fg = 1;
			break;
		case 'h':
		default:
			usage(argv[0]);
			break;
		}
	}

	if (!fg) {
		r = daemonize();
		if (r == -1)
			return EXIT_FAILURE;
	}

	return start_daemon(&bxtd, confpath);
}

