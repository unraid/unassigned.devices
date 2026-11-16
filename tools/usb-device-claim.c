/* SPDX-License-Identifier: GPL-2.0-only */
/* Hold a block device without writing data. PHP owns all removal policy. */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <sys/stat.h>
#include <unistd.h>

/* Linux fs.h request, also usable when the build host has older headers. */
#ifndef BLKGETDISKSEQ
#define BLKGETDISKSEQ _IOR(0x12, 128, uint64_t)
#endif

static int refuse(const char *reason)
{
	puts(reason);
	return 1;
}

int main(int argc, char **argv)
{
	char *end, byte;
	uint64_t sequence;
	struct stat st;
	if (argc != 3 || argv[2][0] < '1' || argv[2][0] > '9') return refuse("changed");
	errno = 0;
	unsigned long long expected = strtoull(argv[2], &end, 10);
	if (errno || *end) return refuse("changed");
	int fd = open(argv[1], O_RDONLY | O_EXCL | O_NONBLOCK | O_CLOEXEC | O_NOFOLLOW);
	if (fd < 0) return refuse(errno == EBUSY ? "busy" : "inspection");
	if (fstat(fd, &st) || !S_ISBLK(st.st_mode) || ioctl(fd, BLKGETDISKSEQ, &sequence) || sequence != expected) {
		close(fd);
		return refuse("changed");
	}
	if (fsync(fd)) {
		close(fd);
		return refuse("flush");
	}
	/* The parent sends no bytes. EOF releases the claim after detach or refusal. */
	if (puts("ready") == EOF || fflush(stdout)) { close(fd); return 1; }
	ssize_t n;
	do { n = read(STDIN_FILENO, &byte, 1); } while (n > 0 || (n < 0 && errno == EINTR));
	close(fd);
	return 0;
}
