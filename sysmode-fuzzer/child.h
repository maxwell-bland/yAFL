#ifndef SYSMODE_FUZZER_CHILD_H
#define SYSMODE_FUZZER_CHILD_H

/* Must match map size defined by AFL */
#define AFL_MAP_SIZE (1 << 16)
/* File descriptor read by the coordinator for
   receiving information from the child */
#define PARENT_IN_FD 200

/* Restores the stdin, stdout, and stderr variables */
void restore_io(void);

/* Restores the afl_area_ptr by reading a file
   for the id of the shared memory object that is
   shared with the coordinator and communicated to
   AFL */
void restore_shm(void);

/* Since we may have to run CRIU many times to get the
   child to restore due to kernel race conditions, we
   eventually send it to the parent through a pipe
   after reading the parent PID from a file. */
void send_parent_pid(void);

/* Saves any file that need to be restored to their
   prior state during a restore of a child process */
void restore_file_state(void);
void save_file_state(void);

/* Sets up CRIU and performs a state checkpoint */
void checkpoint_internal(void);

/* Fixes up stdin, stderr, stdout file descriptors to handle recording and
   reading in fuzzer input, sets up the shared memory buffer for communicating
   executed program counters to AFL, and sends the spawing parent process our
   PID */
void restore_child(void);

/* Checkpoints the qemu process by stopping the vm
   and recording proper file state based on command-line
   flags */
void sm_fuzzer_checkpoint(void);

/* Logs executed program counter values to help AFL
   determine whether to mutate fuzzer inputs */
void sm_fuzzer_log(ulong cur_loc);

/* Fuzzes the destination pointer with a given number
   of bytes of input */
void sm_fuzzer_fuzz(uint8_t *dest, int num_bytes);

/* Returns whether the fuzzer is done with a checkpoint */
bool sm_fuzzer_checkpoint_done(void);

#endif
