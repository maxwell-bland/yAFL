#include <stdlib.h> 
#include <criu/criu.h>
#include <sys/shm.h> 
#include "qemu/osdep.h"
#include "sysemu/runstate.h"
#include "sysmode-fuzzer/time-dialation.h"
#include "sysmode-fuzzer/child.h"

/* The below are written during option parsing in softmmu/vl.c */
/* Location of the synchronization directory used by AFL for this
   fuzzing instance; where stdout and stderr are stored to.
   Should include the fuzzer's name */
extern const char *sm_syncdir;
/* The location where checkpointed data is saved to. */
extern const char *sm_fuzzer_checkpoint_dir;
/* Names of files that need to be restored each
   time the child process is restored. */
extern const char *sm_fuzzer_criu_external_state_files;
/* Flag set depending on whether we are validating
   the fuzzer's input. */
extern bool sm_fuzzer_validating_input;

/* This is equivalent to afl-as.h: */
static unsigned char *afl_area_ptr;
/* Instrumentation ratio used to determine whether to
   add a program counter value to AFLs tracking map*/
static unsigned int afl_inst_rms = AFL_MAP_SIZE;

/* Whether the child has already finished checkpointing. */
bool checkpoint_done = false;
/* Whether we have redirected output when validating fuzzing testcases */
bool validation_input_redirected = false;

void restore_file_state(void) {
    if (sm_fuzzer_criu_external_state_files) {
        char copy_str[16384];
        char filename[4098] = {0};
        char tmp[4098] = {0};

        char *basename;
        char *tmp_bn;
        char *pt = filename;
        strcpy(pt, sm_fuzzer_criu_external_state_files);
        while (pt != NULL && *pt) {
            // Cut at the next comma
            int i = 0;
            while (pt[i] && pt[i] != ',') {
                i++;
            }

            if (!pt[i]) {
                i--; // So that the loop halts
            } else {
                pt[i] = 0;
            }

            // Get the base name
            strcpy(tmp, pt);
            basename = strtok(tmp, "/");
            while (1) {
                tmp_bn = strtok(NULL, "/");
                if (tmp_bn) {
                    basename = tmp_bn;
                } else {
                    break;
                }
            }

            // Copy the file
            sprintf(copy_str, "cp %s%s %s", sm_fuzzer_checkpoint_dir, basename, pt);
            if (system(copy_str)) {
                fprintf(stderr, "Child failed to restore file state %s\n",
                        strerror(errno));
            }
            // Next file in the list
            pt += i + 1;
        }
    }
}

void save_file_state(void) {
    if (sm_fuzzer_criu_external_state_files) {
        char copy_str[16384];
        char filename[4098] = {0};

        char *pt = filename;
        strcpy(pt, sm_fuzzer_criu_external_state_files);
        while (pt != NULL && *pt) {
            int i = 0;
            while (pt[i] && pt[i] != ',') {
                i++;
            }

            if (!pt[i]) {
                i--;
            } else {
                pt[i] = 0;
            }

            sprintf(copy_str, "cp %s %s", pt, sm_fuzzer_checkpoint_dir);
            if (system(copy_str)) {
                fprintf(stderr, "Child failed to copy file state %s\n",
                        strerror(errno));
            }

            pt += i + 1;
        }
    }
}

inline void restore_shm(void) {
    /* Reinstate shared memory for fuzzing */
    char shm_id[128];
    strcpy(shm_id, sm_fuzzer_checkpoint_dir);
    strcat(shm_id, "shm_id");
    char id_str[128];
    FILE *shm_f = fopen(shm_id, "r");
    char c;
    int i = 0;
    while (EOF != (c = fgetc(shm_f))) {
        id_str[i++] = c;
    }
    id_str[i] = 0;
    afl_area_ptr = shmat(atoi(id_str), NULL, 0);
}

inline void restore_io(void) {
    char tmp[1024];
    sprintf(tmp, "%s/.cur_input", sm_syncdir);
    stdin = fopen(tmp, "r");
    sprintf(tmp, "%s/stderr", sm_syncdir);
    stderr = fopen(tmp, "a+");
    sprintf(tmp, "%s/stdout", sm_syncdir);
    stdout = fopen(tmp, "a+");
}

inline void send_parent_pid(void) {
    char tmp[1024];
    pid_t ppid;
    sprintf(tmp, "%s/parent_pid", sm_syncdir);
    FILE *pid_file = fopen(tmp, "r");
    if (!fread(&ppid, sizeof(pid_t), 1, pid_file)) {
        fprintf(stderr, "Child read parent PID. %s\n",
                strerror(errno));
        exit(5);
    }
    fclose(pid_file);

    sprintf(tmp, "/proc/%d/fd/%d", ppid, PARENT_IN_FD);
    int comm_channel = open(tmp, O_WRONLY);
    int my_pid = getpid();
    if (write(comm_channel, &my_pid, 4) != 4) {
        fprintf(stderr, "Child failed to write PID to parent. %s\n",
                strerror(errno));
        exit(5);
    }
    close(comm_channel);
}

inline void restore_child(CPUState *cpu) {
    restore_io();
    restore_shm();
    send_parent_pid();
}

inline void checkpoint_internal(void) {
    /* We set a new session ID to avoid conflicting with prior runs */
    setsid();
    checkpoint_done = true;
    criu_init_opts();
    criu_set_log_level(4);
    int fd = open(sm_fuzzer_checkpoint_dir, O_DIRECTORY);
    criu_set_images_dir_fd(fd);
    criu_set_log_file("dump.log");
    close(0);
    close(1);
    close(2);
    criu_dump();
}

inline void sm_fuzzer_checkpoint(CPUState *cpu) {
    if (!sm_fuzzer_validating_input && !checkpoint_done) {
        set_criu_checkpoint_time();
        vm_stop(4);
        save_file_state();
        checkpoint_internal();
        /* Child will start here. */
        restore_child(cpu);
        restore_file_state();
        vm_start();
        set_criu_restore_time();
    } else if (sm_fuzzer_validating_input && !checkpoint_done){
        checkpoint_done = 1;
    }
}

inline void sm_fuzzer_log(ulong cur_loc) {
    if (!sm_fuzzer_validating_input && checkpoint_done) {
        static __thread ulong prev_loc;

        /* Looks like QEMU always maps to fixed locations, so ASAN is not a
           concern. Phew. But instruction addresses may be aligned. Let's mangle
           the value to get something quasi-uniform. */
        cur_loc = (cur_loc >> 4) ^ (cur_loc << 8);
        cur_loc &= AFL_MAP_SIZE - 1;

        /* Implement probabilistic instrumentation by looking at scrambled block
           address. This keeps the instrumented locations stable across runs. */
        if (cur_loc >= afl_inst_rms)
            return;

        afl_area_ptr[cur_loc ^ prev_loc]++;
        prev_loc = cur_loc >> 1;
    }
}

void sm_fuzzer_fuzz(uint8_t *dest, int num_bytes) {
    if (checkpoint_done) {
        if (sm_fuzzer_validating_input && !validation_input_redirected) {
            fclose(stdin);
            stdin = fopen("/dev/stdin", "r");
            validation_input_redirected = true;
        }
        uint8_t res[num_bytes];
        int cnt = fread(res, 1, num_bytes, stdin);
        for (int i = 0; i < num_bytes; i++) {
            if (cnt != 0) {
                *dest = res[i];
                dest++;
                cnt--;
            }
        }
    }
}
