#ifndef SYSMODE_FUZZER_COORDINATOR_H_
#define SYSMODE_FUZZER_COORDINATOR_H_

/* File descriptor for getting output from our AFL parent */
#define AFL_PARENT_OUT 198
/* File descriptor for writing to the AFL parent */
#define AFL_PARENT_IN 199
/* File descriptor the child writes to to speak to the parent */
#define CHILD_PIPE_IN 200
/* File descriptor the parent reads from to get PID from the child */
#define CHILD_PIPE_OUT 201

/* Waits for AFL to tell us it is ready to start another
   child process */
void wait_for_afl_goahead(void);

/* ptraces the child process so we can determine the result of fuzzing */
void ptrace_child(pid_t child_pid);

void send_afl_data(u_int8_t data[4]);

/* We may have created several defunct sm-fuzzer processes
   while spawning this run so we wait for them after the qemu
   child completes */
void wait_for_children(void);

/* We wait for the child qemu process and then send the exit status
   to AFL. */
void send_afl_run_status(pid_t child_pid);

/* Creates a file pointing to the id of the shared memory object
   that will be altered by the child as it records its execution trace */
void create_shm(const char *checkpoint_dir);

/* Create a file so the child knows who its parent is.
   We do this because when the process restores it will have
   a different parent pid than it should, since we may
   have to fork several times to get the criu restore to work. */
void create_pid(const char *fuzzer_name);

/* Creates a pipe through which the child will communicate to send its PID */
void create_child_pipe(void);

/* Sets up the state for restoring the child and restores it. Once this succeeds,
   we can read the child's proper PID and continue execution. */
pid_t create_child(const char *checkpoint_dir);

/* Handles spawning child fuzz instance processes */
int main(int argc, char **argv);

#endif
