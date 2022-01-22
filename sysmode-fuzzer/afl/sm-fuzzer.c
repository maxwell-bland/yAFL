#include <stdio.h>
#include <errno.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <fcntl.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <criu/criu.h>
#include "config.h"
#include "sm-fuzzer.h"

void wait_for_afl_goahead(void) {
    static unsigned char afl_data[4];
    if (read(AFL_PARENT_OUT, afl_data, 4) != 4) {
        fprintf(stderr, "No goahead from parent AFL process!\n");
        exit(2);
    }
}

void ptrace_child(pid_t child_pid) {
    if (ptrace(PTRACE_SEIZE, child_pid, NULL, NULL) < 0) {
        fprintf(stderr, "Failed to ptrace seize child process.\n"
                "Please check restore.log. %s",
                strerror(errno));
        exit(5);
    }
}

void send_afl_data(u_int8_t data[4]) {
    if (write(AFL_PARENT_IN, data, 4) != 4) {
        fprintf(stderr, "Failed to write data to afl. %s",
                strerror(errno));
        exit(5);
    }
}

char child_wait_cmd[1024] = {0};
void wait_for_children(void) {
  char *buff = NULL;
  size_t len = 255;
  FILE *fp = popen(child_wait_cmd, "r");
  while (getline(&buff, &len, fp) >= 0) {
    waitpid(atoi(buff), 0, WNOHANG);
  }
  free(buff);
  fclose(fp);
}

void send_afl_run_status(pid_t child_pid) {
    int status;
    while (1) {
        int w = waitpid(child_pid, &status, __WALL);

        if (w == -1) {
            perror("waitpid error :");
            exit(5);
        }

        if (WIFEXITED(status) || WIFSIGNALED(status)) {
            if (WEXITSTATUS(status) != 0) {
                status = WEXITSTATUS(status);
            }
            send_afl_data((u_int8_t *) &status);
            break;
        }
    }
}

void create_shm(const char *checkpoint_dir) {
    char path[1024];
    strcpy(path, checkpoint_dir);
    strcat(path, "shm_id");
    FILE *shm_f = fopen(path, "w+");
    fputs(getenv(SHM_ENV_VAR), shm_f);
    fclose(shm_f);
}

void create_pid(const char *syncdir_path) {
    char tmp[1024];
    sprintf(tmp, "%s/parent_pid", syncdir_path);
    FILE *pid_file = fopen(tmp, "w+");
    pid_t my_pid = getpid();
    fwrite(&my_pid, sizeof(my_pid), 1, pid_file);
    fclose(pid_file);
}

void create_child_pipe(void) {
    int pipefd[2];
    if (pipe(pipefd)) {
        fprintf(stderr, "Failed to create pipe for child PID. %s\n",
                strerror(errno));
        exit(5);
    }
    dup2(pipefd[1], CHILD_PIPE_IN);
    dup2(pipefd[0], CHILD_PIPE_OUT);
    close(pipefd[0]);
    close(pipefd[1]);
}

char criu_restore_cmd[4098];
pid_t create_child(const char *checkpoint_dir) {
    pid_t pid = fork();
    if (!pid) {
	    while (system(criu_restore_cmd)) {
               wait_for_children();
	    }
	    exit(0);
    }
    if (read(CHILD_PIPE_OUT, &pid, 4) != 4) {
        fprintf(stderr, "Parent failed to read child PID during criu restore.\n");
        exit(5);
    }
    return pid;
}

int main(int argc, char **argv) {
    if (argc != 3) {
        fprintf(stderr, "USAGE: sm-fuzzer {syncdir fuzzer path} {checkpoint dir}\n");
        exit(5);
    }

    create_pid(argv[1]);
    create_shm(argv[2]);
    create_child_pipe();
    sprintf(child_wait_cmd, "ps -aef | awk '$3==%u {print $2}'", getpid());
    sprintf(criu_restore_cmd, "criu restore -d -S -D %s -v4 -o restore.log", argv[2]);

    /* Tell the parent AFL Process we are alive */
    send_afl_data((uint8_t *) "here");

    while (1) {
        wait_for_afl_goahead();
        pid_t child_pid = create_child(argv[2]);
        ptrace_child(child_pid);
        send_afl_data((uint8_t *) &child_pid);
        send_afl_run_status(child_pid);
        wait_for_children();
    }
}
