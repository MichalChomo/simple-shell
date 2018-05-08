#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include <unistd.h>
#include <string.h>
#include <signal.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <pthread.h>
#include <errno.h>
#include <ctype.h>
#include <fcntl.h>
#include <dirent.h>

#define INPUT_SIZE 513
#define MSG_LEN 64
#define ARG_SIZE 32

static const char *prompt = "$ ";
static const char *too_long = "Input too long, ignored\n";
static const char *read_failed = "read() failed\n";
static const char *open_failed = "open() failed\n";
static const char *close_failed = "close() failed\n";
static const char *dup_failed = "dup() failed\n";

pthread_mutex_t mutex;
pthread_cond_t pthread_condition;
char buf[INPUT_SIZE] = {0};
bool read_finished = false;
bool is_exit = false;

extern char **environ;

/**
 * SIGTERM and SIGINT handler.
 */
void exit_handler() {
    is_exit = true;
}

/**
 * SIGCHLD handler.
 */
void child_exit_handler() {
    int status;
    pid_t pid = wait(&status);
    char msg[MSG_LEN];
    int errno_backup = errno;

    sprintf(msg, "[ %d ] exit", pid);
    write(STDOUT_FILENO, msg, strlen((const char*) msg));
    memset(msg, 0, MSG_LEN);
    if (WIFEXITED(status)) {
        sprintf(msg, " with code %d\n", WEXITSTATUS(status));
    } else if (WCOREDUMP(status)) {
        sprintf(msg, " with core dump, signal %d\n", WTERMSIG(status));
    } else {
        sprintf(msg, " , unkown type of termination\n");
    }
    write(STDOUT_FILENO, msg, strlen((const char*) msg));
    sprintf(msg, "$ ");
    write(STDOUT_FILENO, msg, strlen((const char*) msg));
    errno = errno_backup;
}

/**
 * Find redirection character in string and add spaces around it to enable
 * parsing.
 * @param str String to search in.
 * @return String with spaces around redirection character.
 */
char *add_spaces_around_redirect(char *str) {
    char *ret = malloc(strlen(str) + 3);
    char *c = strchr(str, '<');
    int index;
    if (c == NULL) {
        c = strchr(str, '>');
        if (c == NULL) {
            free(ret);
            return NULL;
        }
        index = (int)(c - str);
        memcpy(ret, str, index);
        memcpy(ret + index, " > ", 3);
        memcpy(ret + index + 3, str + index + 1, strlen(str) - index);
    } else {
        index = (int)(c - str);
        memcpy(ret, str, index);
        memcpy(ret + index, " < ", 3);
        memcpy(ret + index + 3, str + index + 1, strlen(str) - index);
    }
    return ret;
}

/**
 * Split the string into substrings delimited by space.
 * @param str String to split.
 * @return Array of substrings.
 */
char **str_split(char *str) {
    char **tmp = malloc(ARG_SIZE * sizeof(char*));
    char *token = NULL;
    char *str_redirect = NULL;
    int i = 0;

    if (str == NULL) {
        tmp[i] = NULL;
        return tmp;
    }
    str_redirect = add_spaces_around_redirect(str);
    if (str_redirect == NULL) {
        str_redirect = str;
    }
    token = strtok(str_redirect, " ");
    while (token != NULL) {
        tmp[i] = malloc(strlen((const char*) token) + 1);
        strcpy(tmp[i], token);
        ++i;
        token = strtok(NULL, " ");
    }
    tmp[i] = NULL;

    return tmp;
}

/**
 * Redirect standard input to file.
 * @param ifilename File to redirect to.
 * @return Original standard input file descriptor.
 */
int set_input_file(const char *ifilename) {
    int stdinfd;
    int inputfd = open(ifilename, O_RDONLY);
    if (inputfd < 0) {
        write(STDERR_FILENO, open_failed, strlen(open_failed));
        return -1;
    }
    stdinfd = dup(STDIN_FILENO); // Save stdin descriptor for restoring.
    if (dup(inputfd) < 0) {
        write(STDERR_FILENO, dup_failed, strlen(dup_failed));
        return -1;
    }
    // Redirect stdin to the file.
    if (dup2(inputfd, STDIN_FILENO) < 0) {
        write(STDERR_FILENO, dup_failed, strlen(dup_failed));
    }
    if (close(inputfd) < 0) {
        write(STDERR_FILENO, close_failed, strlen(close_failed));
        return -1;
    }

    return stdinfd;
}

/**
 * Redirect standard output to file.
 * @param ofilename File to redirect to.
 * @return Original standard output file descriptor.
 */
int set_output_file(const char *ofilename) {
    int stdoutfd;
    int outputfd = open(ofilename, O_WRONLY | O_CREAT | O_TRUNC,
                                  S_IRWXU | S_IRGRP | S_IROTH);
    if (outputfd < 0) {
        write(STDERR_FILENO, open_failed, strlen(open_failed));
        return -1;
    }
    stdoutfd = dup(STDOUT_FILENO); // Save stdout descriptor for restoring.
    if (stdoutfd < 0) {
        write(STDERR_FILENO, dup_failed, strlen(dup_failed));
        return -1;
    }
    // Redirect stdout to the file.
    if (dup2(outputfd, STDOUT_FILENO) < 0) {
        write(STDERR_FILENO, dup_failed, strlen(dup_failed));
    }
    if (close(outputfd) < 0) {
        write(STDERR_FILENO, close_failed, strlen(close_failed));
        return -1;
    }

    return stdoutfd;
}

/**
 * Find out if input or output is redirected and the file to redirect to.
 * @param args        Command line arguments.
 * @param redirect_to File to redirect to, caller must free it.
 * @return 0 - no redirection
 *         1 - stdin redirected
 *         2 - stdout redirected
 */
int check_redirected(char **args, char **redirect_to) {
    bool is_stdin;
    bool is_stdout;
    for (int i = 0; args[i] != NULL; ++i) {
        is_stdin = strcmp(args[i], "<") == 0;
        is_stdout = strcmp(args[i], ">") == 0;
        if (is_stdin || is_stdout) {
            *redirect_to = malloc(strlen(args[i+1]) + 1);
            strcpy(*redirect_to, args[i+1]);
            free(args[i]);
            free(args[i+1]);
            args[i] = NULL;
            args[i+1] = NULL;
        }
        if (is_stdin) {
            return 1;
        } else if (is_stdout) {
            return 2;
        }
    }

    return 0;
}

/**
 * Check if command should run in background.
 * @param args Command line arguments.
 */
bool check_background(char **args) {
    for (int i = 0;; ++i) {
        if (args[i] == NULL) {
            if (strcmp(args[i-1], "&") == 0) {
                free(args[i-1]);
                args[i-1] = NULL;
                return true;
            } else {
                return false;
            }
        }
    }
}

/**
 * Turn handling of SIGCHLD on/off.
 * @param do_handle Determines if handling is on/off.
 */
void set_sigchld_handling(bool do_handle) {
    struct sigaction act;
    sigset_t mask;
    sigemptyset(&mask);
    sigaddset(&mask, SIGINT);
    sigaddset(&mask, SIGTERM);
    if (do_handle) {
        act.sa_handler = child_exit_handler;
    } else {
        act.sa_handler = SIG_DFL;
    }
    act.sa_mask = mask;
    act.sa_flags = SA_NOCLDSTOP;
    sigaction(SIGCHLD, &act, NULL);
}

/**
 * Free the command line arguments array.
 * @param args Array of command line arguments.
 */
void free_args(char **args) {
    for (int i = 0; args[i] != NULL; ++i) {
        free(args[i]);
    }
    free(args);
}

/**
 * Restore the original file descriptor of standard input/output and free
 * the redirected one.
 * @param redirect    Determines if standard input or output was redirected.
 * @param fd          Original file descriptor of standard input/output.
 * @param redirect_to Name of the file input/output redirected to.
 */
void undo_redirect(int redirect, int fd, char *redirect_to) {
    if (redirect == 1) {
        dup2(fd, STDIN_FILENO);
    } else if (redirect == 2) {
        dup2(fd, STDOUT_FILENO);
    }
    if (redirect > 0) {
        close(fd);
        if (redirect_to != NULL) {
            free(redirect_to);
        }
    }
}

/**
 * Parse command line arguments and execute the command.
 */
void *executor_func() {
    pid_t child_pid;
    int fd;
    char **args;
    char *redirect_to = NULL;
    int redirect;
    bool is_background;

    while (!is_exit) {
        pthread_mutex_lock(&mutex);
        while (!read_finished) {
            pthread_cond_wait(&pthread_condition, &mutex);
        }
        args = str_split(buf);
        if (args[0] == NULL) {
            free_args(args);
            read_finished = false;
            pthread_mutex_unlock(&mutex);
            continue;
        } else if (strcmp(args[0], "exit") == 0) {
            free_args(args);
            is_exit = true;
            pthread_mutex_unlock(&mutex);
            break;
        }
        redirect = check_redirected(args, &redirect_to);
        if (redirect == 1) {
            fd = set_input_file(redirect_to);
        } else if (redirect == 2) {
            fd = set_output_file(redirect_to);
        }
        is_background = check_background(args);
        if (is_background) {
            redirect = 2;
            redirect_to = malloc(strlen("/dev/null") + 1);
            strcpy(redirect_to, "/dev/null");
            fd = set_output_file(redirect_to);
            set_sigchld_handling(true);
        } else {
            set_sigchld_handling(false);
        }
        child_pid = fork();
        if (child_pid == 0) {
            execvp(args[0], args);
            free_args(args);
            break;
        } else {
            free_args(args);
            undo_redirect(redirect, fd, redirect_to);
            memset(buf, 0, INPUT_SIZE);
            if (!is_background) {
                while (true) {
                    if (waitpid(child_pid, NULL, WNOHANG) > 0) {
                        is_exit = false;
                        break;
                    }
                }
            }
            read_finished = false;
            pthread_mutex_unlock(&mutex);
        }
    }
    pthread_exit(NULL);
}

int main(int argc, char *argv[], char **envp) {
    int ret;
    pthread_t executor_thread;
    struct sigaction act;
    sigset_t mask;
    sigemptyset(&mask);
    act.sa_handler = exit_handler;
    act.sa_mask = mask;
    act.sa_flags = 0;
    sigaction(SIGTERM, &act, NULL);
    sigaction(SIGINT, &act, NULL);

    environ = envp;
    
    ret = pthread_mutex_init(&mutex, NULL);
    if (ret != 0) {
        fprintf(stderr, "Can't init mutex: %s\n", strerror(ret));
        return 2;
    }
    ret = pthread_cond_init(&pthread_condition, NULL);
    if (ret != 0) {
        fprintf(stderr, "Can't init condition variable: %s\n", strerror(ret));
        return 3;
    }
    ret = pthread_create(&executor_thread, NULL, &executor_func, NULL);
    if (ret != 0) {
        fprintf(stderr, "Can't create thread: %s\n", strerror(ret));
        return 1;
    }

    while (!is_exit) {
        pthread_mutex_lock(&mutex);
        memset(buf, 0, INPUT_SIZE);
        write(STDOUT_FILENO, prompt, strlen(prompt));
        ret = read(fileno(stdin), buf, INPUT_SIZE);
        read_finished = true;
        if (ret < 0) {
            if (!is_exit) {
                write(STDERR_FILENO, read_failed, strlen(read_failed));
            }
        } else if (ret < INPUT_SIZE) {
            if (isspace(buf[strlen(buf) - 1]) != 0) {
                buf[strlen(buf) - 1] = 0;
            }
        } else {
            write(STDERR_FILENO, too_long, strlen(too_long));
            // Read until the end of input.
            while (read(fileno(stdin), buf, INPUT_SIZE) >= INPUT_SIZE);
        }
        pthread_cond_signal(&pthread_condition);
        pthread_mutex_unlock(&mutex);
        usleep(1000);
    }

    pthread_join(executor_thread, NULL);
    pthread_mutex_destroy(&mutex);

    return 0;
}
