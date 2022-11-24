/**
 * @file tsh.c
 * @brief A tiny shell program with job control
 *
 * This .c file is an implementation of a Linux shell program called tiny shell
 * (tsh). This shell support limited features such as built-in command
 * operation, foreground/background job control and management, and Input/Output
 * redirection.
 *
 * The user can use this shell as a normal shell (such as bash) to run jobs.
 * There are two types of jobs that tsh supports, a foreground job and a
 * background job. A job is recognized as a foreground job by default. It means
 * that until this job process is terminated or stopped, the shell will not be
 * ready for the next command. The user can also run a job in the background by
 * adding a "&" to the end of the command line.
 *
 * The command line can be divided into two types, the built-in command and the
 * non-built-in command. For the built-in commands, there are four commands that
 * tsh support. "quit": The shell will terminate "jobs" the shell will print out
 * a list of all current background jobs. "bg (PID)" or bg (%JID): The shell
 * will resume this job and run it as a background job. "fg (PID)" or fg (%JID):
 * The shell will resume this job and run it as a foreground job.
 *
 * If the given command line is not parsed as a built-in command, then the shell
 * will run the input job either in foreground or in background as the user's
 * request. The shell is also able to reap all the terminated or changed state
 * children. The signal handler for SIGINT will do all the jobs without waiting
 * for child termination. As the foreground job runs, the user can send two
 * signals to the foreground job, SIGINT and SIGTSTP. By typing CRTL+C, the user
 * can send a SIGINT to the entire process group that contains the foreground
 * job. The job will terminate when it receives this signal, and this job will
 * be removed from the job list. By typing CRTL+Z, the user can send a SIGTSTP
 * to the entire process group that contains the foreground job. The job will be
 * stopped when it receives this signal. The user can resume this job by using
 * the built-in command bg/fg (PID)/(%JID).
 *
 * The shell also supports input and output redirection.
 * If the user want to change the output destination from stdout to a file, the
 * character > followed by a location can be used to alter the source of the
 * output. If the user want to change the input destination from stdin to a
 * file, the character < followed by a location can be used to alter the source
 * of the input.
 *
 * @author Taichen Ling <taichenl@andrew.cmu.edu>
 */

#include "csapp.h"
#include "tsh_helper.h"

#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <getopt.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

/*
 * If DEBUG is defined, enable contracts and printing on dbg_printf.
 */
#ifdef DEBUG
/* When debugging is enabled, these form aliases to useful functions */
#define dbg_printf(...) printf(__VA_ARGS__)
#define dbg_requires(...) assert(__VA_ARGS__)
#define dbg_assert(...) assert(__VA_ARGS__)
#define dbg_ensures(...) assert(__VA_ARGS__)
#else
/* When debugging is disabled, no code gets generated for these */
#define dbg_printf(...)
#define dbg_requires(...)
#define dbg_assert(...)
#define dbg_ensures(...)
#endif

/* Function prototypes */
void eval(const char *cmdline);

void sigchld_handler(int sig);
void sigtstp_handler(int sig);
void sigint_handler(int sig);
void sigquit_handler(int sig);
void cleanup(void);

/**
 * @brief <Write main's function header documentation. What does main do?>
 *
 * TODO: Delete this comment and replace it with your own.
 *
 * "Each function should be prefaced with a comment describing the purpose
 *  of the function (in a sentence or two), the function's arguments and
 *  return value, any error cases that are relevant to the caller,
 *  any pertinent side effects, and any assumptions that the function makes."
 */
int main(int argc, char **argv) {
    int c;
    char cmdline[MAXLINE_TSH]; // Cmdline for fgets
    bool emit_prompt = true;   // Emit prompt (default)

    // Redirect stderr to stdout (so that driver will get all output
    // on the pipe connected to stdout)
    if (dup2(STDOUT_FILENO, STDERR_FILENO) < 0) {
        perror("dup2 error");
        exit(1);
    }

    // Parse the command line
    while ((c = getopt(argc, argv, "hvp")) != EOF) {
        switch (c) {
        case 'h': // Prints help message
            usage();
            break;
        case 'v': // Emits additional diagnostic info
            verbose = true;
            break;
        case 'p': // Disables prompt printing
            emit_prompt = false;
            break;
        default:
            usage();
        }
    }

    // Create environment variable
    if (putenv(strdup("MY_ENV=42")) < 0) {
        perror("putenv error");
        exit(1);
    }

    // Set buffering mode of stdout to line buffering.
    // This prevents lines from being printed in the wrong order.
    if (setvbuf(stdout, NULL, _IOLBF, 0) < 0) {
        perror("setvbuf error");
        exit(1);
    }

    // Initialize the job list
    init_job_list();

    // Register a function to clean up the job list on program termination.
    // The function may not run in the case of abnormal termination (e.g. when
    // using exit or terminating due to a signal handler), so in those cases,
    // we trust that the OS will clean up any remaining resources.
    if (atexit(cleanup) < 0) {
        perror("atexit error");
        exit(1);
    }

    // Install the signal handlers
    Signal(SIGINT, sigint_handler);   // Handles Ctrl-C
    Signal(SIGTSTP, sigtstp_handler); // Handles Ctrl-Z
    Signal(SIGCHLD, sigchld_handler); // Handles terminated or stopped child

    Signal(SIGTTIN, SIG_IGN);
    Signal(SIGTTOU, SIG_IGN);

    Signal(SIGQUIT, sigquit_handler);

    // Execute the shell's read/eval loop
    while (true) {
        if (emit_prompt) {
            printf("%s", prompt);

            // We must flush stdout since we are not printing a full line.
            fflush(stdout);
        }

        if ((fgets(cmdline, MAXLINE_TSH, stdin) == NULL) && ferror(stdin)) {
            perror("fgets error");
            exit(1);
        }

        if (feof(stdin)) {
            // End of file (Ctrl-D)
            printf("\n");
            return 0;
        }

        // Remove any trailing newline
        char *newline = strchr(cmdline, '\n');
        if (newline != NULL) {
            *newline = '\0';
        }

        // Evaluate the command line
        eval(cmdline);
    }

    return -1; // control never reaches here
}

/**
 * @brief eval is the main routine that parse, translate, and process the
 * command line arguments.
 *
 * The function "eval" can be divided into two main parts, built-in command
 * handling, and non-built-in command handling. Firstly the function will
 * evaluate the validity of the command line input. If it is an invalid line or
 * line with errors, it will do nothing and return. Then it will evaluate the
 * command line and see if it is one of the four built-in commands. -If it is
 * the built-in command "quit," then the shell will terminate by calling exit(0)
 * -If it is the built-in command "jobs," the shell will print out a list of all
 * current background jobs. -If it is the built-in command "bg," followed by a
 * PID or a JID, the shell will resume this job by sending a SIGCONT signal and
 * run this job as a background job. -If it is the built-in command "fg,"
 * followed by a PID or a JID, the shell will resume this job by sending a
 * SIGCONT signal and run this job as a background job. If it is non of the
 * cases above, the shell will fork a child to run the provided job from the
 * command line.
 *
 * NOTE: The shell is supposed to be a long-running process, so this function
 *       (and its helpers) should avoid exiting on error.  This is not to say
 *       they shouldn't detect and print (or otherwise handle) errors!
 */

void eval(const char *cmdline) {
    parseline_return parse_result;
    struct cmdline_tokens token;

    // Parse command line
    parse_result = parseline(cmdline, &token);
    sigset_t mask;
    sigset_t prev;
    sigset_t empty;
    sigfillset(&mask);

    if (parse_result == PARSELINE_ERROR || parse_result == PARSELINE_EMPTY) {
        return;
    }
    // receive "quit"
    if (token.builtin == BUILTIN_QUIT) {
        exit(0);
    }
    // receive "jobs"
    if (token.builtin == BUILTIN_JOBS) {
        sigprocmask(SIG_BLOCK, &mask, &prev);
        if (token.outfile != NULL) {
            int fd = open(token.outfile, O_WRONLY | O_CREAT, 0666);
            if (fd < 0) {
                printf("%s\n", strerror(errno));
                return;
            }
            dup2(STDOUT_FILENO, fd);
            if (!list_jobs(fd)) {
                printf(
                    "An error occured while writing to the file descriptor\n");
            }
        } else {
            if (!list_jobs(STDOUT_FILENO)) {
                printf(
                    "An error ocurred while writing to the file descriptor\n");
            }
        }

        sigprocmask(SIG_SETMASK, &prev, NULL);
        return;
    }
    // receive "bg" or "fg"
    if (token.builtin == BUILTIN_BG || token.builtin == BUILTIN_FG) {
        sigprocmask(SIG_BLOCK, &mask, &prev);
        char *next = token.argv[1];
        pid_t thisPID;
        // Empty after bg or fg
        if (next == NULL) {
            sigprocmask(SIG_SETMASK, &prev, NULL);
            if (token.builtin == BUILTIN_BG) {
                printf("bg command requires PID or %%jobid argument\n");
            } else {
                printf("fg command requires PID or %%jobid argument\n");
            }
            return;
        }
        // JID Provided
        if (next[0] == '%') {
            char *start = next + 1;
            char **end = NULL;
            jid_t parsedJID = (jid_t)strtol(start, end, 10);
            // check if the given JID exists.
            if (!job_exists(parsedJID)) {
                printf("%%%d: No such job\n", parsedJID);
                sigprocmask(SIG_SETMASK, &prev, NULL);
                return;
            }
            thisPID = job_get_pid(parsedJID);
            // pid provided
        } else if (next[0] >= '0' && next[0] <= '9') {
            char *start = next;
            char **end = NULL;
            pid_t parsedPID = (pid_t)strtol(start, end, 10);
            jid_t corJID = job_from_pid(parsedPID);
            if (corJID == 0) {
                printf("No such job\n");
                sigprocmask(SIG_SETMASK, &prev, NULL);
                return;
            }
            thisPID = parsedPID;
            // not a % (jid) or a number (pid), must be invalid.
        } else {
            sigprocmask(SIG_SETMASK, &prev, NULL);
            if (token.builtin == BUILTIN_BG) {
                printf("bg: argument must be a PID or %%jobid\n");

            } else {
                printf("fg: argument must be a PID or %%jobid\n");
            }
            return;
        }
        jid_t thisJID = job_from_pid(thisPID);
        // If the continued job is background, change its state and print
        if (token.builtin == BUILTIN_BG) {
            job_set_state(thisJID, BG);
            if (kill(-thisPID, SIGCONT) == -1) {
                printf("Failed to send signal\n");
                return;
            }
            const char *jobcmd = job_get_cmdline(thisJID);
            sigprocmask(SIG_SETMASK, &prev, NULL);
            printf("[%d] (%d) %s\n", thisJID, thisPID, jobcmd);
            return;
            // If the continued job is foreground, change its state and wait for
            // it to finish
        } else {
            job_set_state(thisJID, FG);
            if (kill(-thisPID, SIGCONT) == -1) {
                printf("Failed to send signal\n");
                return;
            }
            while (fg_job() == thisJID) {
                sigsuspend(&prev);
            }
            sigprocmask(SIG_SETMASK, &prev, NULL);
            return;
        }
    }
    // If the codes reach here, the command is not builtin command.
    sigemptyset(&empty);
    pid_t pid;
    // Has to block all signals here instead of only blocking SIGCHLD, or race
    // condition will occur if send SIGINT or SIGTSTP to the fg job.
    sigprocmask(SIG_BLOCK, &mask, &prev);
    if ((pid = fork()) == 0) {
        sigprocmask(SIG_SETMASK, &prev, NULL);
        setpgid(0, 0);
        // If output file is given, do output redirection
        if (token.infile == NULL && token.outfile != NULL) {
            int fd = open(token.outfile, O_WRONLY | O_CREAT, 0666);
            dup2(STDOUT_FILENO, fd);
            if (execve(token.argv[0], token.argv, environ) < 0) {
                printf("execve failed\n");
                return;
            }
            // If input file is given, do input redirection
        } else if (token.infile != NULL && token.outfile == NULL) {
            int fd = open(token.infile, O_RDONLY, 0);
            if (fd < 0) {
                printf("%s: %s\n", token.infile, strerror(errno));
                exit(1);
            }
            dup2(fd, STDIN_FILENO);
            if (execve(token.argv[0], token.argv, environ) < 0) {
                printf("execve failed\n");
                return;
            }
            // If both input and output files are given, do redirection.
        } else if (token.infile != NULL && token.outfile != NULL) {
            int fdin = open(token.infile, O_RDONLY, 0);
            int fdout = open(token.outfile, O_WRONLY | O_CREAT, 0666);
            if (fdin < 0) {
                printf("%s: %s\n", token.infile, strerror(errno));
                exit(1);
            }
            dup2(fdin, STDIN_FILENO);
            dup2(STDOUT_FILENO, fdout);
            if (execve(token.argv[0], token.argv, environ) < 0) {
                printf("execve failed\n");
                return;
            }
            // No I/O file given, do STDIN and STDOUT.
        } else {
            if (execve(token.argv[0], token.argv, environ) < 0) {
                printf("execve failed\n");
                return;
            }
        }
    }
    if (parse_result == PARSELINE_FG) {
        add_job(pid, FG, cmdline);
        jid_t jid = job_from_pid(pid);
        while (fg_job() == jid) {
            sigsuspend(&prev);
        }
        sigprocmask(SIG_SETMASK, &prev, NULL);

    } else if (parse_result == PARSELINE_BG) {
        add_job(pid, BG, cmdline);
        jid_t jid = job_from_pid(pid);
        sigprocmask(SIG_SETMASK, &prev, NULL);
        printf("[%d] (%d) %s\n", jid, pid, cmdline);
    }
    return;
}

/*****************
 * Signal handlers
 *****************/

/**
 * @brief sigchld_hander will handle the SIGCHLD signal. When the process
 * receive SIGCHLD, this handler will trigger.
 *
 * TODO: This function will trigger every time the process receives a SIGCHLD
 * signal. It reaps or change the state of child processes. The waitpid function
 * will not suspends execution of the calling process by passing in WNOHANG. It
 * will return the pid of the reaped process or value 0 immediately. The waitpid
 * function will also return when a child process becomes stopped by passing in
 * WUNTRACED. After the function got a pid return, it will check the status. If
 * WIFEXITED(status), means the child process terminated normally. The job will
 * be deleted from the job list If WIFSIGNALED(status), means the child process
 * is terminated by a signal. THe job will be deleted from the job list, and
 * print a message indicating this. If WIFSTOPPED(status), means that the child
 * process is stopped for some reason. This job's state will be set to ST
 * (stop), and print a message indicating this.
 */
void sigchld_handler(int sig) {
    int olderrno = errno;
    sigset_t mask;
    sigset_t prev;
    pid_t pid;
    int status;
    sigfillset(&mask);
    while ((pid = waitpid(-1, &status, WNOHANG | WUNTRACED)) > 0) {
        // A child is terminated normally
        if (WIFEXITED(status)) {
            sigprocmask(SIG_BLOCK, &mask, &prev);
            jid_t deletedJob = job_from_pid(pid);
            if (verbose) {
                sio_printf("Job [%d] (%d) terminated normally (status %d)\n",
                           deletedJob, pid, WEXITSTATUS(status));
            }
            delete_job(deletedJob);
            sigprocmask(SIG_SETMASK, &prev, NULL);
            // A child is terminated by a signal(SIGINT)
        } else if (WIFSIGNALED(status)) {
            sigprocmask(SIG_BLOCK, &mask, &prev);
            jid_t deletedJob = job_from_pid(pid);
            int termSignal = WTERMSIG(status);
            sio_printf("Job [%d] (%d) terminated by signal %d\n", deletedJob,
                       pid, termSignal);
            delete_job(deletedJob);
            sigprocmask(SIG_SETMASK, &prev, NULL);
            // A child is stopped by receving SIGTSTP
        } else if (WIFSTOPPED(status)) {
            sigprocmask(SIG_BLOCK, &mask, &prev);
            jid_t stoppedJob = job_from_pid(pid);
            int stopSignal = WSTOPSIG(status);
            sio_printf("Job [%d] (%d) stopped by signal %d\n", stoppedJob, pid,
                       stopSignal);
            job_set_state(stoppedJob, ST);
            sigprocmask(SIG_SETMASK, &prev, NULL);
            // Other cases
        } else {
            sigprocmask(SIG_BLOCK, &mask, &prev);
            jid_t deletedJob = job_from_pid(pid);
            delete_job(deletedJob);
            sigprocmask(SIG_SETMASK, &prev, NULL);
        }
    }
    errno = olderrno;
}

/**
 * @brief sigint_hander will handle the SIGINT signal. When the process receive
 * SIGINT, this handler will trigger.
 *
 * TODO: This function will trigger every time the process receives a SIGINT
 * signal. The handler will send the signal to the foreground job.
 */
void sigint_handler(int sig) {
    int olderrno = errno;
    sigset_t mask;
    sigset_t prev;
    sigfillset(&mask);
    sigprocmask(SIG_BLOCK, &mask, &prev);
    jid_t fgjid = fg_job();
    if (fgjid != 0) {
        pid_t fgpid = job_get_pid(fgjid);
        kill(-fgpid, sig);
    }
    sigprocmask(SIG_SETMASK, &prev, NULL);
    errno = olderrno;
}

/**
 * @brief sigtstp_hander will handle the SIGTSTP signal. When the process
 * receive SIGTSTP, this handler will trigger.
 *
 * This function will trigger every time the process receives a SIGTSTP signal.
 * The handler will send the signal to the foreground job.
 *
 */
void sigtstp_handler(int sig) {
    int olderrno = errno;
    sigset_t mask;
    sigset_t prev;
    sigfillset(&mask);
    sigprocmask(SIG_BLOCK, &mask, &prev);
    jid_t fgjid = fg_job();
    if (fgjid != 0) {
        pid_t fgpid = job_get_pid(fgjid);
        kill(-fgpid, sig);
    }
    sigprocmask(SIG_SETMASK, &prev, NULL);
    errno = olderrno;
}

/**
 * @brief Attempt to clean up global resources when the program exits.
 *
 * In particular, the job list must be freed at this time, since it may
 * contain leftover buffers from existing or even deleted jobs.
 */
void cleanup(void) {
    // Signals handlers need to be removed before destroying the joblist
    Signal(SIGINT, SIG_DFL);  // Handles Ctrl-C
    Signal(SIGTSTP, SIG_DFL); // Handles Ctrl-Z
    Signal(SIGCHLD, SIG_DFL); // Handles terminated or stopped child

    destroy_job_list();
}
