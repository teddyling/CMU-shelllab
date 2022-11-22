/**
 * @file tsh.c
 * @brief A tiny shell program with job control
 *
 * TODO: Delete this comment and replace it with your own.
 * <The line above is not a sufficient documentation.
 *  You will need to write your program documentation.
 *  Follow the 15-213/18-213/15-513 style guide at
 *  http://www.cs.cmu.edu/~213/codeStyle.html.>
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
 * @brief <What does eval do?>
 *
 * TODO: Delete this comment and replace it with your own.
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
    // receive "job"
    if (token.builtin == BUILTIN_JOBS) {
        sigprocmask(SIG_BLOCK, &mask, &prev);
        if (!list_jobs(STDOUT_FILENO)) {
            printf("An error ocurred while writing to the file descriptor\n");
        };
        sigprocmask(SIG_SETMASK, &prev, NULL);
        return;
    }
    // receive "bg" or "fg"
    if (token.builtin == BUILTIN_BG || token.builtin == BUILTIN_FG) {
        sigprocmask(SIG_BLOCK, &mask, &prev);
        char* next = token.argv[1];
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
            char* start = next + 1;
            char** end = NULL;
            jid_t parsedJID = (jid_t) strtol(start, end, 10);
            // check if the given JID exists.
            if (!job_exists(parsedJID)) {
                printf("%%%d: No such job\n", parsedJID);
                sigprocmask(SIG_SETMASK, &prev, NULL);
                return;
            }
            thisPID = job_get_pid(parsedJID);
        // pid provided
        } else if (next[0] >= '0' && next[0] <= '9') {
            char* start = next;
            char** end = NULL;
            pid_t parsedPID = (pid_t) strtol(start, end, 10);
            jid_t corJID = job_from_pid(parsedPID);
            if (corJID  == 0) {
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
            const char* jobcmd = job_get_cmdline(thisJID);
            sigprocmask(SIG_SETMASK, &prev, NULL);
            printf("[%d] (%d) %s\n", thisJID, thisPID, jobcmd);
            return;
        // If the continued job is foreground, change its state and wait for it to finish
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
    // Has to block all signals here instead of only blocking SIGCHLD, or race condition will occur if send SIGINT or SIGTSTP to the fg job.
    sigprocmask(SIG_BLOCK, &mask, &prev);
    if ((pid = fork()) == 0) {
        sigprocmask(SIG_SETMASK, &prev, NULL);
        setpgid(0, 0);
        if (execve(token.argv[0], token.argv, environ) < 0) { 
            printf("execve failed\n");
            return;
        }
    }
    if (parse_result == PARSELINE_FG) {
        add_job(pid, FG, cmdline);
        jid_t jid = job_from_pid(pid);
        while(fg_job() == jid) {
            sigsuspend(&prev);
        }
        sigprocmask(SIG_SETMASK, &prev, NULL);


    } else if (parse_result == PARSELINE_BG){
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
 * @brief <What does sigchld_handler do?>
 *
 * TODO: Delete this comment and replace it with your own.
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
                sio_printf("Job [%d] (%d) terminated normally (status %d)\n", deletedJob, pid, WEXITSTATUS(status));
            }
            delete_job(deletedJob);
            sigprocmask(SIG_SETMASK, &prev, NULL);
        // A child is terminated by a signal(SIGINT)
        } else if (WIFSIGNALED(status)) {
            sigprocmask(SIG_BLOCK, &mask, &prev);
            jid_t deletedJob = job_from_pid(pid);
            int termSignal = WTERMSIG(status);
            sio_printf("Job [%d] (%d) terminated by signal %d\n", deletedJob, pid, termSignal);
            delete_job(deletedJob);
            sigprocmask(SIG_SETMASK, &prev, NULL);
        // A child is stopped by receving SIGTSTP
        } else if (WIFSTOPPED(status)) {
            sigprocmask(SIG_BLOCK, &mask, &prev);
            jid_t stoppedJob = job_from_pid(pid);
            int stopSignal = WSTOPSIG(status);
            sio_printf("Job [%d] (%d) stopped by signal %d\n", stoppedJob, pid, stopSignal);
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
 * @brief <What does sigint_handler do?>
 *
 * TODO: Delete this comment and replace it with your own.
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
        if (kill(-fgpid, sig) == -1) {
            sio_printf("Failed to send signal\n");
        }
    }
    sigprocmask(SIG_SETMASK, &prev, NULL);
    errno = olderrno;
}

/**
 * @brief <What does sigtstp_handler do?>
 *
 * TODO: Delete this comment and replace it with your own.
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
        if (kill(-fgpid, sig) == -1) {
            sio_printf("Failed to send signal\n");
        }
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
