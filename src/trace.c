#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <unistd.h>
#include <sys/user.h>
#include <sys/wait.h>

#include <syscall.h>
#include <sys/reg.h>
#include <sys/ptrace.h>

#define FATAL(...) \
    do { \
        fprintf(stderr, "strace: " __VA_ARGS__); \
        fputc('\n', stderr); \
        exit(EXIT_FAILURE); \
    } while (0)

void h_openat(pid_t pid);
void h_ptrace(pid_t pid);
void getstr(u_int64_t addr, char *str, int len, pid_t pid);

int main(int argc, char *argv[]) {
	if (argc < 2) {
		FATAL("too few arguments: %d", argc);
	}

	pid_t pid = fork();
	switch (pid) {
		case -1:
			FATAL("%s", strerror(errno));
			break;
		case 0:
			ptrace(PTRACE_TRACEME, 0, 0, 0);

			execvp(argv[1], argv + 1);
			FATAL("%s", strerror(errno));
	}

	int insystem = 0;
	long long orgi_rax, rax;
	int status;
	for (;;) {
		wait(&status);
        if(WIFEXITED(status))
            break;

		struct user_regs_struct regs;
		orgi_rax = ptrace(PTRACE_PEEKUSER, pid, 8 * ORIG_RAX, NULL);

		switch (orgi_rax) {
			case SYS_open:
				ptrace(PTRACE_GETREGS, pid, 0, &regs);
				if (insystem == 0) {
					insystem = 1;
					printf("rax=%lld, rbx=%lld, rcx=%lld. rdx=%lld\n",
							regs.rax, regs.rbx, regs.rcx, regs.rdx);
				} else {
					insystem = 0;
					printf("return %lld", regs.rax);
				}
				break;
			case SYS_openat:
				h_openat(pid);
				break;
			case SYS_ptrace:
				h_ptrace(pid);
				break;
			case SYS_exit:
				ptrace(PTRACE_GETREGS, pid, 0, &regs);
				exit(regs.rdi);
				break;
		}
		if (ptrace(PTRACE_SYSCALL, pid, 0, 0) == -1) {
            FATAL("%s", strerror(errno));
        }
	}
	return 0;
}

void h_ptrace(pid_t pid) {
	static int insystem = 0;
	struct user_regs_struct regs;
	if (!insystem) {
		insystem = 1;
		return;
	} else {
		// 出系统调用
		insystem = 0;
		ptrace(PTRACE_GETREGS, pid, 0, &regs);
		printf("SYS_ptrace: return %lld\n", regs.rax);
		// 强制子进程更改返回值为非-1
		puts("更改pthread返回值");
		regs.rax = 0;
		ptrace(PTRACE_SETREGS, pid, 0, &regs);
	}
}

bool havech(char a[], int len, char c) {
	while (len-- > 0) {
		if (a[len] == c) {
			return true;
		}
	}
	return false;
}

void getstr(u_int64_t addr, char *str, int len, pid_t pid) {
	int i = 0;
	union {
		long c;
		char s[8];
	}data;

	int j = len / 8;
	char *tstr = str;

	memset(data.s, 1, 8);
	while (i < j && !havech(data.s, 8, '\0')) {
		data.c = ptrace(PTRACE_PEEKDATA, pid, addr+i*8, NULL);
		memcpy(tstr, data.s, 8);
		tstr += 8;
		i += 1;
	}
	j = len % 8;
	if (j != 0 && !havech(data.s, 8, '\0')) {
		data.c = ptrace(PTRACE_PEEKDATA, pid, addr+i*8, NULL);
		memcpy(tstr, data.s, j);
		tstr += j;
	}
	*tstr = '\0';
}

void h_openat(pid_t pid) {
	static int insystem = 0;
	struct user_regs_struct regs;
	char str[256];

	ptrace(PTRACE_GETREGS, pid, 0, &regs);
	if (!insystem) {
		// 进入系统调用
		insystem = 1;
		getstr(regs.rsi, str, sizeof(str), pid);
//		 printf("SYS_opennat: rbx=%lld,  rcx=%lld, rdx=%lld. rsi=%llx\n",
//				regs.rbx, regs.rcx, regs.rdx, regs.rsi);
		printf("SYS_openat: %s\n", str);

	} else {
		// 出系统调用
		insystem = 0;
		printf("SYS_opennat： return %lld\n", regs.rax);
	}
}
