#include "headers.h"
#include <unistd.h>

#define STACK_SIZE (1024*1024)
static char stack[STACK_SIZE];

int pipefd[2];

char *const c_args[] = {
	"/bin/bash",
	NULL,
};

// c_main 
int c_main(void *arg) {
	char ch;
	int ret;
	
	// 等待父进程
	close(pipefd[1]);
	read(pipefd[0], &ch, 1);

    printf("Container: eUID = %ld;  eGID = %ld, UID=%ld, GID=%ld\n",
        (long) geteuid(), (long) getegid(), (long) getuid(), (long) getgid());


	sethostname("container", 10);
	// 重新挂载proc
	mount("proc", "/proc", "proc", 0, NULL);

	ret = execv("/bin/bash", c_args);
	if (ret < 0) {
		perror("execv");
		return 1;
	}
	return 1;
}

void set_map(char *file, int inside_id, int outside_id, int length) {
	FILE *fp = fopen(file, "w");
	if (NULL == fp) {
		perror("fopen");
			return;
	}
	fprintf(fp, "%d %d %d", inside_id, outside_id, length);
	fclose(fp);
}

void set_uid_map(pid_t pid, int inside_id, int outside_id, int length) {
	char file[256];
	snprintf(file, 256, "/proc/%d/uid_map", pid);
	set_map(file, inside_id, outside_id, length);
}

void set_group_deny(char *file) {
	FILE *fp;
	fp = fopen(file, "w");
	fprintf(fp, "deny");
	fclose(fp);
}

void set_gid_map(pid_t pid, int inside_id, int outside_id, int length) {
	char file[256];
	
	// 设置setgroups为deny
	sprintf(file, "/proc/%d/setgroups", pid);
	set_group_deny(file);
	
	snprintf(file, 256, "/proc/%d/gid_map", pid);
	set_map(file, inside_id, outside_id, length);
}


int main(int argc, char *argv[])
{
	int pid;
	const int uid = getuid(), gid = getgid();

	pipe(pipefd);
	printf("Parent: eUID = %ld;  eGID = %ld, UID=%ld, GID=%ld\n",
            (long) geteuid(), (long) getegid(), (long) getuid(), (long) getgid());

	// 启动命名空间
	pid = clone(c_main, stack + STACK_SIZE, CLONE_NEWUSER |
			CLONE_NEWIPC | CLONE_NEWNET | CLONE_NEWUTS |
			CLONE_NEWNS | CLONE_NEWPID | SIGCHLD, NULL);
	if (pid <= 0) {
		perror("clone");
		return 1;
	}
	// 映射uid和gid
	set_uid_map(pid, 0, uid, 1);
	printf("%d\n", gid);
	set_gid_map(pid, 0, gid, 1);

	// 通知子进程
	close(pipefd[1]);
	

	waitpid(pid, NULL, 0);
	// 父重新挂载proc
	mount("proc", "/proc", "proc", 0, NULL);
	puts("c finished");
	return 0;
}
