#include "headers.h"
#include <stdio.h>
#include <unistd.h>

extern int optind, opterr, optopt;
extern char *optarg;
extern int erron;

#define STACK_SIZE (1024*1024)
static char fsy[] = "/tmp/sandbox/";
static char fsy_upper [256];
static char fsy_worker[256];
static char fsy_merged[256];
static bool is_net = false;
static int  strace_fun = 0;
static char stack[STACK_SIZE];

int pipefd[2];

char *const c_args[] = {
	"/bin/bash",
	NULL,
};

int c_main(void *arg);
void c_remount(void);
void handle_arg(int argc, char *argv[]);
void maked(void);
void mkoverlay(void);
void print_id(void);
void set_map(char *file, int inside_id, int outside_id, int length); // set_map()设置映射值
void set_uid_map(pid_t pid, int inside_id, int outside_id, int length);
void set_group_deny(char *file);
void set_gid_map(pid_t pid, int inside_id, int outside_id, int length);
void umount_overlay(void);

// c_main 
int c_main(void *arg) {
	char ch;
	int ret;
	uid_t uid = getuid();

	// 等待父进程
	close(pipefd[1]);
	read(pipefd[0], &ch, 1);

	sethostname("container", 10);

	// 重新挂载文件系统
	c_remount();
	
	// 永久放弃特权
	setresuid(uid, uid, uid);
	puts("c_main");
	print_id();

	ret = execv("/bin/bash", c_args);
	if (ret < 0) {
		perror("execv");
		return 1;
	}
	return 1;
}

void maked() {
	time_t t;
	struct tm *tp;
	char tstr[30];
	char filename[256];

	time(&t);
	tp = gmtime(&t);
	snprintf(tstr, 30, "%d_%d_%d_%d_%d_%d", 1900+tp->tm_year, 1+tp->tm_mon,
			tp->tm_mday, (tp->tm_hour+8)%24, tp->tm_min, tp->tm_sec);
	snprintf(filename, 256, "%s/%s/", fsy, tstr);
	mkdir(filename, 0755);
	// 目录填充
	strcat(fsy_worker, filename);
	strcat(fsy_worker, "/worker/");
	strcat(fsy_merged, filename);
	strcat(fsy_merged, "/merged/");
	strcat(fsy_upper, filename);
	strcat(fsy_upper, "/upper/");
	mkdir(fsy_upper, 0755);
	mkdir(fsy_worker, 0755);
	mkdir(fsy_merged, 0755);
}

void c_remount() {
	// 重新挂载proc
	if (chroot(fsy_merged) != 0) {
		perror("chroot");
	}
	chdir("/");
	mount("proc", "/proc", "proc", 0, NULL);

}
void mkoverlay() {
	DIR *dp;
	char cmd[2048];

	// 构建overlay位置
	dp = opendir(fsy);
	if (NULL == dp) {
		if (mkdir(fsy, 0755) == -1){
			perror("mkdir");
			fprintf(stderr, "文件夹[%s]创建失败\n", fsy);
			exit(1);
		}
	}
	closedir(dp); // 释放文件夹
	// 创建相应目录
	maked();

	// 挂载overlay
	snprintf(cmd, 2048, "mount -t overlay overlay -o lowerdir=/,upperdir=%s,workdir=%s %s",
			fsy_upper, fsy_worker, fsy_merged);
	system(cmd);
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

void handle_arg(int argc, char *argv[]) {
	int c, opt;
	char *end;
	while (EOF != (c = getopt(argc, argv, "hns:"))) {
		switch (c) {
			case 'h':
				printf("%s [-hn] [-s [1 2 3]] \n", argv[0]);
				puts("\t-h: manual");
				puts("\t-n: enable network");
				puts("\t-s: enable starce");
				puts("\t\t 1. strace");
				puts("\t\t 2. inotify");
				puts("\t\t 3. seccom");
				exit(0);
				break;
			case 'n':
				is_net = true;
				break;
			case 's':
				opt = strtol(optarg, &end, 10);
				if (end == optarg) {
					fprintf(stderr, "ERROR: can't convert string(\"%s\") to number\n", optarg);
					exit(1);
				}
			default:
				printf("%s: unknow option:%c\n", argv[0], optopt);
				exit(1);
				break;
		}
	}
}

void umount_overlay() {
	if (umount(fsy_merged) != 0) {
		perror("umount");
		exit(1);
	}
}

void print_id() {
	uid_t uid, euid, suid;
	getresuid(&uid, &euid, &suid);
	printf("uid=%d, gid=%d, euid=%d, egid=%d, suid=%d\n",
			getuid(), getgid(), geteuid(), getegid(), suid);
}

int main(int argc, char *argv[])
{
	int pid;
	uid_t uid = getuid(), euid = geteuid(), suid;
	gid_t gid = getgid(), egid = getegid();
	print_id();

	getresuid(&uid, &euid, &suid);

	// 权限设置
	prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0); // 避免类似execve的系统调用授予父级没有的权限

	// 命令行参数处理
	handle_arg(argc, argv);

	setresuid(euid, euid, -1); // 获取权限
	print_id();
	// 构建overlay
	mkoverlay();
	setresuid(uid, uid, -1); // 暂时放弃权限
	print_id();

	pipe(pipefd);
	// 启动命名空间
	pid = clone(c_main, stack + STACK_SIZE, CLONE_NEWUSER |
			CLONE_NEWIPC | CLONE_NEWNET | CLONE_NEWUTS |
			CLONE_NEWNS | CLONE_NEWPID | SIGCHLD, NULL);
	if (pid <= 0) {
		perror("clone");
		return 1;
	}
	setresuid(euid, euid, -1); // 获取权限
	print_id();
	// 映射uid和gid
	set_uid_map(pid, 0, 0, 65535);
	set_gid_map(pid, 0, 0, 65535);
	setresuid(uid, uid, -1); // 暂时放弃权限
	print_id();

	// 通知子进程
	close(pipefd[1]);
	
	// 判断网络连接是否启用
	if (is_net) {
		char cmd[30];
		sprintf(cmd, "./net.sh %d", pid);
		printf("%s\n", cmd);
//		system(cmd);
	}
	
	// 等待子进程退出
	waitpid(pid, NULL, 0);
	
	// 获取权限
	setresuid(euid, euid, -1);
	// 父重新挂载proc
	mount("proc", "/proc", "proc", 0, NULL);
	// 卸载overlay
	umount_overlay();
	// 放弃权限
	setresuid(uid, uid, uid);
	
	puts("c finished");
	return 0;
}
