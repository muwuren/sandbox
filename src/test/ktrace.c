#include<stdio.h>
#include<sys/ptrace.h>
int main(int argc, char* argv[])
{
	    if(-1 == ptrace(PTRACE_TRACEME))
		{
			        printf("Debugger!\n");
					        return 1;
							    
		}
		    printf("Hello Ptrace!\n");
			    return 0;
				
}
