#include<stdio.h>
#include<unistd.h>
#include<sys/syscall.h>

#define MAXSIZE 80
#define LEN_MAX 20 
int main(void){
    int num;    
    int pid[MAXSIZE]; 
    unsigned long time[MAXSIZE];
    char command[MAXSIZE][LEN_MAX];
    
    syscall(333, &num, pid, time, command);
    printf("process number is %d\n", num);
    printf("PID		TIME/ms		COMMAND\n");
    for(int i = 0; i < num; i++)
        printf("%-3d		%-7lu		%s\n",pid[i], time[i], command[i]);
}    
