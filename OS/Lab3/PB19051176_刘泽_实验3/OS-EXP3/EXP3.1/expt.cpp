#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/timer.h>
#include <linux/pid.h>
#include <linux/sched.h>
#include <linux/sched/signal.h>
#include <linux/jiffies.h>

MODULE_LICENSE("GPL");
MODULE_AUTHOR("PB19051176");
MODULE_DESCRIPTION("Os lab3 task2!/n");

struct timer_list timer;
static int func = -1;
static int pid = -1;
module_param(func, int, 0644);
module_param(pid, int, 0644);

void timer_function(struct timer_list* t){
     int counter = 0;
     struct task_struct* task;
     for_each_process(task){
         if(task->mm == NULL)//kernel process
		counter++;
     }
     printk(KERN_ALERT"The number of kernel process is %d\n", counter); 
     mod_timer(&timer, jiffies + (5 * HZ));
}

static int __init my_module_init(void){
	printk(KERN_ALERT"***My Module Init!***\n");           
	if(func == 1){//task 1
            	struct task_struct* task; 
            	printk(KERN_ALERT"PID\tSTATE\t\tCOMMAND\n");
            	for_each_process(task){
               	if(task->mm == NULL)//kernel process
                  	printk(KERN_ALERT"%-d\t%-ld\t\t%s\n", task->pid, task->state, task->comm);      
            	}
            	return 0;
        }  
        else if(func == 2){//task 2
		timer_setup(&timer, timer_function, 0);
            	timer.expires = jiffies + (5 * HZ);
            	add_timer(&timer);
            	return 0;
        }
        else if(func == 3){//task 3
                struct list_head* pos;
		struct pid* cur_pid = find_get_pid(pid);
		struct task_struct* cur_thread;
		struct task_struct* cur_task = pid_task(cur_pid, PIDTYPE_PID);
		printk(KERN_ALERT"pid receive successfully:%d!\n", pid);
		if(cur_task->parent == NULL)
			printk("His Father is NULL!\n");
		else
			printk(KERN_ALERT"His Father is:pid=%5d state=%-5ld comm=%-s\n", cur_task->parent->pid, cur_task->parent->state, cur_task->parent->comm);
		list_for_each(pos, &(cur_task->children)){
                        struct task_struct* cur_children = list_entry(pos, struct task_struct, sibling); 
			printk(KERN_ALERT"His Children is:pid=%5d state=%-5ld comm=%-s\n", cur_children->pid, cur_children->state, cur_children->comm);
		}
		list_for_each(pos, &(cur_task->parent->children)){
 			struct task_struct* cur_sibling = list_entry(pos, struct task_struct, sibling);
			printk(KERN_ALERT"His Sibling is:pid=%5d state=%-5ld comm=%-s\n", cur_sibling->pid, cur_sibling->state, cur_sibling->comm);
		}
		cur_thread = cur_task; 
		do{
			printk(KERN_ALERT"His Thread is:pid=%5d state=%-5ld comm=%-s\n",cur_thread->pid, cur_thread->state, cur_thread->comm);
		}while_each_thread(cur_task, cur_thread);
	}
	return 0;
}

static void __exit my_module_exit(void){
		printk(KERN_ALERT"***My Module Exit!***\n");
        	del_timer(&timer);
}

module_init(my_module_init);
module_exit(my_module_exit);  
	         
           
           
