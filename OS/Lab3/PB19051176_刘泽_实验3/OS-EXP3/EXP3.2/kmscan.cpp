#include <linux/errno.h>
#include <linux/fs.h>
#include <linux/kthread.h>
#include <linux/wait.h>
#include <linux/err.h>
#include <linux/types.h>
#include <linux/freezer.h>
#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/pid.h>
#include <linux/moduleparam.h>
#include <linux/timer.h>
#include <linux/jiffies.h>
#include <linux/string.h>
#include <linux/proc_fs.h>
#include <linux/seq_file.h>
#include <linux/signal.h>
#include <linux/mm.h>
#include <linux/rmap.h>


MODULE_LICENSE("GPL");
MODULE_AUTHOR("PB19051176");
MODULE_DESCRIPTION("Lab3 task3!\n");

#define MAX 10
#define kmscan_RUN_STOP 0
#define kmscan_RUN_START 1

typedef typeof(follow_page)*  my_follow_page;
typedef typeof(page_referenced)*  my_page_referenced;

char pid_str[MAX];
static struct proc_dir_entry* proc_kmscan = NULL;
static struct proc_dir_entry* kmscan_pid = NULL;
static struct task_struct* kmscan_thread = NULL;

static unsigned int pid = 0;
static unsigned int kmscan_func = 0;
static unsigned int kmscan_run = kmscan_RUN_STOP;
static unsigned int kmscan_thread_sleep_millisecs = 5000;

static unsigned int kmscan_pid_exist = 0;
static unsigned int vma_num;
static unsigned int file_count;
static unsigned int active_file_count;
static unsigned int anon_count;
static unsigned int active_anon_count;

static int kmscan_show(struct seq_file* m, void* v){
    	pid_t* pid_n = (pid_t*)m->private;
    	if (pid_n != NULL){
        	seq_printf(m, "%d\n", *pid_n);
    	}
   	return 0;
}

static int kmscan_open(struct inode* inode, struct file* file){
    	return single_open(file, kmscan_show, PDE_DATA(inode));
}


struct proc_ops kmscan_ops = {
    	.proc_open = kmscan_open,
    	.proc_read = seq_read,
    	.proc_release = single_release,
};

static DECLARE_WAIT_QUEUE_HEAD(kmscan_thread_wait);

static DEFINE_MUTEX(kmscan_thread_mutex);

static int func1_to_do(void){
        struct pid* cur_pid;
	struct task_struct* cur_task;
	struct vm_area_struct* vm_head;
	struct vm_area_struct* cur_vm;
	
	int ispidValid = 0;
	struct task_struct* task;
	for_each_process(task){
		if(task->pid == pid){
			ispidValid = 1;
			break;
		}	
	}
	if(ispidValid == 0){
		printk(KERN_ALERT"The pid:%d is invalid!\n",pid);
		return -EINVAL;
	}

	vma_num = 0;
	cur_pid = find_get_pid(pid);
	cur_task = pid_task(cur_pid, PIDTYPE_PID);
	vm_head = cur_task->mm->mmap;	
	if(vm_head != NULL){
       		vma_num++;
		cur_vm = vm_head->vm_next;
		while(cur_vm != vm_head && cur_vm != NULL){
			vma_num++;
			cur_vm = cur_vm->vm_next;
		}
	}
 	printk(KERN_ALERT"vma_count == %d", vma_num);
	
	if(kmscan_pid != NULL)
		proc_remove(kmscan_pid);
	sprintf(pid_str, "%d", pid);
	kmscan_pid = proc_mkdir(pid_str, proc_kmscan);
	if(kmscan_pid == NULL){
	        printk(KERN_ALERT"Func1 create /porc/kmscan/%s/ failed\n", pid_str);
		kmscan_pid_exist = 0;
        	return -EINVAL;
    	}
	proc_create_data("vma_count", 0664, kmscan_pid, &kmscan_ops, &vma_num);
	return 0;
}

static int func2_to_do(void){
	
	int ispidValid = 0;
	unsigned long address;
	struct task_struct* task;
	struct pid* cur_pid;
	struct task_struct* cur_task;
	struct vm_area_struct* vm_head;
	struct vm_area_struct* cur_vm;
	struct page* cur_page;
	
	my_follow_page mfollow_page;
	my_page_referenced mpage_referenced;
	mfollow_page = (my_follow_page)0xffffffffa6c73af0;
	mpage_referenced = (my_page_referenced)0xffffffffa6c8e030;
	
	
	
	for_each_process(task){
		if(task->pid == pid){
			ispidValid = 1;
			break;
		}	
	}
	if(ispidValid == 0){
		printk(KERN_ALERT"The pid:%d is invalid!\n",pid);
		return -EINVAL;
	}

	file_count = 0;
	active_file_count = 0;
	anon_count = 0;
	active_anon_count = 0;
	cur_pid = find_get_pid(pid);
	cur_task = pid_task(cur_pid, PIDTYPE_PID);
	vm_head = cur_task->mm->mmap;
	if(vm_head != NULL){
		cur_vm = vm_head;
		do{
		   	for(address = cur_vm->vm_start; address < cur_vm->vm_end; address += PAGE_SIZE){
				cur_page = mfollow_page(cur_vm, address, FOLL_GET);
				if(cur_page){
					file_count++;
					if(PageAnon(cur_page))  anon_count++;
					if(mpage_referenced(cur_page, 0, cur_page->mem_cgroup, &(cur_vm->vm_flags))){
						active_file_count++;
						if(PageAnon(cur_page))  active_anon_count++;	
					}
				}
			}    
         	cur_vm = cur_vm->vm_next;    
	  }while(cur_vm != vm_head && cur_vm != NULL);			 					
	}

	if(kmscan_pid != NULL)
		proc_remove(kmscan_pid);
	sprintf(pid_str, "%d", pid);
	kmscan_pid = proc_mkdir(pid_str, proc_kmscan);
	if(kmscan_pid == NULL){
	        printk(KERN_ALERT"Func1 create /porc/kmscan/%s/ failed\n", pid_str);
			kmscan_pid_exist = 0;
        	return -EINVAL;
    }
	proc_create_data("file", 0664, kmscan_pid, &kmscan_ops, &file_count);
	proc_create_data("active_file", 0664, kmscan_pid, &kmscan_ops, &active_file_count);
	proc_create_data("anon", 0664, kmscan_pid, &kmscan_ops, &anon_count);
	proc_create_data("active_anon", 0664, kmscan_pid, &kmscan_ops, &active_anon_count);
	return 0;
}

static int kmscand_should_run(void){
    	return (kmscan_run & kmscan_RUN_START);
}

static void kmscan_to_do(void){
	if(kmscan_func == 1) 
		func1_to_do();			
    else if(kmscan_func == 2)
		func2_to_do();
}

static int kmscand_thread(void* nothing){
    	set_freezable();
    	set_user_nice(current, 5);
    	while (!kthread_should_stop())
        {
            mutex_lock(&kmscan_thread_mutex);
            if(kmscand_should_run())
               	kmscan_to_do();
            mutex_unlock(&kmscan_thread_mutex);
            try_to_freeze();
            if(kmscand_should_run())
            {
               schedule_timeout_interruptible(
                 msecs_to_jiffies(kmscan_thread_sleep_millisecs));
            }
            else
            {
               wait_event_freezable(kmscan_thread_wait,
                  kmscand_should_run() || kthread_should_stop());
            }
        }
        return 0;
}

#ifdef CONFIG_SYSFS

/*
 * This all compiles without CONFIG_SYSFS, but is a waste of space.
 */

#define kmscan_ATTR_RO(_name) \
        static struct kobj_attribute _name##_attr = __ATTR_RO(_name)

#define kmscan_ATTR(_name)                         \
        static struct kobj_attribute _name##_attr = \
                __ATTR(_name, 0644, _name##_show, _name##_store)

static ssize_t sleep_millisecs_show(struct kobject* kobj, struct kobj_attribute* attr, char* buf){
    return sprintf(buf, "%u\n", kmscan_thread_sleep_millisecs);
}

static ssize_t sleep_millisecs_store(struct kobject* kobj, struct kobj_attribute* attr, const char* buf, size_t count){
    	unsigned long msecs;
    	int err;

    	err = kstrtoul(buf, 10, &msecs);
    	if(err || msecs > UINT_MAX)
        	return -EINVAL;

    	kmscan_thread_sleep_millisecs = msecs;

    	return count;
}
kmscan_ATTR(sleep_millisecs);

static ssize_t pid_show(struct kobject* kobj, struct kobj_attribute* attr, char* buf){
    return sprintf(buf, "%u\n", pid);
}

static ssize_t pid_store(struct kobject* kobj, struct kobj_attribute* attr, const char* buf, size_t count){
    	unsigned long tmp;
    	int err;

    	err = kstrtoul(buf, 10, &tmp);
    	if (err || tmp > UINT_MAX)
        	return -EINVAL;

    	pid = tmp;

    	return count;
}
kmscan_ATTR(pid);


static ssize_t func_show(struct kobject* kobj, struct kobj_attribute* attr, char* buf){
    	return sprintf(buf, "%u\n", kmscan_func);
}

static ssize_t func_store(struct kobject* kobj, struct kobj_attribute* attr, const char* buf, size_t count){
	unsigned long tmp;
	int err;

    	err = kstrtoul(buf, 10, &tmp);
    	if(err || tmp > UINT_MAX)
        	return -EINVAL;

    	kmscan_func = tmp;

    	return count;
}
kmscan_ATTR(func);

static ssize_t run_show(struct kobject* kobj, struct kobj_attribute* attr, char* buf){
    	return sprintf(buf, "%u\n", kmscan_run);
}

static ssize_t run_store(struct kobject* kobj, struct kobj_attribute* attr, const char* buf, size_t count){
	int err;
    	unsigned long flags;
    	err = kstrtoul(buf, 10, &flags);
    	if(err || flags > UINT_MAX)
        	return -EINVAL;
    	if(flags > kmscan_RUN_START)
        	return -EINVAL;
    	
	mutex_lock(&kmscan_thread_mutex);
    	if(kmscan_run != flags){
        	kmscan_run = flags;
    	}
    	mutex_unlock(&kmscan_thread_mutex);

    	if(flags & kmscan_RUN_START)
        	wake_up_interruptible(&kmscan_thread_wait);
    	return count;
}
kmscan_ATTR(run);



static struct attribute* kmscan_attrs[] = {
    // 扫描进程的扫描间隔 为5秒 
    &sleep_millisecs_attr.attr,
    &pid_attr.attr,
    &func_attr.attr,
    &run_attr.attr,
    NULL,
};


static struct attribute_group kmscan_attr_group = {
    .attrs = kmscan_attrs,
    .name = "kmscan",
};
#endif /* CONFIG_SYSFS */

static int lab3_task3_init(void){
	int err;
	printk(KERN_ALERT"Task3 init success!\n");
	
      	//procfs 
	proc_kmscan = proc_mkdir("kmscan", NULL);
	if(proc_kmscan == NULL){
		remove_proc_entry("kmscan", NULL);
	        printk(KERN_ALERT"proc create %s failed\n", "kmscan");
        	return -EINVAL;
    	}

	//sysfs
	kmscan_thread = kthread_run(kmscand_thread, NULL, "kmscan");
	if(IS_ERR(kmscan_thread)){
        	pr_err(KERN_ALERT"kmscan: creating kthread failed\n");
        	err = PTR_ERR(kmscan_thread);
        	goto out;
    	}

	#ifdef CONFIG_SYSFS
    		err = sysfs_create_group(mm_kobj, &kmscan_attr_group);
    		if(err){     
			pr_err(KERN_ALERT"kmscan: register sysfs failed\n");
        		kthread_stop(kmscan_thread);
        		goto out;
    		}
	#else
    		kmscan_run = KSCAN_RUN_STOP;
	#endif  /* CONFIG_SYSFS */

	out:    return err;	
}

static void lab3_task3_exit(void){	
	proc_remove(proc_kmscan);
    	if(kmscan_thread){
        	kthread_stop(kmscan_thread);
        	kmscan_thread = NULL;
    	}
	#ifdef CONFIG_SYSFS
    		sysfs_remove_group(mm_kobj, &kmscan_attr_group);
	#endif
	printk(KERN_ALERT"Task3 exit success!\n");
}

module_init(lab3_task3_init);
module_exit(lab3_task3_exit);





