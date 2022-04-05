#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/timer.h>
#include <linux/pid.h>
#include <linux/sched.h>
#include <linux/sched/signal.h>
#include <linux/mm.h>
#include <linux/pgtable.h>


MODULE_LICENSE("GPL");
MODULE_AUTHOR("PB19051176");
MODULE_DESCRIPTION("Os lab3 bonus!/n");

static int pid = -1;

module_param(pid,int,0644);


static int lab3_bonus_init(void){
	pgd_t *temp_pgd = NULL;
	p4d_t *temp_p4d = NULL;
	pud_t *temp_pud = NULL;
	pmd_t *temp_pmd = NULL;
	pte_t *temp_pte = NULL;
	unsigned long address;
	struct task_struct* cur_task = NULL;
	struct pid* cur_pid = NULL;
	struct mm_struct* cur_mm = NULL;
	struct vm_area_struct* vm_head = NULL;
	struct vm_area_struct* cur_vm = NULL;
	cur_pid = find_get_pid(pid);
	cur_task = pid_task(cur_pid, PIDTYPE_PID);
	cur_mm = cur_task->mm;
	vm_head = cur_mm->mmap;
	printk(KERN_ALERT"lab3 bonus init!\n");
	if(vm_head != NULL){
		cur_vm = vm_head;
		do{
		   for(address = cur_vm->vm_start; address < cur_vm->vm_end; address += PAGE_SIZE){
			temp_pgd = pgd_offset(cur_mm, address);
			if(pgd_none(*temp_pgd)) continue;
			
			temp_p4d = p4d_offset(temp_pgd, address);
			if(p4d_none(*temp_p4d)) continue;

			temp_pud = pud_offset(temp_p4d, address);
			if(pud_none(*temp_pud)) continue;	
			
			temp_pmd = pmd_offset(temp_pud, address);
			if(pmd_none(*temp_pmd)) continue;
			
			temp_pte = pte_offset_kernel(temp_pmd, address);
			if(pte_none(*temp_pte)) continue;
			printk(KERN_ALERT"vir_addsess = 0x%lx , page_address = 0x%lx\n", address, pte_val(*temp_pte) & 0x7fffffffffffff & PAGE_MASK);	
		   }    
                   cur_vm = cur_vm->vm_next;    
	  	}while(cur_vm != vm_head && cur_vm != NULL);	
	}
	return 0;		
}

static void lab3_bonus_exit(void){
	printk(KERN_ALERT"lab3 bonus exit!\n");
}


module_init(lab3_bonus_init);
module_exit(lab3_bonus_exit); 

