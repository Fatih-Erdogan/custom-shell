#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/list.h>
#include <linux/module.h>
#include <linux/pid.h>
#include <linux/sched.h>
#include <linux/slab.h>

// Meta Information
MODULE_LICENSE("GPL");
MODULE_AUTHOR("ME");
MODULE_DESCRIPTION("A module that gives process tree info");

#define DEVICE_NAME	"mymodule"
#define MODULE_BUFFER_SIZE	12500
#define TEMP_BUFFER_SIZE	50

static int device_open(struct inode *inode, struct file *file);
static int device_release(struct inode *inode, struct file *file);
static ssize_t device_read(struct file *filp, char *buffer, size_t length, loff_t *offset);
static ssize_t device_write(struct file *filp, const char *buff, size_t len, loff_t *off);

static void recursive_node(struct task_struct *t, int is_root, int is_eldest);
static void get_node_info(struct task_struct *t, int is_root, int is_eldest, char* buf, int size_buf);
static struct task_struct* get_eldest(struct task_struct *t);
static unsigned long get_create_time_sec(struct task_struct *t);

static struct file_operations fops = {
	.read = device_read,
	.write = device_write,
	.open = device_open,
	.release = device_release
};

//char *name;
int param_pid;
static int Major;
static int Device_Open = 0;
static char MODULE_BUFFER[MODULE_BUFFER_SIZE];
static char TEMP_BUFFER[TEMP_BUFFER_SIZE];

/*
 * module_param(foo, int, 0000)
 * The first param is the parameters name
 * The second param is its data type
 * The final argument is the permissions bits,
 * for exposing parameters in sysfs (if non-zero) at a later stage.
 */

/*
module_param(name, charp, S_IRUSR | S_IWUSR | S_IRGRP | S_IROTH);
MODULE_PARM_DESC(name, "name of the caller");
*/
module_param(param_pid, int, 0644);
MODULE_PARM_DESC(param_pid, "root pid to create the process tree");

// A function that runs when the module is first loaded
int simple_init(void) {

	Major = register_chrdev(0, DEVICE_NAME, &fops);
	if (Major < 0){
		printk(KERN_ERR "Registering the character device failed with %d\n", Major);
		return Major;
	}
	else{
		printk(KERN_INFO "Major number for mymodule: %d\n", Major);
	}
	return 0;
}

// A function that runs when the module is removed
void simple_exit(void) {
	unregister_chrdev(Major, DEVICE_NAME);
	printk(KERN_INFO "%s unloaded\n", "mymodule");
}

// File ops
static int device_open(struct inode *inode, struct file *file){
	if (Device_Open) {return -EBUSY;}
	Device_Open++;
	return 0;
}

static int device_release(struct inode *inode, struct file *file){
	Device_Open--;
	return 0;
}

static ssize_t device_write(struct file *filp, const char *buff, size_t len, loff_t *off){
        printk(KERN_ERR "Writing is to device is not supported.\n");
        return -EINVAL;
}

static ssize_t device_read(struct file *filp, char *buffer, size_t length, loff_t *offset){
        struct task_struct *ts;
        size_t bytes_read;
        size_t bytes_to_cpy;

        ts = get_pid_task(find_get_pid(param_pid), PIDTYPE_PID);

	if (ts == NULL){
		printk(KERN_ERR "Error finding the process id: %d\n", param_pid);
		return -ESRCH;
	}
	
	MODULE_BUFFER[0] = 0;
	TEMP_BUFFER[0] = 0;
	
	recursive_node(ts, 1, 0);

	bytes_read = (size_t) strlen(MODULE_BUFFER);
	bytes_to_cpy = (bytes_read < length) ? bytes_read : length;
	if (copy_to_user(buffer, MODULE_BUFFER, bytes_to_cpy)) {
		return -EFAULT;
	}

	return bytes_to_cpy;
}

// helpers for device_read
static void recursive_node(struct task_struct *t, int is_root, int is_eldest){
	struct task_struct *task;
	struct list_head *list;
	struct task_struct *eldest;

        get_node_info(t, is_root, is_eldest, TEMP_BUFFER, TEMP_BUFFER_SIZE);
        snprintf(MODULE_BUFFER + strlen(MODULE_BUFFER), MODULE_BUFFER_SIZE - strlen(MODULE_BUFFER), "%s", TEMP_BUFFER);
        eldest = get_eldest(t);
	
	list_for_each(list, &t->children){
		task = list_entry(list, struct task_struct, sibling);
		if (task == eldest){
			recursive_node(task, 0, 1);
		}
		else{
			recursive_node(task, 0, 0);
		}
	}
}
static void get_node_info(struct task_struct *t, int is_root, int is_eldest, char *buf, int size_buf){
	int pid;
	int ppid;
	unsigned long creat_time;

	creat_time = get_create_time_sec(t);
	pid = (int) (t->pid);
	ppid = is_root ? 0 : (int) (t->real_parent->pid);
	snprintf(buf, size_buf, "%d,%d,%d,%lu|", ppid, pid, is_eldest, creat_time);
}
static struct task_struct* get_eldest(struct task_struct *t){
	struct task_struct *child;
	struct task_struct *eldest = NULL;
	struct list_head *list;
	u64 min_start = ULLONG_MAX;

	list_for_each(list, &t->children){
		child = list_entry(list, struct task_struct, sibling);
		if (child->start_time < min_start){
			min_start = child->start_time;
			eldest = child;
		}
	}

	return eldest;
}

static unsigned long get_create_time_sec(struct task_struct *t) {
	u64 system_since_boot_sec;
	u64 boot_time_sec;
	u64 task_since_boot_sec;
	unsigned long creat_sec;

	system_since_boot_sec = ktime_get_boottime_ns() / 1000000000;
	boot_time_sec = ktime_get_real_seconds() - system_since_boot_sec;
	task_since_boot_sec = ktime_to_ns(t->start_time) / 1000000000;
	creat_sec = task_since_boot_sec + boot_time_sec;

	return creat_sec;
}



module_init(simple_init);
module_exit(simple_exit);
