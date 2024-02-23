#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <termios.h> // termios, TCSANOW, ECHO, ICANON
#include <unistd.h>

#include <fcntl.h> // file control for the pipe synchronising the return of the parent
#include <ctype.h> // isdigit
#include <time.h> 
#include <math.h>

#define REDIRECT_FLAG	'*'
#define READ_END	0
#define WRITE_END	1
#define ALIAS_FILE_NAME	"alias_shellect.txt"
#define MAX_NUM_ALIAS	100
#define MODULE_PATH	"/home/usr/Desktop/SHARED/Assignments/Project1/module/mymodule.ko"
#define MODULE_NAME	"mymodule"
#define DEVICE_NAME	"mymodule_dev"
#define DEVICE_PATH	"/dev/mymodule_dev"
#define MODULE_PID_PATH	"/sys/module/mymodule/parameters/param_pid"
#define MODULE_OUT_SIZE	12500
#define PLOTTER_FILE_PATH	"/home/usr/Desktop/SHARED/Assignments/Project1/plot.gp"
#define TEMP_DATA_FILE	"tree_data.txt"

int Major;
int Module_Loaded = 0;

const char *sysname = "Shellect";


enum return_codes {
	SUCCESS = 0,
	EXIT = 1,
	UNKNOWN = 2,
};

struct command_t {
	char *name;
	bool background;
	bool auto_complete;
	int arg_count;
	char **args;
	char *redirects[3]; // in/out redirection
	int redirect_stdout_last;
	struct command_t *next; // for piping
};


char *alias_command_names[MAX_NUM_ALIAS];
struct command_t *alias_commands[MAX_NUM_ALIAS];


/**
 * Prints a command struct
 * @param struct command_t *
 */
void print_command(struct command_t *command) {
	int i = 0;
	printf("Command: <%s>\n", command->name);
	printf("\tIs Background: %s\n", command->background ? "yes" : "no");
	printf("\tNeeds Auto-complete: %s\n",
		   command->auto_complete ? "yes" : "no");
	printf("\tRedirects:\n");

	for (i = 0; i < 3; i++) {
		printf("\t\t%d: %s\n", i,
			   command->redirects[i] ? command->redirects[i] : "N/A");
	}

	printf("\tArguments (%d):\n", command->arg_count);

	for (i = 0; i < command->arg_count; ++i) {
		printf("\t\tArg %d: %s\n", i, command->args[i]);
	}

	if (command->next) {
		printf("\tPiped to:\n");
		print_command(command->next);
	}
}

/**
 * Release allocated memory of a command
 * @param  command [description]
 * @return         [description]
 */
int free_command(struct command_t *command) {
	if (command->arg_count) {
		for (int i = 0; i < command->arg_count; ++i)
			free(command->args[i]);
		free(command->args);
	}

	for (int i = 0; i < 3; ++i) {
		if (command->redirects[i])
			free(command->redirects[i]);
	}

	if (command->next) {
		free_command(command->next);
		command->next = NULL;
	}

	free(command->name);
	free(command);
	return 0;
}

/**
 * Show the command prompt
 * @return [description]
 */
int show_prompt() {
	char cwd[1024], hostname[1024];
	gethostname(hostname, sizeof(hostname));
	getcwd(cwd, sizeof(cwd));
	printf("%s@%s:%s %s$ ", getenv("USER"), hostname, cwd, sysname);
	return 0;
}

/**
 * Parse a command string into a command struct
 * @param  buf     [description]
 * @param  command [description]
 * @return         0
 */
int parse_command(char *buf, struct command_t *command) {
	const char *splitters = " \t"; // split at whitespace
	int index, len;
	len = strlen(buf);

	// trim left whitespace
	while (len > 0 && strchr(splitters, buf[0]) != NULL) {
		buf++;
		len--;
	}

	while (len > 0 && strchr(splitters, buf[len - 1]) != NULL) {
		// trim right whitespace
		buf[--len] = 0; // null terminator
	}

	// auto-complete
	if (len > 0 && buf[len - 1] == '?') {
		command->auto_complete = true;
	}

	// background
	if (len > 0 && buf[len - 1] == '&') {
		command->background = true;
	}

	char *pch = strtok(buf, splitters);
	if (pch == NULL) {
		command->name = (char *)malloc(1);
		command->name[0] = 0;
	} else {
		command->name = (char *)malloc(strlen(pch) + 1);
		strcpy(command->name, pch);
	}

	command->args = (char **)malloc(sizeof(char *));

	int redirect_index;
	int arg_index = 0;
	char temp_buf[1024], *arg;

	while (1) {
		
		// tokenize input on splitters
		pch = strtok(NULL, splitters);
		if (!pch)
			break;
		arg = temp_buf;
		strcpy(arg, pch);
		len = strlen(arg);

		// empty arg, go for next
		// it cannot in fact enter here bc strtok never !!!!!!!
		if (len == 0) {
			continue;
		}
		

		// trim left whitespace
		// in fact it was already trimmed again bc strtok !!!!!!!!
		while (len > 0 && strchr(splitters, arg[0]) != NULL) {
			arg++;
			len--;
		}


		// trim right whitespace
		// in fact it was already trimmed again bc strtok !!!!!!!!
		while (len > 0 && strchr(splitters, arg[len - 1]) != NULL) {
			arg[--len] = 0;
		}


		// empty arg, go for next
		// no need for this either !!!!!!!!!!!!!!!!!!!!!
		if (len == 0) {
			continue;
		}


                // check the flag for redirect index,
                // if there is a flag, put the current element to the appropriate place
                // then continue;
                // if there is no flag continue as usual
		int control = 0;
		for (int i =  0; i < 3; i++){
			if (command->redirects[i] && command->redirects[i][0] == REDIRECT_FLAG) {
				command->redirects[i] = (char *) realloc(command->redirects[i], strlen(arg) + 1);
				strcpy(command->redirects[i], arg);
				control = 1;
				break;
			}
		}
		if (control) {
			continue;
		}
		


		// piping to another command
		if (strcmp(arg, "|") == 0) {
			struct command_t *c = malloc(sizeof(struct command_t));
			int l = strlen(pch);
			pch[l] = splitters[0]; // restore strtok termination
			index = 1;
			while (pch[index] == ' ' || pch[index] == '\t')
				index++; // skip whitespaces

			parse_command(pch + index, c);
			pch[l] = 0; // put back strtok termination
			command->next = c;
			
			// continue;
			// I think we should break here, why to continue reading
			break;
		}

		// background process
		if (strcmp(arg, "&") == 0) {
			// handled before
			continue;
		}

		// handle input redirection
		redirect_index = -1;
		if (arg[0] == '<') {
			redirect_index = 0;
		}

		if (arg[0] == '>') {
			if (len > 1 && arg[1] == '>') {
				redirect_index = 2;
				arg++;
				len--;
			} else {
				redirect_index = 1;
			}
			command->redirect_stdout_last = redirect_index;
		}

		if (redirect_index != -1) {
			if (strlen(arg + 1) < 1){
				command->redirects[redirect_index] = malloc(2);
				command->redirects[redirect_index][0] = REDIRECT_FLAG;
				command->redirects[redirect_index][1] = 0;
			}
			else {
				command->redirects[redirect_index] = malloc(strlen(arg));
				strcpy(command->redirects[redirect_index], arg + 1);
			}
			continue;
		}

		// normal arguments
		if (len > 1 && (arg[0] == '"' || arg[0] == '\'')){
			arg++;
			len--;
		}
		if (arg[strlen(arg) - 1] == '"' || arg[strlen(arg) - 1] == '\''){
			arg[--len] = 0;
		}

		command->args =
			(char **)realloc(command->args, sizeof(char *) * (arg_index + 1));

		command->args[arg_index] = (char *)malloc(len + 1);
		strcpy(command->args[arg_index++], arg);
	}
	command->arg_count = arg_index;

	// increase args size by 2
	command->args = (char **)realloc(
		command->args, sizeof(char *) * (command->arg_count += 2));

	// shift everything forward by 1
	for (int i = command->arg_count - 2; i > 0; --i) {
		command->args[i] = command->args[i - 1];
	}

	// set args[0] as a copy of name
	command->args[0] = strdup(command->name); // returns the pointer to the allocated place

	// set args[arg_count-1] (last) to NULL
	command->args[command->arg_count - 1] = NULL;

	return 0;
}

// this is all visual! 
// putchar(' ') doesnt mean that you entered a space, it only displays it
void prompt_backspace() {
	putchar(8); // go back 1
	putchar(' '); // write empty over
	putchar(8); // go back 1 again
}

/**
 * Prompt a command from the user
 * @param  buf      [description]
 * @param  buf_size [description]
 * @return          [description]
 */
int prompt(struct command_t *command) {
	size_t index = 0;
	char c;
	char buf[4096];
	static char oldbuf[4096];

	// tcgetattr gets the parameters of the current terminal
	// STDIN_FILENO will tell tcgetattr that it should write the settings
	// of stdin to oldt
	static struct termios backup_termios, new_termios;
	tcgetattr(STDIN_FILENO, &backup_termios);
	new_termios = backup_termios;
	// ICANON normally takes care that one line at a time will be processed
	// that means it will return if it sees a "\n" or an EOF or an EOL
	new_termios.c_lflag &=
		~(ICANON |
		  ECHO); // Also disable automatic echo. We manually echo each char.
	// Those new settings will be set to STDIN
	// TCSANOW tells tcsetattr to change attributes immediately.
	tcsetattr(STDIN_FILENO, TCSANOW, &new_termios);

	show_prompt();
	buf[0] = 0;

	char memory_char = 0;
	while (1) {
		c = memory_char == 0 ? getchar() : memory_char;		// blocking command, waits for a char to be written
		memory_char = 0;
		
		// printf("Keycode: %u\n", c); 				// DEBUG: uncomment for debugging

		// handle tab
		if (c == 9) {
			buf[index++] = '?'; // autocomplete
			break;
		}

		// handle backspace
		if (c == 127) {
			if (index > 0) {
				prompt_backspace();
				index--;
			}
			continue;
		}

		if (c == 27) {
			c = getchar();
			// if 91 then it is an arrow
			if (c == 91){
				c = getchar();
			}
			// if not 91 it means user just pressed esc
			// and the next character now should be processed
			else {
				memory_char = c;
				continue;
			}

			if (c == 66 || c == 67 || c == 68){
				continue;
			}
                	if (c == 65) {
                        	while (index > 0) {
                                	prompt_backspace();
                                	index--;
                        	}

                        	char tmpbuf[4096];
                       		printf("%s", oldbuf);
                        	strcpy(tmpbuf, buf);
                        	strcpy(buf, oldbuf);
                        	strcpy(oldbuf, tmpbuf);
                        	index += strlen(buf);
                        	continue;
                	}
		}

		putchar(c); // echo the character
		buf[index++] = c;
		if (index >= sizeof(buf) - 1)
			break;
		if (c == '\n') // enter key
			break;
		if (c == 4){ // Ctrl+D
			return EXIT;
		}
	}

	// trim newline from the end
	if (index > 0 && buf[index - 1] == '\n') {
		index--;
	}

	// null terminate string
	buf[index++] = '\0';
	strcpy(oldbuf, buf);

	parse_command(buf, command);

	// print_command(command); // DEBUG: uncomment for debugging

	// restore the old settings
	tcsetattr(STDIN_FILENO, TCSANOW, &backup_termios);
	return SUCCESS;
}

int process_command(struct command_t *command);
void restore_aliases();
void free_aliases();
void remove_module();

int main() {
	pid_t program_pid = getpid();
	restore_aliases();
	while (1) {
		struct command_t *command = malloc(sizeof(struct command_t));

		// set all bytes to 0
		memset(command, 0, sizeof(struct command_t));

		// printf("\n");
		int code;
		code = prompt(command);
		if (code == EXIT) {
			break;
		}

		code = process_command(command);
		if (code == EXIT) {
			break;
		}
		if (code == UNKNOWN){
			break;
		}

		free_command(command);
	}
	free_aliases();
	if (getpid() == program_pid){
		remove_module();
	}
	return 0;
}

int xdd(struct command_t *command);
int alias(struct command_t * command);
int good_morning(struct command_t *command);
int piano(struct command_t *command);
int pvis(struct command_t *command);
int load_module();

int process_command(struct command_t *command) {
	int r;

	// search for the command in aliases
	int counter = 0;
	while (alias_command_names[counter]){
		if (strcmp(alias_command_names[counter], command->name) == 0){
			memcpy(command, alias_commands[counter], sizeof(struct command_t));
			break;
		}
		counter++;
	}

	if (strcmp(command->name, "") == 0) {
		return SUCCESS;
	}

	if (strcmp(command->name, "exit") == 0) {
		return EXIT;
	}

	if (strcmp(command->name, "cd") == 0) {
		if (command->arg_count > 0) {
			r = chdir(command->args[1]);
			if (r == -1) {
				printf("-%s: %s: %s\n", sysname, command->name,
					   strerror(errno));
			}

			return SUCCESS;
		}
	}

	if (strcmp(command->name, "pvis") == 0){
		if (load_module() != 0){
			printf("Error loading module.\n");
			return SUCCESS;
		}
	}

	if (strcmp(command->name, "alias") == 0) { 
		alias(command); 
		return SUCCESS;
	}


	int fd_confirm_setpgid[2];
	int fd_confirm_control[2];
	int fd_execv_control[2];
	if (pipe(fd_confirm_setpgid) == -1 || pipe(fd_confirm_control) == -1 || pipe(fd_execv_control) == -1){
		fprintf(stderr, "error in piping\n");
		return SUCCESS;
	}
	pid_t pid = fork();
	// child
	if (pid == 0) {
		/// This shows how to do exec with environ (but is not available on MacOs)
		// extern char** environ; // environment variables
		// execvpe(command->name, command->args, environ); // exec+args+path+environ

		/// This shows how to do exec with auto-path resolve
		// add a NULL argument to the end of args, and the name to the beginning
		// as required by exec

		// TODO: do your own exec with path resolving using execv()
		// do so by replacing the execvp call below
		// execvp(command->name, command->args); // exec+args+path


		// try to create a new process group and make the child process be the leader of it
		// this is achieved through setpgid(0, 0);
		// inform parent about the setpgid() is executed and it was succcessfull or not
		int confirm = setpgid(0,0);
		close(fd_confirm_setpgid[READ_END]);
		write(fd_confirm_setpgid[WRITE_END], &confirm, sizeof(int));
		close(fd_confirm_setpgid[WRITE_END]);

		close(fd_confirm_control[WRITE_END]);
		read(fd_confirm_control[READ_END], &confirm, sizeof(int));
		close(fd_confirm_control[READ_END]);

		// close the read end and close the write end in case of a successful exec call
		close(fd_execv_control[READ_END]);
		fcntl(fd_execv_control[WRITE_END], F_SETFD, FD_CLOEXEC);
		

		// handle redirecting file descriptors
		int fd_stored_stdout = dup(STDOUT_FILENO);
		if (command->redirects[0]){
			// change stdin
			int new_stdin = open(command->redirects[0], O_RDONLY);
			if (new_stdin == -1) {
				printf("Couldn't find %s", command->redirects[0]);
				return EXIT;
			}

			// Replace stdin with the file descriptor of the file
			if (dup2(new_stdin, STDIN_FILENO) == -1) {
				printf("dup2() failed for STDIN");
				close(new_stdin);
				return EXIT;
			}
		}

		if (command->redirects[1]){
			// change stdout
			// delete and write
			int new_stdout = open(command->redirects[1], O_WRONLY | O_CREAT | O_TRUNC, 0666);
			// done before last stdout control bc even if that is not the last one
			// the content of the file is deleted
			if (new_stdout == -1){
				printf("Failed opening %s\n", command->redirects[1]);
				return EXIT;
			}
			// checks wheter the last redirection written in the command
			// is > or not (it can be >>)
			if (command->redirect_stdout_last == 1){
				if (dup2(new_stdout, STDOUT_FILENO) == -1){
					printf("dup2() failed for STDOUT");
					close(new_stdout);
					return EXIT;
				}
			}
			// it means this is not the last one so no need for this file descriptor to remain opened
			else{
				close(new_stdout);
			}
		}

		if (command->redirects[2] && command->redirect_stdout_last == 2){
			// change stdout
			// append
			int new_stdout = open(command->redirects[2], O_WRONLY | O_CREAT | O_APPEND, 0666);
                        if (new_stdout == -1){
                                printf("Failed opening %s\n", command->redirects[2]);
                                return EXIT;
                       	}

			if (command->redirect_stdout_last == 2){
				if (dup2(new_stdout, STDOUT_FILENO) == -1){
					printf("dup2() failed for STDOUT");
					close(new_stdout);
					return EXIT;
				}
			}
			// it means this is not the last one so no need for this file descriptor to remain opened
			else{
				close(new_stdout);
			}
		}


		///////////////// builtin commands //////////////////////
		if (strcmp(command->name, "xdd") == 0){
			// if background, tell parent to continue by closing write end
			if (command->background){
				close(fd_execv_control[WRITE_END]);
			}
			xdd(command);
                	// restore stdout but in fact no need
                	dup2(fd_stored_stdout, STDOUT_FILENO);
                	close(fd_stored_stdout);
			// if foreground now, tell parent that child is done
			if (!command->background){
				close(fd_execv_control[WRITE_END]);
			}
			return EXIT;
		}

		if(strcmp(command->name, "good_morning") == 0){
			if (command->background){
                                close(fd_execv_control[WRITE_END]);
                        }
                        good_morning(command);
                        // restore stdout but in fact no need
                        dup2(fd_stored_stdout, STDOUT_FILENO);
                        close(fd_stored_stdout);
                        // if foreground now, tell parent that child is done
                        if (!command->background){
                                close(fd_execv_control[WRITE_END]);
                        }
                        return EXIT;
		}
                if(strcmp(command->name, "piano") == 0){
                        if (command->background){
                                close(fd_execv_control[WRITE_END]);
                        }
                        piano(command);
                        // restore stdout but in fact no need
                        dup2(fd_stored_stdout, STDOUT_FILENO);
                        close(fd_stored_stdout);
                        // if foreground now, tell parent that child is done
                        if (!command->background){
                                close(fd_execv_control[WRITE_END]);
                        }
                        return EXIT;
                }
		if(strcmp(command->name, "pvis") == 0){
			if (command->background){
                                close(fd_execv_control[WRITE_END]);
                        }
                        pvis(command);
                        // restore stdout but in fact no need
                        dup2(fd_stored_stdout, STDOUT_FILENO);
                        close(fd_stored_stdout);
                        // if foreground now, tell parent that child is done
                        if (!command->background){
                                close(fd_execv_control[WRITE_END]);
                        }
                        return EXIT;
		}

		// char *informative_msg = (confirm == 1) ? "Parent didn't gave the control!" : "Got the control now!";
		// printf("This is child speaking. %s\n", informative_msg);
		char path_command[4096];
		char cur_dir[1024];
	       	getcwd(cur_dir, sizeof(cur_dir));
		char *formatting_str;
		char *cpy_all_paths;
		char *cur_path;

		
		// if the command name starts with "./" it means this is a relative path
		if (strlen(command->name) > 1 && command->name[0] == '.' && command->name[1] == '/'){
			formatting_str = cur_dir[strlen(cur_dir) - 1] == '/' ? "%s%s" : "%s/%s";
			// + 2 for jumping over ./
			snprintf(path_command, sizeof(path_command), formatting_str, cur_dir, command->name + 2);
		}
		// if the command name starts with "/" it means this is an absolute path
		else if (command->name[0] == '/'){
			strcpy(path_command, command->name);
		}
		else{
			char *all_paths = getenv("PATH");
                	// one for ":" and one for null terminator
                	cpy_all_paths = malloc(sizeof(char) * strlen(all_paths) + strlen(cur_dir) + 1 + 1);

                	strcpy(cpy_all_paths, cur_dir);
                	strcpy(cpy_all_paths + strlen(cpy_all_paths), ":");
			strcpy(cpy_all_paths + strlen(cpy_all_paths), all_paths);

			cur_path = strtok(cpy_all_paths, ":");
                	formatting_str = (cur_path[strlen(cur_path) - 1] == '/') ? "%s%s" : "%s/%s";
                	snprintf(path_command, sizeof(path_command), formatting_str, cur_path, command->name);
		}
		// Note: if execv() succeeds, it never returns!!!
		while (execv(path_command, command->args) == -1){
			cur_path = strtok(NULL, ":");
			if (cur_path == NULL){
				break;
			}
                        formatting_str = (cur_path[strlen(cur_path) - 1] == '/') ? "%s%s" : "%s/%s";
                        snprintf(path_command, sizeof(path_command), formatting_str, cur_path, command->name);
		}
		free(cpy_all_paths);
		// restore stdout to print
		dup2(fd_stored_stdout, STDOUT_FILENO);
		close(fd_stored_stdout);
        	printf("-%s: %s: command not found\n", sysname, command->name);
        	close(fd_execv_control[WRITE_END]);
        	return EXIT;
	}

	else {
		// TODO: implement background processes here
		int new_pg_confirm;
		// no need for the write end of execv_control
		close(fd_execv_control[WRITE_END]);
		close(fd_confirm_setpgid[WRITE_END]);
		read(fd_confirm_setpgid[READ_END], &new_pg_confirm, sizeof(int));
		close(fd_confirm_setpgid[READ_END]);
		// background case
		if (command->background){
			int conf = 1;
			close(fd_confirm_control[READ_END]);
			write(fd_confirm_control[WRITE_END], &conf, sizeof(int));
			close(fd_confirm_control[WRITE_END]);
			// block the parent until the write end is closed by the child process
			// when the child closes it whether by executing the command
			// or it cant find the command and after printing the not found statement, it will close it
			read(fd_execv_control[READ_END], &conf, sizeof(int));
			close(fd_execv_control[READ_END]);
			return SUCCESS;
		}
		// foreground and group creation successfull
		// the parent is already waiting for the child, so not necessary anymore
		close(fd_execv_control[READ_END]);
		if (!command->background && (new_pg_confirm == 0)){
			int conf = 0;
			// give terminal control to the child's process group
			// printf("Gave control to child process\n");
			tcsetpgrp(STDIN_FILENO, pid);
			// inform child that it has the terminal control now
                        close(fd_confirm_control[READ_END]);
                        write(fd_confirm_control[WRITE_END], &conf, sizeof(int));
                        close(fd_confirm_control[WRITE_END]);
			// wait for current child to finish
			waitpid(pid, NULL, 0);
			
			// as this shell is not the session leader nor belongs to the foreground process group
			// when it tries to change the terminal controlling group, it will receive a SIGTTOU.
			// if not handled, the shell is exited
			// so set that signal to ignore signal, change the terminal controlling group,
			// set the signal back to default
			signal(SIGTTOU, SIG_IGN);
			tcsetpgrp(STDIN_FILENO, getpgrp());
			signal(SIGTTOU, SIG_DFL);
			
			return SUCCESS;
		}

		// foreground but group creation not successfull
		else { // (!command->background && (new_pg_confirm != 0)){
			int conf = 0;
			// printf("Group creation not successfull!\nIf you send a signal it will also be captured by the shel itself.\n");
                        close(fd_confirm_control[READ_END]);
                        write(fd_confirm_control[WRITE_END], &conf, sizeof(int));
                        close(fd_confirm_control[WRITE_END]);
			waitpid(pid, NULL, 0);
			return SUCCESS;
		}
	}
}

// builtin commands
int piano(struct command_t *command){
	// args: -r for record -p for play
	// 	file to save the recording / to play the recording from
	if (command->arg_count != 4){
		fprintf(stderr, "Illegal number of arguments\n");
		return EXIT;
	}

	char *flag;
	char *file;
	if (command->args[1][0] == '-'){
		flag = command->args[1];
		file = command->args[2];
	}
	else{
		flag = command->args[2];
                file = command->args[1];
	}
	if (!(flag[1] == 'r' || flag[1] == 'p')){
		fprintf(stderr, "Invalid flag\n");
		return EXIT;
	}
	bool record;
	record = flag[1] == 'r';

        static struct termios backup_termios, new_termios;
        char c;
	tcgetattr(STDIN_FILENO, &backup_termios);
        new_termios = backup_termios;
        new_termios.c_lflag &= ~(ICANON | ECHO);
        tcsetattr(STDIN_FILENO, TCSANOW, &new_termios);
	
	double semitone_ratio = pow(2.0, 1.0 / 12.0);
	char command_buf[128];
	char *template = "play -n synth 0.5 sin %f > /dev/null 2>&1";
	double do1 = 261.63;
	double re = do1 * pow(semitone_ratio, 2.0);
	double mi = do1 * pow(semitone_ratio, 4.0);
	double fa = do1 * pow(semitone_ratio, 5.0);
	double sol = do1 * pow(semitone_ratio, 7.0);
	double la = do1 * pow(semitone_ratio, 9.0);
	double si = do1 * pow(semitone_ratio, 11.0);
	double do2 = do1 * pow(semitone_ratio, 12.0);
        
	
	int stdin_cpy = dup(STDIN_FILENO);
	int fd_file;
	fd_file = record ? open(file, O_WRONLY | O_CREAT | O_TRUNC, 0666) : open(file, O_RDONLY, 0666);
	if (fd_file == -1){
		fprintf(stderr, "Error opneing file\n");
		return EXIT;
	}
	if (!record){
		dup2(fd_file, STDIN_FILENO);
	}
	
	
	int t;
	int time_until_now = 0;
	time_t base_time = time(NULL);
	while (read(STDIN_FILENO, &c, sizeof(char)) && c != '\n'){
		switch(c){
			case 'a':
				snprintf(command_buf, sizeof(command_buf), template, do1);
				break;
			case 's':
				snprintf(command_buf, sizeof(command_buf), template, re);
				break;
			case 'd':
				snprintf(command_buf, sizeof(command_buf), template, mi);
				break;
			case 'f':
				snprintf(command_buf, sizeof(command_buf), template, fa);
				break;
			case 'h':
				snprintf(command_buf, sizeof(command_buf), template, sol);
				break;
			case 'j':
				snprintf(command_buf, sizeof(command_buf), template, la);
				break;
			case 'k':
				snprintf(command_buf, sizeof(command_buf), template, si);
				break;
			case 'l':
				snprintf(command_buf, sizeof(command_buf), template, do2);
				break;
			default:
				printf("Invalid key...\n");
				continue;
		}
		if (record){
			t = (int) ((int) (time(NULL) - base_time) - time_until_now);
			time_until_now += t;
			write(fd_file, &c, sizeof(char));
			write(fd_file, &t, sizeof(int));
		}
		else{
			read(STDIN_FILENO, &t, sizeof(int));
			sleep(t);
		}
		system(command_buf);
	}
	if (record){
		write(fd_file, "\n", sizeof(char));
	}

	dup2(stdin_cpy, STDIN_FILENO);
	close(stdin_cpy);
	close(fd_file);
	tcsetattr(STDIN_FILENO, TCSANOW, &backup_termios);
	return EXIT;
}

void remove_module(){
	char rm_module[128];
	char rm_device[128];
	if (Module_Loaded){	
		snprintf(rm_module, sizeof(rm_module), "sudo rmmod %s 2>/dev/null", MODULE_NAME);
		snprintf(rm_device, sizeof(rm_device), "sudo rm %s 2>/dev/null", DEVICE_PATH);
		system(rm_module);
		system(rm_device);
		Module_Loaded = 0;
	}
}
int load_module(){
	FILE *fp;
	char line[1024];
        char load_module[512];
        char for_dev_file[512];
	int major = -1;
	
	if (!Module_Loaded){
                // load the module
                snprintf(load_module, sizeof(load_module), "sudo insmod %s param_pid=1", MODULE_PATH);
                system(load_module);
                Module_Loaded = 1;
                // find the Major
                fp = popen("sudo dmesg | grep 'Major number for mymodule' | tail -n 1", "r");
                if (fp == NULL) {
                        fprintf(stderr, "Error opening dmesg.\n");
                        return EXIT;
                }
                while (fgets(line, sizeof(line), fp) != NULL) {
                        if (strstr(line, "Major number for mymodule") != NULL) {
                                sscanf(line, "[ %*f] Major number for mymodule: %d", &major);
                                break;
                        }
                }
                pclose(fp);
                if (major == -1){
                        fprintf(stderr, "Couldn't found major number.\n");
                        return EXIT;
                }
                // create the device file using major
                snprintf(for_dev_file, sizeof(for_dev_file), "sudo mknod %s c %d 0", DEVICE_PATH, major);
                system(for_dev_file);
                Major = major;
		return SUCCESS;
        }

	else{
		return SUCCESS;
	}
}

void save_out_module(char *out_module, int fd_out);
void plot_tree_n_remove_data(char *plotter_file, char *data_file, char *out_name);
int pvis(struct command_t *command){
	int pid;
	int fd_temp_file;
	int fd_device;
	char parameter_command[128];
	char module_out[MODULE_OUT_SIZE];
	

	// change the parameters of the module
	pid = atoi(command->args[1]);
	snprintf(parameter_command, sizeof(parameter_command), "echo %d | sudo tee %s >/dev/null", pid, MODULE_PID_PATH);
	//snprintf(parameter_command, sizeof(parameter_command), "sudo sh echo %d > %s", pid, MODULE_PID_PATH);
	system(parameter_command);

	// open the device file and read
	fd_device = open(DEVICE_PATH, O_RDONLY);
	if (fd_device == -1) {
		fprintf(stderr, "Couldn't open device file.\n");
		return EXIT;
	}
	int bytes_read = read(fd_device, module_out, sizeof(module_out));
	if (bytes_read < 0){
		fprintf(stderr, "Error reading the device file.\n");
		return EXIT;
	}
	close(fd_device);
	module_out[bytes_read] = 0;
	
	fd_temp_file = open(TEMP_DATA_FILE, O_WRONLY | O_CREAT | O_TRUNC, 0666);
	if (fd_temp_file == -1){
		fprintf(stderr, "Error opening out file.\n");
		return EXIT;
	}
	save_out_module(module_out, fd_temp_file);
	close(fd_temp_file);

	plot_tree_n_remove_data(PLOTTER_FILE_PATH, TEMP_DATA_FILE, command->args[2]);

	return EXIT;
}

void plot_tree_n_remove_data(char *plotter_file, char *data_file, char *out_name){
        char plot_command[128];
        char rm_temp_file_command[128];

        snprintf(plot_command, sizeof(plot_command), "gnuplot -c %s %s %s", plotter_file, data_file, out_name);
        snprintf(rm_temp_file_command, sizeof(rm_temp_file_command), "rm %s", data_file);
        system(plot_command);
        system(rm_temp_file_command);
}

void save_out_module(char *out_module, int fd_out){
	char *entry;
	char entry_str[50];
	char module_out[MODULE_OUT_SIZE];
	char *headers = "PID\tPPID\tIsEldest\tCreationTime\n";
	char *entry_format = "%d\t%d\t%d\t%s\n";
	char *root_entry_format = "%d\t%s\t%d\t%s\n";

	int ppid;
	int pid;
	int isEldest;
	unsigned long time_sec;
	time_t time_obj;
	struct tm *parsed_time;
	int hour;
	int minute;
	int second;

	char time_str[20];
	
	write(fd_out, headers, strlen(headers));

	strcpy(module_out, out_module);
	entry = strtok(module_out, "|");
	while (entry != NULL){
		if (strlen(entry) < 10){
			entry = strtok(NULL, "|");
			continue;
		}
		sscanf(entry, "%d,%d,%d,%lu", &ppid, &pid, &isEldest, &time_sec);
		time_obj = (time_t) time_sec;
		parsed_time = localtime(&time_obj);
		hour = parsed_time->tm_hour;
		minute = parsed_time->tm_min;
		second = parsed_time->tm_sec;
		snprintf(time_str, sizeof(time_str), "%02d:%02d:%02d", hour, minute, second);
		if (ppid == 0){
			snprintf(entry_str, sizeof(entry_str), root_entry_format, pid, "NaN", isEldest, time_str);
		}
		else{
			snprintf(entry_str, sizeof(entry_str), entry_format, pid, ppid, isEldest, time_str);
		}
		write(fd_out, entry_str, strlen(entry_str));
		entry = strtok(NULL, "|");
	}
}


int xdd(struct command_t *command){
        if (!(command->arg_count == 4 || command->arg_count == 5)){
                fprintf(stderr, "Expected 2 or 3 arguments, given %d\n", command->arg_count - 2);
                return EXIT;
        }

        int divisor;
        char *divisor_str;
	char *path;
        if (strcmp(command->args[1], "-g") == 0){
                divisor_str = command->args[2];
		path = command->args[3];
        }
        else if (strcmp(command->args[2], "-g") == 0){
                divisor_str = command->args[3];
		path = command->args[1];
        }
        else{
                fprintf(stderr, "Expected '-g' flag in arguments, didn't received!\n");
                return EXIT;
        }
        // check divisor_str and convert it to int
        for (size_t i = 0; i < strlen(divisor_str); i++){
                if (!isdigit((unsigned char) divisor_str[i])){
                        fprintf(stderr, "Group size should be a positive integer!\n");
                        return EXIT;
                }
        }

        divisor = atoi(divisor_str);
	int fd_inp_file;
	fd_inp_file = path ? open(path, O_RDONLY) : dup(STDIN_FILENO);
	if (fd_inp_file == -1){
		fprintf(stderr, "Error opening the file: %s\n", path);
		return SUCCESS;
	}
        
        char *buffer;
        int counter = 0;
        int bytes_read;
        int group_size = 16 / divisor;
        buffer = malloc(sizeof(char) * group_size);
        while ((bytes_read = read(fd_inp_file, buffer, group_size)) > 0){
                printf("%08x:  ", counter * group_size);
                for (int i = 0; i < bytes_read; i ++){
                        printf("%02x ", (unsigned char) buffer[i]);
                }
                printf(" %.*s\n", bytes_read, buffer);
                counter++;
        }
        if (bytes_read == -1){
                fprintf(stderr, "Error reading the file!\n");
        }
        free(buffer);
	close(fd_inp_file);
        return EXIT;
}

int good_morning(struct command_t *command){
	if (command->arg_count != 4){
		fprintf(stderr, "Illegal number of arguments\n");
	}
	int mins;
	char *path_to_audio;
	int mins_idx;
	int path_idx;
	for (int i = 1; i < 3; i ++){
		size_t k = 0;
		while (k < strlen(command->args[i])){
			if (!isdigit(command->args[i][k])){
				break;
			}
			k++;
		}
		if (k == strlen(command->args[i])){
			mins_idx = i;
			path_idx = mins_idx == 1 ? 2 : 1;
			break;
		}
	}
	if (!mins_idx){
		fprintf(stderr, "good_morning found illegal arguments\n");
		return EXIT;
	}
	mins = atoi(command->args[mins_idx]);
	path_to_audio = command->args[path_idx];
	if (path_to_audio[0] != '/'){
		fprintf(stderr, "Need to provide an absoulte path\n");
		return EXIT;
	}

	time_t now;
	struct tm *time_object;
	time(&now);
	now += mins * 60;
	time_object = localtime(&now);

	int minute = time_object->tm_min;
	int hour = time_object->tm_hour;
	int day_of_month = time_object->tm_mday;
	int month = time_object->tm_mon + 1;
	int day_of_week = time_object->tm_wday;
	char *usr = getenv("USER");
	char cmd_buffer[256];
	char crontab_entry[512];
	char system_call[600];
	snprintf(cmd_buffer, sizeof(cmd_buffer), "%s %s", "mpg123", path_to_audio);
	snprintf(crontab_entry, sizeof(crontab_entry),"%d\t%d\t%d\t%d\t%d\t%s", minute, hour, day_of_month, month, day_of_week, cmd_buffer);
	snprintf(system_call, sizeof(system_call), "(crontab -l 2>/dev/null; echo \"%s\") | crontab -u %s -", crontab_entry, usr);
	
	int result = system(system_call);
	if (result != 0) {
		fprintf(stderr, "Error adding crontab entry.");
		return EXIT;
	}
		
	return EXIT;
}


int alias(struct command_t * command){
	// needs at least 2 args
	if (command->arg_count < 4){
		printf("Expected more arguments.\n");
		return SUCCESS;
	}
	// find the current alias index while looking for the new alias name,
	// if it exists this is an error
	int idx = 0;
	while (alias_command_names[idx]){
		if (strcmp(alias_command_names[idx], command->args[1]) == 0){
			printf("Alias %s already exists.\n", command->args[1]);
			return SUCCESS;
		}
		idx++;
	}

	char *home_dir = getenv("HOME");
	char aliasfile_path[1024];
	snprintf(aliasfile_path, sizeof(aliasfile_path), "%s/%s", home_dir, ALIAS_FILE_NAME);
	int fd_alias_file = open(aliasfile_path, O_WRONLY | O_CREAT | O_APPEND, 0666);
	if (fd_alias_file == -1){
		printf("Error opening alias file.\n");
		return SUCCESS;
	}
	
	char alias_name[64];
	char alias_command_str[1024];
	alias_command_str[0] = 0;
	// save command and args for later and for current session
	for (int i = 1; i < (command->arg_count - 1); i++){
		write(fd_alias_file, command->args[i], sizeof(char) * strlen(command->args[i]));
		write(fd_alias_file, " ", sizeof(char));
		// save the name for current session
		if (i == 1){
			strcpy(alias_name, command->args[i]);
		}
		// save the command for current session
		else {
			strcpy(alias_command_str + strlen(alias_command_str), command->args[i]);
			strcpy(alias_command_str + strlen(alias_command_str), " ");
		}
	}
	// handle redirections
	if (command->redirects[0]){
		write(fd_alias_file, "< ", sizeof(char) * 2);
		write(fd_alias_file, command->redirects[0], sizeof(char) * strlen(command->redirects[0]));
                write(fd_alias_file, " ", sizeof(char));
	}
	int first_control, second_control;
	if (command->redirect_stdout_last){
		second_control = command->redirect_stdout_last;
		first_control = (second_control == 1) ? 2 : 1;
	}
	char *redirect_str;
	if (command->redirects[first_control]){
		redirect_str = (first_control == 1) ? "> " : ">> ";
                write(fd_alias_file, redirect_str, sizeof(char) * strlen(redirect_str));
                write(fd_alias_file, command->redirects[first_control], sizeof(char) * strlen(command->redirects[first_control]));
                write(fd_alias_file, " ", sizeof(char));
	}
	if (command->redirects[second_control]){
                redirect_str = (second_control == 1) ? "> " : ">> ";
                write(fd_alias_file, redirect_str, sizeof(char) * strlen(redirect_str));
                write(fd_alias_file, command->redirects[second_control], sizeof(char) * strlen(command->redirects[second_control]));
                write(fd_alias_file, " ", sizeof(char));
        }
	// handle other fields
        if (command->auto_complete){
                write(fd_alias_file, "? ", sizeof(char) * 2);
        }
	if (command->background){
		write(fd_alias_file, "& ", sizeof(char) * 2);
	}
	write(fd_alias_file, "\n", sizeof(char));


	// make it available to current session:
	alias_command_names[idx] = malloc(sizeof(char) * (strlen(alias_name) + 1));
	strcpy(alias_command_names[idx], alias_name);
	
	struct command_t *new_alias_cmd = malloc(sizeof(struct command_t));
	memset(new_alias_cmd, 0, sizeof(struct command_t));
	parse_command(alias_command_str, new_alias_cmd); // this will only parse the name and arguments, not redirections etc.
	alias_commands[idx] = new_alias_cmd;
	
	new_alias_cmd->auto_complete = command->auto_complete;
	new_alias_cmd->background = command->background;
	for (int i = 0; i < 3; i++){
		if (command->redirects[i]){
			char *redir_str = malloc(strlen(command->redirects[i]) + 1);
			strcpy(redir_str, command->redirects[i]);
			new_alias_cmd->redirects[i] = redir_str;
		}
	}
	if (command->redirect_stdout_last){
		new_alias_cmd->redirect_stdout_last = command->redirect_stdout_last;
	}

	close(fd_alias_file);
	return SUCCESS;
}

void restore_aliases(){
        char *home_dir = getenv("HOME");
        char aliasfile_path[1024];
        snprintf(aliasfile_path, sizeof(aliasfile_path), "%s/%s", home_dir, ALIAS_FILE_NAME);
	FILE *alias_file = fopen(aliasfile_path, "r");
	if (alias_file == NULL){
		printf("During restoring aliases, error occured opening alias file!\n");
		return;
	}
	
	char *temp_ptr;
	char line[1024];
	int counter = 0;
	while (fgets(line, sizeof(line), alias_file)){	
                while (strlen(line) > 0 && strchr(" \t\n", line[strlen(line) - 1])){
                        line[strlen(line) - 1] = '\0';
                }
		temp_ptr = strtok(line, " \n\t");
		if (temp_ptr == NULL){
                        continue;
                }
		
		alias_command_names[counter] = malloc(sizeof(char) * strlen(temp_ptr) + 1);
		strcpy(alias_command_names[counter], temp_ptr);
		struct command_t *cur_command = malloc(sizeof(struct command_t));
		temp_ptr = temp_ptr + strlen(temp_ptr) + 1;
		
		parse_command(temp_ptr, cur_command);
		alias_commands[counter] = cur_command;
		counter++;
	}
	return;

}

void free_aliases(){
	int idx = 0;
	while (alias_command_names[idx]){
		free(alias_command_names[idx]);
		free_command(alias_commands[idx]);
		idx++;
	}
	return;
}





