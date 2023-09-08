#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <unistd.h>

/* Ignore these functions */
void buffering() {
    setvbuf(stdout, NULL, _IONBF, 0);
	setvbuf(stdin, NULL, _IONBF, 0);
	setvbuf(stderr, NULL, _IONBF, 0);
}

void timeout(int sig) {
    if (sig == SIGALRM) {
        printf("[!] DOS Alert\n");
        _exit(0);
    }
}

void kill_signal() {
    signal(SIGALRM, timeout);
    alarm(60);
}

// Real challenge starts here

void func() {
    printf("[*] Are you lost? I think you should go to your home\n");
    printf("What's your address?: ");
    char input[100];
    gets(input);
    printf("We have informed the authorities\n");
}

int main() {
    buffering();
    kill_signal();
    func();
}
