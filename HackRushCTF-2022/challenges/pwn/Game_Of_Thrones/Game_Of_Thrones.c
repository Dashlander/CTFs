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

void win() {
    FILE* f = fopen("flag.txt", "r");
    char flag[100];
    fscanf(f, "%s", flag);
    printf("%s\n", flag);
    fclose(f);
}

void func() {
    printf("[*] Game of Thrones is considered to be one of the best series ever made.\n");
    printf("What's your thoughts?: ");
    char input[100];
    fgets(input, 100, stdin);
    puts(input);
    _exit(0);
}

int main() {
    buffering();
    kill_signal();
    func();
}
