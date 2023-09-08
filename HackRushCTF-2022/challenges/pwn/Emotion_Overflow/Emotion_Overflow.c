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

void joy() {
    FILE* f = fopen("flag.txt", "r");
    char flag[100];
    fscanf(f, "%s", flag);
    printf("%s\n", flag);
    fclose(f);
}

void show_emotion() {
    printf("People tell me that I get easily overflowed by emotions.\n");
    printf("That's not true. Here, try to send me a message\n");
    char message[100];
    gets(message);
    puts("Thanks for your message!\n");
}

int main() {
    buffering();
    kill_signal();
    show_emotion();
}
