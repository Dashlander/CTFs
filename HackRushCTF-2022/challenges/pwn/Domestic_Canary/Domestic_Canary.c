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

void about_canary() {
    printf("[*] Here is some (useful?) information about the canary bird.\n");
    printf("The Canary is a domesticated form of the wild canary, a small songbird in the finch family originating from the Macaronesian Islands\n(the Azores, Madeira and the Canary Islands).\n");
    printf("Do you want to say something?: ");
    char thoughts[100];
    gets(thoughts);
    puts(thoughts);
}

int main() {
    buffering();
    kill_signal();
    about_canary();
    printf("Let's hear the information again to remember it well\n");
    about_canary();
}
