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
        printf("[!] Oops, Stayed too long at the bank\n");
        _exit(0);
    }
}

void kill_signal() {
    signal(SIGALRM, timeout);
    alarm(60);
}

// Real challenge starts here

void print_flag() {
    FILE* f = fopen("flag.txt", "r");
    char flag[100];
    fscanf(f, "%s", flag);
    printf("%s\n", flag);
    fclose(f);
}

void welcome() {
    printf("[*] Welcome to the super secure bank.\n");
    printf("We store your money in a secure manner.\n");
    printf("The super rich get a special treatment though :P\n");
}

int balance = 500;

int menu() {
    printf("\n[*] Menu: \n");
    printf("1. Show balance.\n");
    printf("2. Debit money.\n");
    printf("3. Credit money.\n");
    printf("4. Buy the flag (1000 Rs each).\n");
    printf("5. VIP access.\n");
    printf("6. Exit.\n");
    printf("[*] Choose one of these options: ");
    int choice;
    int status = scanf("%d", &choice);
    if ((choice == 1 || choice == 2 || choice == 3 || choice == 4 || choice == 5 || choice == 6) && status == 1) {
        printf("%d\n", choice);
        return choice;
    } else {
        printf("Invalid choice\n");
        _exit(0);
    }
}

void show_balance() {
    printf("[*] Here is your remaining balance: %d\n", balance);
}

void debit_money() {
    printf("Input the number of notes you want (In the denomination of Rs. 10): ");
    int notes;
    scanf("%d", &notes);
    if(notes > 0) {
        int debit_amount = notes * 10;
        if(debit_amount <= balance) {
            balance = balance - debit_amount;
            show_balance();
        } else {
            printf("[!] You don't have enough money\n");
        }
    }
}

void credit_money() {
    printf("How many Rs. are you crediting: ");
    int credit_amount;
    scanf("%d", &credit_amount);
    if(credit_amount < 0 || credit_amount > 100) {
        printf("[!] Can't add this much money at once\n");
        return;
    }
    if(balance + credit_amount > 2000) {
        printf("[!] You are not supposed to have this much money");
        return;
    }
    balance = balance + credit_amount;
}

void buy_a_flag() {
    printf("You sure you want to spend Rs. 1000 to buy a flag? (yes/no): ");
    char agree[10];
    scanf("%s", agree);
    if (agree[0] == 'Y' || agree[0] == 'y') {
        if(balance >= 1000) {
            printf("Here is your flag: HackRushCTF{normie_hai_kya?_aise_flag_thodi_na_milega}\n");
            balance = balance - 1000;
        } else {
            printf("[!] Not enough money\n");
        }
    }
}

void vip() {
    if(balance >= 100000) {
        printf("[+] Welcome sir!\nPlease find the correct flag: ");
        print_flag();
    } else {
        printf("[!] You are not rich enough :(\n");
    }
}

void bank() {
    welcome();
    int choice = 0;
    while (choice != 6) {
        choice = menu();
        if(choice == 1) {
            show_balance();
        } else if(choice == 2) {
            debit_money();
        } else if(choice == 3) {
            credit_money();
        } else if(choice == 4) {
            buy_a_flag();
        } else if(choice == 5) {
            vip();
        }
    }
}

int main() {
    buffering();
    kill_signal();
    bank();
}
