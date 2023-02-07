#include <stdlib.h>
#include <stdio.h>
#include <syslog.h>

int main(int argc, char *argv[]) {
    openlog(argv[0], LOG_PERROR, LOG_USER);
    if (argc < 2) {
        syslog(LOG_ERR, "2 arguments required, found %d\n", argc);
        exit(1);
    }
    FILE *myfile = fopen(argv[1], "w");
    if (myfile == NULL) {
        syslog(LOG_ERR, "Could not create file %s, %m\n", argv[1]);
        exit(1);
    } else {
        fputs(argv[2], myfile);
        fclose(myfile);
        syslog(LOG_DEBUG, "Writing %s to %s\n", argv[2], argv[1]);
    }
}
