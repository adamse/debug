#include <stdio.h>
#include <unistd.h>

int main(int argc, char ** argv) {
  setbuf(stdout, NULL);
  while (1) {
    printf("h");
    usleep(500000);
  }
}
