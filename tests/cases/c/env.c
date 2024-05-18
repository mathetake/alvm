#include <stdio.h>
#include <stdlib.h>

int main() {
  printf("FOO_YEAH: %s\n", getenv("FOO_YEAH"));
  printf("FOO_WHAT: %s\n", getenv("FOO_WHAT"));
  return 0;
}