#include <sys/types.h>
#include <regex.h>

int main(int argc, char *argv[])
{
  regex_t r;
  if (argc < 3) { printf("%s regex string",argv[0]); exit(1); }
  if (regcomp(&r, argv[1], REG_EXTENDED|REG_NOSUB)) {
    perror("regcomp");
    exit(-1);
  }
  if (regexec(&r, argv[2], 0, 0, 0)) {
    perror("no match");
    exit(-1);
  }
  regfree(&r);
  printf("match!\n");
}
