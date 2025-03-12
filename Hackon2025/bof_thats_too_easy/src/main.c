// gcc main.c -fno-stack-protector -fno-pic -no-pie -o chall
#include <stdio.h>

__attribute__( ( constructor ) ) void init() {
  setvbuf( stdin, NULL, _IONBF, NULL );
  setvbuf( stdout, NULL, _IONBF, NULL );
  setvbuf( stderr, NULL, _IONBF, NULL );
}

int main( void ) {
  char buf[0x10] = { 0 };
  scanf( "%s", buf );
  return 0;
}
