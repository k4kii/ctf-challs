#include <stdio.h>
#include <string.h>
#include <unistd.h>

#define MAX_NOTES 10
#define MAX_NOTE_LEN ( ( u8 ) - 1 )
#define TO_LOWER( c ) ( c < 'a' ? c + 32 : c )
#define PER_LINE_PRINT_CHARS 40

typedef unsigned long long u64;
typedef unsigned int u32;
typedef unsigned short u16;
typedef unsigned char u8;

enum OPTIONS {
  CREATE,
  VIEW,
  EDIT,
  EXIT
};

enum TWIT_LEN {
  SMALL,
  MEDIUM,
  HUGE
};

typedef struct {
  u16 day;
  u16 month;
  u16 year;
} date_t;

typedef struct {
  date_t date;
  u16 len_choize;
  u16 is_used;
  char text[MAX_NOTE_LEN];
} twit_t;

twit_t twit[MAX_NOTES] = { 0 };

u8 get_u8() {
  int val;
  printf( "> " );
  scanf( "%d", &val );
  return (u8)val;
}

int sanitize_idx( u8 idx ) {
  if ( idx >= MAX_NOTE_LEN ) {
    return -1;
  }
  return idx;
}

u8 get_note_idx() {
  int note_idx = -1;
  do {
    printf( "Choose the note index (0-9)\n" );
    note_idx = sanitize_idx( get_u8() );
    if ( note_idx < 0 ) {
      printf( "Invalid note, try again!\n" );
    }
  } while ( note_idx < 0 );

  return (u8)note_idx;
}

void show_options() {
  printf(
      "Wellcome to your note taking app:)\n"
      "%d: Create new note\n"
      "%d: View existing note\n"
      "%d: Edit existing note\n"
      "%d: Exit app\n",
      CREATE,
      VIEW,
      EDIT,
      EXIT );
}

void set_date( twit_t *note ) {
  u32 day = 0, month = 0, year = 0;
  u32 *date = (u32 *)( &note->date );
  printf( "Set the note's date (format: dd/mm/yy):\n" );
  scanf( "%d/%d/%d", &day, &month, &year );
  date[0] = ( (u16)day );
  date[0] += ( ( (u16)month ) << 16 );
  date[1] = year;
  // note->date.day = (u8) day;
  // note->date.month = (u8) month;
  // note->date.year = (u32) year;
}

void set_note_text( twit_t *note ) {
  unsigned int sure = 0;
  unsigned int len;
  char buf[255] = { 0 };
  char keep_changes[3] = { 0 };

  switch ( note->len_choize ) {
    case SMALL:
      len = (u8)( MAX_NOTE_LEN / 4 );
      break;
    case MEDIUM:
      len = (u8)( MAX_NOTE_LEN / 2 );
      break;

    case HUGE:
      len = (u8)( MAX_NOTE_LEN );
      break;

    default:
      break;
  }

  while ( !sure ) {
    printf( "Input your text: " );
    read( 0, buf, len % 1000 );

    printf( "Current text:\n" );
    printf( "%s", buf );
    printf( "\nKeep changes? [y/N]: " );

    scanf( "%2s", keep_changes );
    sure = keep_changes[0] == 'y' || keep_changes[0] == 'Y';
  }

  snprintf( note->text, MAX_NOTE_LEN, "%s", buf );
  char *newline = strchr( note->text, '\n' );
  if ( newline )
    *newline = '\0';
}

void create_note() {
  int note_sz;
  u8 note_idx = get_note_idx();

  twit_t *curr = &twit[note_idx];

  if ( curr->is_used ) {
    printf( "There already exists a note in index %d\n", note_idx );
    return;
  }
  curr->is_used = 1;

  printf( "Choose note size [(S)mall/(m)edium/(l)arge]: " );
  char choize[2];
  scanf( "%2s", choize );

  switch ( TO_LOWER( choize[0] ) ) {
    case 'm':
      curr->len_choize = MEDIUM;
      break;

    case 'l':
      curr->len_choize = HUGE;
      break;

    default:
      curr->len_choize = SMALL;
      break;
  }

  set_note_text( curr );
  set_date( curr );
}

void edit_note() {
  int idx = get_note_idx();
  twit_t *curr = &twit[idx];

  if ( !curr->is_used ) {
    printf( "You can't edit a non-existing note, create it instead!\n" );
    return;
  }

  set_note_text( curr );
}

void print_cage_without_bottom( char *str, int len, int per_line_chars ) {
  char *aux = str;
  putc( '+', stdout );
  for ( int i = 0; i < per_line_chars + 2; i++ ) {
    putc( '-', stdout );
  }
  putc( '+', stdout );
  putc( '\n', stdout );

  int interations = len % per_line_chars ? ( len / per_line_chars ) + 1 : len / per_line_chars;
  for ( int i = 0; i < interations; i++ ) {
    int written_chars = 0;
    printf( "| %.*s%n", per_line_chars, aux, &written_chars );
    for ( int i = written_chars; i < per_line_chars + 2; i++ ) {
      putc( ' ', stdout );
    }
    puts( " |" );
    aux += written_chars;
  }
}

void print_cage( char *title, char *str, int per_line_chars ) {
  char *aux = str;

  int title_len = strlen( title ), str_len = strlen( str );
  print_cage_without_bottom( title, title_len, title_len );
  print_cage_without_bottom( str, str_len, per_line_chars );

  putc( '+', stdout );
  for ( int i = 0; i < per_line_chars + 2; i++ ) {
    putc( '-', stdout );
  }
  putc( '+', stdout );
  putc( '\n', stdout );
}

void pprint( twit_t *curr ) {
  char date[100] = { 0 };
  snprintf( date, 100, "%d/%d/%d", curr->date.day, curr->date.month, curr->date.year );

  print_cage( "Date", date, PER_LINE_PRINT_CHARS );
  print_cage( "Note", curr->text, PER_LINE_PRINT_CHARS );
}

void view_note() {
  int idx = get_note_idx();

  twit_t *curr = &twit[idx];

  if ( !curr->is_used ) {
    printf( "Note %d is empty!\n", idx );
    return;
  }

  pprint( curr );
}

void menu() {
  int exit_ = 0;
  while ( !exit_ ) {
    show_options();
    u8 opt = get_u8();
    switch ( opt ) {
      case CREATE:
        create_note();
        break;

      case EDIT:
        edit_note();
        break;

      case VIEW:
        view_note();
        break;

      case EXIT:
        exit_ = 1;
        break;

      default:
        printf( "Invalid option! %x %c\n", opt, opt );
        break;
    }
  }
  printf( "See you next time!\n" );
}

int main( void ) {
  setvbuf( stdout, NULL, _IONBF, 0 );
  setvbuf( stdin, NULL, _IONBF, 0 );
  menu();
  return 0;
}
