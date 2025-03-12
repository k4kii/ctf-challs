#include <linux/cdev.h>
#include <linux/delay.h>
#include <linux/err.h>
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/ioctl.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/printk.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/types.h>
#include <linux/uaccess.h>

#define DEV_NAME "keasy_chall"
static unsigned int chall_dev_major = 0;
static struct class *class;

#define MAX_CHNK_SZ 0x1000
#define MAX_CHNKS 20
#define NAME_LEN 100

static DEFINE_MUTEX( lock );

struct chall_params_t {
  unsigned int idx;
  char *name;
  size_t name_size;
  char *content;
  size_t content_size;
};
static struct chall_params_t user_param;

struct note_t {
  int is_freed;
  void *content;
  size_t size;
  char name[NAME_LEN];
};
static struct note_t notes[MAX_CHNKS];

static int chall_open( struct inode *, struct file * );
static int chall_close( struct inode *, struct file * );
static long chall_ioctl( struct file *, unsigned int, unsigned long );

struct file_operations fops = {
    .owner = THIS_MODULE,
    .open = chall_open,
    .unlocked_ioctl = chall_ioctl,
    .release = chall_close };

static long add_note( void ) {
  unsigned int idx = -1, chnk_size = -1;
  int ret = 0;
  mutex_lock( &lock );

  idx = user_param.idx;
  chnk_size = user_param.content_size;

  if ( idx >= MAX_CHNKS ) {
    ret = -ENOENT;
    goto unlock_and_exit;
  }

  if ( !chnk_size || chnk_size >= MAX_CHNK_SZ || user_param.name_size >= NAME_LEN ) {
    ret = -EINVAL;
    goto unlock_and_exit;
  }

  printk( "[DBG]: No invalid params" );

  if ( copy_from_user( notes[idx].name, user_param.name, user_param.name_size ) ) {
    ret = -EFAULT;
    goto unlock_and_exit;
  }

  char *aux_buf = kmalloc( chnk_size, GFP_KERNEL );

  if ( !aux_buf ) {
    ret = -ENOMEM;
    goto unlock_and_exit;
  }

  notes[idx].content = aux_buf;

  if ( copy_from_user( notes[idx].content, user_param.content, chnk_size ) ) {
    ret = -EAGAIN;
    kfree( notes[idx].content );
    notes[idx].content = 0;
    goto unlock_and_exit;
  }

unlock_and_exit:
  mutex_unlock( &lock );

  return ret;
}

static long del_note( unsigned int i ) {
  int ret = 0;
  mutex_lock( &lock );

  if ( i >= MAX_CHNKS ) {
    ret = -EINVAL;
    goto unlock_and_exit;
  }

  if ( notes[i].is_freed || !notes[i].content ) {
    ret = -EFAULT;
    goto unlock_and_exit;
  }

  printk( "[DBG]: No invalid params" );

  kfree( notes[i].content );
  notes[i].is_freed = 1;

unlock_and_exit:
  mutex_unlock( &lock );

  return ret;
}

#ifdef EASY_MODE
static long edit_note( void ) {
  int ret = 0;
  unsigned int idx;
  size_t len;

  mutex_lock( &lock );
  idx = user_param.idx;

  if ( idx >= MAX_CHNKS ) {
    ret = -EINVAL;
    goto unlock_and_exit;
  }

  if ( notes[idx].is_freed || !notes[idx].content ) {
    ret = -EBADF;
    goto unlock_and_exit;
  }

  printk( "[DBG]: No invalid params" );

  len = MIN( user_param.content_size, notes[idx].size );

  if ( copy_from_user( notes[idx].content, user_param.content, len ) ) {
    ret = -EBADR;
    goto unlock_and_exit;
  }

unlock_and_exit:
  mutex_unlock( &lock );
  return ret;
}
#endif

static long show_note( unsigned int i ) {
  int ret = 0;

  mutex_lock( &lock );

  if ( i >= MAX_CHNKS ) {
    ret = -EINVAL;
    goto unlock_and_exit;
  }

  printk( "[DBG]: No invalid params" );

  printk( "To be implemented..." );

unlock_and_exit:
  mutex_unlock( &lock );

  return ret;
}

static long chall_ioctl( struct file *filp, unsigned int cmd, unsigned long arg ) {
  // chall_params_t user_param;
  if ( copy_from_user( &user_param, (int __user *)arg, sizeof( struct chall_params_t ) ) ) {
    return -EFAULT;
  }

  switch ( cmd ) {
    case 0xd00d:
      return add_note();
      break;
    case 0xcafe:
      return del_note( user_param.idx );
      break;
    case 0xbeef:
      return show_note( user_param.idx );
      break;
#ifdef EASY_MODE
    case 0xbabe:
      return edit_note();
      break;
#endif
    default:
      return -EBADF;
      break;
  }
}

static int chall_open( struct inode *inode, struct file *filp ) {
  return 0;
}

static int chall_close( struct inode *inode, struct file *filp ) {
  return 0;
}

static int chall_init( void ) {
  if ( ( chall_dev_major = register_chrdev( 0, DEV_NAME, &fops ) ) < 0 ) {
    pr_err( "Registering char dev failed %d\n", chall_dev_major );
    goto error;
  }

  class = class_create( DEV_NAME );

  if ( IS_ERR( class ) ) {
    pr_err( "Error creating class\n" );
    goto class_create_err;
  };

  if ( IS_ERR( device_create( class, NULL, MKDEV( chall_dev_major, 0 ), NULL, DEV_NAME ) ) ) {
    pr_err( "Error on device_create" );
    goto device_create_err;
  }

  printk( "%s driver(major: %d) installed\n", DEV_NAME, chall_dev_major );

  return 0;

device_create_err:
  class_destroy( class );

class_create_err:
  unregister_chrdev( chall_dev_major, DEV_NAME );

error:
  return -1;
}

static void chall_destroy( void ) {
  for ( int i = 0; i < MAX_CHNKS; i++ ) {
    if ( !notes[i].is_freed && notes[i].content )
      kfree( notes[i].content );
    notes[i].content = 0;
  }

  device_destroy( class, MKDEV( chall_dev_major, 0 ) );
  class_destroy( class );
  unregister_chrdev( chall_dev_major, DEV_NAME );

  printk( "Driver %s removed\n", DEV_NAME );
}

module_init( chall_init );
module_exit( chall_destroy );

MODULE_LICENSE( "GPL" );
MODULE_AUTHOR( "xin0" );
