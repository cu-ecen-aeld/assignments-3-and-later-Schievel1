/**
 * @file aesdchar.c
 * @brief Functions and data related to the AESD char driver implementation
 *
 * Based on the implementation of the "scull" device driver, found in
 * Linux Device Drivers example code.
 *
 * @author Dan Walkes
 * @date 2019-10-22
 * @copyright Copyright (c) 2019
 *
 */

#include <linux/cdev.h>
#include <linux/fs.h> // file_operations
#include <linux/init.h>
#include <linux/module.h>
#include <linux/printk.h>
#include <linux/types.h>
#include "aesdchar.h"

int aesd_major = 0; // use dynamic major
int aesd_minor = 0;

MODULE_AUTHOR("Pascal Jaeger");
MODULE_LICENSE("Dual BSD/GPL");

struct aesd_dev aesd_device;

int aesd_open(struct inode *inode, struct file *filp) {
  struct aesd_dev *dev;

  PDEBUG("open");
  dev = container_of(inode->i_cdev, struct aesd_dev, cdev);
  filp->private_data = dev;

  return 0;
}

int aesd_release(struct inode *inode, struct file *filp) {
  PDEBUG("release");
  filp->private_data = NULL;
  return 0;
}

ssize_t aesd_read(struct file *filp, char __user *buf, size_t count,
                  loff_t *f_pos) {
  ssize_t retval = 0;
  size_t offset_in_entry = 0;
  size_t rem_by_read = 0;
  struct aesd_buffer_entry
      *entryp; // Points to particular entry in circular buffer
  size_t rem_by_copy = 0;
  struct aesd_circular_buffer *kbuf = NULL;
  const char *ret_string = NULL;
  struct mutex *mutex_p = NULL;

  struct aesd_dev *dev_p =
      (struct aesd_dev *)(filp->private_data); // gets dev from aesd_open
  if (dev_p == NULL)
    goto fail;
  mutex_p = &(dev_p->buf_mtx); // get mutex pointer from the dev
  if (mutex_p == NULL)
    goto fail;
  kbuf = &(dev_p->kbuf); // get the buffer from dev
  if (kbuf == NULL)
    goto fail;
  if (filp == NULL || buf == NULL || f_pos == NULL) // check arguments
    return -EFAULT;
  if (mutex_lock_interruptible(mutex_p) != 0) // lock mutex
    return -ERESTARTSYS;

  entryp = aesd_circular_buffer_find_entry_offset_for_fpos(kbuf, *f_pos,
                                                           &offset_in_entry);
  if (entryp == NULL)
    goto fail;

  rem_by_read = entryp->size - offset_in_entry;

  // Prevent to read more than what user has requested
  if (rem_by_read > count)
    rem_by_read = count;

  ret_string = entryp->buffptr + offset_in_entry;
  if (ret_string == NULL)
    goto fail;

  rem_by_copy = copy_to_user(buf, ret_string, rem_by_read);

  retval = rem_by_read - rem_by_copy;
  *f_pos += rem_by_read - rem_by_copy;

  PDEBUG("read %zu bytes with offset %lld", count, *f_pos);

fail:
  mutex_unlock(mutex_p);
  return retval;
}

ssize_t aesd_write(struct file *filp, const char __user *buf, size_t count,
                   loff_t *f_pos) {
  ssize_t retval = -ENOMEM;

  const char *oldst_etry = NULL;
  struct aesd_circular_buffer *kbuf = NULL;
  struct aesd_buffer_entry *interm_entry = NULL;
  size_t rem_byt_tbd = 0;
  size_t byt_cpd = 0;

  struct aesd_dev *dev_p = (struct aesd_dev *)(filp->private_data);
  struct mutex *mutex_p = NULL;

  if (dev_p == NULL)
    goto fail;
  kbuf = &(dev_p->kbuf);
  if (kbuf == NULL)
    goto fail;
  mutex_p = &(dev_p->buf_mtx);
  if (mutex_p == NULL)
    goto fail;
  if (filp == NULL || buf == NULL || f_pos == NULL)
    return -EFAULT;
  if (mutex_lock_interruptible(mutex_p) != 0)
    return -ERESTARTSYS;

  interm_entry = &(dev_p->interm_entry);
  if (interm_entry == NULL)
    goto fail;
  if (interm_entry->size == 0)
    interm_entry->buffptr = kmalloc(count, GFP_KERNEL);
  else
    interm_entry->buffptr =
        krealloc(interm_entry->buffptr, interm_entry->size + count,
                 GFP_KERNEL);
  if (interm_entry->buffptr == NULL)
    goto fail;

  PDEBUG("write %zu bytes with offset %lld", count, *f_pos);

  rem_byt_tbd = copy_from_user(
      (char *)(interm_entry->buffptr + interm_entry->size), buf, count);
  byt_cpd = count - rem_byt_tbd;

  interm_entry->size += byt_cpd;

  // write over ot cb on \n
  if (memchr(interm_entry->buffptr, '\n', interm_entry->size) != NULL) {

    // kfree oldest entry if buffer full
    oldst_etry = aesd_circular_buffer_add_entry(kbuf, interm_entry);
    if (oldst_etry != NULL)
      kfree(oldst_etry);

    interm_entry->size = 0;
    interm_entry->buffptr = NULL;
  }
  retval = byt_cpd;

fail:
  mutex_unlock(mutex_p);
  return retval;
}

struct file_operations aesd_fops = {
    .owner = THIS_MODULE,
    .read = aesd_read,
    .write = aesd_write,
    .open = aesd_open,
    .release = aesd_release,
};

static int aesd_setup_cdev(struct aesd_dev *dev) {
  int err, devno = MKDEV(aesd_major, aesd_minor);

  cdev_init(&dev->cdev, &aesd_fops);
  dev->cdev.owner = THIS_MODULE;
  dev->cdev.ops = &aesd_fops;
  err = cdev_add(&dev->cdev, devno, 1);
  if (err) {
    printk(KERN_ERR "Error %d adding aesd cdev", err);
  }
  return err;
}

int aesd_init_module(void) {
  dev_t dev = 0;
  int result;
  result = alloc_chrdev_region(&dev, aesd_minor, 1, "aesdchar");
  aesd_major = MAJOR(dev);
  if (result < 0) {
    printk(KERN_WARNING "Can't get major %d\n", aesd_major);
    return result;
  }
  memset(&aesd_device, 0, sizeof(struct aesd_dev));

  aesd_circular_buffer_init(&aesd_device.kbuf);
  mutex_init(&aesd_device.buf_mtx);

  result = aesd_setup_cdev(&aesd_device);

  if (result) {
    unregister_chrdev_region(dev, 1);
  }
  return result;
}

void aesd_cleanup_module(void) {
  dev_t devno = MKDEV(aesd_major, aesd_minor);
  cdev_del(&aesd_device.cdev);
  unregister_chrdev_region(devno, 1);
}

module_init(aesd_init_module);
module_exit(aesd_cleanup_module);
