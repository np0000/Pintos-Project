#include "filesys/filesys.h"
#include <debug.h>
#include <stdio.h>
#include <string.h>
#include "filesys/file.h"
#include "filesys/free-map.h"
#include "filesys/inode.h"
#include "filesys/directory.h"
#include "filesys/cache.h"
#include "threads/thread.h"

/* Partition that contains the file system. */
struct block *fs_device;

static void do_format (void);

/* Initializes the file system module.
   If FORMAT is true, reformats the file system. */
void
filesys_init (bool format) 
{
  fs_device = block_get_role (BLOCK_FILESYS);
  if (fs_device == NULL)
    PANIC ("No file system device found, can't initialize file system.");

  inode_init ();
  free_map_init ();
  cache_init ();
  if (format) 
    do_format ();

  free_map_open ();
}

/* Shuts down the file system module, writing any unwritten data
   to disk. */
void
filesys_done (void) 
{
  cache_write_back_all ();
  free_map_close ();
}

/* Creates a file named NAME with the given INITIAL_SIZE.
   Returns true if successful, false otherwise.
   Fails if a file named NAME already exists,
   or if internal memory allocation fails. */

// new one
bool
filesys_create (const char *name, off_t initial_size, bool is_dir) 
{
  block_sector_t inode_sector = 0;
  struct dir *dir = thread_current()->cur_dir;
  if(name[0] == '/' || dir == NULL){
    dir = dir_open_root();
  }
  else{
    dir = dir_reopen(dir);
  }

  // find the location according to the path
  int length = strlen(name);
  char path[length + 1];
  char *filename;
  memcpy(path, name, length + 1);

  //parse all arguments
  char *token, *save_ptr;
  for (token = strtok_r (path, "/", &save_ptr); token != NULL;
      token = strtok_r (NULL, "/", &save_ptr)){
    if (strlen(token) == 0){
      continue;
    }
    
    filename = token;

    // find the dir/file in current dir
    struct inode *inode;

    if (dir_lookup(dir, token, &inode) == false){
      break;
    }

    // if the inode is a directory, change current dir to it
    // if the inode is a file, something is wrong
    if (inode_is_dir(inode)){
      dir_close(dir);
      dir = dir_open(inode);
    }
    else{
      dir_close(dir);
      inode_close(inode);
      return false;
    }
  }

  if (token == NULL){
    dir_close(dir);
    return false;
  }

  bool success = (dir != NULL
                  && free_map_allocate (1, &inode_sector)
                  && inode_create (inode_sector, initial_size, is_dir)
                  && dir_add (dir, filename, inode_sector));

  if (is_dir == true){
    struct inode *inode;
    struct dir *new_dir;
    if (dir_lookup(dir, filename, &inode)){
      new_dir = dir_open(inode);
      // create two dir entries pointing to "." and ".."
      char* d = ".";
      char* dd = "..";
      success = (success 
                && dir_add(new_dir, d, inode_get_inumber(inode))
                && dir_add(new_dir, dd, inode_get_inumber(dir_get_inode(dir))));
      dir_close(new_dir);
    }
  }
  
  if (!success && inode_sector != 0) 
    free_map_release (inode_sector, 1);
  dir_close (dir);

  return success;
}

/* Opens the file with the given NAME.
   Returns the new file if successful or a null pointer
   otherwise.
   Fails if no file named NAME exists,
   or if an internal memory allocation fails. */

// new one
struct file *
filesys_open (const char *name)
{
  if (strlen(name) == 0){
    return false;
  }

  block_sector_t inode_sector = 0;
  struct dir *dir = thread_current()->cur_dir;

  if(name[0] == '/' || dir == NULL){
    dir = dir_open_root();
  }
  else{
    dir = dir_reopen(dir);
  }

  // find the location according to the path
  int length = strlen(name);
  char path[length + 1];
  memcpy(path, name, length + 1);
  
  struct inode *inode = NULL;

  //parse all arguments
  char *token, *save_ptr;
  for (token = strtok_r (path, "/", &save_ptr); token != NULL;
      token = strtok_r (NULL, "/", &save_ptr)){
    if (strlen(token) == 0){
      continue;
    }

    // find the dir/file in current dir
    if (dir_lookup(dir, token, &inode) == false){
      dir_close (dir);
      return false;
    }

    // if the inode is a directory, change current dir to it
    if (inode_is_dir(inode)){
      dir_close(dir);
      dir = dir_open(inode);
    }
    
  }

  if (inode == NULL){
    inode = dir_get_inode(dir);
  }

  if (inode_is_dir(inode)){
    return dir;
  }
  
  dir_close(dir);
  return file_open (inode);
}

/* Deletes the file named NAME.
   Returns true if successful, false on failure.
   Fails if no file named NAME exists,
   or if an internal memory allocation fails. */

bool
filesys_remove (const char *name) 
{
  //printf("remove: %s\n", name);
  block_sector_t inode_sector = 0;
  struct dir *dir = thread_current()->cur_dir;

  if(name[0] == '/' || dir == NULL){
    dir = dir_open_root();
  }
  else{
    dir = dir_reopen(dir);
  }

  // find the location according to the path
  int length = strlen(name);
  char path[length + 1];
  char *filename;

  memcpy(path, name, length + 1);
  
  struct inode *inode = NULL;

  //parse all arguments
  char *token, *save_ptr;
  for (token = strtok_r (path, "/", &save_ptr); token != NULL;
      token = strtok_r (NULL, "/", &save_ptr)){
    if (strlen(token) == 0){
      continue;
    }

    filename = token;

    // find the dir/file in current dir
    if (dir_lookup(dir, token, &inode) == false){
      dir_close (dir);
      return false;
    }
    
    // if the inode is a directory, change current dir to it
    if (inode_is_dir(inode)){
      dir_close(dir);
      dir = dir_open(inode);
    }
    else{
      break;
    }
  }

  if (inode == NULL){
    dir_close(dir);
    return false;
  }

  bool success = false;

  if (inode_is_dir(inode)){
    if (dir_is_empty(dir) && inode_get_inumber(inode) != inode_get_inumber(dir_get_inode(thread_current()->cur_dir))){
      // remove the dir from parent dir
      struct inode *parent_inode;
      struct dir *parent_dir;
      char *t = "..";
      if (dir_lookup(dir, "..", &parent_inode) == false){
        printf("Something is wrong in filesys_remove.\n");
        dir_close (dir);
        return false;
      }
      parent_dir = dir_open(parent_inode);
      success = dir_remove (parent_dir, filename);
      dir_close(parent_dir);
    }
  }
  else{
    success = dir_remove (dir, filename);
  }

  dir_close (dir); 

  return success;
}

bool filesys_chdir(char *name){

  struct dir *dir = thread_current()->cur_dir;

  if(name[0] == '/' || dir == NULL){
    dir = dir_open_root();
  }
  else{
    dir = dir_reopen(dir);
  }

  // find the location according to the path
  int length = strlen(name);
  char path[length + 1];
  memcpy(path, name, length + 1);

  //parse all arguments
  char *token, *save_ptr;
  for (token = strtok_r (path, "/", &save_ptr); token != NULL;
      token = strtok_r (NULL, "/", &save_ptr)){
    if (strlen(token) == 0){
      continue;
    }

    // find the dir/file in current dir
    struct inode *inode;

    if (dir_lookup(dir, token, &inode) == false){
      dir_close(dir);
      return false;
    }

    // if the inode is a directory, change current dir to it
    // if the inode is a file, something is wrong
    if (inode_is_dir(inode)){
      dir_close(dir);
      dir = dir_open(inode);
    }
    else{
      dir_close(dir);
      inode_close(inode);
      return false;
    }
  }

  bool success = (dir != NULL);
  
  dir_close(thread_current()->cur_dir);
  thread_current()->cur_dir = dir;
  
  return success;
}


/* Formats the file system. */
static void
do_format (void)
{
  printf ("Formatting file system...");
  free_map_create ();
  if (!dir_create (ROOT_DIR_SECTOR, 16))
    PANIC ("root directory creation failed");
  free_map_close ();
  printf ("done.\n");
}


bool file_is_open (struct file *f)
{
  struct file_with_fd* target = NULL;
  struct thread* t = thread_current();
  
  /* Invalid argument. */
  if (t == NULL || f == NULL)
    return false;
  
  for (struct list_elem* ptr = list_begin(&t->opened_files); 
        ptr != list_end(&t->opened_files); 
        ptr = ptr->next)
    {
      target = list_entry(ptr, struct file_with_fd, elem);
      if (inode_get_inumber(dir_get_inode(target->file)) == inode_get_inumber(dir_get_inode(f))){
        return true;
      }
    }

  return false;
}