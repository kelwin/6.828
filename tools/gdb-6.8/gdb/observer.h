/* GDB Notifications to Observers.

   Copyright (C) 2004, 2005, 2007, 2008 Free Software Foundation, Inc.

   This file is part of GDB.

   This program is free software; you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.
  
   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.
  
   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.

   --

   This file was generated using observer.sh and observer.texi.  */

#ifndef OBSERVER_H
#define OBSERVER_H

struct observer;
struct bpstats;
struct so_list;
struct objfile;

/* normal_stop notifications.  */

typedef void (observer_normal_stop_ftype) (struct bpstats *bs);

extern struct observer *observer_attach_normal_stop (observer_normal_stop_ftype *f);
extern void observer_detach_normal_stop (struct observer *observer);
extern void observer_notify_normal_stop (struct bpstats *bs);

/* target_changed notifications.  */

typedef void (observer_target_changed_ftype) (struct target_ops *target);

extern struct observer *observer_attach_target_changed (observer_target_changed_ftype *f);
extern void observer_detach_target_changed (struct observer *observer);
extern void observer_notify_target_changed (struct target_ops *target);

/* executable_changed notifications.  */

typedef void (observer_executable_changed_ftype) (void *unused_args);

extern struct observer *observer_attach_executable_changed (observer_executable_changed_ftype *f);
extern void observer_detach_executable_changed (struct observer *observer);
extern void observer_notify_executable_changed (void *unused_args);

/* inferior_created notifications.  */

typedef void (observer_inferior_created_ftype) (struct target_ops *objfile, int from_tty);

extern struct observer *observer_attach_inferior_created (observer_inferior_created_ftype *f);
extern void observer_detach_inferior_created (struct observer *observer);
extern void observer_notify_inferior_created (struct target_ops *objfile, int from_tty);

/* solib_loaded notifications.  */

typedef void (observer_solib_loaded_ftype) (struct so_list *solib);

extern struct observer *observer_attach_solib_loaded (observer_solib_loaded_ftype *f);
extern void observer_detach_solib_loaded (struct observer *observer);
extern void observer_notify_solib_loaded (struct so_list *solib);

/* solib_unloaded notifications.  */

typedef void (observer_solib_unloaded_ftype) (struct so_list *solib);

extern struct observer *observer_attach_solib_unloaded (observer_solib_unloaded_ftype *f);
extern void observer_detach_solib_unloaded (struct observer *observer);
extern void observer_notify_solib_unloaded (struct so_list *solib);

/* new_objfile notifications.  */

typedef void (observer_new_objfile_ftype) (struct objfile *objfile);

extern struct observer *observer_attach_new_objfile (observer_new_objfile_ftype *f);
extern void observer_detach_new_objfile (struct observer *observer);
extern void observer_notify_new_objfile (struct objfile *objfile);

#endif /* OBSERVER_H */
