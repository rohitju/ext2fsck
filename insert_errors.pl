#! /usr/bin/perl -w

##
# $cmuPDL: insert_errors.pl,v 1.4 2010/02/27 10:58:19 rajas Exp $
#

##
# @author Raja Sambasivan
#
# Uses debugfs to Insert errors that test passes 2, 3, and 4 of students' fsck.  
##

#### Package declarations ########

use strict;
use warnings;
use diagnostics;
#use Test::Harness::Assert;
use Getopt::Long;
use File::Spec;
use Data::Dumper;


######

# Partition table info for the provided disk image
my %g_partition_table = ( 1 => [63, 48132],
                          3 => [48195, 48195],
                          6 => [112518, 48132]);

# Config file specifying modifiable files and directories
my $g_config_file;

# The disk image
my $g_image_file;

# Temporary directory in which to store interim files
my $g_tmp_dir;

# Location where temporary partition file will be stored
my $g_partition_file;

# The debugfs executable location
my $g_debugfs_exe = "/sbin/debugfs";

# The maximum number of errors to insert
my $g_num_errors = 5;

# The partiton number on which to operate
my $g_partition_num = 1;


#######

##
# Prints usage
##
sub print_usage {
    print "./insert_errors.pl --config_file --image --tmp_dir --partition (OPTIONAL)\n";
    print "\tconfig_file: The configuration file to use\n";
    print "\timage: The disk image file\n";
    print "\ttmp_dir: Temporary directory for storing interim files\n";
    print "\tpartition: (OPTIONAL) The partition in which to insert errors\n";
    print "\t\tMust match the config fle and must be an ext2 partition\n";


    
}


##
# Retrieves input options
##
sub get_options {
    GetOptions("image=s"       => \$g_image_file,
	       "tmp_dir=s"         => \$g_tmp_dir,
	       "config_file=s"     => \$g_config_file,
	       "partition:i"       => \$g_partition_num);

    if (!defined $g_image_file || !defined $g_tmp_dir || 
        !defined $g_config_file || 
        !defined $g_partition_table{$g_partition_num}) {
        print_usage();
        exit(-1);
    }
    
    system("mkdir -p $g_tmp_dir");
    
    $g_partition_file = "$g_tmp_dir/" . "partition_" . 
        $g_partition_num;
}


##
# Extracts partition 1 and places it in $g_tmp_dir
#
# @return: The name of the file containing partition 1
##
sub extract_partition {
  
    my $start = $g_partition_table{$g_partition_num}->[0];
    my $end = $g_partition_table{$g_partition_num}->[1];
    my $cmd = "dd if=$g_image_file of=$g_partition_file bs=512 ".
        "skip=$start count=$end";
    
    if (system($cmd) != 0) {
	print "Could not extract partition";
	exit(-1);
    }
}

##
# Imports partition 1 back into the disk image
##
sub import_partition {
    
    my $start = $g_partition_table{$g_partition_num}->[0];
    my $end = $g_partition_table{$g_partition_num}->[1];
    my $cmd = "dd if=$g_partition_file of=$g_image_file bs=512 ".
        "seek=$start conv=notrunc";
    if (system($cmd) != 0) {
        print "Could not import partition back into disk image";
        exit(-1);
    }
}


##
# Evaluates the configuration file and inserts into namepace C
##
sub eval_config_file {
    {
        print "Evaluating configuration file\n";
        {
            package C;
            unless (do $g_config_file) {
                print "Could not evaluate $g_config_file --- ABORTING\n";
                exit(-1);
            }
        }
        print "Done evaluating configuration file\n";
    }
}

##
# Canonicalizes a directory by inserting a trailing '/' if necessary
#
# @param dir: The directory to canonicalize
# @return canon_dir: The canonicalized directory
##
sub canonicalize_dir {
#    assert(scalar(@_) == 1);
    my ($dir) = @_;

    my @dir_elems = split(//, $dir);
    if ($dir_elems[scalar(@dir_elems) - 1] ne '/') {
        push(@dir_elems, '/');
    }

    my $canon_dir = join('', @dir_elems);

    return $canon_dir;
}


##
# Selects a file or directory from @g_dirs and @g_files and returns it
#
# @param select_dir: 0 if a file is to be returned, 1 if a directory
# @param replace: 1 if the selected object is chosen with replacement
#
# @return obj: The path to the selected file or directory
##
sub choose_file_or_dir {
#    assert(scalar(@_) == 2);
    my ($select_dir, $replace) = @_;
    
    my $obj;
    my $idx;
    
    if($select_dir == 1 && scalar @C::g_dirs > 0) {
        $idx = int(rand(scalar @C::g_dirs));
        $obj = $C::g_dirs[$idx];
        
        if($replace == 0) {
            splice(@C::g_dirs, $idx, 1);
        }
    } elsif ($select_dir == 0 && scalar @C::g_files > 0) {
        $idx = int(rand(scalar @C::g_files));
        $obj = $C::g_files[$idx];
        
        if($replace == 0) {
            splice(@C::g_files, $idx, 1)
        }
    } else {
        print "Could not choose a file or a directory.  Aborting\n";
        exit(-1);
    }
    
    return($obj);
}


##
# Returns an object to @C::g_dirs or @C::g_files.  It is the callers
# responsibility to know whether or not the entry already exists in the array
# into which it is to be inserted
# 
# @param obj: The object to insert into the appropriate array
# @param is_dir: Whether the object is a file or directory
##
sub return_file_or_dir {
#    assert(scalar(@_) == 2);
    my ($obj, $is_dir) = @_;

    if ($is_dir == 1) {
        push(@C::g_dirs, $obj);
    } else {
        push(@C::g_files, $obj);
    }
}


##
# Given a directory, this function removes all files and subdirectories within
# this directory from @C::g_dirs and @C::g_files.
# 
# @param dir: The dir whose files are to be removed 
##
sub remove_subdirs_and_files {
#    assert(scalar(@_) == 1);
    my ($dir) = @_;

    my $canon_dir = canonicalize_dir($dir);

    my $i = 0;
    while ($i < scalar(@C::g_files)) { 
        
        my $cur_file = $C::g_files[$i];
        my ($volume, $dir_portion, $file_portion) = File::Spec->splitpath($cur_file, 0);
        
        if(canonicalize_dir($dir_portion) =~ /$canon_dir/) { 
            # print "Removing file $cur_file from array " . 
            #   " because it is in a subdirectory of $canon_dir\n";
            splice(@C::g_files, $i, 1);
        } else {
            $i++;
        }
    }

    $i = 0;
    while ($i < scalar(@C::g_dirs)) {
        my $cur_dir = $C::g_dirs[$i];

        if (canonicalize_dir($cur_dir) =~ /$canon_dir/) { 
            # print "Removing directory $cur_dir from array " . 
            #    "because it is in a subdirectory of $canon_dir\n";
            splice(@C::g_dirs, $i, 1);
        } else {
            $i++;
        }
    }    
}


## 
# Executes debugfs in write mode on $g_partition_file
##
sub execute_debug_fs_cmd {
#    assert(scalar @_ == 1);
    my ($cmd_file) = @_;
    
    my $cmd = $g_debugfs_exe . " -w -f $cmd_file $g_partition_file";
    system($cmd) == 0 
	or die "Could not execute debugfs\n";
}


##
# Tests Phase 2 of myfsck
#
# Creates unreferenced inodes by using debugfs to unlink a file or
# directory.  This works because unlinking files using debugfs does
# not automatically deallocate the file's inodes and contents.  If the
# chosen file is hard-linked to multiple directories, this function
# will not create an unreferenced inode --- it'll simply reduce the
# link count.
##
sub create_unreferenced_inodes {
    
    # Choose whether to unlink a directory or a file
    my $unlink_dir = int(rand(2));
    my $unlink_obj = choose_file_or_dir($unlink_dir, 0);

    print "Trying to create an unreferenced inode by " .
        "unlinking $unlink_obj\n";

    if ($unlink_dir) { 
        # Make sure all subdirectories and files of $unlink_obj are
        # removed from the C::@g_dirs and C::@g_files
        remove_subdirs_and_files($unlink_obj);
    }
    
    my $cmd = "echo \"unlink $unlink_obj\" ".
	    "> $g_tmp_dir/debugfs_cmds";
    system($cmd) == 0
        or die "Could not create debugfs command file\n";
	
    execute_debug_fs_cmd("$g_tmp_dir/debugfs_cmds");
}


##
# Tests phase 3 of myfsck
#
# Links the chosen file to the chosen directory using debugs. 
# This works because hardlinking files using debugfs does not
# change the file's link count.  
##
sub change_link_count {
    
    # Need to make sure that a file is not linked into a directory in which it
    # already exsts
    my $file;
    my $dir;
    my $done = 0;
    while (!$done) { 
        $file = choose_file_or_dir(0, 1);
        $dir = canonicalize_dir(choose_file_or_dir(1, 1));
        
        my ($volume, $file_path, $filename) = File::Spec->splitpath($file, 0);

        $file_path = canonicalize_dir($file_path);
        if ($dir =~ /$file_path/) {
            # print "Trying to link $file to same directory $dir\n";
        } else {
            $done = 1;
        }
    }
    
    print "Changing link count of $file by " .
        "linking it to $dir\n";
    
    my $cmd = "echo \"link $file $dir\" ".
        "> $g_tmp_dir/debugfs_cmds";
    system($cmd) == 0 
        or die "Could not create debugfs_cmd";
    
    execute_debug_fs_cmd("$g_tmp_dir/debugfs_cmds");
}


##
# Tests phase 4 of my fsck
#
# Uses the clearb functionality of debugfs to clear
# allocated blocks.
##
sub free_allocated_block {
    
    my $block = int(rand(2000));
    # Avoid writing over superblock and group descriptor info used by EXT-2.
    $block += 10;
    
    print "Clearing block: $block\n";
    
    my $cmd = "echo \"freeb $block\" ".
        "> $g_tmp_dir/debugfs_cmds";
    system($cmd) == 0 
        or die "Could not create debugfs_cmd";
    
    execute_debug_fs_cmd("$g_tmp_dir/debugfs_cmds");
}


## 
# A dispatch table for calling the various error insertion fns
##
my %error_func = ( 0 => \&create_unreferenced_inodes,
                   1 => \&change_link_count,
                   2 => \&free_allocated_block );

##
# Cleans up files in $g_tmp_dir
##
sub clean_up {
    system("rm $g_partition_file");
    system("rm $g_tmp_dir/debugfs_cmds");
}


#######

# Set a random seed
srand (time ^ $$ ^ unpack "%L*", `ps axww | gzip -f`);

# Get input options
get_options();

# Evaluate the configuration file
eval_config_file();

# Extract the partition
extract_partition();

# Add up to $g_num_errors errors
my @error_type;
for (my $i = 0; $i < $g_num_errors; $i++) {
    my $error_type = int(rand(3));
    $error_func{$error_type}->();
}

import_partition();
clean_up();











    
