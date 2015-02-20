#!/usr/bin/perl -w

# $cmuPDL: run_fsck.pl, v $

##
# @author Raja Sambasivan
##

#### Package declarations ###########

use strict;
use warnings;
use diagnostics;
#use Test::Harness::Assert;
use Getopt::Long;

########

# Lists mapping from ext-2 partion -> [start sector, length]
my %g_partition_table = ( 1 => [63, 48132],
			  3 => [48195, 48195],
			  6 => [112518, 48132]);

my $g_fsck_exec = "/sbin/fsck.ext2";

my $g_image_file;

my $g_partition_num;

my $g_tmp_dir;


########

sub print_usage {
    print "./run_fsck.pl --partition --tmp_dir --image\n";
    print "\tpartition: The partition number on which to run system fsck\n";
    print "\ttmp_dir: Directory in which to place extracted partition\n";
    print "\timage: The disk image file\n";
}

sub get_options {
    GetOptions("partition=i"    => \$g_partition_num,
	       "image=s"       => \$g_image_file,
	       "tmp_dir=s"     => \$g_tmp_dir);

    if (!defined $g_partition_num || !defined $g_image_file || !defined $g_tmp_dir) {
	print_usage();
	exit(-1);
    }
}

sub run_system_fsck {
    my @partitions_to_check;

    # Create array of partitions to check
    if ($g_partition_num == 0) {
	@partitions_to_check = keys %g_partition_table;
    } else {
	$partitions_to_check[0] = $g_partition_num;
    }
    
    foreach (@partitions_to_check) {
	if(!defined $g_partition_table{$_}) {
	    print "Trying to run fsck on an invalid partition\n";
	    exit(-1);
	}

	# Get informaton about relevant partition
	my $p_data_file = "$g_tmp_dir/partition_" . "$_";;
	my $p_start = $g_partition_table{$_}->[0];
	my $p_length = $g_partition_table{$_}->[1];
	print "Extracted partition name is: $p_data_file\n";
	print "Partition start sector: $p_start.  Length: $p_length\n";
	
	# Extract partition and place it in $g_tmp_dir
	my $cmd = "dd if=$g_image_file of=$p_data_file bs=512 ".
	    "skip=$p_start count=$p_length";
	if (system($cmd) != 0) {
	    print "Could not extract partition $_";
	    exit(-1);
	}

	#Execute fsck on the extracted partition
	$cmd = "$g_fsck_exec -y -f $p_data_file";

	my $output = `$cmd`;
	print "$output";

	if ($? == 0) {
	    print "Found no errors\n";
	}
	else {

	    my @lines = split(/\n/, $output);
	    my $count = 0;
	    foreach (@lines) {
		if ($_ =~ m/yes$/ == 1) {
		    $count++;
		}
	    }	
	    if ($count >0) {
		print "Found $count errors\n";
	    }
	    else {
		print "Found unknown errors\n";
	    }
	}
    }
}
	

#####

get_options();
run_system_fsck();
