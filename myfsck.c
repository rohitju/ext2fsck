#include<stdio.h>
#include<stdlib.h>
#include<unistd.h>
#include<string.h>
#include<fcntl.h>
#include<inttypes.h>
#include<stdbool.h>
#include<sysexits.h>
#include "ext2_fs.h"

static int device;
const unsigned int sector_size_bytes = 512;
typedef struct {
    unsigned char part_type;
    uint32_t partition_start;
    uint32_t partition_length;
} p_metadata;

typedef enum {DIRECTORY_DATA_BLOCK, FILE_DATA_BLOCK} db_type;

void get_partition_details(int part_number, p_metadata *data);
void read_sectors (int64_t start_sector, unsigned int num_sectors, void *into);
void read_superblock_info(int part_number, struct ext2_super_block *superblock);
void read_gd_info(int part_number, struct ext2_group_desc *gd_info);
unsigned char get_partition_type (unsigned char *sector, int part_num);
void read_inode_info(uint32_t inode_num, struct ext2_inode *i_info);
bool inode_allocated(uint32_t inode_num, char **bitmap);
void read_data_block(uint32_t block_num, db_type type);
void read_group_descriptor_table();
void traverse_directories(int inode_num, bool count_links, bool fix_blocks);
void fix_directory_pointers(int inode_num, int parent_inode_num);
void fix_dangling_nodes();
void indirect_traversal(int curr_level, int max_indirection, int block_num, bool fix_blocks);
struct ext2_dir_entry_2* read_directory_block(int block_num, int *count);
void write_sectors (int64_t start_sector, unsigned int num_sectors, void *from);
void print_sector (unsigned char *buf);
void print_disk_bitmap(int block_group_num);
void print_actual_bitmap(int block_group_num);
void mark_actual_inode(int inode_num);
void mark_actual_block(int block_num);
void add_to_lost_found(int inode_num);
void set_directory_entry(int data_block, int directory_number, struct ext2_dir_entry_2 new_entry);
void mark_subtrees(int inode_num);
void increment_link_count(int inode_num);
void write_inode_entry(int inode_num, struct ext2_inode i_info);
uint32_t get_inode_sector_offset(uint32_t inode_size, uint32_t inode_index);
void persist_block_bitmap();
void check_partition();
void free_memory();

int block_size;
int sectors_per_block;
uint32_t partition_start;
struct ext2_super_block super;
char *group_descriptor_table;
int lost_found;
char **actual_inode_bitmap;
int number_block_groups;
int *link_count;
char **actual_block_bitmap;

unsigned int round_div(unsigned int dividend, unsigned int divisor)
{
    return (dividend + (divisor / 2)) / divisor;
}

int main (int argc, char **argv){
    int part_number;
    char *image_path;
    int c, i, j;
    bool all = false;
    int check_part = -1;
    while ((c = getopt (argc, argv, ":p:i:f:")) != -1) {
        switch (c)
        {
            case 'p':
                part_number = atoi(optarg);
                if(part_number <= 0) {
                    fprintf(stderr, "Option 'p' requires a positive integer argument\n. Will exit now...");
                    exit(EX_USAGE);
                }
                break;
            case 'i':
                image_path = optarg;
                strncpy(image_path, optarg, 100);
                break;
            case 'f':
                check_part = atoi(optarg);
                all = true;
                break;
            case '?':
                if (optopt == 'p' || optopt == 'i')
                    fprintf(stderr, "Argument not given for option %c\n", optopt);
                else if (isprint(optopt))
                    fprintf (stderr, "Unknown option `-%c'.\n", optopt);
                else
                    fprintf (stderr, "Unknown option character `\\x%x'.\n", optopt);
                exit(EX_USAGE);
                break;
            default:
                break;
        }
    }


    if ((device = open(image_path, O_RDWR)) == -1) {
        perror("Could not open device file");
        exit(EX_NOINPUT);
    } 
    p_metadata part_detail;
    if(!all) {
        get_partition_details(part_number, &part_detail);
        partition_start = part_detail.partition_start;
        if (part_detail.part_type != 0xFF) {
            printf("0x%02X %d %d\n", part_detail.part_type, part_detail.partition_start, 
                    part_detail.partition_length);
        }
        else 
            printf("-1\n");
    }
    else if (check_part == 0){ //Check errors of all partitions
        j = 1;
        while (true){
            printf("Fixing errors of partition %d\n",j);
            memset(&part_detail, 0, sizeof(p_metadata));   
            get_partition_details(j, &part_detail);
            if (part_detail.part_type == 0xFF) {
                exit(EX_OK);
            }
            if(part_detail.part_type != 0x83){
                j++;
                continue;
            }
            partition_start = part_detail.partition_start;
            read_superblock_info(j, &super);
            block_size = 1024 << super.s_log_block_size;
            sectors_per_block = block_size / sector_size_bytes;
            group_descriptor_table = (char*)malloc(sectors_per_block * sector_size_bytes);
            read_group_descriptor_table();
            number_block_groups = round_div(super.s_blocks_count, super.s_blocks_per_group);
            actual_inode_bitmap = (char **)malloc(number_block_groups * sizeof(char *));
            for (i = 0; i < number_block_groups; i++){
                actual_inode_bitmap[i] = (char *)calloc(sectors_per_block * sector_size_bytes, sizeof(char));
            }
            int block_start;
            unsigned char buf[sector_size_bytes * sectors_per_block];
            actual_block_bitmap = (char **)malloc(number_block_groups * sizeof(char *));
            for (i = 0; i < number_block_groups; i++){
                actual_block_bitmap[i] = (char *)calloc(sectors_per_block * sector_size_bytes, sizeof(char));
                block_start = read_bytes(group_descriptor_table, 32 * i, 4); 
                read_sectors(partition_start + (block_start * sectors_per_block), sectors_per_block, buf);
                memcpy(actual_block_bitmap[i], buf, sectors_per_block * sector_size_bytes);
            }

            link_count = (int *)malloc((super.s_inodes_count + 1) * sizeof(int));
            memset(link_count, 0, (super.s_inodes_count + 1));
            
            for (i = 1; i <= 255; i++)
                mark_actual_block(i);
            check_partition();
            j++;
        }
    }
    else {  //Check for errors on a single partition
        memset(&part_detail, 0, sizeof(p_metadata));   
        get_partition_details(check_part, &part_detail);
        if (part_detail.part_type != 0x83) {
            printf("Invalid partition type\n");
            exit(EX_DATAERR);
        }
        printf("Checking partition %d\n", check_part);
        partition_start = part_detail.partition_start;
        read_superblock_info(check_part, &super);
        block_size = 1024 << super.s_log_block_size;
        sectors_per_block = block_size / sector_size_bytes;
        group_descriptor_table = (char*)malloc(sectors_per_block * sector_size_bytes);
        read_group_descriptor_table();
        number_block_groups = round_div(super.s_blocks_count, super.s_blocks_per_group);
        actual_inode_bitmap = (char **)malloc(number_block_groups * sizeof(char *));
        for (i = 0; i < number_block_groups; i++){
            actual_inode_bitmap[i] = (char *)calloc(sectors_per_block * sector_size_bytes, sizeof(char));
        }

        int block_start;
        unsigned char buf[sector_size_bytes * sectors_per_block];
        actual_block_bitmap = (char **)malloc(number_block_groups * sizeof(char *));
        for (i = 0; i < number_block_groups; i++){
            actual_block_bitmap[i] = (char *)calloc(sectors_per_block * sector_size_bytes, sizeof(char));
            block_start = read_bytes(group_descriptor_table, 32 * i, 4); 
            read_sectors(partition_start + (block_start * sectors_per_block), sectors_per_block, buf);
            memcpy(actual_block_bitmap[i], buf, sectors_per_block * sector_size_bytes);
        }

        link_count = (int *)malloc((super.s_inodes_count + 1) * sizeof(int));
        memset(link_count, 0, (super.s_inodes_count + 1));
        
        for (i = 1; i <= 255; i++)
            mark_actual_block(i);
        check_partition();
    }
    free_memory();
    exit(EX_OK);
}

void free_memory(){
    int i;
    free(link_count);
    for (i = 0; i < number_block_groups; i++){
        free(actual_block_bitmap[i]);
    }
    free(actual_block_bitmap);
    for (i = 0; i < number_block_groups; i++){
        free(actual_inode_bitmap[i]);
    }
    free(actual_inode_bitmap);
    free(group_descriptor_table);
}

void check_partition(){
    //Pass 1
    fix_directory_pointers(2, 2);

    //Pass 2
    traverse_directories(2, false, false);
    fix_dangling_nodes();
    fix_directory_pointers(2, 2);

    //Pass 3
    traverse_directories(2, true, false);
    traverse_directories(2, false, true);

    //Pass 4
    persist_block_bitmap();
}

//Find inodes which are not connected to the directory tree
void fix_dangling_nodes(){
    int i;
    struct ext2_inode i_info;

    //Add any isolated branches to our bitmap
    for(i = 11; i <= super.s_inodes_count; i++){
        if(inode_allocated(i, NULL)){
            read_inode_info(i, &i_info);
            if ((i_info.i_mode & 0xf000) == 0x4000){
                mark_subtrees(i);
            }
        } 
    }

    //Add to lost+found
    for(i = 11; i <= super.s_inodes_count; i++){
        if(inode_allocated(i, (char **)NULL) && !inode_allocated(i, actual_inode_bitmap)){
            printf("Inode %d is lost! Adding it to lost+found\n", i);
            add_to_lost_found(i);
        }    
    }

}

void write_inode_entry(int inode_num, struct ext2_inode i_info){
    int block_group = (inode_num - 1) / super.s_inodes_per_group;
    int offset = block_group * 32;
    int inode_table_start = read_bytes(group_descriptor_table, offset + 8, 4);
    int inode_index = (inode_num - 1) % super.s_inodes_per_group;

    unsigned char buf[sector_size_bytes * sectors_per_block];
    read_sectors(partition_start + (inode_table_start * sectors_per_block) + get_inode_sector_offset(super.s_inode_size, inode_index), 
            1, buf);

    uint32_t num_inodes_sector = sector_size_bytes / super.s_inode_size;
    offset = ((inode_index % num_inodes_sector)) * super.s_inode_size; 

    struct ext2_inode *new_inode = (struct ext2_inode*)(buf + offset);
    new_inode->i_links_count = i_info.i_links_count;
    write_sectors(partition_start + (inode_table_start * sectors_per_block) + get_inode_sector_offset(super.s_inode_size, inode_index),
            1, buf);
}

//Add a new directory entry to a data block
void add_directory_entry(int inode_num, struct ext2_dir_entry_2 new_entry){
    bool new_block = false;
    struct ext2_inode i_info;
    read_inode_info(lost_found, &i_info);
    struct ext2_dir_entry_2 prev_entry;
    int i, j;

    for(i = 0; i < 12; i++){

        if(i_info.i_block[i] == 0){
            new_block = true;
            break;
        }
        struct ext2_dir_entry_2 *directory_entries;
        int count;
        directory_entries = read_directory_block(i_info.i_block[i], &count);
        int dir_block_free = sector_size_bytes * sectors_per_block;

        for (j = 0; j < count; j++){
            dir_block_free -= ((((__u16)8 + directory_entries[j].name_len)+3) & ~0x03);
        }

        if(dir_block_free >=  ((((__u16)8 + new_entry.name_len)+3) & ~0x03)){ //Is there space in this data block for a dir entry
            //Modify rec_len of last dir entry
            prev_entry = directory_entries[count - 1];
            prev_entry.rec_len =  ((((__u16)8 + prev_entry.name_len)+3) & ~0x03);
            set_directory_entry(i_info.i_block[i], count - 1, prev_entry);

            //Add new directory entry
            new_entry.rec_len =  (((dir_block_free)+3) & ~0x03);
            set_directory_entry(i_info.i_block[i], count, new_entry);
            break;
        }

    }

}

//Add an inode to the lost+found directory
void add_to_lost_found(int inode_num){
    int i, name_len;
    char name[255];
    name_len = sprintf(name, "%d", inode_num);
    struct ext2_inode i_info;
    read_inode_info(inode_num, &i_info);

    struct ext2_dir_entry_2 lost_found_entry;
    lost_found_entry.inode = inode_num;
    lost_found_entry.rec_len = name_len + 8;
    lost_found_entry.name_len = name_len;
    for(i = 0; i < name_len; i++){
        lost_found_entry.name[i] = name[i];
    }
    if((i_info.i_mode & 0xf000) == 0x8000)
        lost_found_entry.file_type = 1;
    else if((i_info.i_mode & 0xf000) == 0x4000)
        lost_found_entry.file_type = 2;
    else if((i_info.i_mode & 0xf000) == 0x2000)
        lost_found_entry.file_type = 3;
    else if((i_info.i_mode & 0xf000) == 0x6000)
        lost_found_entry.file_type = 4;
    else if((i_info.i_mode & 0xf000) == 0x1000)
        lost_found_entry.file_type = 5;
    else if((i_info.i_mode & 0xf000) == 0xC000)
        lost_found_entry.file_type = 6;
    else if((i_info.i_mode & 0xf000) == 0xA000)
        lost_found_entry.file_type = 7;
    else
        lost_found_entry.file_type = 0;

    add_directory_entry(lost_found, lost_found_entry);
}

void increment_link_count(int inode_num){
    link_count[inode_num]++;
}

void read_group_descriptor_table(){
    read_sectors(partition_start + (sectors_per_block * 2), sectors_per_block, group_descriptor_table);
}

//Traverse indirected blocks
void indirect_traversal(int curr_level, int max_indirection, int block_num, bool fix_blocks){
    if (fix_blocks)
        mark_actual_block(block_num);
    if(curr_level == max_indirection){
        return;
    }
    int offset = 0;
    unsigned char buf[sector_size_bytes * sectors_per_block];
    read_sectors(partition_start + (sectors_per_block * block_num), sectors_per_block, buf);
    while (offset < (sectors_per_block * sector_size_bytes)){
        int curr_block = read_bytes(buf, offset, 4);
        if(curr_block != 0)
            indirect_traversal(curr_level + 1, max_indirection, curr_block, fix_blocks);
        offset  = offset + 4;
    }
}

//Mark inode number as allocated
void mark_actual_inode(int inode_num){
    int block_group = (inode_num - 1) / super.s_inodes_per_group;
    int inode_index = (inode_num - 1) % super.s_inodes_per_group;
    int inode_byte_index = inode_index / 8;
    int inode_byte_offset = inode_index % 8;
    int mask = 1 << inode_byte_offset;
    actual_inode_bitmap[block_group][inode_byte_index] |= mask; 
}

//Set a directory entry in a given data block
void set_directory_entry(int data_block, int directory_number, struct ext2_dir_entry_2 new_entry){
    unsigned char buf[sector_size_bytes * sectors_per_block];
    read_sectors(partition_start + (sectors_per_block * data_block), sectors_per_block, buf);
    int i = 0;
    int offset = 0;
    int dir_length;
    while (i < directory_number){
        dir_length = read_bytes(buf, offset + 4, 2);
        offset = offset + dir_length;
        i++;
    }
    struct ext2_dir_entry_2 *old_entry = (struct ext2_dir_entry_2 *)(buf + offset);
    old_entry->inode = new_entry.inode;
    old_entry->rec_len = new_entry.rec_len;
    old_entry->name_len = new_entry.name_len;
    old_entry->file_type = new_entry.file_type;
    for(i = 0; i < new_entry.name_len; i++)
        old_entry->name[i] = new_entry.name[i];
    write_sectors(partition_start + (sectors_per_block * data_block), sectors_per_block, buf);
}

//Check that "." and ".." point to the right inode numbers
void fix_directory_pointers(int inode_num, int parent_num){
    struct ext2_inode i_info;
    read_inode_info(inode_num, &i_info);
    if((i_info.i_mode & 0xf000) == 0x4000){
        int i, j;
        int num_entries;
        for(i = 0; i < 12; i++){
            if(i_info.i_block[i] == 0)
                continue;
            struct ext2_dir_entry_2 *directory_entries;
            int count;
            directory_entries = read_directory_block(i_info.i_block[i], &count);

            for (j = 0; j < count; j++){
                if (directory_entries[j].inode == 0)
                    continue;
                struct ext2_inode dir_inode;
                char names[255];
                int k;

                for(k = 0; k < directory_entries[j].name_len; k++){
                    names[k] = directory_entries[j].name[k];
                }
                names[k] = '\0';

                //Fix any directory pointer issues
                if (!strcmp(names, "..")){
                    if(!(directory_entries[j].inode == parent_num)){
                        printf("Parent directory points to %d when it should be %d\n", directory_entries[j].inode, parent_num);
                        directory_entries[j].inode = parent_num;
                        set_directory_entry(i_info.i_block[i], j, directory_entries[j]);
                    }
                }
                if (!strcmp(names, ".")){
                    if(!(directory_entries[j].inode == inode_num)){
                        printf("Current directory points to %d when it should be %d\n", directory_entries[j].inode, inode_num);
                        directory_entries[j].inode = inode_num;
                        set_directory_entry(i_info.i_block[i], j, directory_entries[j]);
                    }
                }
                if (!strncmp(names, "lost+found", directory_entries[j].name_len)){
                    lost_found = directory_entries[j].inode;
                }

                read_inode_info(directory_entries[j].inode, &dir_inode);
                if((dir_inode.i_mode & 0xf000) == 0x4000 && strcmp(names, ".")
                        && strcmp(names, ".."))
                    fix_directory_pointers(directory_entries[j].inode, inode_num);
            }

        }
    }
}

//Find disconnected subtrees in the directory tree and mark them except the root
void mark_subtrees(int inode_num){
    struct ext2_inode i_info;
    read_inode_info(inode_num, &i_info);
    if((i_info.i_mode & 0xf000) == 0x4000){
        int i, j;
        int num_entries;
        for(i = 0; i < 12; i++){
            if(i_info.i_block[i] == 0)
                continue;
            struct ext2_dir_entry_2 *directory_entries;
            int count;
            directory_entries = read_directory_block(i_info.i_block[i], &count);

            for (j = 0; j < count; j++){
                if (directory_entries[j].inode == 0)
                    continue;
                char names[255];
                int k;
                for(k = 0; k < directory_entries[j].name_len; k++){
                    names[k] = directory_entries[j].name[k];
                }
                names[k] = '\0';
                //printf("Marking inode %d\n", directory_entries[j].inode);
                if(strcmp(names, ".") && strcmp(names, ".."))
                    mark_actual_inode(directory_entries[j].inode);
            }

        }
    }
}

//Check if a given block is allocated else mark it as allocated
void mark_actual_block(int block_num){
    int block_group = (block_num - 1) / super.s_blocks_per_group;
    int block_index = (block_num - 1) % super.s_blocks_per_group;
    int block_byte_index = block_index / 8;
    int block_byte_offset = (block_index % 8);
    int mask = 1 << block_byte_offset;
    if((actual_block_bitmap[block_group][block_byte_index] & mask) == 0){
        if(block_num > 255)
            printf("Allocated block %d is not marked as allocated. Fixed\n", block_num);
        actual_block_bitmap[block_group][block_byte_index] |= mask; 
    }

}

//Write the block bitmap to disk
void persist_block_bitmap(){
    int i;
    int block_start;
    for (i = 0; i < number_block_groups; i++){
        block_start = read_bytes(group_descriptor_table, 32 * i, 4); 
        write_sectors(partition_start + (block_start * sectors_per_block), sectors_per_block, actual_block_bitmap[i]);
    }
}

//Function to traverse the directory tree
void traverse_directories(int inode_num, bool count_links, bool fix_blocks){
    mark_actual_inode(inode_num);   //Kepp track of the reachable inodes
    struct ext2_inode i_info;
    read_inode_info(inode_num, &i_info);

    if (link_count[inode_num] != 0 && !count_links){
        if (link_count[inode_num] != i_info.i_links_count){
            printf("Incorrect link count %d for inode %d. Should be %d.\n", 
                    i_info.i_links_count, inode_num, link_count[inode_num]);
            i_info.i_links_count = link_count[inode_num];
            write_inode_entry(inode_num, i_info);
        }
    }
    if((i_info.i_mode & 0xf000) == 0x4000){
        int i, j;
        int num_entries;
        for(i = 0; i < 12; i++){
            if(i_info.i_block[i] == 0)
                continue;
            if (fix_blocks)
                mark_actual_block(i_info.i_block[i]);
            struct ext2_dir_entry_2 *directory_entries;
            int count;
            directory_entries = read_directory_block(i_info.i_block[i], &count);

            for (j = 0; j < count; j++){
                if (directory_entries[j].inode == 0)
                    continue;
                struct ext2_inode dir_inode;
                char names[255];
                int k;
                mark_actual_inode(directory_entries[j].inode);
                if (count_links)
                    increment_link_count(directory_entries[j].inode);
                read_inode_info(directory_entries[j].inode, &dir_inode);
                for(k = 0; k < directory_entries[j].name_len; k++){
                    names[k] = directory_entries[j].name[k];
                }
                names[k] = '\0';
                if(strcmp(names, ".")
                        && strcmp(names, "..")){
                    traverse_directories(directory_entries[j].inode, count_links, fix_blocks);
                }
            }

        }
    }
    else if ((i_info.i_mode & 0xf000) == 0x8000){
        int i;
        mark_actual_inode(inode_num);
        for(i = 0; i < 12; i++){
            if(i_info.i_block[i] == 0)
                continue;
            if (fix_blocks)
                mark_actual_block(i_info.i_block[i]);
        }
        //Read singly indirect block
        int singly_indirect_block = i_info.i_block[12];
        if (singly_indirect_block != 0){
            //mark_actual_block(singly_indirect_block)
            indirect_traversal(0, 1, singly_indirect_block, fix_blocks);
        }

        //Read doubly indirect block
        int doubly_indirect_block = i_info.i_block[13];
        if (doubly_indirect_block != 0){
            //mark_actual_block(doubly_indirect_block);
            indirect_traversal(0, 2, doubly_indirect_block, fix_blocks);
        }

        //Read triply indirect block
        int triply_indirect_block = i_info.i_block[14];
        if (triply_indirect_block != 0){
            //mark_actual_block(triply_indirect_block);
            indirect_traversal(0, 3, triply_indirect_block, fix_blocks);
        }
    }

}

//Read directory blocks from a given block number and store number of entries in count
struct ext2_dir_entry_2* read_directory_block(int block_num, int *count){
    unsigned char buf[sector_size_bytes * sectors_per_block];
    read_sectors(partition_start + (sectors_per_block * block_num), sectors_per_block, buf);
    int offset = 0;
    int i;
    int j = 0;
    int current_size = 0;
    uint32_t inode_num;
    uint16_t dir_length;
    char name_len;
    char file_type;
    char names[255];
    struct ext2_dir_entry_2 *directories = (struct ext2_dir_entry_2*)malloc(sizeof(struct ext2_dir_entry_2));

    while(offset < (sectors_per_block * sector_size_bytes)){
        struct ext2_dir_entry_2 *entry = (struct ext2_dir_entry_2 *)malloc(sizeof(struct ext2_dir_entry_2));
        inode_num = read_bytes(buf, offset, 4);
        dir_length = read_bytes(buf, offset + 4, 2);
        name_len = read_bytes(buf, offset + 6, 1);
        file_type = read_bytes(buf, offset + 7, 1);

        entry->inode = inode_num;
        entry->rec_len = dir_length;
        entry->name_len = name_len;
        entry->file_type = file_type;
        for (i = 0; i < name_len; i++){
            names[i] = *(buf + offset + 8 + i);
            entry->name[i] = *(buf + offset + 8 + i);
        }
        names[i] = '\0';
        offset = offset + dir_length;
        directories = realloc(directories, (current_size + 1) * sizeof(struct ext2_dir_entry_2));
        current_size++;
        directories[j++] = *entry;
    }
    *count = j;
    return directories;
}

void read_sectors (int64_t start_sector, unsigned int num_sectors, void *into)
{
    ssize_t ret;
    int64_t lret;
    int64_t sector_offset;
    ssize_t bytes_to_read;

    sector_offset = start_sector * sector_size_bytes;

    if ((lret = lseek64(device, sector_offset, SEEK_SET)) != sector_offset) {
        fprintf(stderr, "Seek to position %"PRId64" failed: "
                "returned %"PRId64"\n", sector_offset, lret);
        exit(EX_IOERR);
    }

    bytes_to_read = sector_size_bytes * num_sectors;

    if ((ret = read(device, into, bytes_to_read)) != bytes_to_read) {
        fprintf(stderr, "Read sector %"PRId64" length %d failed: "
                "returned %"PRId64"\n", start_sector, num_sectors, ret);
        exit(EX_IOERR);
    }
}

void write_sectors (int64_t start_sector, unsigned int num_sectors, void *from)
{
    ssize_t ret;
    int64_t lret;
    int64_t sector_offset;
    ssize_t bytes_to_write;

    sector_offset = start_sector * sector_size_bytes;

    if ((lret = lseek64(device, sector_offset, SEEK_SET)) != sector_offset) {
        fprintf(stderr, "Seek to position %"PRId64" failed: "
                "returned %"PRId64"\n", sector_offset, lret);
        exit(EX_IOERR);
    }

    bytes_to_write = sector_size_bytes * num_sectors;

    if ((ret = write(device, from, bytes_to_write)) != bytes_to_write) {
        fprintf(stderr, "Write sector %"PRId64" length %d failed: "
                "returned %"PRId64"\n", start_sector, num_sectors, ret);
        exit(EX_IOERR);
    }
}

//Store details about partition part_number in struct pointed to by data
void get_partition_details(int part_number, p_metadata *data){
    if (part_number < 0) {
        data->part_type = -1;
        return ;
    }
    int curr_part_number = 0;
    int curr_sector = 0; 
    unsigned char buf[sector_size_bytes];
    int ebr_start_lba = 0;
    int prev_ebr_lba = 0;
    int prev_sector = 0;
    int part_start;
    int part_length;
    unsigned char part_type;

    while (curr_part_number <= part_number) {
        read_sectors(curr_sector, 1, buf);
        prev_sector = curr_sector;
        int i;
        for (i = 0; i < 4; i++){
            part_type = get_partition_type(buf, i);

            //Check if partition 2 is not EBR, then break
            if (curr_sector != 0 && i == 1 && part_type != 0x05)
                break;
            if (!(part_type == 0x05 && curr_sector != 0)){  //Increment counter if not EBR in sector 0
                curr_part_number++;
                if (curr_part_number > part_number) {
                    data->part_type = -1;
                    return;
                }
            }
            if (curr_part_number == part_number) {
                part_start = (prev_sector == 0 ? 0 : curr_sector) + get_partition_start(buf, i);
                part_length = get_partition_length(buf, i);
                data->part_type = part_type;
                data->partition_start = part_start;
                data->partition_length = part_length;
                return;
            }
            if (part_type == 0x05 && curr_sector == 0) {
                ebr_start_lba = get_partition_start(buf, i);
                prev_ebr_lba = ebr_start_lba;
                prev_sector = curr_sector;
                curr_sector = ebr_start_lba;
            }
            else if (part_type == 0x05 && curr_sector != 0) {
                prev_ebr_lba = get_partition_start(buf, i);
                prev_sector = curr_sector;
                curr_sector = ebr_start_lba + prev_ebr_lba;
                break;
            }
        }
        if (curr_sector == prev_sector)
            break;
    } 
    if (curr_part_number < part_number) {
        data->part_type = -1;
        return;
    }
}

//Assume least significant byte in buf[3]
int convert_bytes_to_uint32 (unsigned char *buf) {
    return buf[3] + (buf[2] << 8) + (buf[1] << 16) + (buf[0] << 24);
}

//Assume least significant byte in buf[1]
int convert_bytes_to_uint16 (unsigned char *buf) {
    return buf[1] + (buf[0] << 8);
}

//Assume least significant byte in buf[1]
unsigned char convert_bytes_to_byte (unsigned char *buf) {
    return buf[0];
}

int read_bytes (unsigned char *sector, int offset, int num_bytes) {
    unsigned char buf[4];
    int i;
    for (i = num_bytes - 1; i >= 0; i--){
        buf[i] = sector[offset++];
    }
    if (num_bytes == 2)
        return convert_bytes_to_uint16(buf);
    else if (num_bytes == 4)
        return convert_bytes_to_uint32(buf);
    else
        return convert_bytes_to_byte(buf);
}

int get_partition_length (unsigned char *sector, int part_num) {
    int byte_offset = 446 + (part_num) * 16 + 12;
    return read_bytes(sector, byte_offset, 4);
}

int get_partition_start (unsigned char *sector, int part_num) {
    int byte_offset = 446 + (part_num) * 16 + 8;
    return read_bytes(sector, byte_offset, 4);
}

int get_magic_number (unsigned char *sector) {
    unsigned char buf[2];
    int byte_offset = 56;
    return read_bytes(sector, byte_offset, 2);
}

unsigned char get_partition_type (unsigned char *sector, int part_num) {
    return sector[446 + (part_num) * 16 + 4];
}

//Read superblock info
void read_superblock_info(int part_number, struct ext2_super_block *superblock) {
    unsigned char buf[sector_size_bytes];
    p_metadata part_detail;
    get_partition_details(part_number, &part_detail);
    read_sectors(part_detail.partition_start + 2, 1, buf);
    superblock->s_inodes_count = read_bytes(buf, 0, 4);
    superblock->s_blocks_count = read_bytes(buf, 4, 4);
    superblock->s_free_blocks_count = read_bytes(buf, 12, 4);
    superblock->s_free_inodes_count = read_bytes(buf, 16, 4);
    superblock->s_log_block_size = read_bytes(buf, 24, 4);
    superblock->s_blocks_per_group = read_bytes(buf, 32, 4);
    superblock->s_inodes_per_group = read_bytes(buf, 40, 4);
    superblock->s_magic = read_bytes(buf, 56, 4);
    superblock->s_inode_size = read_bytes(buf, 88, 2);
    return;
}

//Read group descriptor info into memory location pointed to by gd_info
void read_gd_info(int block_group, struct ext2_group_desc *gd_info) {
    int offset = block_group * 32;
    gd_info->bg_block_bitmap = read_bytes(group_descriptor_table, offset+0, 4);
    gd_info->bg_inode_bitmap = read_bytes(group_descriptor_table, offset+4, 4);
    gd_info->bg_inode_table = read_bytes(group_descriptor_table, offset+8, 4);
    gd_info->bg_free_blocks_count = read_bytes(group_descriptor_table, offset+12, 2);
    gd_info->bg_free_inodes_count = read_bytes(group_descriptor_table, offset+14, 2);
    return;
}

uint32_t get_inode_sector_offset(uint32_t inode_size, uint32_t inode_index) {
    return inode_index/(sector_size_bytes/inode_size);
}

//Read inode info into memory location pointed to by i_info
void read_inode_info(uint32_t inode_num, struct ext2_inode *i_info) {
    int block_group = (inode_num - 1) / super.s_inodes_per_group;
    struct ext2_group_desc gd_info;
    read_gd_info(block_group, &gd_info);
    uint32_t inode_table_start = gd_info.bg_inode_table;
    int inode_index = (inode_num - 1) % super.s_inodes_per_group;
    unsigned char buf[sector_size_bytes];
    read_sectors(partition_start + (inode_table_start * sectors_per_block) + get_inode_sector_offset(super.s_inode_size, inode_index), 
            1, buf);
    uint32_t num_inodes_sector = sector_size_bytes / super.s_inode_size;
    uint32_t offset = ((inode_index % num_inodes_sector)) * super.s_inode_size; 
    i_info->i_mode = read_bytes(buf, offset + 0, 2);
    i_info->i_size = read_bytes(buf, offset + 4, 4);
    i_info->i_links_count = read_bytes(buf, offset + 26, 2);
    int i;
    for(i = 0; i < 15; i++){
        i_info->i_block[i] = read_bytes(buf, offset + 40 + (i * 4), 4);
    }    
}

//Check if inode has been allocated
bool inode_allocated(uint32_t inode_num, char **bitmap) {
    int block_group = (inode_num - 1) / super.s_inodes_per_group;
    int offset = block_group * 32;
    int inode_index = (inode_num - 1) % super.s_inodes_per_group;
    int inode_byte_index = inode_index / 8;
    int inode_byte_offset = inode_index % 8;

    unsigned char buf[sector_size_bytes * sectors_per_block];
    uint32_t bitmap_block = read_bytes(group_descriptor_table, offset + 4, 4);
    if(!bitmap)
        read_sectors(partition_start + (bitmap_block * sectors_per_block), sectors_per_block, buf);
    else{
        memcpy(buf, bitmap[block_group], sector_size_bytes * sectors_per_block);
    }
    unsigned char bitmap_byte = read_bytes(buf, inode_byte_index, 1);
    if (bitmap_byte & (1 << (inode_byte_offset)))
        return true;
    else
        return false;
}

